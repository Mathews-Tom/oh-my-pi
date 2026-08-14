/**
 * Resource-permission enforcement for LSP-applied workspace edits and
 * executed workspace commands.
 *
 * `extractLspPaths` (`tools/permissions/tool-path-targets.ts`) only sees the
 * declared `file`/`new_name` arguments of an `lsp` call — sound for the
 * request, but a `rename` or an applied `code_actions` result returns a
 * server-computed `WorkspaceEdit` that can touch any URI (creates, renames,
 * deletes, or a multi-file `TextDocumentEdit`), and `applyWorkspaceEdit`
 * writes every one of them without passing back through the tool gate. A
 * code action can also execute an arbitrary `workspace/executeCommand`
 * whose filesystem surface is not declared anywhere. Both are gated here,
 * at the exact call sites in `lsp/index.ts` that apply them, since the
 * server response — not the declared request — is what needs checking.
 */
import type { Dirent } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { loadPermissionsConfig } from "../tools/permissions/config";
import { checkStructuredTargets, PermissionDeniedError, permissionRoots } from "../tools/permissions/gate";
import { decideTarget } from "../tools/permissions/resolve";
import { scanDenialMessage, scanOpaqueArguments } from "../tools/permissions/scan";
import type { PathTarget, PermissionRoots } from "../tools/permissions/types";
import type { Command, DocumentChange, Location, SymbolInformation, TextEdit, WorkspaceEdit } from "./types";
import { uriToFile } from "./utils";

/**
 * Every URI a `WorkspaceEdit` touches, split by how `applyWorkspaceEdit`
 * (`lsp/edits.ts`) actually applies it: a text edit (`edit.changes` map entry
 * or a `TextDocumentEdit`'s `textDocument.uri`) calls `applyTextEdits`, which
 * reads the whole file before rewriting it; `create` writes empty content
 * with nothing to read; `rename`/`delete` use `fs.rename`/`fs.rm` — neither
 * reads the file's content either. `create` and `rename` are kept apart from
 * a flat URI list (rather than folded into one `resourceOpUris`) because
 * each needs its own descendant enumeration: a `create`/`rename` can
 * implicitly create missing parent directories, and a directory `rename`
 * moves an entire subtree in one syscall — see
 * {@link collectMissingParentTargets} and
 * {@link collectDirectoryRenameDescendantTargets}.
 */
function collectWorkspaceEditUris(edit: WorkspaceEdit): {
	textEditUris: string[];
	createUris: string[];
	renamePairs: Array<{ oldUri: string; newUri: string }>;
	deleteUris: string[];
} {
	const textEditUris = new Set<string>();
	const createUris = new Set<string>();
	const renamePairs: Array<{ oldUri: string; newUri: string }> = [];
	const deleteUris = new Set<string>();
	if (edit.changes) {
		for (const uri in edit.changes) textEditUris.add(uri);
	}
	if (edit.documentChanges) {
		for (const change of edit.documentChanges) {
			if ("textDocument" in change && change.textDocument) {
				textEditUris.add(change.textDocument.uri);
			} else if ("kind" in change && change.kind) {
				if (change.kind === "create") {
					createUris.add(change.uri);
				} else if (change.kind === "rename") {
					renamePairs.push({ oldUri: change.oldUri, newUri: change.newUri });
				} else if (change.kind === "delete") {
					deleteUris.add(change.uri);
				}
			}
		}
	}
	return {
		textEditUris: [...textEditUris],
		createUris: [...createUris],
		renamePairs,
		deleteUris: [...deleteUris],
	};
}

/**
 * Every file inside `directoryUri`, recursively, as write-access targets —
 * the concrete files `fs.rm(dirPath, { recursive: true })`
 * (`applyWorkspaceEdit`, `lsp/edits.ts`) actually removes. A `delete`
 * resource op names only the directory URI itself, so authorizing that one
 * URI alone lets the recursive removal take a write-denied descendant
 * (`config/.env` under an allowed `config/`) with it, unchecked. Mirrors
 * `enumerateRenamePairs` (`lsp/tool.ts`) — the same gap already closed for a
 * directory *rename*. Returns no targets (rather than throwing) for a
 * non-directory or unreadable URI: a plain-file delete is already fully
 * authorized by its own URI, and a directory that vanished between the
 * edit's computation and this check has nothing left to enumerate.
 */
async function collectDirectoryDeleteTargets(directoryUri: string): Promise<PathTarget[]> {
	const directoryPath = uriToFile(directoryUri);
	try {
		if (!(await stat(directoryPath)).isDirectory()) return [];
	} catch {
		return [];
	}
	let entries: Dirent[];
	try {
		entries = await readdir(directoryPath, { recursive: true, withFileTypes: true });
	} catch {
		return [];
	}
	const targets: PathTarget[] = [];
	for (const entry of entries) {
		targets.push({
			raw: path.join(entry.parentPath ?? directoryPath, entry.name),
			access: "write",
			field: "workspaceEdit",
		});
	}
	return targets;
}

/**
 * Every missing ancestor directory `fs.mkdir(path.dirname(filePath), {
 * recursive: true })` (`applyWorkspaceEdit`) would create, as write-access
 * targets — walked from `filePath`'s parent up to the first existing
 * ancestor. `applyWorkspaceEdit` runs this unconditionally for both `create`
 * and `rename` (against the new path), so a rule like
 * `permissions.deny.write: ["**\/blocked"]` that only ever sees the leaf
 * file (`blocked/file.ts`, which the glob does not match) never catches the
 * denied directory itself being created on the way to writing that file.
 * Returns no targets once an ancestor already exists — nothing further up
 * the chain would be created either.
 */
async function collectMissingParentTargets(filePath: string): Promise<PathTarget[]> {
	const targets: PathTarget[] = [];
	let dir = path.dirname(filePath);
	for (;;) {
		try {
			await stat(dir);
			break;
		} catch {
			// Missing — fs.mkdir(dir, { recursive: true }) would create it.
		}
		targets.push({ raw: dir, access: "write", field: "workspaceEdit" });
		const parent = path.dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	return targets;
}

/**
 * When `oldUri` resolves to an existing directory, every file inside it
 * recursively, as a pair of write-access targets — one at its source path,
 * one at its projected destination under `newUri` — the concrete files
 * `fs.rename(oldPath, newPath)` (`applyWorkspaceEdit`) actually moves as one
 * subtree when the resource op names a directory rather than a single file.
 * A `rename` resource op names only the two directory URIs, so authorizing
 * those alone lets the whole-subtree move take a write-denied descendant
 * (`tree/private.key` under an allowed `tree/`) with it, unchecked. Mirrors
 * `enumerateRenamePairs` (`lsp/tool.ts`), the same gap already closed for the
 * dedicated `rename_file` action. Returns no targets for a non-directory or
 * unreadable `oldUri`: a plain-file rename is already fully authorized by
 * its own oldUri/newUri.
 */
async function collectDirectoryRenameDescendantTargets(oldUri: string, newUri: string): Promise<PathTarget[]> {
	const oldPath = uriToFile(oldUri);
	const newPath = uriToFile(newUri);
	try {
		if (!(await stat(oldPath)).isDirectory()) return [];
	} catch {
		return [];
	}
	let entries: Dirent[];
	try {
		entries = await readdir(oldPath, { recursive: true, withFileTypes: true });
	} catch {
		return [];
	}
	const targets: PathTarget[] = [];
	for (const entry of entries) {
		if (!entry.isFile()) continue;
		const absOld = path.join(entry.parentPath ?? oldPath, entry.name);
		const rel = path.relative(oldPath, absOld);
		targets.push({ raw: absOld, access: "write", field: "workspaceEdit" });
		targets.push({ raw: path.join(newPath, rel), access: "write", field: "workspaceEdit" });
	}
	return targets;
}

function requireRootsOrDeny(toolName: string, profile: string, roots: PermissionRoots | null): PermissionRoots {
	if (roots) return roots;
	throw new PermissionDeniedError(
		toolName,
		"permissions.profile",
		`Tool "${toolName}" is blocked: permissions.profile is "${profile}" but this call has no session, ` +
			`so the workspace roots the rules are measured against cannot be determined.\n` +
			`To allow it: set permissions.profile: off.`,
	);
}

/**
 * Refuse to apply a workspace edit that touches a path the resource
 * permission layer denies. No-ops under `permissions.profile: off`,
 * mirroring the gate's own short-circuit. Every URI is checked as a write —
 * applying an edit always mutates, whatever the source file's own access
 * would have been. A text-edit target is also checked for `read`:
 * `applyTextEdits` reads the whole file before rewriting it, so a target
 * that is write-allowed but read-denied would otherwise let the edit's
 * server-computed content bypass `permissions.deny.read`. `create` and
 * `rename` additionally authorize every missing parent directory
 * `applyWorkspaceEdit`'s `fs.mkdir(…, { recursive: true })` would create,
 * and a directory `rename` additionally authorizes every descendant the
 * underlying `fs.rename` moves as one subtree — both filesystem side
 * effects a flat URI check alone would miss.
 */
export async function assertWorkspaceEditAllowed(
	edit: WorkspaceEdit,
	context: AgentToolContext | undefined,
	toolName: string,
): Promise<void> {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return;
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	const { textEditUris, createUris, renamePairs, deleteUris } = collectWorkspaceEditUris(edit);
	const [deleteDescendantTargets, createParentTargets, renameParentTargets, renameDescendantTargets] =
		await Promise.all([
			Promise.all(deleteUris.map(collectDirectoryDeleteTargets)).then(groups => groups.flat()),
			Promise.all(createUris.map(uri => collectMissingParentTargets(uriToFile(uri)))).then(groups => groups.flat()),
			Promise.all(renamePairs.map(pair => collectMissingParentTargets(uriToFile(pair.newUri)))).then(groups =>
				groups.flat(),
			),
			Promise.all(renamePairs.map(pair => collectDirectoryRenameDescendantTargets(pair.oldUri, pair.newUri))).then(
				groups => groups.flat(),
			),
		]);
	const targets: PathTarget[] = [
		...textEditUris.flatMap(uri => [
			{ raw: uriToFile(uri), access: "write" as const, field: "workspaceEdit" },
			{ raw: uriToFile(uri), access: "read" as const, field: "workspaceEdit" },
		]),
		...createUris.map(uri => ({ raw: uriToFile(uri), access: "write" as const, field: "workspaceEdit" })),
		...renamePairs.flatMap(pair => [
			{ raw: uriToFile(pair.oldUri), access: "write" as const, field: "workspaceEdit" },
			{ raw: uriToFile(pair.newUri), access: "write" as const, field: "workspaceEdit" },
		]),
		...deleteUris.map(uri => ({ raw: uriToFile(uri), access: "write" as const, field: "workspaceEdit" })),
		...deleteDescendantTargets,
		...createParentTargets,
		...renameParentTargets,
		...renameDescendantTargets,
	];
	const denial = checkStructuredTargets(targets, policy, roots);
	if (denial) throw new PermissionDeniedError(toolName, denial.rule, denial.reason);
}

/**
 * Refuse to read diagnostics for any file a glob/`*` `diagnostics` target
 * expanded to. `extractLspPaths` only sees the declared `file` argument
 * literally — a glob like `src/**\/*.ts` or the workspace sentinel `*`
 * checks that string itself, not the concrete files `resolveDiagnosticTargets`
 * expands it to and `refreshFile` then opens. Checked here, against the
 * expanded list, before any of them is opened.
 */
export function assertDiagnosticTargetsAllowed(
	resolvedTargets: readonly string[],
	context: AgentToolContext | undefined,
	toolName: string,
): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return;
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	const targets: PathTarget[] = resolvedTargets.map(raw => ({ raw, access: "read", field: "file" }));
	const denial = checkStructuredTargets(targets, policy, roots);
	if (denial) throw new PermissionDeniedError(toolName, denial.rule, denial.reason);
}

/**
 * Whether an active resource permission policy has read restrictions
 * (`permissions.deny.read` rules or `permissions.confineReads`) that a
 * project-aware LSP server (tsserver, rust-analyzer, …) must not be exposed
 * to via eager/lazy indexing — see every warmup/sync helper that lazily
 * creates a client mid-write or at startup.
 */
export function isLspReadRestricted(context: AgentToolContext | undefined): boolean {
	const policy = loadPermissionsConfig(context?.settings);
	return !!policy && (policy.deny.read.length > 0 || policy.confineReads);
}

/**
 * Refuse to run workspace-wide `diagnostics` (`file: "*"`) under a policy
 * that denies specific paths from being read. This branch spawns an actual
 * compiler (`tsc`, `cargo check`, `go build`, `pyright`, …) over the whole
 * project - unlike a glob, its real read surface cannot be expanded to a
 * finite list and authorized the way {@link assertDiagnosticTargetsAllowed}
 * checks a glob's matches, so there is no sound way to let it run while
 * still keeping a denied file's content (or even its diagnostics) out of
 * the compiler's output. Fails closed rather than risk that leak; a caller
 * that needs diagnostics under a profile with active read-deny rules must
 * scope the call to a specific file or glob instead of `*`.
 */
export function assertWorkspaceDiagnosticsAllowed(context: AgentToolContext | undefined, toolName: string): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy || (policy.deny.read.length === 0 && !policy.confineReads)) return;
	throw new PermissionDeniedError(
		toolName,
		"permissions.deny.read",
		`Tool "${toolName}" is blocked: workspace-wide diagnostics (file: "*") spawn a compiler whose real read ` +
			`surface cannot be limited to authorized paths, and permissions.profile: ${policy.profile} has active ` +
			`permissions.deny.read rule(s) or permissions.confineReads: true.\n` +
			`To allow it: scope the call to a specific file or glob instead of "*", or set permissions.profile: off.`,
	);
}

/**
 * Refuse a targetless LSP action that starts every configured language
 * server under a policy that denies specific paths from being read.
 * `capabilities` (with no `file`) and `reload *` both iterate every
 * configured server and call the client resolver directly — bypassing
 * `extractLspPaths` entirely, since neither declares a `file` argument for
 * the pre-execution gate to check — so a project-aware server would start
 * and index the whole restricted workspace with no check anywhere. Fails
 * closed the same way {@link assertWorkspaceDiagnosticsAllowed} does for
 * workspace-wide diagnostics.
 */
export function assertLspStartupAllowed(context: AgentToolContext | undefined, toolName: string): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy || (policy.deny.read.length === 0 && !policy.confineReads)) return;
	throw new PermissionDeniedError(
		toolName,
		"permissions.deny.read",
		`Tool "${toolName}" is blocked: this action starts every configured language server, including ` +
			`project-aware ones whose real read surface (workspace indexing via project references) cannot be ` +
			`limited to authorized paths, and permissions.profile: ${policy.profile} has active permissions.deny.read ` +
			`rule(s) or permissions.confineReads: true.\n` +
			`To allow it: scope the call to a specific file, or set permissions.profile: off.`,
	);
}

/**
 * Filter `definition`/`type_definition`/`implementation`/`references`
 * locations down to ones the resource permission policy allows reading. The
 * declared `file` argument is checked before the request goes out, but the
 * server-returned locations can land in an entirely different file -
 * `formatLocationWithContext` opens each one directly to render surrounding
 * source, so a symbol defined in (or referenced from) a path matching
 * `permissions.deny.read` would otherwise surface that file's content
 * through the allowed source's own navigation result. Filtered rather than
 * denying the whole call, matching how a recursive search tool (`grep`,
 * `glob`) drops individual denied entries instead of failing outright.
 */
export function filterAuthorizedLocations(
	locations: readonly Location[],
	context: AgentToolContext | undefined,
	toolName: string,
): Location[] {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return [...locations];
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	return locations.filter(
		location =>
			decideTarget({ raw: uriToFile(location.uri), access: "read", field: "location" }, policy, roots).kind !==
			"deny",
	);
}

/**
 * Filter workspace-symbol (`action: "symbols"` with `file: "*"` or omitted)
 * results down to ones the resource permission policy allows reading. The
 * declared `file`/`*` argument is checked before the request goes out, but
 * `workspace/symbol` returns server-provided symbols from arbitrary files
 * across the project - `formatSymbolInformation` surfaces each result's
 * `location.uri`, so a symbol defined in a file matching
 * `permissions.deny.read` (e.g. `private.ts`) would otherwise be surfaced
 * despite the read rule. Filtered rather than denying the whole call,
 * matching {@link filterAuthorizedLocations}.
 */
export function filterAuthorizedSymbols(
	symbols: readonly SymbolInformation[],
	context: AgentToolContext | undefined,
	toolName: string,
): SymbolInformation[] {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return [...symbols];
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	return symbols.filter(
		symbol =>
			decideTarget({ raw: uriToFile(symbol.location.uri), access: "read", field: "location" }, policy, roots)
				.kind !== "deny",
	);
}

/**
 * Filter a server-returned `WorkspaceEdit`'s entries down to ones the
 * resource permission policy allows reading, for use only when
 * *previewing* (`apply: false`) rather than applying it. `formatWorkspaceEdit`
 * renders every entry's path directly into the model-visible output, so a
 * `rename`/`rename_file` preview would otherwise expose a path matching
 * `permissions.deny.read` even though {@link assertWorkspaceEditAllowed}
 * blocks the same edit from actually being applied. Filtered rather than
 * denying the whole preview, matching {@link filterAuthorizedLocations}. A
 * `rename`/`create`/`delete` resource op is dropped unless every URI it
 * names is allowed, since a partial preview of a paired rename would
 * misrepresent what applying it does.
 */
export function filterAuthorizedWorkspaceEditForPreview(
	edit: WorkspaceEdit,
	context: AgentToolContext | undefined,
	toolName: string,
): WorkspaceEdit {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return edit;
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	const isAllowed = (uri: string): boolean =>
		decideTarget({ raw: uriToFile(uri), access: "read", field: "workspaceEdit" }, policy, roots).kind !== "deny";

	const filtered: WorkspaceEdit = {};
	if (edit.changes) {
		const changes: Record<string, TextEdit[]> = {};
		for (const [uri, edits] of Object.entries(edit.changes)) {
			if (isAllowed(uri)) changes[uri] = edits;
		}
		filtered.changes = changes;
	}
	if (edit.documentChanges) {
		filtered.documentChanges = edit.documentChanges.filter((change: DocumentChange) => {
			if ("textDocument" in change && change.textDocument) return isAllowed(change.textDocument.uri);
			if ("kind" in change && change.kind) {
				if (change.kind === "create") return isAllowed(change.uri);
				if (change.kind === "rename") return isAllowed(change.oldUri) && isAllowed(change.newUri);
				if (change.kind === "delete") return isAllowed(change.uri);
			}
			return true;
		});
	}
	if (edit.changeAnnotations) filtered.changeAnnotations = edit.changeAnnotations;
	return filtered;
}

/**
 * Refuse to execute a `workspace/executeCommand` whose arguments reference a
 * denied path. A command's real filesystem surface is not statically
 * declared — the server can do anything with it — so this is the same
 * best-effort literal scan an opaque tool (`bash`, `eval`, …) gets, over the
 * command name and its argument list, honouring `permissions.opaqueToolScan`
 * exactly as the top-level gate does for every other opaque call.
 *
 * `prompt` mode is honoured interactively when `context.ui`/`context.hasUI`
 * are available (the caller confirms or denies the specific command), since
 * this scan runs mid-execution — after the server has already returned the
 * command — with no path back through the wrapper's own approval prompt.
 * Without a live UI (a headless caller — subagent, `-p`, RPC, ACP) this
 * fails closed rather than silently waving the command through, matching
 * the wrapper's own no-interactive-UI behaviour for a required approval.
 */
export async function assertLspCommandAllowed(
	command: Command,
	context: AgentToolContext | undefined,
	toolName: string,
): Promise<void> {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy || policy.opaqueToolScan === "off") return;
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	const hit = scanOpaqueArguments(
		{ command: command.command, arguments: command.arguments },
		"strings",
		policy,
		roots,
	);
	if (!hit) return;
	const message = scanDenialMessage(toolName, hit);
	if (policy.opaqueToolScan === "prompt") {
		if (context?.hasUI && context.ui) {
			const approved = await context.ui.confirm(`${toolName}: workspace command needs approval`, message);
			if (approved) return;
			throw new PermissionDeniedError(toolName, hit.rule, `${message}\n\nDenied by user.`);
		}
		throw new PermissionDeniedError(
			toolName,
			hit.rule,
			`${message}\n\npermissions.opaqueToolScan: prompt requires an interactive UI to confirm a workspace ` +
				`command mid-execution; none is available here, so this fails closed.\n` +
				`To allow it: add "${hit.rule}" to permissions.allow.${hit.access}, or set permissions.opaqueToolScan: off.`,
		);
	}
	throw new PermissionDeniedError(toolName, hit.rule, message);
}
