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
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { loadPermissionsConfig } from "../tools/permissions/config";
import { checkStructuredTargets, PermissionDeniedError, permissionRoots } from "../tools/permissions/gate";
import { decideTarget } from "../tools/permissions/resolve";
import { scanDenialMessage, scanOpaqueArguments } from "../tools/permissions/scan";
import type { PathTarget, PermissionRoots } from "../tools/permissions/types";
import type { Command, Location, WorkspaceEdit } from "./types";
import { uriToFile } from "./utils";

function collectWorkspaceEditUris(edit: WorkspaceEdit): string[] {
	const uris = new Set<string>();
	if (edit.changes) {
		for (const uri in edit.changes) uris.add(uri);
	}
	if (edit.documentChanges) {
		for (const change of edit.documentChanges) {
			if ("textDocument" in change && change.textDocument) {
				uris.add(change.textDocument.uri);
			} else if ("kind" in change && change.kind) {
				if (change.kind === "create") {
					uris.add(change.uri);
				} else if (change.kind === "rename") {
					uris.add(change.oldUri);
					uris.add(change.newUri);
				} else if (change.kind === "delete") {
					uris.add(change.uri);
				}
			}
		}
	}
	return [...uris];
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
 * would have been.
 */
export function assertWorkspaceEditAllowed(
	edit: WorkspaceEdit,
	context: AgentToolContext | undefined,
	toolName: string,
): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return;
	const roots = requireRootsOrDeny(toolName, policy.profile, permissionRoots(context));
	const targets: PathTarget[] = collectWorkspaceEditUris(edit).map(uri => ({
		raw: uriToFile(uri),
		access: "write",
		field: "workspaceEdit",
	}));
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
