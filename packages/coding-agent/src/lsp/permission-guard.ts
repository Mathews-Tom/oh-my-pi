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
import { scanDenialMessage, scanOpaqueArguments } from "../tools/permissions/scan";
import type { PathTarget, PermissionRoots } from "../tools/permissions/types";
import type { Command, WorkspaceEdit } from "./types";
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
 * Refuse to execute a `workspace/executeCommand` whose arguments reference a
 * denied path. A command's real filesystem surface is not statically
 * declared — the server can do anything with it — so this is the same
 * best-effort literal scan an opaque tool (`bash`, `eval`, …) gets, over the
 * command name and its argument list, honouring `permissions.opaqueToolScan`
 * exactly as the top-level gate does for every other opaque call.
 */
export function assertLspCommandAllowed(
	command: Command,
	context: AgentToolContext | undefined,
	toolName: string,
): void {
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
	throw new PermissionDeniedError(toolName, hit.rule, scanDenialMessage(toolName, hit));
}
