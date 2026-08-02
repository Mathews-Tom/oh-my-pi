/**
 * The enforcement point.
 *
 * This runs unconditionally in `ExtensionToolWrapper.execute`, before the
 * approval prompt is computed and independent of `tools.approvalMode`. That
 * placement is the whole design: subagents force `tools.approvalMode: yolo`
 * (`task/executor.ts`), so a guard expressed as an approval tier or a fourth
 * mode is bypassed by spawning a `task`. A hard check here is not.
 *
 * It can only ever refuse. There is no branch that returns "approved", so no
 * permissions setting can promote a call past `tools.approval`.
 *
 * One seam is deliberately outside the boundary: `ctx.invokeTool` delegates to
 * the *unwrapped* native tool (`extensibility/extensions/runner.ts`) so a
 * wrapper extension inherits the approval its own call already cleared. That
 * path is not re-gated here, so an installed extension re-registering a
 * built-in sits inside the trust boundary. The `xd://` device route is fine —
 * it dispatches through the wrapped inner tool.
 */
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { FileType, glob } from "@oh-my-pi/pi-natives";
import { loadPermissionsConfig } from "./config";
import { decideTarget } from "./resolve";
import { scanDenialMessage, scanOpaqueArguments } from "./scan";
import { classifyTool } from "./tool-path-targets";
import type { PathTarget, PermissionPolicy, PermissionRoots } from "./types";

/** Raised when a tool call is refused by a resource permission rule. */
export class PermissionDeniedError extends Error {
	constructor(
		readonly toolName: string,
		readonly rule: string,
		message: string,
	) {
		super(message);
		this.name = "PermissionDeniedError";
	}
}

function toArgsRecord(params: unknown): Record<string, unknown> | null {
	if (!params || typeof params !== "object" || Array.isArray(params)) return null;
	return params as Record<string, unknown>;
}

/**
 * The roots confinement measures against, taken from the live session rather
 * than from settings.
 *
 * A worktree subagent is created with `workspace.additionalDirectories: []`
 * and its own cwd (`task/executor.ts`), and `/add-dir` mutates the session, so
 * the session manager is the only source that reflects both.
 *
 * `null` when there is no session manager: falling back to `process.cwd()`
 * would measure containment against whatever directory the process happens to
 * sit in, which can silently *widen* the boundary. Callers treat that as a
 * denial instead.
 */
export function permissionRoots(context: AgentToolContext | undefined): PermissionRoots | null {
	const manager = context?.sessionManager;
	if (!manager) return null;
	return { cwd: manager.getCwd(), additionalDirectories: manager.getAdditionalDirectories() };
}

/**
 * Evaluate the declared path arguments of one tool call.
 *
 * Returns the first denial, or `null` when every target passes. Exported for
 * tests and for the opaque scan, which shares the same decision procedure.
 */
export function checkStructuredTargets(
	targets: readonly PathTarget[],
	policy: PermissionPolicy,
	roots: PermissionRoots,
): { target: PathTarget; rule: string; reason: string } | null {
	for (const target of targets) {
		const decision = decideTarget(target, policy, roots);
		if (decision.kind === "deny") return { target, rule: decision.rule, reason: decision.reason };
	}
	return null;
}

/**
 * Return the normalized file candidates a native recursive search may open.
 *
 * The initial native `glob` is metadata-only. Each candidate then passes the
 * same read decision as declared targets before its relative path enters the
 * native search allowlist. A path absent from the returned list is never opened
 * by the subsequent `grep` or `ast_grep` call.
 */
export async function collectPermittedSearchPaths(
	searchPath: string,
	globFilter: string | undefined,
	recursive: boolean,
	useGitignore: boolean,
	context: AgentToolContext | undefined,
	signal?: AbortSignal,
): Promise<string[] | undefined> {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return undefined;

	const roots = permissionRoots(context);
	if (!roots) {
		throw new PermissionDeniedError(
			"search",
			"permissions.profile",
			`Search is blocked: permissions.profile is "${policy.profile}" but this call has no session, so the ` +
				`workspace roots the rules are measured against cannot be determined.\n` +
				`To allow it: set permissions.profile: off.`,
		);
	}
	const metadata = await Bun.file(searchPath).stat();
	if (!metadata.isDirectory()) return undefined;

	const candidates = await glob({
		pattern: globFilter ?? "**/*",
		path: searchPath,
		fileType: FileType.File,
		recursive,
		hidden: true,
		gitignore: useGitignore,
		includeNodeModules: globFilter?.includes("node_modules"),
		signal,
	});
	return candidates.matches
		.filter(candidate => {
			const target: PathTarget = {
				raw: path.resolve(searchPath, candidate.path),
				access: "read",
				field: "path",
			};
			return decideTarget(target, policy, roots).kind === "allow";
		})
		.map(candidate => candidate.path);
}

/**
 * Outcome of the gate.
 *
 * `null` means "the gate has nothing to say" — the call proceeds exactly as it
 * would have. A string is a reason the caller must turn into an interactive
 * confirmation. There is deliberately no "approved" outcome: this layer can
 * add a prompt or refuse outright, never remove either.
 */
export type PermissionGateResult = string | null;

/**
 * Refuse — or, for an opaque tool under `opaqueToolScan: prompt`, gate — a call
 * that reaches an off-limits path.
 *
 * Short-circuits on `permissions.profile: off` after a single settings read,
 * so the default configuration does no filesystem work and allocates nothing.
 */
export function enforceResourcePermissions(
	toolName: string,
	params: unknown,
	context: AgentToolContext | undefined,
): PermissionGateResult {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return null;

	const args = toArgsRecord(params);
	const toolClass = classifyTool(toolName, args);
	if (toolClass.kind === "pathless") return null;

	const roots = permissionRoots(context);
	if (!roots) {
		throw new PermissionDeniedError(
			toolName,
			"permissions.profile",
			`Tool "${toolName}" is blocked: permissions.profile is "${policy.profile}" but this call has no ` +
				`session, so the workspace roots the rules are measured against cannot be determined.\n` +
				`To allow it: set permissions.profile: off.`,
		);
	}

	// `opaqueToolScan` decides the outcome for both the opaque class and a
	// structured tool whose payload is not the object its schema declares.
	const scanOutcome = (scan: "shell" | "strings"): PermissionGateResult => {
		if (policy.opaqueToolScan === "off") return null;
		const hit = scanOpaqueArguments(params, scan, policy, roots);
		if (!hit) return null;
		const message = scanDenialMessage(toolName, hit);
		if (policy.opaqueToolScan === "prompt") return message;
		throw new PermissionDeniedError(toolName, hit.rule, message);
	};

	if (toolClass.kind === "opaque") return scanOutcome(toolClass.scan);

	if (!args) {
		// A structured tool always takes an object, so a non-object payload
		// means the declared shape does not apply — a tool with
		// `lenientArgValidation` reaches `execute` unvalidated. Fall through to
		// the literal scan rather than allowing something whose declared
		// targets cannot be read.
		return scanOutcome("strings");
	}

	const denial = checkStructuredTargets(toolClass.extract(args, context), policy, roots);
	if (denial) throw new PermissionDeniedError(toolName, denial.rule, denial.reason);
	return null;
}

/**
 * Recheck the files a recursive search/edit tool actually touched, after it
 * executes, against the same policy the declared-argument gate already
 * evaluated before the call.
 *
 * `grep`/`ast_grep`/`ast_edit` accept a scope root but then recurse beneath
 * it, so `enforceResourcePermissions`'s pre-execution check only ever sees
 * that root — `grep({ path: ".", gitignore: false })` passes it and can
 * still surface `.env` contents. `TOOL_PATH_CLASSES[tool].resultTargets`
 * re-derives the real file set from what the tool reports it visited
 * (`details.files`); this evaluates that set the same way `enforceResourcePermissions`
 * evaluates declared targets and throws before the result is handed back to
 * the caller, so a denied file the tool already opened locally never reaches
 * the model. No-ops for a tool with no `resultTargets` extractor and, like
 * the pre-execution gate, short-circuits entirely under `permissions.profile: off`.
 */
export function enforcePostExecutionResourcePermissions(
	toolName: string,
	details: unknown,
	context: AgentToolContext | undefined,
): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return;

	const toolClass = classifyTool(toolName);
	if (toolClass.kind !== "structured" || !toolClass.resultTargets) return;

	enforceTargets(toolName, toolClass.resultTargets(details), policy, context);
}

/**
 * Evaluate a target set a tool derived at runtime, rather than from its
 * declared arguments.
 *
 * The `lsp` tool's write surface is a server-supplied `WorkspaceEdit`, not its
 * `file` argument: a rename started inside an allowed file can name any
 * destination the language server chooses. `lsp/index.ts` extracts the real
 * destinations and calls this *before* applying anything, so the check
 * precedes the write instead of reporting it afterwards.
 *
 * Short-circuits under `permissions.profile: off` exactly like the other two
 * entry points, so the default configuration pays a single settings read.
 */
export function enforceResourcePathTargets(
	toolName: string,
	targets: readonly PathTarget[],
	context: AgentToolContext | undefined,
): void {
	const policy = loadPermissionsConfig(context?.settings);
	if (!policy) return;
	enforceTargets(toolName, targets, policy, context);
}

/** Resolve the roots (failing closed without a session) and evaluate `targets`. */
function enforceTargets(
	toolName: string,
	targets: readonly PathTarget[],
	policy: PermissionPolicy,
	context: AgentToolContext | undefined,
): void {
	const roots = permissionRoots(context);
	if (!roots) {
		throw new PermissionDeniedError(
			toolName,
			"permissions.profile",
			`Tool "${toolName}" is blocked: permissions.profile is "${policy.profile}" but this call has no ` +
				`session, so the workspace roots the rules are measured against cannot be determined.\n` +
				`To allow it: set permissions.profile: off.`,
		);
	}

	const denial = checkStructuredTargets(targets, policy, roots);
	if (denial) throw new PermissionDeniedError(toolName, denial.rule, denial.reason);
}
