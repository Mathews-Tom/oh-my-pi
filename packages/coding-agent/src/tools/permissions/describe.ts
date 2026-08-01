/**
 * Operator-facing description of the resource permission layer.
 *
 * This lives beside the policy rather than in the slash-command registry for
 * one reason: the useful half of the answer is not the active profile, it is
 * *which tools the layer cannot soundly guard*. That half is derived from
 * {@link TOOL_PATH_CLASSES}, so it has to move whenever that table moves. A
 * copy in the command layer would drift silently and start overstating the
 * guarantee — the exact failure this text exists to prevent.
 *
 * Output is plain text with no theme colours: it is rendered through
 * `showStatus` in the TUI and `sessionUpdate` over ACP, and both take a string.
 */
import { replaceTabs, TRUNCATE_LENGTHS, truncateToWidth } from "../render-utils";
import { TOOL_PATH_CLASSES } from "./tool-path-targets";
import type { PermissionPolicy, PermissionProfile } from "./types";

/** The built-in tool names of each trust class, sorted for stable output. */
export interface ToolGuardSummary {
	/** Class A — declared path arguments, enforced exactly. */
	readonly structured: readonly string[];
	/** Class B — best-effort literal scan of opaque arguments. Never a sandbox. */
	readonly opaque: readonly string[];
	/** No filesystem surface, so nothing to guard. */
	readonly pathless: readonly string[];
}

/** Partition {@link TOOL_PATH_CLASSES} by trust class. */
export function summarizeToolGuards(): ToolGuardSummary {
	const structured: string[] = [];
	const opaque: string[] = [];
	const pathless: string[] = [];
	for (const [name, toolClass] of Object.entries(TOOL_PATH_CLASSES)) {
		switch (toolClass.kind) {
			case "structured":
				structured.push(name);
				break;
			case "opaque":
				opaque.push(name);
				break;
			case "pathless":
				pathless.push(name);
				break;
		}
	}
	return {
		structured: structured.sort(),
		opaque: opaque.sort(),
		pathless: pathless.sort(),
	};
}

/**
 * Glob lists come from user settings, so they are untrusted display text: a tab
 * punches a hole in the status area and an overlong entry wraps the pane.
 */
function ruleLine(label: string, globs: readonly string[]): string | null {
	if (globs.length === 0) return null;
	const rules = globs.map(glob => replaceTabs(truncateToWidth(glob, TRUNCATE_LENGTHS.LINE)));
	return `  ${label}: ${rules.join(", ")}`;
}

/**
 * The honesty surface: what the layer enforces exactly, what it only scans for
 * literals, and what it does not look at.
 *
 * `opaqueToolScan` is folded into the Class B label because `off` turns that
 * best-effort scan into no check at all, and a reader who sees "Class B" while
 * the scan is disabled would otherwise assume some residual protection.
 */
function toolCoverageLines(policy: PermissionPolicy | null): string[] {
	const guards = summarizeToolGuards();
	const scan = policy?.opaqueToolScan ?? "deny";
	const classB =
		scan === "off"
			? "not checked at all, permissions.opaqueToolScan is off"
			: `best-effort literal scan only, never a sandbox; scan=${scan}`;
	return [
		"Tool coverage:",
		`  Class A (${guards.structured.length}) — declared paths enforced exactly: ${guards.structured.join(", ")}`,
		`  Class B (${guards.opaque.length}) — ${classB}: ${guards.opaque.join(", ")}`,
		`  No filesystem surface (${guards.pathless.length}): ${guards.pathless.join(", ")}`,
		"  MCP, extension, and any other tool absent from the table is treated as Class B.",
	];
}

function policyLines(policy: PermissionPolicy): string[] {
	const lines = [
		`  Confine reads to workspace: ${policy.confineReads ? "yes" : "no"}`,
		`  Confine writes to workspace: ${policy.confineWrites ? "yes" : "no"}`,
		`  Opaque tool scan: ${policy.opaqueToolScan}`,
	];
	for (const line of [
		ruleLine("Deny read", policy.deny.read),
		ruleLine("Deny write", policy.deny.write),
		ruleLine("Allow read", policy.allow.read),
		ruleLine("Allow write", policy.allow.write),
	]) {
		if (line) lines.push(line);
	}
	return lines;
}

/**
 * Full `/perm` report: the active profile, the rules it resolves to, and the
 * tool-class breakdown. `policy` is `null` exactly when the profile is `off`.
 *
 * `headerNote` is appended to the profile line so a `/perm <profile>` switch
 * gets one report rather than a confirmation line followed by a near-identical
 * header.
 */
export function describePermissionState(
	profile: PermissionProfile,
	policy: PermissionPolicy | null,
	headerNote?: string,
): string {
	const suffix = headerNote ? ` ${headerNote}` : "";
	const header =
		profile === "off"
			? `Permission profile: off — no resource permission enforcement.${suffix}`
			: `Permission profile: ${profile}.${suffix}`;
	const body = policy ? policyLines(policy) : ["  Enable for this session with /perm workspace or /perm strict."];
	return [
		header,
		...body,
		"",
		...toolCoverageLines(policy),
		"",
		"  This layer can only subtract; it never auto-approves. tools.approvalMode still applies.",
		"  Persist a profile with the settings key: permissions.profile",
	].join("\n");
}
