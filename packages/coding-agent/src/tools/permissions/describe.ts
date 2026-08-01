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
import { ACTION_OPAQUE_TOOLS, TOOL_PATH_CLASSES } from "./tool-path-targets";
import type { PermissionPolicy, PermissionProfile } from "./types";

/** The built-in tool names of each trust class, sorted for stable output. */
export interface ToolGuardSummary {
	/** Class A — declared path arguments, enforced exactly, for every action. */
	readonly structured: readonly string[];
	/**
	 * Class A for most actions, Class B for the ones named here. Reported
	 * apart from {@link structured} because `classifyTool` downgrades these
	 * per call, and a report that folded them in would promise exact
	 * enforcement for `debug launch` and `lsp request` — the two calls in the
	 * table that reach arbitrary code.
	 */
	readonly mixed: readonly { readonly name: string; readonly opaqueActions: readonly string[] }[];
	/** Class B — best-effort literal scan of opaque arguments. Never a sandbox. */
	readonly opaque: readonly string[];
	/** No filesystem surface, so nothing to guard. */
	readonly pathless: readonly string[];
}

/** Partition {@link TOOL_PATH_CLASSES} by trust class. */
export function summarizeToolGuards(): ToolGuardSummary {
	const structured: string[] = [];
	const mixed: { name: string; opaqueActions: readonly string[] }[] = [];
	const opaque: string[] = [];
	const pathless: string[] = [];
	for (const [name, toolClass] of Object.entries(TOOL_PATH_CLASSES)) {
		switch (toolClass.kind) {
			case "structured": {
				const opaqueActions = ACTION_OPAQUE_TOOLS[name];
				if (opaqueActions) mixed.push({ name, opaqueActions: [...opaqueActions].sort() });
				else structured.push(name);
				break;
			}
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
		mixed: mixed.sort((a, b) => a.name.localeCompare(b.name)),
		opaque: opaque.sort(),
		pathless: pathless.sort(),
	};
}

/**
 * Glob lists come from user settings, so they are untrusted display text: a
 * tab punches a hole in the status area and an overlong line wraps the pane.
 * Bounding the *joined* line, not just each individual glob, matters once a
 * profile configures enough rules that even short entries add up past
 * `TRUNCATE_LENGTHS.LINE` once comma-joined — truncating each glob alone
 * never caps that. Tabs are replaced before measuring width, not after:
 * `replaceTabs` can expand a single-character tab into several spaces, so
 * truncating first and expanding tabs afterward can push the rendered line
 * back past the limit the truncation was supposed to enforce.
 */
function ruleLine(label: string, globs: readonly string[]): string | null {
	if (globs.length === 0) return null;
	const rules = globs.map(glob => replaceTabs(glob));
	return truncateToWidth(`  ${label}: ${rules.join(", ")}`, TRUNCATE_LENGTHS.LINE);
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
	const mixed = guards.mixed.map(entry => `${entry.name} (${entry.opaqueActions.join(", ")})`).join("; ");
	return [
		"Tool coverage:",
		`  Class A (${guards.structured.length}) — declared paths enforced exactly: ${guards.structured.join(", ")}`,
		`  Class A/B (${guards.mixed.length}) — declared paths enforced except these actions, ` +
			`which fall back to the Class B scan: ${mixed}`,
		`  Class B (${guards.opaque.length}) — ${classB}: ${guards.opaque.join(", ")}`,
		`  No filesystem surface (${guards.pathless.length}): ${guards.pathless.join(", ")}`,
		"  MCP, extension, and any other tool absent from the table is treated as Class B.",
		// Named rather than left to be discovered: `grep`/`ast_grep` recurse
		// inside the native searcher, which reports a count of files searched but
		// not their names and takes no exclusion globs, so the recheck can only
		// see files that produced a match. A denied file that matches nothing is
		// still opened. Closing it needs the native searcher to exclude paths or
		// return its visited set; until then, saying so is the honest position.
		"  Recursive search (grep, ast_grep) is rechecked only on files that matched; a denied file",
		"  beneath an allowed root is still opened if it matches nothing. Deny the root, not the file.",
	];
}

function policyLines(policy: PermissionPolicy): string[] {
	const lines = [
		`  Confine reads to workspace: ${policy.confineReads ? "yes" : "no"}`,
		`  Confine writes to workspace: ${policy.confineWrites ? "yes" : "no"}`,
		`  Opaque tool scan: ${policy.opaqueToolScan}`,
	];
	// The profile's own carve-outs get their own label rather than being folded
	// into "Allow": they relax the deny globs above but NOT confinement, so a
	// report that listed `**/.env.example` as an allow rule would tell an
	// operator that `/tmp/.env.example` is writable under `strict` when it is not.
	for (const line of [
		ruleLine("Deny read", policy.deny.read),
		ruleLine("Deny write", policy.deny.write),
		ruleLine("Allow read", policy.allow.read),
		ruleLine("Allow write", policy.allow.write),
		ruleLine("Deny carve-out read (still confined)", policy.carveOut.read),
		ruleLine("Deny carve-out write (still confined)", policy.carveOut.write),
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
