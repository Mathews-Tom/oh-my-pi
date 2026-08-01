/**
 * The resource permission decision procedure.
 *
 * Pure with respect to configuration — it takes an already-merged
 * {@link PermissionPolicy} and never reads `Settings` — so the whole policy
 * surface is testable without a session.
 */
import * as path from "node:path";
import { extractUriScheme } from "../../internal-urls/parse";
import { isInternalUrlPath, isReadableUrlPath, resolveToCwd, splitPathAndSel } from "../path-utils";
import { confineToRoots, relativeToRoots } from "./confine";
import { matchGlob } from "./matcher";
import { ALLOW, type PathTarget, type PermissionDecision, type PermissionPolicy, type PermissionRoots } from "./types";

/**
 * Schemes the {@link InternalUrlRouter} owns that `isInternalUrlPath` does not
 * list.
 *
 * `TOP_LEVEL_INTERNAL_URL_PREFIXES` (`../path-utils.ts`) is deliberately the
 * narrower set: it drives `resolveToCwd`'s hard refusal, so adding to it would
 * change how every tool resolves these strings. The guard needs the *routing*
 * set instead — anything the router claims is not a user filesystem target,
 * whether or not `resolveToCwd` would happily turn it into a path.
 */
const ROUTED_INTERNAL_SCHEMES: Record<string, true> = {
	xd: true,
	memory: true,
	history: true,
	issue: true,
	pr: true,
	omp: true,
};

/**
 * True when a raw path argument is not a user filesystem target at all.
 *
 * Internal URLs (`local://`, `vault://`, `xd://`, `memory://`, …) address the
 * session's own sandbox and device surface, exactly as plan mode treats them,
 * and `http(s)://` is not a filesystem path either. Confining or denying these
 * would break the artifact and device routes without protecting any file.
 */
export function isExemptPathArgument(raw: string): boolean {
	const trimmed = raw.trim();
	if (!trimmed) return true;
	if (isInternalUrlPath(trimmed) || isReadableUrlPath(trimmed)) return true;
	const scheme = extractUriScheme(trimmed);
	return !!scheme && ROUTED_INTERNAL_SCHEMES[scheme] === true;
}

/** All roots the policy measures containment against, cwd first. */
export function permissionRootList(roots: PermissionRoots): string[] {
	return [roots.cwd, ...roots.additionalDirectories];
}

/**
 * Resolve a raw tool path argument to the absolute path the tool will act on.
 *
 * Mirrors `resolveToCwd`, which is what every structured-path tool uses, so
 * the guard and the tool cannot disagree about the target. A path that
 * `resolveToCwd` refuses (an internal scheme reaching this far) is reported as
 * unresolvable rather than guessed at, and the caller fails closed.
 */
export function resolveTargetPath(raw: string, cwd: string): string | null {
	try {
		return resolveToCwd(raw, cwd);
	} catch {
		return null;
	}
}

const CONFINE_READS_RULE = "permissions.confineReads";
const CONFINE_WRITES_RULE = "permissions.confineWrites";

/**
 * Decide one resolved path target against the policy.
 *
 * Order is fixed by design:
 *
 * 1. an explicit `permissions.allow.<access>` carve-out wins outright — the
 *    gitignore-negation model, so `.env.example` is expressible;
 * 2. confinement, when enabled for this access;
 * 3. deny globs, matched against workspace-relative path, absolute path, and
 *    basename so a rule written either way behaves as the user expects.
 *
 * An allow carve-out relaxes *this* layer only. It never touches
 * `tools.approvalMode` or `tools.approval.<tool>`, so it cannot auto-approve
 * anything the user would otherwise have been prompted for.
 */
export function decidePathTarget(
	target: PathTarget,
	absolutePath: string,
	policy: PermissionPolicy,
	roots: PermissionRoots,
): PermissionDecision {
	const rootList = permissionRootList(roots);
	const relative = relativeToRoots(absolutePath, rootList);
	const candidates = [relative, absolutePath, path.basename(absolutePath)].filter((c): c is string => !!c);

	const allowed = matchGlob(policy.allow[target.access], candidates);
	if (allowed) return ALLOW;

	const confine = target.access === "write" ? policy.confineWrites : policy.confineReads;
	if (confine) {
		const containment = confineToRoots(absolutePath, rootList);
		if (!containment.contained) {
			const rule = target.access === "write" ? CONFINE_WRITES_RULE : CONFINE_READS_RULE;
			return { kind: "deny", rule, reason: containmentReason(containment.reason, target, absolutePath, rootList) };
		}
	}

	const denied = matchGlob(policy.deny[target.access], candidates);
	if (denied) {
		return {
			kind: "deny",
			rule: denied,
			reason:
				`${target.access === "write" ? "Writing" : "Reading"} "${target.raw}" is blocked by the ` +
				`resource permission rule "${denied}" (permissions.profile: ${policy.profile}).\n` +
				`To allow it: add "${denied}" to permissions.allow.${target.access}, ` +
				`or set permissions.profile: off.`,
		};
	}

	return ALLOW;
}

function containmentReason(
	reason: "outside" | "dangling-symlink" | "unreadable" | "no-roots",
	target: PathTarget,
	absolutePath: string,
	rootList: readonly string[],
): string {
	const verb = target.access === "write" ? "Writing" : "Reading";
	const setting = target.access === "write" ? CONFINE_WRITES_RULE : CONFINE_READS_RULE;
	const rootsText = rootList.join(", ");
	if (reason === "dangling-symlink") {
		return (
			`${verb} "${target.raw}" is blocked: it is an unresolvable symlink, so ${setting} cannot ` +
			`tell whether it lands inside the workspace.\n` +
			`To allow it: replace the dangling link, or set ${setting}: false.`
		);
	}
	if (reason === "unreadable") {
		return (
			`${verb} "${target.raw}" (${absolutePath}) is blocked: it could not be inspected, so ${setting} ` +
			`cannot tell whether it lands inside the workspace.\n` +
			`To allow it: fix the permissions on its parent directory, or set ${setting}: false.`
		);
	}
	if (reason === "no-roots") {
		return (
			`${verb} "${target.raw}" is blocked: ${setting} is on but no workspace root could be resolved.\n` +
			`To allow it: set ${setting}: false.`
		);
	}
	return (
		`${verb} "${target.raw}" (${absolutePath}) is blocked by ${setting}: it is outside every ` +
		`workspace root (${rootsText}).\n` +
		`To allow it: add the directory with /add-dir, add a glob to permissions.allow.${target.access}, ` +
		`or set ${setting}: false.`
	);
}

/**
 * Every filesystem spelling one raw argument can name.
 *
 * `read` and `grep` peel a trailing read selector before opening the file
 * (`splitPathAndSelPreferringLiteral`), so `.env:raw` opens `.env`. Checking
 * only the raw string would let a selector suffix walk straight past every
 * deny glob. Both spellings are checked and either one denying is a denial,
 * which is the fail-closed reading: a real file named `a:1-2` is additionally
 * measured as `a`, which is stricter, never looser.
 */
function targetSpellings(target: PathTarget): PathTarget[] {
	const peeled = splitPathAndSel(target.raw).path;
	if (peeled === target.raw) return [target];
	return [target, { ...target, raw: peeled }];
}

/**
 * Decide a raw target end to end: exemption, resolution, then the policy.
 *
 * Fails closed. A path that cannot be resolved to an absolute location is
 * denied rather than waved through, because "we could not tell what this
 * touches" is not a reason to allow it once a profile is active.
 */
export function decideTarget(target: PathTarget, policy: PermissionPolicy, roots: PermissionRoots): PermissionDecision {
	if (isExemptPathArgument(target.raw)) return ALLOW;
	for (const spelling of targetSpellings(target)) {
		const absolutePath = resolveTargetPath(spelling.raw, roots.cwd);
		if (!absolutePath) {
			return {
				kind: "deny",
				rule: "permissions.profile",
				reason:
					`Cannot resolve "${spelling.raw}" (argument "${spelling.field}") to a filesystem path, so the ` +
					`resource permission layer cannot verify it (permissions.profile: ${policy.profile}).\n` +
					`To allow it: pass a plain path, or set permissions.profile: off.`,
			};
		}
		const decision = decidePathTarget(spelling, absolutePath, policy, roots);
		if (decision.kind === "deny") return decision;
	}
	return ALLOW;
}
