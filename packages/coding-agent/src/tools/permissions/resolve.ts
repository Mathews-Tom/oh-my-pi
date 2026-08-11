/**
 * The resource permission decision procedure.
 *
 * Pure with respect to configuration — it takes an already-merged
 * {@link PermissionPolicy} and never reads `Settings` — so the whole policy
 * surface is testable without a session. One narrow exception:
 * {@link decideVaultTarget} calls `resolveVaultUrlToPath`, which reads the
 * global settings singleton (`vault.enabled`) and a process-wide vault-root
 * cache — there is no way to resolve a `vault://` URL to the real file it
 * addresses without that lookup, and exempting it entirely (the prior
 * behavior) is unsound: `vault://` is a real filesystem surface, not an
 * internal one.
 */
import * as path from "node:path";
import { extractUriScheme } from "../../internal-urls/parse";
import { resolveVaultUrlToPath } from "../../internal-urls/vault-protocol";
import { isInternalUrlPath, isReadableUrlPath, isSshUrl, resolveToCwd, splitPathAndSel } from "../path-utils";
import { confineToRoots, relativeSpellingGroups } from "./confine";
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
 * Internal URLs (`local://`, `xd://`, `memory://`, …) address the
 * session's own sandbox and device surface, exactly as plan mode treats them,
 * and `http(s)://` is not a filesystem path either. Confining or denying these
 * would break the artifact and device routes without protecting any file.
 *
 * `ssh://` and `vault://` are deliberately excluded even though
 * `isInternalUrlPath` lists both (`path-utils.ts`'s
 * `TOP_LEVEL_INTERNAL_URL_PREFIXES` is a routing table for the
 * read/write/search tools, not a permission-exempt set): `ssh://` is a real
 * remote filesystem surface reachable via `read`/`write`/`grep`
 * (`docs/permissions.md`), so `read ssh://host/home/user/.env` must face the
 * same deny/allow globs as the local spelling — see {@link decideSshTarget}.
 * `vault://` resolves to a real file on disk through the Obsidian
 * integration — see {@link decideVaultTarget}.
 */
export function isExemptPathArgument(raw: string): boolean {
	const trimmed = raw.trim();
	if (!trimmed) return true;
	if (isSshUrl(trimmed) || isVaultUrl(trimmed)) return false;
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
 * 1. confinement, when enabled for this access — checked unconditionally, so
 *    no allow glob (including the built-in `**\/.env.example` carve-out) can
 *    ever write outside every workspace root;
 * 2. an explicit `permissions.allow.<access>` carve-out wins over a deny
 *    glob by name — the gitignore-negation model, so `.env.example` is
 *    expressible;
 * 3. deny globs, matched against workspace-relative path, absolute path, and
 *    basename so a rule written either way behaves as the user expects.
 *
 * An allow carve-out relaxes *this* layer only. It never touches
 * `tools.approvalMode` or `tools.approval.<tool>`, so it cannot auto-approve
 * anything the user would otherwise have been prompted for.
 */
/**
 * Permission globs are documented and written with `/` (`**\/.ssh/**`), but
 * on Windows `path.relative`/an absolute path use `\`, and `Bun.Glob` does
 * not treat the two as equivalent - `**\/.ssh/**` never matches `.ssh\config`.
 * `path.basename` alone rescues only filename-only rules; a directory-scoped
 * rule (the common case) is silently bypassed without this.
 */
function normalizeCandidate(candidate: string): string {
	return candidate.replaceAll("\\", "/");
}

export function decidePathTarget(
	target: PathTarget,
	absolutePath: string,
	policy: PermissionPolicy,
	roots: PermissionRoots,
): PermissionDecision {
	const rootList = permissionRootList(roots);

	const confine = target.access === "write" ? policy.confineWrites : policy.confineReads;
	if (confine) {
		const containment = confineToRoots(absolutePath, rootList);
		if (!containment.contained) {
			const rule = target.access === "write" ? CONFINE_WRITES_RULE : CONFINE_READS_RULE;
			return { kind: "deny", rule, reason: containmentReason(containment.reason, target, absolutePath, rootList) };
		}
	}

	// Checked as two separate identities, not one merged candidate list: a
	// symlink alias (`.env.example -> .env`) contributes both the lexical
	// spelling and the realpath-resolved canonical spelling. Merging them
	// before matching would let an allow glob on the alias (`**/.env.example`)
	// short-circuit the whole decision before the canonical spelling ever
	// gets checked against `**/.env` - the alias would then silently
	// authorize reading/writing its own deny-listed backing file. Each
	// identity gets its own allow-then-deny check instead, so an allow
	// override on one spelling can never clear a deny on the other.
	const spellings = relativeSpellingGroups(absolutePath, rootList);
	// `absolutePath` itself is a POSIX-style internal-URL selector, an
	// already-forward-slash SSH remote path, or a real filesystem path, so
	// normalizing every backslash here is safe for all three.
	const identities = [
		[...spellings.lexical, spellings.resolved, path.basename(spellings.resolved)].map(normalizeCandidate),
		[...spellings.canonical, spellings.realTarget, path.basename(spellings.realTarget)].map(normalizeCandidate),
	];

	for (const candidates of identities) {
		if (matchGlob(policy.allow[target.access], candidates)) continue;
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

/** `vault://[vault-name|_]/<path>`. */
const VAULT_URL_RE = /^vault:\/\//i;

/** True when `raw` is a `vault://` URL, checked before general internal-URL exemption. */
function isVaultUrl(raw: string): boolean {
	return VAULT_URL_RE.test(raw);
}

/**
 * Decide a `vault://` target against the policy.
 *
 * Unlike `ssh://`, this resolves to a real *local* file (the Obsidian vault
 * lives on disk) through `resolveVaultUrlToPath`'s cached-root indirection,
 * so once resolved it gets the full local-path treatment — confinement plus
 * deny/allow — exactly as a plain path would, via {@link decidePathTarget}.
 * Resolution failure (`vault.enabled: false`, no cached vault root yet — the
 * very first `vault://` call in a session, before any read has discovered
 * one — a URL shape the resolver rejects, or the target escaping the vault
 * root) fails closed: "we don't know what this touches" is not a reason to
 * allow it once a profile is active.
 */
function decideVaultTarget(target: PathTarget, policy: PermissionPolicy, roots: PermissionRoots): PermissionDecision {
	let absolutePath: string;
	try {
		absolutePath = resolveVaultUrlToPath(target.raw);
	} catch (error) {
		const detail = error instanceof Error ? error.message : String(error);
		return {
			kind: "deny",
			rule: "permissions.profile",
			reason:
				`Cannot resolve "${target.raw}" (argument "${target.field}") to a filesystem path (${detail}), so ` +
				`the resource permission layer cannot verify it (permissions.profile: ${policy.profile}).\n` +
				`To allow it: read vault:// first so the vault root is cached, or set permissions.profile: off.`,
		};
	}
	return decidePathTarget(target, absolutePath, policy, roots);
}

/** `ssh://[user@]host[:port]/<remote-path>`, capturing the remote path. */
const SSH_URL_RE = /^ssh:\/\/[^/]*(\/.*)?$/i;

/**
 * Decide an `ssh://` target against the policy.
 *
 * There is no local root to confine against (the file lives on a remote
 * host), so this checks only the deny/allow globs — the same lists a local
 * path faces — against the URL's remote path component and its basename.
 * Unparseable input (no path component at all, e.g. a bare `ssh://host`)
 * fails closed: there is nothing to verify, and `permissions.profile` being
 * active is not a reason to wave it through.
 */
function decideSshTarget(target: PathTarget, policy: PermissionPolicy): PermissionDecision {
	const remotePath = SSH_URL_RE.exec(target.raw)?.[1];
	if (!remotePath) {
		return {
			kind: "deny",
			rule: "permissions.profile",
			reason:
				`Cannot resolve a remote path from "${target.raw}" (argument "${target.field}"), so the resource ` +
				`permission layer cannot verify it (permissions.profile: ${policy.profile}).\n` +
				`To allow it: pass an ssh:// URL with a path, or set permissions.profile: off.`,
		};
	}
	let decoded: string;
	try {
		decoded = decodeURIComponent(remotePath);
	} catch {
		decoded = remotePath;
	}
	const candidates = [decoded, path.posix.basename(decoded)].filter((c): c is string => !!c);

	const allowed = matchGlob(policy.allow[target.access], candidates);
	if (allowed) return ALLOW;

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
		if (isSshUrl(spelling.raw)) {
			const decision = decideSshTarget(spelling, policy);
			if (decision.kind === "deny") return decision;
			continue;
		}
		if (isVaultUrl(spelling.raw)) {
			const decision = decideVaultTarget(spelling, policy, roots);
			if (decision.kind === "deny") return decision;
			continue;
		}
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
