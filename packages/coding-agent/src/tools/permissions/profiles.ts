/**
 * Built-in permission profiles and the merge onto user overrides.
 *
 * Profiles exist so the common case is one setting rather than a hand-written
 * glob list. Everything a profile contributes is additive to the user's own
 * lists — a profile can never remove a rule the user asked for.
 */
import type { AccessGlobs, PermissionPolicy, PermissionProfile } from "./types";

// Secrets denied under `strict`, for both read and write.
//
// Path globs, not command globs: `*` does not cross `/`, so a rule that must
// match at any depth is spelled `**/.env` and never `*.env`.
export const STRICT_SECRET_DENY_GLOBS: readonly string[] = [
	"**/.env",
	"**/.env.*",
	"**/id_rsa",
	"**/id_ed25519",
	"**/id_ecdsa",
	"**/*.pem",
	"**/*.key",
	"**/*.p12",
	"**/.aws/credentials",
	"**/.ssh/**",
	"**/secrets.json",
];

// Carve-outs shipped with `strict` so the common case needs no user rule.
//
// `**/.env.*` would otherwise swallow the checked-in templates that live
// beside a real `.env` in most repositories.
export const STRICT_SECRET_ALLOW_GLOBS: readonly string[] = ["**/.env.example", "**/.env.sample"];

const NO_GLOBS: AccessGlobs = { read: [], write: [] };

interface ProfileDefaults {
	readonly confineReads: boolean;
	readonly confineWrites: boolean;
	readonly deny: AccessGlobs;
	readonly allow: AccessGlobs;
}

const PROFILE_DEFAULTS: Record<PermissionProfile, ProfileDefaults> = {
	off: { confineReads: false, confineWrites: false, deny: NO_GLOBS, allow: NO_GLOBS },
	// Writes are where an escape is destructive; reading `/var/log` or
	// `~/.gitconfig` is routine, so reads stay unconfined by default.
	workspace: { confineReads: false, confineWrites: true, deny: NO_GLOBS, allow: NO_GLOBS },
	strict: {
		confineReads: false,
		confineWrites: true,
		deny: { read: STRICT_SECRET_DENY_GLOBS, write: STRICT_SECRET_DENY_GLOBS },
		allow: { read: STRICT_SECRET_ALLOW_GLOBS, write: STRICT_SECRET_ALLOW_GLOBS },
	},
};

/** User-supplied overrides, all optional; absent means "take the profile's". */
export interface PermissionOverrides {
	readonly confineReads?: boolean | undefined;
	readonly confineWrites?: boolean | undefined;
	readonly denyRead?: readonly string[] | undefined;
	readonly denyWrite?: readonly string[] | undefined;
	readonly allowRead?: readonly string[] | undefined;
	readonly allowWrite?: readonly string[] | undefined;
	readonly opaqueToolScan?: PermissionPolicy["opaqueToolScan"] | undefined;
}

/** Trim and drop empties, without deduplicating against anything else. */
function trimmedGlobs(list: readonly string[] | undefined): readonly string[] {
	if (!list || list.length === 0) return [];
	const out: string[] = [];
	for (const glob of list) {
		const trimmed = glob.trim();
		if (trimmed) out.push(trimmed);
	}
	return out;
}

function mergeGlobs(base: readonly string[], extra: readonly string[] | undefined): readonly string[] {
	const trimmedExtra = trimmedGlobs(extra);
	if (trimmedExtra.length === 0) return base;
	const seen = new Set(base);
	const out = [...base];
	for (const glob of trimmedExtra) {
		if (seen.has(glob)) continue;
		seen.add(glob);
		out.push(glob);
	}
	return out;
}

/**
 * Merge a profile with user overrides into the policy the gate evaluates.
 *
 * Glob lists are unioned rather than replaced: a profile's secret list is a
 * floor, and `permissions.deny.*` raises it. There is deliberately no way to
 * subtract from a profile's deny list except through `permissions.allow.*`,
 * which is the single, explicit escape hatch.
 *
 * `explicitAllow`/`explicitDeny` carry the user's own overrides apart from
 * the merged lists above, so `decidePathTarget` can let a user's own deny
 * outrank a profile's own carve-out (see {@link PermissionPolicy.explicitAllow}).
 */
export function buildPermissionPolicy(
	profile: PermissionProfile,
	overrides: PermissionOverrides = {},
): PermissionPolicy {
	const defaults = PROFILE_DEFAULTS[profile];
	return {
		profile,
		confineReads: overrides.confineReads ?? defaults.confineReads,
		confineWrites: overrides.confineWrites ?? defaults.confineWrites,
		deny: {
			read: mergeGlobs(defaults.deny.read, overrides.denyRead),
			write: mergeGlobs(defaults.deny.write, overrides.denyWrite),
		},
		allow: {
			read: mergeGlobs(defaults.allow.read, overrides.allowRead),
			write: mergeGlobs(defaults.allow.write, overrides.allowWrite),
		},
		explicitAllow: {
			read: trimmedGlobs(overrides.allowRead),
			write: trimmedGlobs(overrides.allowWrite),
		},
		explicitDeny: {
			read: trimmedGlobs(overrides.denyRead),
			write: trimmedGlobs(overrides.denyWrite),
		},
		opaqueToolScan: overrides.opaqueToolScan ?? "deny",
	};
}
