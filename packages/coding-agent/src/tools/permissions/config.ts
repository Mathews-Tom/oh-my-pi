/**
 * Bridge between `Settings` and the pure policy layer.
 *
 * Kept apart from `resolve.ts` on purpose: the decision procedure must stay
 * testable without a session, and this is the only module in the directory
 * that knows a settings store exists.
 */
import type { Settings } from "../../config/settings";
import { validateGlobPattern } from "./matcher";
import { buildPermissionPolicy } from "./profiles";
import type { PermissionPolicy, PermissionProfile } from "./types";

type GlobListKey =
	| "permissions.deny.read"
	| "permissions.deny.write"
	| "permissions.allow.read"
	| "permissions.allow.write";

/**
 * Reads one glob list and validates every pattern before it can ever reach
 * `matchGlob`. `Bun.Glob` never throws on a malformed pattern — it silently
 * compiles into something that matches nothing — so a typo'd
 * `permissions.deny.*` entry would otherwise leave the path it names
 * unprotected with no error anywhere. Throwing here instead is the same
 * fail-closed direction the gate already takes for every other unverifiable
 * input: the exception propagates out of `enforceResourcePermissions` and
 * blocks the call, so a bad pattern is loud rather than a silent gap.
 */
function globList(settings: Settings, key: GlobListKey): readonly string[] | undefined {
	const value = settings.get(key);
	if (!Array.isArray(value)) return undefined;
	const patterns = value.filter((entry): entry is string => typeof entry === "string");
	for (const pattern of patterns) {
		const problem = validateGlobPattern(pattern);
		if (problem) {
			throw new Error(
				`${key} has an invalid glob pattern "${pattern}": ${problem}. Fix or remove it — a malformed ` +
					`pattern compiles without error but matches nothing, so the rule it was meant to enforce is silently unenforced.`,
			);
		}
	}
	return patterns;
}

/**
 * Cheap pre-check so the `off` path never builds a policy at all.
 *
 * `settings.get("permissions.profile")` is typed `PermissionProfile` but
 * that's a cast, not a runtime guarantee — a settings store that doesn't
 * validate the schema (a hand-rolled test stub, a corrupted config file, a
 * value from a since-renamed profile) can return anything. Validated here
 * against the actual enum and falling back to "off" rather than letting an
 * unrecognized value reach `buildPermissionPolicy`'s `PROFILE_DEFAULTS`
 * lookup, which throws an unhelpful `undefined is not an object` instead of
 * failing loud with a clear cause — and "off" is the safe direction for a
 * profile-driven feature that already defaults to off.
 */
const KNOWN_PROFILES: ReadonlySet<PermissionProfile> = new Set(["off", "workspace", "strict"]);

export function readPermissionProfile(settings: Settings | undefined): PermissionProfile {
	const raw = settings?.get("permissions.profile");
	return typeof raw === "string" && KNOWN_PROFILES.has(raw as PermissionProfile) ? (raw as PermissionProfile) : "off";
}

/**
 * Materialize the active policy, or `null` when the profile is `off`.
 *
 * A `null` return is the signal that the gate must do nothing — no glob
 * compilation, no `realpath`, no allocation beyond this one settings read.
 */
export function loadPermissionsConfig(settings: Settings | undefined): PermissionPolicy | null {
	const profile = readPermissionProfile(settings);
	if (profile === "off" || !settings) return null;
	return buildPermissionPolicy(profile, {
		confineReads: settings.get("permissions.confineReads"),
		confineWrites: settings.get("permissions.confineWrites"),
		denyRead: globList(settings, "permissions.deny.read"),
		denyWrite: globList(settings, "permissions.deny.write"),
		allowRead: globList(settings, "permissions.allow.read"),
		allowWrite: globList(settings, "permissions.allow.write"),
		opaqueToolScan: settings.get("permissions.opaqueToolScan") ?? "deny",
	});
}
