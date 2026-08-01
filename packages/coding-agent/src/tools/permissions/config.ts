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

const PERMISSION_PROFILES: ReadonlySet<string> = new Set<PermissionProfile>(["off", "workspace", "strict"]);

/**
 * Cheap pre-check so the `off` path never builds a policy at all.
 *
 * The value is validated rather than asserted. `Settings.get` is typed against
 * the schema, but the gate runs on whatever a session, an override, or an SDK
 * embedder actually put there, and an unrecognized value used to index
 * `PROFILE_DEFAULTS` to `undefined` and take the gate down with a bare
 * `TypeError` — a crash inside a security check decides nothing and names
 * nothing the operator can fix. Same fail-loud direction as a malformed glob
 * ({@link globList}): absent means `off`, present-but-wrong is an error.
 */
export function readPermissionProfile(settings: Settings | undefined): PermissionProfile {
	const value = settings?.get("permissions.profile");
	if (value === undefined || value === null) return "off";
	if (typeof value !== "string" || !PERMISSION_PROFILES.has(value)) {
		throw new Error(
			`permissions.profile is ${JSON.stringify(value)}, which is not one of "off", "workspace", or "strict". ` +
				`Fix or remove it — the resource permission layer cannot tell which rules to apply.`,
		);
	}
	return value as PermissionProfile;
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
