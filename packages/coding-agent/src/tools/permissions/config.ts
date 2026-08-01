/**
 * Bridge between `Settings` and the pure policy layer.
 *
 * Kept apart from `resolve.ts` on purpose: the decision procedure must stay
 * testable without a session, and this is the only module in the directory
 * that knows a settings store exists.
 */
import type { Settings } from "../../config/settings";
import { buildPermissionPolicy } from "./profiles";
import type { PermissionPolicy, PermissionProfile } from "./types";

type GlobListKey =
	| "permissions.deny.read"
	| "permissions.deny.write"
	| "permissions.allow.read"
	| "permissions.allow.write";

function globList(settings: Settings, key: GlobListKey): readonly string[] | undefined {
	const value = settings.get(key);
	if (!Array.isArray(value)) return undefined;
	return value.filter((entry): entry is string => typeof entry === "string");
}

/** Cheap pre-check so the `off` path never builds a policy at all. */
export function readPermissionProfile(settings: Settings | undefined): PermissionProfile {
	return settings?.get("permissions.profile") ?? "off";
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
