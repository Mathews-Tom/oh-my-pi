/**
 * Core types for the resource permission layer.
 *
 * The layer answers exactly one question — *may this tool call touch this
 * path?* — and it can only ever **subtract**. A path it permits still faces
 * `tools.approvalMode` and `tools.approval.<tool>` exactly as before, so no
 * combination of these settings can auto-approve anything.
 */

/** Whether a resolved path target is about to be read or written. */
export type PathAccess = "read" | "write";

/**
 * Base policy tier.
 *
 * - `off` — no enforcement. The gate short-circuits on this value before any
 *   filesystem work, so existing sessions pay nothing.
 * - `workspace` — writes must land under a workspace root; reads unrestricted.
 * - `strict` — `workspace` plus the built-in secret deny globs.
 */
export type PermissionProfile = "off" | "workspace" | "strict";

/** What the Class B literal scan does when it spots a denied path. */
export type OpaqueToolScanMode = "deny" | "prompt" | "off";

/** A single filesystem target a tool call declared, before resolution. */
export interface PathTarget {
	/** The path as the tool received it, whitespace-trimmed; used verbatim in messages. */
	readonly raw: string;
	/** The access the owning tool is about to perform on it. */
	readonly access: PathAccess;
	/** Tool argument the path came from, for an actionable denial message. */
	readonly field: string;
}

/** Deny/allow glob lists, split by the access they govern. */
export interface AccessGlobs {
	readonly read: readonly string[];
	readonly write: readonly string[];
}

/** A fully merged policy: profile defaults plus user overrides. */
export interface PermissionPolicy {
	readonly profile: PermissionProfile;
	readonly confineReads: boolean;
	readonly confineWrites: boolean;
	readonly deny: AccessGlobs;
	readonly allow: AccessGlobs;
	readonly opaqueToolScan: OpaqueToolScanMode;
}

/** The workspace roots a confinement check measures against. */
export interface PermissionRoots {
	/** Session cwd, absolute. */
	readonly cwd: string;
	/** `workspace.additionalDirectories`, absolute. */
	readonly additionalDirectories: readonly string[];
}

/**
 * Outcome of evaluating one {@link PathTarget}.
 *
 * `deny` carries the rule that fired verbatim so the message names something
 * the user can actually go and change, and so the model can adapt instead of
 * retrying the same call.
 */
export type PermissionDecision =
	| { readonly kind: "allow" }
	| {
			readonly kind: "deny";
			/** The exact rule text — a glob, or a confinement rule name. */
			readonly rule: string;
			/** Human-readable explanation naming the setting to change. */
			readonly reason: string;
	  };

/** Convenience singleton for the overwhelmingly common outcome. */
export const ALLOW: PermissionDecision = { kind: "allow" };
