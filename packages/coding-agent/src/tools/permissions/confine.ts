/**
 * Symlink-safe containment against N workspace roots.
 *
 * This is `confineToWorkspace` (`../path-utils.ts`) generalized from one root
 * to `[cwd, ...workspace.additionalDirectories]`, sharing its helpers rather
 * than reimplementing them, and preserving its behaviour deliberately:
 *
 * - the roots themselves are realpath-resolved, so a workspace reached through
 *   a link of its own (`/tmp` on macOS) still contains its contents;
 * - an existing target is realpath-resolved outright, so `ws/link/passwd`
 *   under `ws/link -> /etc` is caught;
 * - a target that is itself a *dangling* symlink is refused, because deciding
 *   where it lands would mean reimplementing multi-hop symlink resolution
 *   against a link that can be re-pointed between the check and the write;
 * - otherwise the deepest existing ancestor is resolved and the remaining
 *   segments re-applied, which is the only thing resolvable for a file that
 *   does not exist yet.
 *
 * Three intentional divergences, all consequences of the different input:
 * `confineToWorkspace` guards an untrusted *relative* download path, this
 * guards an *already-resolved absolute* tool target.
 *
 * 1. **A root itself is contained.** A download always names a file; a tool
 *    target may legitimately be a workspace root (`glob path: "."`).
 * 2. **No pre-realpath lexical gate.** `confineToWorkspace` refuses absolute
 *    inputs outright (`path-utils.ts:545`) and then rejects anything lexically
 *    outside its single root before touching the filesystem. Here every input
 *    is absolute, so the equivalent gate would reject every additional root.
 *    A target that is lexically outside but whose realpath lands inside a root
 *    is therefore contained — correct for a multi-root guard, and strictly a
 *    question of which real file is at stake.
 * 3. **The ancestor walk climbs to `/` rather than halting at the root.** It
 *    follows from (2): with no single root to halt at, the walk stops at the
 *    filesystem root. The projected path is checked against every real root
 *    either way, so the outcome is unchanged.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { isEnoent } from "@oh-my-pi/pi-utils";
import { isUnderRootLexical, tryRealpath } from "../path-utils";

/** Why a target failed containment, or that it passed. */
export type ContainmentResult =
	| { readonly contained: true; readonly root: string }
	| {
			readonly contained: false;
			readonly reason: "outside" | "dangling-symlink" | "unreadable" | "no-roots";
	  };

/**
 * Whether `absolutePath` lands inside one of `roots`.
 *
 * `absolutePath` must already be resolved the way the owning tool resolves it
 * (see `resolveToCwd`), so the guard and the tool cannot disagree about which
 * file is at stake.
 *
 * Fail-closed throughout: an unresolvable root contributes nothing, and a
 * target whose destination cannot be determined is *not* contained.
 */
export function confineToRoots(absolutePath: string, roots: readonly string[]): ContainmentResult {
	const resolved = path.resolve(absolutePath);
	const realRoots: string[] = [];
	for (const root of roots) {
		// An unresolvable root is not a workspace that can contain anything.
		const real = tryRealpath(path.resolve(root));
		if (real) realRoots.push(real);
	}
	if (realRoots.length === 0) return { contained: false, reason: "no-roots" };

	// An existing target is authoritative: resolve it outright so a symlink
	// pointing out of the workspace is caught rather than trusted.
	const realTarget = tryRealpath(resolved);
	if (realTarget) {
		for (const root of realRoots) {
			if (isUnderRootLexical(realTarget, root, { includeRoot: true })) return { contained: true, root };
		}
		return { contained: false, reason: "outside" };
	}

	// `realpath` also fails on a dangling link, and a write follows that link
	// wherever it points. "Cannot tell where this lands" is the whole answer.
	//
	// Only a definitive ENOENT means "ordinary not-yet-created path". Any other
	// `lstat` failure (EACCES on a parent, transient I/O) leaves the shape of
	// the target unknown, and an unknown target must not be projected into a
	// root — that would be the one way this function could fail open.
	try {
		if (fs.lstatSync(resolved).isSymbolicLink()) return { contained: false, reason: "dangling-symlink" };
	} catch (err) {
		if (!isEnoent(err)) return { contained: false, reason: "unreadable" };
	}

	// Walk up to the deepest ancestor that does exist, resolve that, then
	// re-apply the segments below it. `path.resolve` above already folded any
	// `..`, so those segments cannot climb back out.
	const tail: string[] = [path.basename(resolved)];
	let ancestor = path.dirname(resolved);
	for (;;) {
		const real = tryRealpath(ancestor);
		if (real) {
			const projected = path.join(real, ...[...tail].reverse());
			for (const root of realRoots) {
				if (isUnderRootLexical(projected, root, { includeRoot: true })) return { contained: true, root };
			}
			return { contained: false, reason: "outside" };
		}
		const parent = path.dirname(ancestor);
		// Ran past the filesystem root without finding anything real.
		if (parent === ancestor) return { contained: false, reason: "outside" };
		tail.push(path.basename(ancestor));
		ancestor = parent;
	}
}

/**
 * Every workspace-relative spelling of `absolutePath` that lands under one of
 * `roots` — the raw (lexical) path plus its realpath-resolved form.
 *
 * Both are returned, not just the first one found: a symlink alias inside the
 * workspace (`safe -> .env`, both under the same root) is contained under its
 * lexical spelling (`safe`) on the very first root/target pair, which used to
 * make this function return early and never surface the resolved spelling
 * (`.env`) at all — so a deny rule written as `**\/.env` never saw the alias.
 * Returning both lets a caller's glob match test whichever spelling the rule
 * was written for, without weakening the separate (and stricter) "resolves
 * outside every root" containment check in {@link confineToRoots}.
 *
 * Realpath-aware on both sides so a symlinked root (macOS `/tmp` ->
 * `/private/tmp`) still yields a relative candidate; without that, a user rule
 * written as `config/secrets.json` would silently never match.
 */
export function relativeToRoots(absolutePath: string, roots: readonly string[]): string[] {
	const resolved = path.resolve(absolutePath);
	const realTarget = tryRealpath(resolved) ?? resolved;
	const out: string[] = [];
	const seen = new Set<string>();
	for (const root of roots) {
		const resolvedRoot = path.resolve(root);
		for (const candidateRoot of [resolvedRoot, tryRealpath(resolvedRoot)]) {
			if (!candidateRoot) continue;
			for (const target of [resolved, realTarget]) {
				const relative = path.relative(candidateRoot, target);
				if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) continue;
				if (!seen.has(relative)) {
					seen.add(relative);
					out.push(relative);
				}
			}
		}
	}
	return out;
}
