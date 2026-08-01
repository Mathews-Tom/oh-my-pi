/**
 * Glob compilation and matching for permission rules.
 *
 * `Bun.Glob` is the house matcher (14+ callsites) and needs no dependency. The
 * regex forms occasionally requested for command policies are deliberately not
 * supported here: path rules and command rules are different dialects, and
 * conflating them is how a user ends up writing `*.env` and believing nested
 * secrets are covered.
 *
 * `Bun.Glob` accepts any string — a malformed pattern such as `[a-` compiles
 * and then matches nothing rather than throwing. There is deliberately no
 * try/catch here pretending otherwise: if a future runtime does throw, the
 * exception propagates out of the gate and blocks the tool call, which is the
 * fail-closed direction for a deny layer.
 */

/**
 * Compiled globs are cached process-wide keyed by pattern text.
 *
 * A policy is stable for the life of a settings generation, and the same
 * handful of patterns is re-matched on every tool call, so compiling once is
 * the difference between a hot path and a hot loop. The cache is keyed by the
 * pattern itself, so two policies sharing one secret rule share one glob.
 */
const GLOB_CACHE = new Map<string, Bun.Glob>();

/** Bound so a pathological config cannot grow the cache without limit. */
const GLOB_CACHE_LIMIT = 512;

/**
 * The first pattern in `patterns` matching any of `candidates`, or `null`.
 *
 * Returning the *pattern* rather than a boolean is what lets a denial name the
 * exact rule the user wrote, which is the difference between a message they can
 * act on and one they have to reverse-engineer.
 */
export function matchGlob(patterns: readonly string[], candidates: readonly string[]): string | null {
	for (const pattern of patterns) {
		let glob = GLOB_CACHE.get(pattern);
		if (!glob) {
			glob = new Bun.Glob(pattern);
			// Past the bound, stop caching rather than thrash: a full clear
			// would make every subsequent call recompile the whole policy.
			if (GLOB_CACHE.size < GLOB_CACHE_LIMIT) GLOB_CACHE.set(pattern, glob);
		}
		for (const candidate of candidates) {
			if (candidate && glob.match(candidate)) return pattern;
		}
	}
	return null;
}
