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
 * and then matches nothing rather than throwing (verified: `new
 * Bun.Glob("[a-")` never throws for any input tried against it). That would
 * otherwise leave a typo'd `permissions.deny.*` rule silently unenforced with
 * no error anywhere, so {@link validateGlobPattern} runs at settings load
 * (`config.ts`) rather than relying on a throw that never comes.
 */

/**
 * Cheap, conservative validity check for a glob pattern, independent of
 * `Bun.Glob`'s own (silently-permissive) behavior.
 *
 * Walks brace expansion (`{...}`) and character-class (`[...]`) grammar well
 * enough to catch the ways a truncated or typo'd pattern most commonly goes
 * wrong: `{a,b` (unterminated brace), `[a-` (unterminated class), and two
 * subtler cases that compile without error yet match nothing at all —
 * `[]`/`[!]`/`[^]` (an empty class: per the POSIX dialect `Bun.Glob` follows,
 * a `]` immediately after `[`, `[!`, or `[^` is a literal class member, not
 * the closer, so an empty-looking class has no real closer and is dead) and
 * a trailing `\` with nothing left to escape. Not a full glob-grammar parser;
 * a pattern that parses cleanly but is otherwise nonsensical still compiles
 * (as always) and is the user's own concern. Returns a human-readable
 * problem description, or `null` when the pattern is well-formed.
 */
export function validateGlobPattern(pattern: string): string | null {
	let braceDepth = 0;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\") {
			if (i === pattern.length - 1) return `dangling "\\" escape at end of pattern`;
			i++; // an escaped char is a literal, even if it's a bracket/brace
			continue;
		}
		if (ch === "[") {
			i++;
			if (pattern[i] === "!" || pattern[i] === "^") i++;
			if (pattern[i] === "]") i++; // a "]" right after "[" (or "[!"/"[^") is a literal member
			while (i < pattern.length && pattern[i] !== "]") {
				if (pattern[i] === "\\") i++;
				i++;
			}
			if (i >= pattern.length) return `unterminated "[" character class`;
			continue; // outer loop's increment steps past the closing "]"
		}
		if (ch === "{") braceDepth++;
		else if (ch === "}") braceDepth = Math.max(0, braceDepth - 1);
	}
	if (braceDepth > 0) return `unterminated "{" brace expansion`;
	return null;
}

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

/** A pattern match, plus the exact candidate spelling that satisfied it. */
export interface GlobMatch {
	readonly pattern: string;
	readonly candidate: string;
}

/**
 * The first pattern in `patterns` matching any of `candidates`, alongside the
 * specific candidate spelling that matched, or `null`.
 *
 * Surfacing the candidate (not just the pattern) is what lets a caller
 * re-check a *different* glob list against that exact spelling rather than
 * the whole candidate set — see {@link matchGlob}'s callers in `resolve.ts`,
 * where a carve-out must only suppress a deny that matched the same lexical
 * or resolved spelling, never a deny that matched a different one. The
 * returned `candidate` is the original, unnormalized spelling — matching is
 * separator-agnostic below, but spelling-identity comparisons elsewhere are
 * not meant to be.
 *
 * `path.relative`/`path.resolve`/`path.basename` all yield `\`-separated
 * candidates on Windows, while `Bun.Glob`'s documented pattern rules use `/`.
 * A directory-sensitive rule such as `config/secrets.json`, `**\/.aws/credentials`,
 * or `src/generated/**` therefore matched neither the relative nor the
 * absolute Windows candidate — only the basename candidate ever compiled a
 * separator-free string, which rescues a basename-only pattern but nothing
 * that names an intermediate directory. Normalizing every candidate before
 * matching, rather than gating on `process.platform`, keeps this path
 * exercised (and testable) on every OS instead of only on a Windows CI
 * runner; a POSIX filename containing a literal backslash is accepted
 * fallout, the same class of tradeoff `path-utils.ts`'s quote-stripping
 * already makes for a POSIX name literally wrapped in double quotes.
 */
export function matchGlobCandidate(patterns: readonly string[], candidates: readonly string[]): GlobMatch | null {
	for (const pattern of patterns) {
		let glob = GLOB_CACHE.get(pattern);
		if (!glob) {
			glob = new Bun.Glob(pattern);
			// Past the bound, stop caching rather than thrash: a full clear
			// would make every subsequent call recompile the whole policy.
			if (GLOB_CACHE.size < GLOB_CACHE_LIMIT) GLOB_CACHE.set(pattern, glob);
		}
		for (const candidate of candidates) {
			const normalized = candidate.includes("\\") ? candidate.replace(/\\/g, "/") : candidate;
			if (normalized && glob.match(normalized)) return { pattern, candidate };
		}
	}
	return null;
}

/**
 * The first pattern in `patterns` matching any of `candidates`, or `null`.
 *
 * Returning the *pattern* rather than a boolean is what lets a denial name the
 * exact rule the user wrote, which is the difference between a message they can
 * act on and one they have to reverse-engineer.
 */
export function matchGlob(patterns: readonly string[], candidates: readonly string[]): string | null {
	return matchGlobCandidate(patterns, candidates)?.pattern ?? null;
}
