/**
 * Class B: best-effort literal scan of opaque tool arguments.
 *
 * `bash`, `eval`, `browser`, `computer`, `hub`, and every MCP or extension
 * tool take arbitrary code or a command line. Sound enforcement against that
 * is undecidable — `cat .env` is also `$(echo Lmk|base64 -d)` — so this looks
 * for a *literal* reference to a denied path and nothing more. It stops
 * accidents and naive prompt injection. **It is not a sandbox.** The real
 * boundary for arbitrary code is `tools.approval.bash: deny`, which already
 * exists and is unchanged by this layer.
 *
 * Only deny globs are consulted. Confinement is deliberately not applied here:
 * a shell line naming `/usr/bin/env` is not a write to it, and treating every
 * absolute literal as an escaping write would make the scan unusable.
 */

import * as path from "node:path";
import { tokenizeShellSegments } from "../shell-tokenize";
import { relativeToRoots } from "./confine";
import { matchGlob } from "./matcher";
import { isExemptPathArgument, permissionRootList, resolveTargetPath } from "./resolve";
import type { PathAccess, PermissionPolicy, PermissionRoots } from "./types";

/** A literal in an opaque argument that matched a deny rule. */
export interface ScanHit {
	/** The literal exactly as it appeared in the arguments. */
	readonly literal: string;
	/** The deny glob that matched it. */
	readonly rule: string;
	/** Which deny list it came from. */
	readonly access: PathAccess;
}

/** Depth bound so a pathological nested argument object cannot stall a call. */
const MAX_SCAN_DEPTH = 6;
/** Literal bound for the same reason — a long script yields many tokens. */
const MAX_SCAN_LITERALS = 512;

function collectStrings(value: unknown, out: string[], depth: number): void {
	if (out.length >= MAX_SCAN_LITERALS) return;
	if (typeof value === "string") {
		out.push(value);
		return;
	}
	if (depth >= MAX_SCAN_DEPTH || !value || typeof value !== "object") return;
	if (Array.isArray(value)) {
		for (const entry of value) collectStrings(entry, out, depth + 1);
		return;
	}
	for (const entry of Object.values(value as Record<string, unknown>)) collectStrings(entry, out, depth + 1);
}

/** Whitespace, quotes, grouping, and the `=` that separates `--flag=path`. */
const LITERAL_SPLIT_RE = /[\s'"`()=]+/;

/**
 * Push `parts` onto `out` one at a time, stopping the instant `out` reaches
 * {@link MAX_SCAN_LITERALS}. `out.push(...parts)` was the previous shape —
 * that materializes every token from a single oversized argument before the
 * cap is ever consulted (defeating the bound for one long string, not just
 * many short ones) and a spread call large enough can itself throw
 * `RangeError` before `push` runs at all. Returns whether the cap was hit, so
 * the caller can stop scanning further tokens/values without doing any more
 * work than the cap allows.
 */
function pushCapped(out: string[], parts: readonly string[]): boolean {
	for (const part of parts) {
		if (out.length >= MAX_SCAN_LITERALS) return true;
		out.push(part);
	}
	return out.length >= MAX_SCAN_LITERALS;
}

/**
 * Split raw strings into the literals worth testing.
 *
 * Shell arguments go through `tokenizeShellSegments`, the same tokenizer the
 * bash approval-pattern matcher uses, so quoting and operators are handled
 * consistently. Tokens are then split again on `=` so `--env-file=.env` yields
 * `.env`; everything else is split directly.
 */
function candidateLiterals(values: readonly string[], scan: "shell" | "strings"): string[] {
	const literals: string[] = [];
	for (const value of values) {
		if (literals.length >= MAX_SCAN_LITERALS) break;
		if (scan === "shell") {
			const before = literals.length;
			let capped = false;
			for (const segment of tokenizeShellSegments(value)) {
				for (const token of segment) {
					if (pushCapped(literals, token.split(LITERAL_SPLIT_RE))) {
						capped = true;
						break;
					}
				}
				if (capped) break;
			}
			// A tokenizer that found nothing in *this* value (unterminated
			// quoting, an empty segment) must still contribute its words —
			// checked per value, not against the accumulated array, or only
			// the first value could ever reach the fallback.
			if (!capped && literals.length === before) pushCapped(literals, value.split(LITERAL_SPLIT_RE));
			if (literals.length >= MAX_SCAN_LITERALS) break;
			continue;
		}
		if (pushCapped(literals, value.split(LITERAL_SPLIT_RE))) break;
	}
	return literals;
}

/**
 * Cheap reject for tokens that cannot be a path reference worth testing.
 *
 * A leading `-` is a flag, not a path: matching `--color` against a deny glob
 * only produces false denials. A single character cannot name anything a rule
 * realistically targets. Both are scan limitations, and Class B is documented
 * as best-effort precisely because limitations like these exist.
 */
function looksLikePathReference(literal: string): boolean {
	if (literal.length < 2 || literal.length > 4096) return false;
	if (literal.startsWith("-")) return false;
	return true;
}

/**
 * Scan opaque tool arguments for a literal reference to a denied path.
 *
 * Returns the first hit, or `null`. Both deny lists are consulted regardless
 * of what the command would actually do with the path: an opaque tool gives no
 * way to tell a read from a write, and under-matching here is the failure mode
 * that matters.
 */
export function scanOpaqueArguments(
	params: unknown,
	scan: "shell" | "strings",
	policy: PermissionPolicy,
	roots: PermissionRoots,
): ScanHit | null {
	if (policy.deny.read.length === 0 && policy.deny.write.length === 0) return null;

	const strings: string[] = [];
	collectStrings(params, strings, 0);
	if (strings.length === 0) return null;

	const rootList = permissionRootList(roots);
	const seen = new Set<string>();
	for (const literal of candidateLiterals(strings, scan)) {
		if (!looksLikePathReference(literal) || seen.has(literal)) continue;
		seen.add(literal);
		if (isExemptPathArgument(literal)) continue;

		const absolute = resolveTargetPath(literal, roots.cwd);
		// A literal the resolver rejects is not a path reference; unlike a
		// declared path argument there is nothing to fail closed about.
		if (!absolute) continue;

		const relatives = relativeToRoots(absolute, rootList);
		// Same normalization `decidePathTarget` applies (`resolve.ts`) - permission
		// globs are written with `/`, but `path.relative`/an absolute path (and
		// the literal itself, when it is a Windows-spelled path the caller typed
		// verbatim, e.g. `C:\Users\me\.ssh\config`) use `\` on Windows, which
		// `Bun.Glob` treats as a distinct, non-equivalent character.
		const candidates = [...relatives, absolute, path.basename(absolute), literal].map(candidate =>
			candidate.replaceAll("\\", "/"),
		);

		for (const access of ["read", "write"] as const) {
			if (matchGlob(policy.allow[access], candidates)) continue;
			const rule = matchGlob(policy.deny[access], candidates);
			if (rule) return { literal, rule, access };
		}
	}
	return null;
}

/** The message a scan hit surfaces, naming the rule and how to relax it. */
export function scanDenialMessage(toolName: string, hit: ScanHit): string {
	return (
		`Tool "${toolName}" refers to "${hit.literal}", which is blocked by the resource permission ` +
		`rule "${hit.rule}" (permissions.deny.${hit.access}).\n` +
		`This is a literal scan of an opaque tool's arguments, not a sandbox — it cannot see through ` +
		`indirection, and the boundary for arbitrary code is "tools.approval.${toolName}: deny".\n` +
		`To allow it: add "${hit.rule}" to permissions.allow.${hit.access}, ` +
		`or set permissions.opaqueToolScan: off.`
	);
}
