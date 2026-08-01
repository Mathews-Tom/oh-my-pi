/**
 * Which tool arguments are filesystem paths, and what the tool does with them.
 *
 * Two classes, and the split is the honest boundary of the whole feature:
 *
 * - **structured** — the tool declares its path arguments, so enforcement is
 *   sound. `read`, `write`, `edit`, `grep`, `glob`, `ast_grep`, `ast_edit`,
 *   `lsp`, `debug`, `inspect_image`, `security_scan`.
 * - **opaque** — the tool takes arbitrary code or a command line. `cat .env`
 *   can be spelled `$(echo Lmk|base64 -d)`, so no static analysis is sound
 *   here. These get a best-effort literal scan, which stops accidents and
 *   naive prompt injection and is **not** a sandbox.
 *
 * `pathless` is the third state and exists so the exhaustiveness test can tell
 * "deliberately has no paths" from "nobody classified this yet". An unknown
 * tool name — MCP, extension, custom — defaults to `opaque`, so a new
 * `filesystem/read_file {path: ".env"}` is scanned rather than waved through.
 */
import { Patch } from "@oh-my-pi/hashline";
// The leaf module, not the `../../lsp` barrel: `lsp/index.ts` imports the
// permission gate to validate server-supplied workspace edits, so pulling the
// barrel in here would close an import cycle.
import { LSP_READONLY_ACTIONS } from "../../lsp/actions";
import { BUILTIN_TOOL_NAMES, HIDDEN_TOOL_NAMES, normalizeToolName } from "../builtin-names";
import type { PathAccess, PathTarget } from "./types";

/** Pulls the declared path arguments out of one tool call's arguments. */
export type PathTargetExtractor = (args: Record<string, unknown>) => PathTarget[];

/** Pulls the files a tool actually touched out of its result details, for the post-execution recheck. */
export type ResultPathTargetExtractor = (details: unknown) => PathTarget[];

export type ToolPathClass =
	| {
			readonly kind: "structured";
			readonly extract: PathTargetExtractor;
			/**
			 * For a tool whose declared scope root can diverge from the files it
			 * actually opens — `grep`/`ast_grep`/`ast_edit` recurse beneath the
			 * checked root — this re-derives the real target set from the
			 * executed result, so the gate can recheck it after the fact.
			 * `undefined` for every tool whose declared targets are already the
			 * tool's complete filesystem surface.
			 */
			readonly resultTargets?: ResultPathTargetExtractor;
	  }
	| { readonly kind: "opaque"; readonly scan: "shell" | "strings" }
	| { readonly kind: "pathless" };

/**
 * `glob`, `grep`, and `ast_grep` accept several roots in one string argument.
 * Splitting here keeps the guard looking at the same entries the tool will.
 */
const MULTI_PATH_SEPARATOR = ";";

function pushPath(out: PathTarget[], raw: unknown, access: PathAccess, field: string): void {
	if (typeof raw !== "string") return;
	const trimmed = raw.trim();
	if (!trimmed) return;
	out.push({ raw: trimmed, access, field });
}

function pushDelimited(out: PathTarget[], raw: unknown, access: PathAccess, field: string): void {
	if (typeof raw !== "string") return;
	for (const part of raw.split(MULTI_PATH_SEPARATOR)) pushPath(out, part, access, field);
}

function pushArray(out: PathTarget[], raw: unknown, access: PathAccess, field: string): void {
	if (!Array.isArray(raw)) return;
	for (const entry of raw) pushPath(out, entry, access, field);
}

/** A single top-level string argument. */
function singlePath(field: string, access: PathAccess): PathTargetExtractor {
	return args => {
		const out: PathTarget[] = [];
		pushPath(out, args[field], access, field);
		return out;
	};
}

/** A single top-level string argument holding `;`-delimited entries. */
function delimitedPath(field: string, access: PathAccess): PathTargetExtractor {
	return args => {
		const out: PathTarget[] = [];
		pushDelimited(out, args[field], access, field);
		return out;
	};
}

const APPLY_PATCH_FILE_RE = /^\*\*\* (?:Add|Delete|Update) File: (.+)$/;
const APPLY_PATCH_MOVE_RE = /^\*\*\* Move to: (.+)$/;
// `MV DEST` is hashline's file-level move op (`HL_MOVE_KEYWORD`,
// `packages/hashline/src/format.ts`): the section's final content is written at
// `DEST`, so `DEST` is a write target. The destination may be quoted when it
// contains spaces, mirroring the tokenizer's `scanMoveDest`.
const HASHLINE_MOVE_RE = /^MV\s+(.+)$/;

function stripQuotes(value: string): string {
	const trimmed = value.trim();
	if (trimmed.length < 2) return trimmed;
	const first = trimmed[0];
	if ((first === '"' || first === "'") && trimmed.endsWith(first)) return trimmed.slice(1, -1);
	return trimmed;
}

/**
 * Paths embedded in an `edit` payload that has no top-level `path`.
 *
 * The hashline and `apply_patch` modes carry their targets inside `input`, as
 * `[path#TAG]` section headers, `MV DEST` move ops, and
 * `*** Update File: path` markers. All three are strict, line-anchored
 * grammars and a mode cannot touch a file it does not name, so extracting them
 * is sound rather than best-effort.
 *
 * Section headers are parsed with `Patch.parse` — the same splitter
 * `Patcher.apply` uses — rather than a hand-rolled `[.+]` regex, so a
 * header's exact interpretation (tag stripping, quoting, a `..` traversal in
 * the path) can never diverge from what the real executor resolves and
 * writes. `MV DEST` and the `apply_patch` markers stay a direct per-line
 * scan: both are single-token grammars with no header-context dependency,
 * and (unlike the header case) scanning bare lines catches a move/marker even
 * outside a well-formed section — strictly more cautious than the real
 * executor, never less.
 */
export function extractEmbeddedEditPaths(input: string): PathTarget[] {
	const out: PathTarget[] = [];
	try {
		for (const section of Patch.parse(input).sections) {
			pushPath(out, section.path, "write", "input");
		}
	} catch {
		// Not hashline-shaped input, or a section body parse error the real
		// executor will also hit; nothing further to extract from headers.
	}
	for (const line of input.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		const applyPatch = APPLY_PATCH_FILE_RE.exec(trimmed) ?? APPLY_PATCH_MOVE_RE.exec(trimmed);
		if (applyPatch) {
			pushPath(out, applyPatch[1], "write", "input");
			continue;
		}
		const move = HASHLINE_MOVE_RE.exec(trimmed);
		if (move) pushPath(out, stripQuotes(move[1]), "write", "input");
	}
	return out;
}

const extractEditPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	// patch/replace modes: one top-level target plus per-edit rename destinations.
	pushPath(out, args.path, "write", "path");
	if (Array.isArray(args.edits)) {
		for (const edit of args.edits) {
			if (edit && typeof edit === "object") {
				pushPath(out, (edit as Record<string, unknown>).rename, "write", "edits[].rename");
			}
		}
	}
	// hashline / apply_patch modes: targets live inside the payload.
	if (typeof args.input === "string") out.push(...extractEmbeddedEditPaths(args.input));
	return out;
};

const extractDebugPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	pushPath(out, args.program, "read", "program");
	pushPath(out, args.file, "read", "file");
	// A debuggee inherits the cwd and can write through it.
	pushPath(out, args.cwd, "write", "cwd");
	return out;
};

/**
 * `debug` actions whose complete filesystem/execution surface is not covered
 * by the declared `program`/`file`/`cwd` fields: `launch` and `attach` start
 * or attach to an arbitrary process with arbitrary `args`, `evaluate` sends
 * a raw debugger expression, `write_memory` writes raw bytes, and
 * `custom_request` sends an arbitrary DAP command with an arbitrary
 * `arguments` payload. A call like
 * `debug({ action: "launch", program: "/bin/sh", args: ["-c", "cat .env"] })`
 * only names `/bin/sh` in a declared field, so `extractDebugPaths` would
 * never see `.env` — these actions get the same best-effort literal scan an
 * opaque tool does instead of a false sense of structured soundness.
 * Breakpoint and inspection actions keep the structured classification: their
 * complete filesystem surface really is `file`/`program`/`cwd`.
 */
const DEBUG_OPAQUE_ACTIONS: ReadonlySet<string> = new Set([
	"launch",
	"attach",
	"evaluate",
	"write_memory",
	"custom_request",
]);

/**
 * `lsp`'s `request` action sends a caller-chosen JSON-RPC `method` (from
 * `query`) with a caller-chosen `payload` directly to the server - there is
 * no declared path field at all, so a call like
 * `lsp({ action: "request", query: "workspace/executeCommand", payload: '{"path":".env"}' })`
 * would otherwise pass the structured gate with zero targets checked. Scanned
 * like `debug`'s opaque actions instead: the raw `query`/`payload` strings go
 * through the same best-effort literal scan an opaque tool gets.
 */
const LSP_OPAQUE_ACTIONS: ReadonlySet<string> = new Set(["request"]);

const extractLspPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	// Invert the tool's own central classification (`lsp/index.ts` uses exactly
	// this set to pick its approval tier) rather than restating which actions
	// write. A local copy drifts: `request` and `reload` are write-tier there
	// and were missing from an earlier hand-rolled list here.
	const action = typeof args.action === "string" ? args.action : "";
	const writes = !LSP_READONLY_ACTIONS.has(action);
	pushPath(out, args.file, writes ? "write" : "read", "file");
	if (action === "rename_file") pushPath(out, args.new_name, "write", "new_name");
	return out;
};

const extractSecurityScanPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	pushArray(out, args.include_paths, "read", "include_paths");
	pushArray(out, args.knowledge_base_paths, "read", "knowledge_base_paths");
	pushPath(out, args.output_root, "write", "output_root");
	// `exclude_paths` only narrows a scan; it is never opened.
	return out;
};

// `hub`, `browser`, `bash`, `eval`, and `computer` all reach arbitrary code —
// a spawned application, an evaluated script, a shell line — so none of them
// gets a structured extractor. Declaring one would imply a soundness the class
// does not have; they are scanned instead.

/**
 * The files a recursive search/edit tool actually visited, from its own
 * result — the post-execution half of the recheck `enforcePostExecutionResourcePermissions`
 * (`gate.ts`) runs against a policy the declared-argument gate already
 * evaluated before the call.
 */
function extractResultFiles(details: unknown, access: PathAccess): PathTarget[] {
	if (!details || typeof details !== "object" || !("files" in details)) return [];
	const { files } = details;
	if (!Array.isArray(files)) return [];
	const out: PathTarget[] = [];
	for (const file of files) pushPath(out, file, access, "files");
	return out;
}

/**
 * Every built-in tool, classified.
 *
 * `test/tools/permissions-tool-classes.test.ts` asserts this covers
 * `BUILTIN_TOOL_NAMES` and `HIDDEN_TOOL_NAMES` exactly, so a future
 * path-taking tool cannot be added without a deliberate classification.
 */
export const TOOL_PATH_CLASSES: Record<string, ToolPathClass> = {
	// ── Class A: structured path arguments ────────────────────────────────
	read: { kind: "structured", extract: singlePath("path", "read") },
	write: { kind: "structured", extract: singlePath("path", "write") },
	edit: { kind: "structured", extract: extractEditPaths },
	glob: { kind: "structured", extract: delimitedPath("path", "read") },
	grep: {
		kind: "structured",
		extract: delimitedPath("path", "read"),
		resultTargets: details => extractResultFiles(details, "read"),
	},
	ast_grep: {
		kind: "structured",
		extract: delimitedPath("path", "read"),
		resultTargets: details => extractResultFiles(details, "read"),
	},
	ast_edit: {
		kind: "structured",
		extract: args => {
			const out: PathTarget[] = [];
			pushArray(out, args.paths, "write", "paths");
			return out;
		},
		// The tool's dry-run pass reads every matched file to render its
		// original lines in the preview, before any `resolve` write happens —
		// so a touched file must clear `deny.read` as well as `deny.write`, not
		// just the latter, or a read-denied source can still reach the model
		// through the diff preview even though the eventual write is blocked.
		resultTargets: details => [...extractResultFiles(details, "read"), ...extractResultFiles(details, "write")],
	},
	lsp: { kind: "structured", extract: extractLspPaths },
	debug: { kind: "structured", extract: extractDebugPaths },
	inspect_image: { kind: "structured", extract: singlePath("path", "read") },
	security_scan: { kind: "structured", extract: extractSecurityScanPaths },

	// ── Class B: opaque — best-effort literal scan, never a sandbox ───────
	bash: { kind: "opaque", scan: "shell" },
	eval: { kind: "opaque", scan: "strings" },
	browser: { kind: "opaque", scan: "strings" },
	computer: { kind: "opaque", scan: "strings" },
	hub: { kind: "opaque", scan: "strings" },

	// ── No filesystem surface ─────────────────────────────────────────────
	ask: { kind: "pathless" },
	checkpoint: { kind: "pathless" },
	github: { kind: "pathless" },
	learn: { kind: "pathless" },
	manage_skill: { kind: "pathless" },
	memory_edit: { kind: "pathless" },
	recall: { kind: "pathless" },
	reflect: { kind: "pathless" },
	retain: { kind: "pathless" },
	rewind: { kind: "pathless" },
	// `task` carries a free-text prompt, not a path. Scanning it would deny an
	// ordinary instruction that merely names a secret ("never touch .env"),
	// while the subagent's own tool calls face this same gate at their own
	// wrapper — which is where the enforcement actually belongs.
	task: { kind: "pathless" },
	todo: { kind: "pathless" },
	web_search: { kind: "pathless" },
	goal: { kind: "pathless" },
	yield: { kind: "pathless" },
};

/**
 * Unknown tools are opaque, not pathless.
 *
 * An MCP or extension tool may well take a `path` argument this table has
 * never seen, so the safe default is to scan its string arguments rather than
 * assume it touches nothing.
 */
export const UNKNOWN_TOOL_CLASS: ToolPathClass = { kind: "opaque", scan: "strings" };

/**
 * The class for `toolName`, normalizing the legacy aliases (`search` -> `grep`,
 * `find` -> `glob`) so an alias gets the structured extractor rather than
 * falling through to the coarser opaque scan.
 *
 * `args` (the call's own arguments, when the caller has them) lets `debug`
 * and `lsp` be classified per-action: `TOOL_PATH_CLASSES.debug`/`.lsp` stay
 * plain structured entries (used directly by tests and as the base
 * extractor), but a call whose `action` is in {@link DEBUG_OPAQUE_ACTIONS} or
 * {@link LSP_OPAQUE_ACTIONS} is classified opaque here, since only the actual
 * call site knows the action.
 */
export function classifyTool(toolName: string, args?: Record<string, unknown> | null): ToolPathClass {
	const normalized = normalizeToolName(toolName);
	if (normalized === "debug") {
		const action = args && typeof args.action === "string" ? args.action : undefined;
		if (action && DEBUG_OPAQUE_ACTIONS.has(action)) return { kind: "opaque", scan: "strings" };
	}
	if (normalized === "lsp") {
		const action = args && typeof args.action === "string" ? args.action : undefined;
		if (action && LSP_OPAQUE_ACTIONS.has(action)) return { kind: "opaque", scan: "strings" };
	}
	return TOOL_PATH_CLASSES[normalized] ?? UNKNOWN_TOOL_CLASS;
}

/** The names this table must cover, for the exhaustiveness test. */
export const CLASSIFIED_TOOL_NAMES: readonly string[] = [...BUILTIN_TOOL_NAMES, ...HIDDEN_TOOL_NAMES];
