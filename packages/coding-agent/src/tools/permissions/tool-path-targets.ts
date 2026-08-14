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
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Patch } from "@oh-my-pi/hashline";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { getManagedSkillsDir, sanitizeSkillName } from "../../autolearn/managed-skills";
// The leaf module, not the `../../lsp` barrel: `lsp/index.ts` imports the
// permission gate to validate server-supplied workspace edits, so pulling the
// barrel in here would close an import cycle.
import { LSP_READONLY_ACTIONS } from "../../lsp/actions";
import { getMemoryRoot, LEARNED_LESSONS_FILE } from "../../memories";
import { loadMnemopiConfig } from "../../mnemopi/config";
import { getMnemopiRetainDbPath, getMnemopiScopedDbPaths } from "../../mnemopi/state";
import { BUILTIN_TOOL_NAMES, DYNAMIC_TOOL_NAMES, HIDDEN_TOOL_NAMES, normalizeToolName } from "../builtin-names";
import { unwrapHashlineHeaderPath } from "../plan-mode-guard";
import type { PathAccess, PathTarget } from "./types";

/** Pulls filesystem paths out of one tool call and its execution context. */
export type PathTargetExtractor = (args: Record<string, unknown>, context?: AgentToolContext) => PathTarget[];

/** Pulls the files a tool actually touched out of its result details, for the post-execution recheck. */
export type ResultPathTargetExtractor = (details: unknown) => PathTarget[];

export type ToolPathClass =
	| {
			readonly kind: "structured";
			readonly extract: PathTargetExtractor;
			/**
			 * Resolves targets whose names are only discoverable by reading a
			 * declared target. The gate invokes this only after `extract` clears
			 * policy, so a denied directory is never enumerated merely to decide
			 * whether its descendants are permitted.
			 */
			readonly postAuthorizationTargets?: PathTargetExtractor;
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

/**
 * A path an operation both reads and writes.
 *
 * Editing an existing file is not a pure write: patch and replace modes open
 * it to locate the edit, and a mismatch error quotes the closest actual source
 * line back to the model. A user who denies only reads
 * (`permissions.deny.read: ["**​/secret.txt"]`) would otherwise see those
 * contents through `edit`, which the write-side rules never covered.
 */
function pushReadWrite(out: PathTarget[], raw: unknown, field: string): void {
	pushPath(out, raw, "read", field);
	pushPath(out, raw, "write", field);
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

/** A top-level write path may be a pasted hashline header. Normalize it before
 *  policy resolution so the guard and WriteTool address the same target. */
function writePath(field: string): PathTargetExtractor {
	return args => {
		const out: PathTarget[] = [];
		const raw = args[field];
		pushPath(out, typeof raw === "string" ? unwrapHashlineHeaderPath(raw) : raw, "write", field);
		return out;
	};
}

const APPLY_PATCH_FILE_RE = /^\*\*\* (Add|Delete|Update) File: (.+)$/;
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
 *
 * Access follows what each op does to the file it names. A hashline section
 * anchors to tags minted from existing content, and `*** Update File` /
 * `*** Delete File` both open the file first, so all three read as well as
 * write. Only the two destinations that are produced rather than consulted —
 * `*** Add File` and a `MV`/`*** Move to` target — are write-only.
 */
export function extractEmbeddedEditPaths(input: string): PathTarget[] {
	const out: PathTarget[] = [];
	try {
		for (const section of Patch.parse(input).sections) {
			pushReadWrite(out, section.path, "input");
		}
	} catch {
		// Not hashline-shaped input, or a section body parse error the real
		// executor will also hit; nothing further to extract from headers.
	}
	for (const line of input.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		const applyPatch = APPLY_PATCH_FILE_RE.exec(trimmed);
		if (applyPatch) {
			if (applyPatch[1] === "Add") pushPath(out, applyPatch[2], "write", "input");
			else pushReadWrite(out, applyPatch[2], "input");
			continue;
		}
		const moveTo = APPLY_PATCH_MOVE_RE.exec(trimmed);
		if (moveTo) {
			pushPath(out, moveTo[1], "write", "input");
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
	// The target is read as well as written — both modes open it to locate the
	// edit, and a mismatch error quotes the closest real source line back.
	pushReadWrite(out, args.path, "path");
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

/**
 * Tools whose class depends on the `action` the call names: structured for
 * most actions, opaque for the ones listed here.
 *
 * The single source of truth for both {@link classifyTool}, which needs it per
 * call, and `/perm` (`describe.ts`), which needs it to report these tools as
 * mixed rather than as pure Class A. Splitting those two readings is exactly
 * how the report came to overstate coverage — enforcement knew `debug launch`
 * was opaque while the report still called `debug` "enforced exactly".
 */
export const ACTION_OPAQUE_TOOLS: Readonly<Record<string, ReadonlySet<string>>> = {
	debug: DEBUG_OPAQUE_ACTIONS,
	lsp: LSP_OPAQUE_ACTIONS,
};

const extractLspPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	// Invert the tool's own central classification (`lsp/index.ts` uses exactly
	// this set to pick its approval tier) rather than restating which actions
	// write. A local copy drifts as new actions are added.
	const action = typeof args.action === "string" ? args.action : "";
	const writes = !LSP_READONLY_ACTIONS.has(action);
	if (writes) pushReadWrite(out, args.file, "file");
	else pushPath(out, args.file, "read", "file");
	if (action === "rename_file") pushPath(out, args.new_name, "write", "new_name");
	return out;
};

/**
 * Managed skills are filesystem mutations even though their storage location
 * is not caller supplied. Resolve the exact regular-file path the executor
 * uses so workspace/strict confinement applies to create, update, and delete.
 */
const extractManagedSkillPaths = (args: Record<string, unknown>, field: string = "name"): PathTarget[] => {
	const out: PathTarget[] = [];
	if (typeof args.name !== "string") return out;
	let name = args.name;
	try {
		name = sanitizeSkillName(name);
	} catch {
		// Let ManageSkillTool/LearnTool report invalid names after the gate; this
		// conservative candidate still prevents a traversal-shaped name escaping.
	}
	const dir = path.join(getManagedSkillsDir(), name);
	if (args.action === "delete") {
		// `deleteManagedSkill` enumerates the directory before recursively
		// removing it, so authorization must cover both operations before that
		// enumeration happens.
		pushReadWrite(out, dir, field);
		return out;
	}
	pushPath(out, path.join(dir, "SKILL.md"), "write", field);
	return out;
};

/**
 * `deleteManagedSkill` recursively removes every existing descendant. Resolve
 * those write targets only after `extractManagedSkillPaths` authorized reading
 * the directory, so a read-denied directory is never enumerated.
 */
const extractManagedSkillDeleteDescendants = (args: Record<string, unknown>, field: string = "name"): PathTarget[] => {
	if (args.action !== "delete" || typeof args.name !== "string") return [];
	let name = args.name;
	try {
		name = sanitizeSkillName(name);
	} catch {
		// The initial extractor keeps the conservative traversal-shaped target.
	}
	const dir = path.join(getManagedSkillsDir(), name);
	let descendants: string[] = [];
	try {
		descendants = fs.readdirSync(dir, { recursive: true }) as string[];
	} catch {
		// Missing/unreadable directory: deleteManagedSkill itself throws before
		// touching anything in that case, so there is nothing further to
		// authorize.
	}
	const out: PathTarget[] = [];
	for (const entry of descendants) pushPath(out, path.join(dir, entry), "write", field);
	return out;
};

const extractSecurityScanPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	pushPath(out, args.output_root, "write", "output_root");
	// `include_paths` and `exclude_paths` are repository-relative scan filters.
	// The preflight guard authorizes the resulting paths from the canonical Git
	// root, which is the only resolution that matches execution. Knowledge-base
	// paths use the same late guard before they are read.
	return out;
};

/**
 * `generate_image` reads any declared `input[].path` reference images and
 * always writes its generated output under the process temp root
 * (`saveImageToTemp`, `image-gen.ts`): a random `omp-image-<id>.<ext>`
 * filename the tool never exposes as a caller-suppliable argument. Without
 * an explicit classification the tool fell to the opaque-string-scan
 * fallback for every unrecognized name, which never enforces confinement
 * and cannot see a path it has no argument to scan.
 */
const extractGenerateImagePaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	if (Array.isArray(args.input)) {
		for (const entry of args.input) {
			if (entry && typeof entry === "object") {
				pushPath(out, (entry as Record<string, unknown>).path, "read", "input");
			}
		}
	}
	out.push({ raw: os.tmpdir(), access: "write", field: "input" });
	return out;
};

/**
 * `retain`/`memory_edit`'s config for path derivation: the exact config their
 * own execution path resolves against.
 *
 * When the session already has an initialized `MnemopiSessionState`, its
 * `config` is what actually opened the session's SQLite handles — captured
 * once at backend startup, per {@link MnemopiSessionState}'s docs, and NOT
 * re-read on later `mnemopi.dbPath`/bank/scoping setting changes (only a
 * `memory.backend` change reinitializes it). Deriving from live settings
 * instead would authorize wherever the *new* settings point while the tool
 * keeps writing the *already-open* database — a settings-drift mismatch that
 * lets a write bypass `confineWrites`/`deny.write` (finding under review).
 * Only fall back to a live config resolution when no session state exists
 * yet: both tools throw before touching any database in that case, so no
 * write happens for a live-settings target to under- or over-authorize.
 */
function resolveMnemopiPathConfig(context: AgentToolContext | undefined) {
	const state = context?.getMnemopiSessionState?.();
	if (state) return state.config;
	const settings = context?.settings;
	return settings ? loadMnemopiConfig(settings, settings.getAgentDir()) : undefined;
}

/**
 * `retain` and `learn` take no path argument at all, but under
 * `memory.backend: mnemopi` both write through the same `rememberScoped` call
 * (`MnemopiSessionState.rememberScoped`, which `LearnTool.execute` calls
 * exactly like `MemoryRetainTool` does) onto the mnemopi SQLite database(s)
 * `resolveBankDbPath` resolves — under the agent memory directory by default,
 * but anywhere `mnemopi.dbPath` points. Deriving that path here (the same
 * config resolution the tools' own execution path uses) is what makes those
 * writes subject to `permissions.confineWrites`/`deny.write` instead of
 * silently bypassing them as "pathless"/local-only. Any other `memory.backend`
 * (e.g. `hindsight`) touches no mnemopi database, so this contributes no
 * targets.
 *
 * Registered as read+write, not write-only: `rememberScoped` opens the
 * database through the same SQLite handle `memory_edit` uses and its
 * `remember` call reads existing pages/indexes as part of the insert, so a
 * write-only target would let a `permissions.deny.read`/`confineReads` rule
 * that blocks the database pass `retain`/`learn` while `memory_edit` (already
 * read+write) is correctly refused.
 */
function extractMnemopiRetainPaths(context: AgentToolContext | undefined): PathTarget[] {
	if (context?.settings?.get("memory.backend") !== "mnemopi") return [];
	const config = resolveMnemopiPathConfig(context);
	if (!config) return [];
	const out: PathTarget[] = [];
	pushReadWrite(out, getMnemopiRetainDbPath(config), "memory");
	return out;
}

const extractRetainPaths: PathTargetExtractor = (_args, context) => extractMnemopiRetainPaths(context);

/**
 * `memory_edit` looks an id up across every bank the session recalls from
 * (retain, recall, global — see `MnemopiSessionState.editScopedMemory`)
 * before writing to whichever one has it, so every scoped database is both a
 * read and a write target: which one actually gets touched is not knowable
 * without doing that lookup.
 */
const extractMemoryEditPaths: PathTargetExtractor = (_args, context) => {
	if (context?.settings?.get("memory.backend") !== "mnemopi") return [];
	const config = resolveMnemopiPathConfig(context);
	if (!config) return [];
	const out: PathTarget[] = [];
	for (const dbPath of getMnemopiScopedDbPaths(config)) {
		pushReadWrite(out, dbPath, "memory");
	}
	return out;
};

/**
 * `recall` and `reflect` take no path argument either, but under
 * `memory.backend: mnemopi` both resolve to `state.recallResultsScoped`
 * (`MemoryRecallTool.execute` / `MemoryReflectTool.execute`), which reads
 * every bank the session recalls from and returns their content to the model.
 * Registered as read-only across the same scoped database set `memory_edit`
 * uses — the superset of banks a scoped lookup can touch — so
 * `confineReads`/`deny.read` on those databases actually apply instead of
 * these two tools passing the gate as pathless.
 */
const extractMnemopiScopedReadPaths: PathTargetExtractor = (_args, context) => {
	if (context?.settings?.get("memory.backend") !== "mnemopi") return [];
	const config = resolveMnemopiPathConfig(context);
	if (!config) return [];
	const out: PathTarget[] = [];
	for (const dbPath of getMnemopiScopedDbPaths(config)) {
		pushPath(out, dbPath, "read", "memory");
	}
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
	write: { kind: "structured", extract: writePath("path") },
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
	generate_image: { kind: "structured", extract: extractGenerateImagePaths },

	// ── Class B: opaque — best-effort literal scan, never a sandbox ───────
	bash: { kind: "opaque", scan: "shell" },
	eval: { kind: "opaque", scan: "strings" },
	browser: { kind: "opaque", scan: "strings" },
	computer: { kind: "opaque", scan: "strings" },
	hub: { kind: "opaque", scan: "strings" },

	ask: { kind: "pathless" },
	checkpoint: { kind: "pathless" },
	github: { kind: "pathless" },
	learn: {
		kind: "structured",
		extract: (args, context) => {
			const out: PathTarget[] = [];
			const settings = context?.settings;
			if (settings?.get("memory.backend") === "local") {
				// `saveLearnedLesson` (`memories/index.ts`) is a read-modify-write
				// through `appendLearnedLine`, which opens the existing file to
				// dedupe/prepend/cap its bullets before writing it back — the same
				// reason the mnemopi retain path below registers read+write rather
				// than write-only.
				pushReadWrite(
					out,
					path.join(getMemoryRoot(settings.getAgentDir(), settings.getCwd()), LEARNED_LESSONS_FILE),
					"memory",
				);
			}
			out.push(...extractMnemopiRetainPaths(context));
			const skill = args.skill;
			if (skill && typeof skill === "object") {
				out.push(...extractManagedSkillPaths(skill as Record<string, unknown>, "skill.name"));
			}
			return out;
		},
		postAuthorizationTargets: args => {
			const skill = args.skill;
			return skill && typeof skill === "object"
				? extractManagedSkillDeleteDescendants(skill as Record<string, unknown>, "skill.name")
				: [];
		},
	},
	manage_skill: {
		kind: "structured",
		extract: args => extractManagedSkillPaths(args),
		postAuthorizationTargets: args => extractManagedSkillDeleteDescendants(args),
	},
	memory_edit: { kind: "structured", extract: extractMemoryEditPaths },
	recall: { kind: "structured", extract: extractMnemopiScopedReadPaths },
	reflect: { kind: "structured", extract: extractMnemopiScopedReadPaths },
	retain: { kind: "structured", extract: extractRetainPaths },
	rewind: { kind: "pathless" },
	// `task` carries a free-text prompt, not a path. Scanning it would deny an
	// ordinary instruction that merely names a secret ("never touch .env"),
	// while the subagent's own tool calls face this same gate at their own
	// wrapper — which is where the enforcement actually belongs.
	task: { kind: "pathless" },
	todo: { kind: "pathless" },
	web_search: { kind: "pathless" },
	goal: { kind: "pathless" },
	think: { kind: "pathless" },
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
 * `args` (the call's own arguments, when the caller has them) lets the
 * {@link ACTION_OPAQUE_TOOLS} entries be classified per-action:
 * `TOOL_PATH_CLASSES.debug`/`.lsp` stay plain structured entries (used
 * directly by tests and as the base extractor), but a call whose `action` is
 * listed there is classified opaque here, since only the actual call site
 * knows the action.
 */
export function classifyTool(toolName: string, args?: Record<string, unknown> | null): ToolPathClass {
	const normalized = normalizeToolName(toolName);
	const opaqueActions = ACTION_OPAQUE_TOOLS[normalized];
	if (opaqueActions) {
		const action = args && typeof args.action === "string" ? args.action : undefined;
		if (action && opaqueActions.has(action)) return { kind: "opaque", scan: "strings" };
	}
	return TOOL_PATH_CLASSES[normalized] ?? UNKNOWN_TOOL_CLASS;
}

/** The names this table must cover, for the exhaustiveness test. */
export const CLASSIFIED_TOOL_NAMES: readonly string[] = [
	...BUILTIN_TOOL_NAMES,
	...HIDDEN_TOOL_NAMES,
	...DYNAMIC_TOOL_NAMES,
];
