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
import type { Dirent } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import * as path from "node:path";
import { Patch } from "@oh-my-pi/hashline";
import { LSP_READONLY_ACTIONS } from "../../lsp";
import * as git from "../../utils/git";
import { BUILTIN_TOOL_NAMES, HIDDEN_TOOL_NAMES, normalizeToolName } from "../builtin-names";
import { normalizePathLikeInput, type ResolvedSearchTarget, toPathList } from "../path-utils";
import { unwrapHashlineHeaderPath } from "../plan-mode-guard";
import { decideTarget, isExemptPathArgument } from "./resolve";
import type { PathAccess, PathTarget, PermissionPolicy, PermissionRoots } from "./types";

/**
 * Pulls the declared path arguments out of one tool call's arguments.
 * `roots` is the session's confinement roots — most extractors ignore it (a
 * declared path is already meant to be read relative to the session cwd),
 * but `security_scan` needs it to find the repository root its own paths
 * are actually resolved against; see {@link extractSecurityScanPaths}.
 */
export type PathTargetExtractor = (args: Record<string, unknown>, roots: PermissionRoots) => PathTarget[];

/**
 * Pulls the files a tool actually touched out of its result details, for the
 * post-execution recheck. `args` is the declared call arguments the
 * pre-execution gate already evaluated — needed so a result extractor can
 * tell whether the *original* target was already exempt (e.g. `local://`)
 * before deciding whether a resolved absolute path needs rechecking; most
 * extractors ignore it.
 */
export type ResultPathTargetExtractor = (args: Record<string, unknown>, details: unknown) => PathTarget[];

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
	| {
			readonly kind: "opaque";
			readonly scan: "shell" | "strings";
			/**
			 * For an action whose real surface is a caller-chosen payload
			 * (needs the opaque scan) but which *also* declares a real
			 * structured path argument — `lsp`'s `request` sends an arbitrary
			 * JSON-RPC method/payload, but still takes a `file` the server
			 * opens before the request goes out. Dropping straight to opaque
			 * loses that field's confinement/deny check entirely (the opaque
			 * scan only matches denied literals, never `confineReads`), so
			 * this runs the declared extractor first, in addition to the
			 * scan, rather than instead of it.
			 */
			readonly alsoExtract?: PathTargetExtractor;
	  }
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
 * `raw` may be a plain string, a `;`-delimited list, a JSON-encoded string
 * array (`'[".env"]'`), or a single outer-quoted literal (`'".env"'`) — the
 * same shapes `toPathList`/`normalizePathLikeInput` (`path-utils.ts`) resolve
 * for the tool itself before it opens anything. Authorizing the raw,
 * un-normalized string instead would check a different, non-existent
 * composite spelling than the real target the tool goes on to read: with an
 * absent search pattern recording no result file, the post-execution recheck
 * ({@link extractResultFiles}) never sees the mismatch either, so this is the
 * only gate that can catch it.
 */
function pushDelimited(out: PathTarget[], raw: unknown, access: PathAccess, field: string): void {
	if (typeof raw !== "string") return;
	for (const entry of toPathList(raw)) {
		for (const part of entry.split(MULTI_PATH_SEPARATOR)) pushPath(out, normalizePathLikeInput(part), access, field);
	}
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

/**
 * `write`'s top-level `path`, unwrapped exactly as `WriteTool` unwraps it
 * before resolving: a copied hashline header (`[../secret#ABCD]`) passed as
 * `path` executes against the unwrapped target, so authorizing the raw
 * bracketed literal instead would check a different path than the one that
 * actually gets written.
 */
function writePath(field: string): PathTargetExtractor {
	return args => {
		const out: PathTarget[] = [];
		const raw = args[field];
		pushPath(out, typeof raw === "string" ? unwrapHashlineHeaderPath(raw) : raw, "write", field);
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

const APPLY_PATCH_ADD_FILE_RE = /^\*\*\* Add File: (.+)$/;
const APPLY_PATCH_EXISTING_FILE_RE = /^\*\*\* (?:Delete|Update) File: (.+)$/;
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
 * `[path#TAG]` section headers, `MV DEST` move ops, and `*** Add/Delete/Update
 * File: path` markers. All three are strict, line-anchored grammars and a
 * mode cannot touch a file it does not name, so extracting them is sound
 * rather than best-effort.
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
			// A hashline section header always carries a `fileHash` snapshot tag
			// (`assertSectionHashPresent` in `@oh-my-pi/hashline`'s patcher rejects
			// a section without one), which can only have come from a prior read
			// of that exact file - hashline has no "create a new file" op, unlike
			// `apply_patch`'s `*** Add File`. Every section therefore reads the
			// file's existing content (and can surface it back through a mismatch
			// error or the applied diff), so it needs `read` in addition to `write`.
			pushPath(out, section.path, "write", "input");
			pushPath(out, section.path, "read", "input");
		}
	} catch {
		// Not hashline-shaped input, or a section body parse error the real
		// executor will also hit; nothing further to extract from headers.
	}
	for (const line of input.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		// `*** Add File` creates a file with no pre-existing content to read -
		// write-only. `*** Update File` and `*** Delete File` both read the
		// current file (`modes/patch.ts` populates `oldContent` for either) and
		// can surface it back through the diff or a context-mismatch error, so
		// both need `read` too.
		const addFile = APPLY_PATCH_ADD_FILE_RE.exec(trimmed);
		if (addFile) {
			pushPath(out, addFile[1], "write", "input");
			continue;
		}
		const existingFile = APPLY_PATCH_EXISTING_FILE_RE.exec(trimmed);
		if (existingFile) {
			pushPath(out, existingFile[1], "write", "input");
			pushPath(out, existingFile[1], "read", "input");
			continue;
		}
		const move = APPLY_PATCH_MOVE_RE.exec(trimmed);
		if (move) {
			pushPath(out, move[1], "write", "input");
			continue;
		}
		const hashlineMove = HASHLINE_MOVE_RE.exec(trimmed);
		if (hashlineMove) pushPath(out, stripQuotes(hashlineMove[1]), "write", "input");
	}
	return out;
}

const extractEditPaths: PathTargetExtractor = args => {
	const out: PathTarget[] = [];
	// patch/replace modes: one top-level target plus per-edit rename destinations.
	//
	// `edits[]` entries carry an optional `op` (JSON `patch` mode only;
	// `replace` mode entries never set one, and an omitted `op` on a `patch`
	// entry defaults to "update" - see `modes/patch.ts`'s `rawOp === "create"
	// || rawOp === "delete" ? rawOp : "update"`). Only when every entry is an
	// explicit `op: "create"` does the call need no pre-existing content: a
	// "create" edit's result never includes `oldContent` (`modes/patch.ts`:
	// `oldText = result.change.type !== "create" ? result.change.oldContent :
	// undefined`), but "update" and "delete" both read the file and surface
	// its prior content through the returned diff - so a `deny.read` rule
	// with no matching `deny.write` must still block them.
	const edits = Array.isArray(args.edits) ? args.edits : [];
	const pureCreate =
		edits.length > 0 &&
		edits.every(edit => edit && typeof edit === "object" && (edit as Record<string, unknown>).op === "create");
	// Unwrapped before authorization for the same reason as `write`'s path
	// (see {@link writePath}): `EditTool` resolves the top-level target via
	// `resolvePlanPath`, which calls `unwrapHashlineHeaderPath` first, so a
	// copied hashline header (`[../secret#ABCD]`) must be checked against
	// that same unwrapped path, not the literal bracketed string.
	const editPath = typeof args.path === "string" ? unwrapHashlineHeaderPath(args.path) : args.path;
	pushPath(out, editPath, "write", "path");
	if (!pureCreate) pushPath(out, editPath, "read", "path");
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
 * or attach to an arbitrary process with arbitrary `args`
 * (`tools/debug.ts:738-760`), `evaluate` sends a raw debugger expression
 * (`:954-968`), `write_memory` writes raw bytes, and `custom_request` sends an
 * arbitrary DAP command with an arbitrary `arguments` payload. A call like
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
	// A write-tier action with a concrete `file` still reads it first:
	// `ensureFileOpen` (`lsp/index.ts`) opens the document with
	// `Bun.file(filePath).text()` and sends its content to the server before
	// applying `rename`/`code_actions`/etc, so `permissions.deny.read` must
	// see this target too — checking only "write" left a file readable via
	// `lsp` whenever writes to it stayed allowed but reads did not.
	if (writes) pushPath(out, args.file, "read", "file");
	if (action === "rename_file") pushPath(out, args.new_name, "write", "new_name");
	return out;
};

/**
 * The repository root `security_scan`'s own `include_paths`/
 * `knowledge_base_paths` are actually resolved against, from the same
 * on-disk `.git` walk `git.repo.root` (`security/preflight.ts`'s
 * `DEFAULT_SECURITY_GIT_ADAPTER`) falls back to when no subprocess is
 * needed. `null` when `cwd` is not inside a repository — `createSecurityScanPlan`
 * throws for that same cwd, so there is no real scan for a stale relative
 * spelling to affect.
 */
function securityScanRoot(cwd: string): string | null {
	return git.repo.resolveSync(cwd)?.repoRoot ?? null;
}

/**
 * `include_paths`/`knowledge_base_paths` entries, resolved against
 * `scanRoot` rather than the session cwd — see {@link extractSecurityScanPaths}.
 */
function pushSecurityScanPaths(
	out: PathTarget[],
	raw: unknown,
	access: PathAccess,
	field: string,
	scanRoot: string | null,
): void {
	if (!Array.isArray(raw)) return;
	for (const entry of raw) {
		if (typeof entry !== "string") continue;
		const trimmed = entry.trim();
		if (!trimmed) continue;
		out.push({ raw: scanRoot ? path.resolve(scanRoot, trimmed) : trimmed, access, field });
	}
}

/**
 * `createSecurityScanPlan` (`security/preflight.ts`) resolves both
 * `include_paths` and `knowledge_base_paths` against the scan's repository
 * root (`buildPlanMaterial`'s `canonicalRoot`), not the session cwd that
 * launched it — the two diverge whenever the session sits in a subdirectory
 * of the repository. Authorizing the raw relative spelling against
 * `roots.cwd`, as every other structured extractor does, would then check a
 * different path than the one the scan actually reads: from `/repo/pkg`,
 * `include_paths: ["private"]` would clear the gate by checking
 * `/repo/pkg/private` while the scan digests `/repo/private`. Resolved here
 * against the same repository root so the gate and the scan can never
 * disagree about the base.
 */
const extractSecurityScanPaths: PathTargetExtractor = (args, roots) => {
	const out: PathTarget[] = [];
	const scanRoot = securityScanRoot(roots.cwd);
	pushSecurityScanPaths(out, args.include_paths, "read", "include_paths", scanRoot);
	pushSecurityScanPaths(out, args.knowledge_base_paths, "read", "knowledge_base_paths", scanRoot);
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
 * result `details.files` — cwd-relative or absolute, the exact display-path
 * shape `formatResultPath` (`file-recorder.ts`) already produces, which
 * `resolveTargetPath` resolves identically either way.
 *
 * `grep`/`ast_grep`/`ast_edit` accept a scope root (`path`) but then
 * recurse beneath it, so the declared-argument extractor above only ever
 * sees that root — `grep({ path: ".", gitignore: false })` passes the
 * pre-execution gate and can still return `.env` contents. This is the other
 * half: re-derive the actual files touched from what the tool reports it
 * touched, so `enforcePostExecutionResourcePermissions` (`gate.ts`) can
 * recheck them against the policy before the result ever reaches the model.
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
 * True when the tool's declared `path` argument was already exempt from the
 * pre-execution gate (`local://`, `memory://`, `artifact://`, …) - a result
 * extractor must skip it too, matching `extractReadResultTargets`. An exempt
 * scheme can resolve its backing file outside every workspace root by
 * design (e.g. `memory://` under the agent directory); rechecking that
 * resolved path against `confineReads` would reject a search that already
 * succeeded and was never meant to be confined.
 */
function isResultTargetsExempt(args: Record<string, unknown>): boolean {
	return typeof args.path === "string" && isExemptPathArgument(args.path);
}

/**
 * The fixed suffix `crates/pi-natives/src/ast.rs` appends to a per-file
 * "syntax tree contains error nodes" parse-error entry, after the file's
 * `display_path`: `format!("{}: parse error (syntax tree contains error
 * nodes)", display_path)`. Other parse-error shapes (pattern compile
 * failures, file-read errors) interleave the pattern and path in a way that
 * cannot be split apart reliably, so only this one — the shape a read-denied
 * file with a syntax error actually produces — is extracted.
 */
const AST_SYNTAX_PARSE_ERROR_SUFFIX = ": parse error (syntax tree contains error nodes)";

/**
 * The file `ast_grep`/`ast_edit` reports as unparseable, from its own
 * result `details.parseErrors`. A file with a syntax error produces no
 * match/replacement — so it never appears in `details.files`, the target
 * {@link extractResultFiles} checks — but its path and the diagnostic text
 * naming it still reach the model through this field, so a read-denied
 * file's path would otherwise leak here even though the tool's real content
 * never does.
 */
function extractAstParseErrorTargets(details: unknown): PathTarget[] {
	if (!details || typeof details !== "object" || !("parseErrors" in details)) return [];
	const { parseErrors } = details;
	if (!Array.isArray(parseErrors)) return [];
	const out: PathTarget[] = [];
	for (const entry of parseErrors) {
		if (typeof entry !== "string" || !entry.endsWith(AST_SYNTAX_PARSE_ERROR_SUFFIX)) continue;
		const path = entry.slice(0, -AST_SYNTAX_PARSE_ERROR_SUFFIX.length);
		pushPath(out, path, "read", "parseErrors");
	}
	return out;
}

/**
 * The concrete file `read` actually opened, from its own result
 * `details.resolvedPath` (or `details.displayReadTargets` for the
 * delimited multi-path recovery branch). The declared-argument extractor
 * above only ever sees the original `path` string, but several recovery
 * branches resolve to a *different* real file without going back through
 * the pre-execution gate:
 *
 * - `ReadTool#tryReadDelimitedPaths` recurses through the tool's own
 *   `execute` for each `;`-delimited part, bypassing the wrapper's gate
 *   entirely — `details.displayReadTargets` lists what was actually read.
 * - Suffix recovery, archive/SQLite backing files, and PDF image members
 *   all authorize the original (possibly missing, possibly logical)
 *   argument, then open a different resolved path — `details.resolvedPath`
 *   is that real target in every one of those branches.
 *
 * Skipped entirely when the *original* declared `path` was already exempt
 * (`local://`, `memory://`, `artifact://`, …): `isExemptPathArgument` let a
 * `read({ path: "local://plan.md" })` pass the pre-execution gate under
 * `strict`, and it resolves to a session-artifact path outside every
 * workspace root by design — rechecking `resolvedPath` against
 * `confineReads` here would reject a read that already succeeded and was
 * never meant to be confined.
 *
 * Rechecked here so `enforcePostExecutionResourcePermissions` (`gate.ts`)
 * catches a denied file before its content ever reaches the model.
 */
function extractReadResultTargets(args: Record<string, unknown>, details: unknown): PathTarget[] {
	if (typeof args.path === "string" && isExemptPathArgument(args.path)) return [];
	if (!details || typeof details !== "object") return [];
	const record = details as Record<string, unknown>;
	const out: PathTarget[] = [];
	if (Array.isArray(record.displayReadTargets)) {
		for (const target of record.displayReadTargets) pushPath(out, target, "read", "displayReadTargets");
		return out;
	}
	pushPath(out, record.resolvedPath, "read", "resolvedPath");
	return out;
}

function extractInspectImageResultTargets(_args: Record<string, unknown>, details: unknown): PathTarget[] {
	if (!details || typeof details !== "object") return [];
	const imagePath = (details as Record<string, unknown>).imagePath;
	if (typeof imagePath !== "string" || imagePath.startsWith("attachment://")) return [];
	return [{ raw: imagePath, access: "read", field: "imagePath" }];
}

/**
 * Every regular file beneath `root` `permissions.deny.read` does not block,
 * decided with the exact same {@link decideTarget} the point-path gate uses
 * so this can never diverge from what a single-file `read`/`grep` call would
 * be denied. Returns `null` when the policy has no `deny.read` rules at all —
 * the common case, where the caller keeps its existing single native
 * recursive call unchanged.
 *
 * `grep`'s native recursion has no exclusion mechanism (its `glob` option is
 * one positive filter, not a deny list), so a broad `grep({ path: "." })`
 * under an active `deny.read` rule would otherwise open every descendant,
 * including one a search matches nothing in — a repeated match/no-match
 * probe against a file whose content should never be inspected at all is
 * itself an oracle over that content, and a post-execution recheck of
 * *matched* files (`extractResultFiles` below) can never see a file that
 * matched nothing. This walk is the only sound way to keep that file from
 * being opened in the first place.
 *
 * Two accepted, narrower trade-offs versus native's own traversal, both
 * scoped to the moment this actually returns non-null (an active
 * `deny.read` rule with something denied in scope — never the default
 * policy): the walk is plain `readdir` recursion rather than ripgrep's
 * optimized one, and the caller ends up searching the returned list as
 * explicit file targets, which — like every other explicit-file grep call —
 * do not get re-filtered through `.gitignore`.
 */
export async function excludeDenyReadDescendants(
	root: string,
	policy: PermissionPolicy,
	roots: PermissionRoots,
	globFilter?: string,
	matchBasename = false,
): Promise<string[] | null> {
	if (policy.deny.read.length === 0) return null;
	const out: string[] = [];
	await collectAllowedReadFiles(
		root,
		policy,
		roots,
		out,
		root,
		globFilter ? new Bun.Glob(globFilter) : undefined,
		matchBasename,
	);
	return out;
}
async function collectAllowedReadFiles(
	dir: string,
	policy: PermissionPolicy,
	roots: PermissionRoots,
	out: string[],
	root: string,
	globFilter: Bun.Glob | undefined,
	matchBasename: boolean,
): Promise<void> {
	let entries: Dirent[];
	try {
		entries = await readdir(dir, { withFileTypes: true });
	} catch {
		return;
	}
	for (const entry of entries) {
		// `.git`'s own object/pack contents are never search targets for any
		// caller of this tool; skipping it outright avoids walking a directory
		// that can rival the working tree in size.
		if (entry.name === ".git") continue;
		const abs = path.join(dir, entry.name);
		const decision = decideTarget({ raw: abs, access: "read", field: "grep" }, policy, roots);
		if (entry.isDirectory()) {
			// A deny on this directory does not mean every descendant is
			// denied too: a trailing `/**` allow pattern (`private/public/**`)
			// matches files under `private/public` but never the bare
			// directory spelling itself, so `deny.read: ["private/**"]` denies
			// this directory's own decision while still meaning to admit
			// `private/public/file.ts` below it. Pruning on the directory's
			// own decision would make that carve-out unreachable no matter
			// what its files decide, so recurse whenever the policy has any
			// `allow.read` rule that could rescue a descendant — each child
			// still gets its own independent `decideTarget` check the moment
			// it is visited.
			if (decision.kind === "deny" && policy.allow.read.length === 0) continue;
			await collectAllowedReadFiles(abs, policy, roots, out, root, globFilter, matchBasename);
			continue;
		}
		if (decision.kind === "deny") continue;
		if (entry.isFile()) {
			if (
				!globFilter ||
				globFilter.match(path.relative(root, abs).replace(/\\/g, "/")) ||
				(matchBasename && globFilter.match(path.basename(abs)))
			) {
				out.push(abs);
			}
			continue;
		}
		if (entry.isSymbolicLink()) {
			// A symlink's own path already cleared `decideTarget` above — under
			// `confineReads` that call resolved it exactly as `read`/`grep` would
			// (realpath, refusing a dangling link) — so what's left here is only
			// classifying the *kind* of what it points to, not re-authorizing it.
			//
			// A symlinked directory is never followed, matching the native
			// grep/AST walkers' `FollowLinks::Never` (`crates/pi-walker`):
			// recursing into it here would convert an arbitrarily large linked
			// tree into explicit file targets and could walk outside the
			// requested root through the link, exactly what `FollowLinks::Never`
			// exists to prevent. A symlinked file is still a single bounded
			// target, same as passing it to `read`/`grep` explicitly.
			const resolved = await stat(abs).catch(() => null);
			if (
				resolved?.isFile() &&
				(!globFilter ||
					globFilter.match(path.relative(root, abs).replace(/\\/g, "/")) ||
					(matchBasename && globFilter.match(path.basename(abs))))
			) {
				out.push(abs);
			}
		}
	}
}

/**
 * Replaces recursive search targets with their individually authorized files
 * while a `deny.read` rule is active. File targets never recurse, so retain
 * them unchanged; directory targets must be expanded before native search can
 * parse or inspect a denied descendant that produces no result.
 */
export async function excludeDenyReadSearchTargets(
	targets: readonly ResolvedSearchTarget[],
	policy: PermissionPolicy,
	roots: PermissionRoots,
	matchBasename = false,
): Promise<ResolvedSearchTarget[] | null> {
	if (policy.deny.read.length === 0) return null;
	const filtered = await Promise.all(
		targets.map(async target => {
			if (target.pathIsFile) return [target];
			const allowedPaths = await excludeDenyReadDescendants(
				target.basePath,
				policy,
				roots,
				target.glob,
				matchBasename,
			);
			return (allowedPaths ?? []).map(basePath => ({ basePath, pathIsFile: true }));
		}),
	);
	return filtered.flat();
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
	read: {
		kind: "structured",
		extract: singlePath("path", "read"),
		resultTargets: extractReadResultTargets,
	},
	write: { kind: "structured", extract: writePath("path") },
	edit: { kind: "structured", extract: extractEditPaths },
	glob: { kind: "structured", extract: delimitedPath("path", "read") },
	grep: {
		kind: "structured",
		extract: delimitedPath("path", "read"),
		resultTargets: (args, details) => (isResultTargetsExempt(args) ? [] : extractResultFiles(details, "read")),
	},
	ast_grep: {
		kind: "structured",
		extract: delimitedPath("path", "read"),
		resultTargets: (args, details) =>
			isResultTargetsExempt(args)
				? []
				: [...extractResultFiles(details, "read"), ...extractAstParseErrorTargets(details)],
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
		resultTargets: (_args, details) => [
			...extractResultFiles(details, "read"),
			...extractResultFiles(details, "write"),
			...extractAstParseErrorTargets(details),
		],
	},
	lsp: { kind: "structured", extract: extractLspPaths },
	debug: { kind: "structured", extract: extractDebugPaths },
	inspect_image: {
		kind: "structured",
		extract: singlePath("path", "read"),
		resultTargets: extractInspectImageResultTargets,
	},
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
	// `think` records a private free-text scratchpad, not a path — same
	// rationale as `task`.
	think: { kind: "pathless" },
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
 * `args` (the call's own arguments, when the caller has them) lets `debug` be
 * classified per-action: `TOOL_PATH_CLASSES.debug` stays a plain structured
 * entry (used directly by tests and as the base extractor), but a call whose
 * `action` is in {@link DEBUG_OPAQUE_ACTIONS} is classified opaque here,
 * since only the actual call site knows the action.
 */
export function classifyTool(toolName: string, args?: Record<string, unknown> | null): ToolPathClass {
	const normalized = normalizeToolName(toolName);
	if (normalized === "debug") {
		const action = args && typeof args.action === "string" ? args.action : undefined;
		if (action && DEBUG_OPAQUE_ACTIONS.has(action)) return { kind: "opaque", scan: "strings" };
	}
	if (normalized === "lsp") {
		const action = args && typeof args.action === "string" ? args.action : undefined;
		if (action && LSP_OPAQUE_ACTIONS.has(action)) {
			return { kind: "opaque", scan: "strings", alsoExtract: extractLspPaths };
		}
	}
	return TOOL_PATH_CLASSES[normalized] ?? UNKNOWN_TOOL_CLASS;
}

/** The names this table must cover, for the exhaustiveness test. */
export const CLASSIFIED_TOOL_NAMES: readonly string[] = [...BUILTIN_TOOL_NAMES, ...HIDDEN_TOOL_NAMES];
