import * as fs from "node:fs/promises";
import * as path from "node:path";
import { formatPathRelativeToCwd } from "../tools/path-utils";
import type { PathTarget } from "../tools/permissions/types";
import { ToolError } from "../tools/tool-errors";
import type {
	CreateFile,
	DeleteFile,
	Position,
	Range,
	RenameFile,
	TextDocumentEdit,
	TextEdit,
	WorkspaceEdit,
} from "./types";
import { uriToFile } from "./utils";

// =============================================================================
// Text Edit Application
// =============================================================================

/**
 * Apply text edits to a string in-memory.
 * Edits are applied in reverse order (bottom-to-top) to preserve line/character indices.
 */
export function applyTextEditsToString(content: string, edits: TextEdit[]): string {
	const lines = content.split("\n");
	const sortedEdits = sortAndValidateTextEdits(edits);

	for (const edit of sortedEdits) {
		const { start, end } = edit.range;

		// Single-line edit: replace substring within same line
		if (start.line === end.line) {
			const line = lines[start.line] || "";
			lines[start.line] = line.slice(0, start.character) + edit.newText + line.slice(end.character);
		} else {
			// Multi-line edit: splice across multiple lines
			const startLine = lines[start.line] || "";
			const endLine = lines[end.line] || "";
			const newContent = startLine.slice(0, start.character) + edit.newText + endLine.slice(end.character);
			lines.splice(start.line, end.line - start.line + 1, ...newContent.split("\n"));
		}
	}

	return lines.join("\n");
}

function comparePosition(a: Position, b: Position): number {
	return a.line === b.line ? a.character - b.character : a.line - b.line;
}
function positionsEqual(a: Position, b: Position): boolean {
	return a.line === b.line && a.character === b.character;
}

function rangesEqual(a: Range, b: Range): boolean {
	return positionsEqual(a.start, b.start) && positionsEqual(a.end, b.end);
}

function isEmptyRange(range: Range): boolean {
	return positionsEqual(range.start, range.end);
}

function formatRange(range: Range): string {
	return `${range.start.line + 1}:${range.start.character + 1}-${range.end.line + 1}:${range.end.character + 1}`;
}

/** True when two ranges overlap (share any position other than a touching boundary). */
export function rangesOverlap(a: Range, b: Range): boolean {
	return comparePosition(a.start, b.end) < 0 && comparePosition(b.start, a.end) < 0;
}

/**
 * Sort edits bottom-to-top for in-place application and reject overlaps.
 * Equal start positions tiebreak by original array index descending so that,
 * applied bottom-up, inserts at the same position land in array order
 * (LSP spec: the order of edits in the array defines the order in the result).
 * Byte-identical non-empty range edits are idempotent, so duplicate server
 * output is collapsed before overlap validation.
 */
export function sortAndValidateTextEdits(edits: TextEdit[]): TextEdit[] {
	const sorted = edits
		.map((edit, index) => ({ edit, index }))
		.sort((a, b) => {
			if (a.edit.range.start.line !== b.edit.range.start.line) {
				return b.edit.range.start.line - a.edit.range.start.line;
			}
			if (a.edit.range.start.character !== b.edit.range.start.character) {
				return b.edit.range.start.character - a.edit.range.start.character;
			}
			return b.index - a.index;
		})
		.map(entry => entry.edit);
	const unique: TextEdit[] = [];
	for (const edit of sorted) {
		const prev = unique[unique.length - 1];
		if (prev && !isEmptyRange(edit.range) && rangesEqual(prev.range, edit.range) && prev.newText === edit.newText) {
			continue;
		}
		unique.push(edit);
	}

	// Detect overlapping ranges: in reverse-sorted order, each edit's start
	// must be >= the next edit's end. If not, the edits would clobber each other
	// once applied bottom-up.
	for (let i = 0; i < unique.length - 1; i++) {
		const later = unique[i].range;
		const earlier = unique[i + 1].range;
		if (comparePosition(earlier.end, later.start) > 0) {
			throw new ToolError(
				`overlapping LSP edits: ${formatRange(earlier)} conflicts with ${formatRange(later)}; LSP produced inconsistent edits`,
			);
		}
	}

	return unique;
}

/**
 * Flatten a WorkspaceEdit's text edits into a Map<uri, TextEdit[]>.
 * Resource operations (create/rename/delete) are ignored — callers handle them separately.
 */
export function flattenWorkspaceTextEdits(edit: WorkspaceEdit): Map<string, TextEdit[]> {
	const out = new Map<string, TextEdit[]>();
	const push = (uri: string, edits: TextEdit[]) => {
		if (edits.length === 0) return;
		const prev = out.get(uri);
		if (prev) prev.push(...edits);
		else out.set(uri, [...edits]);
	};
	if (edit.changes) {
		const changes = edit.changes;
		for (const uri in changes) push(uri, changes[uri]);
	}
	if (edit.documentChanges) {
		for (const change of edit.documentChanges) {
			if ("textDocument" in change && change.textDocument && "edits" in change && change.edits) {
				const tdc = change as TextDocumentEdit;
				const textEdits = tdc.edits.filter((e): e is TextEdit => "range" in e && "newText" in e);
				push(tdc.textDocument.uri, textEdits);
			}
		}
	}
	return out;
}

/**
 * Apply text edits to a file.
 * Edits are applied in reverse order (bottom-to-top) to preserve line/character indices.
 */
export async function applyTextEdits(filePath: string, edits: TextEdit[]): Promise<void> {
	const content = await Bun.file(filePath).text();
	const result = applyTextEditsToString(content, edits);
	await Bun.write(filePath, result);
}

// =============================================================================
// Workspace Edit Application
// =============================================================================

type WorkspaceEditOp =
	| { kind: "text"; uri: string; edits: TextEdit[] }
	| { kind: "create"; uri: string }
	| { kind: "rename"; oldUri: string; newUri: string }
	| { kind: "delete"; uri: string };

/**
 * Flatten documentChanges into an ordered op list. Text edits are accumulated
 * per-URI and flushed before any resource op that touches the same URI (or,
 * for folder rename/delete, any descendant URI) so that renames, creates, and
 * deletes always see the correct prior file state.
 */
function planDocumentChanges(documentChanges: NonNullable<WorkspaceEdit["documentChanges"]>): WorkspaceEditOp[] {
	const ops: WorkspaceEditOp[] = [];
	const pending = new Map<string, TextEdit[]>();

	const flushUri = (uri: string) => {
		const edits = pending.get(uri);
		if (!edits) return;
		pending.delete(uri);
		ops.push({ kind: "text", uri, edits });
	};

	// Flush the exact URI plus every pending descendant (for folder-level
	// resource ops where the queued edits target child files of the target).
	const flushSubtree = (uri: string) => {
		const prefix = uri.endsWith("/") ? uri : `${uri}/`;
		const matches: string[] = [];
		for (const candidate of pending.keys()) {
			if (candidate === uri || candidate.startsWith(prefix)) matches.push(candidate);
		}
		for (const target of matches) {
			flushUri(target);
		}
	};

	for (const change of documentChanges) {
		if ("textDocument" in change && change.textDocument && "edits" in change && change.edits) {
			const tdc = change as TextDocumentEdit;
			const uri = tdc.textDocument.uri;
			const textEdits = tdc.edits.filter((e): e is TextEdit => "range" in e && "newText" in e);
			if (textEdits.length > 0) {
				const prev = pending.get(uri);
				if (prev) prev.push(...textEdits);
				else pending.set(uri, [...textEdits]);
			}
		} else if ("kind" in change && change.kind) {
			if (change.kind === "create") {
				const createOp = change as CreateFile;
				flushUri(createOp.uri);
				ops.push({ kind: "create", uri: createOp.uri });
			} else if (change.kind === "rename") {
				const renameOp = change as RenameFile;
				// Per LSP §3.16.2 documentChanges are applied in declared order.
				// Flush both the source subtree (so prior edits land before the move)
				// AND the destination subtree (so prior edits land on whatever exists
				// at newUri before the rename overwrites/replaces it — relevant under
				// `options.overwrite` and `options.ignoreIfExists`).
				flushSubtree(renameOp.oldUri);
				flushSubtree(renameOp.newUri);
				ops.push({ kind: "rename", oldUri: renameOp.oldUri, newUri: renameOp.newUri });
			} else if (change.kind === "delete") {
				const deleteOp = change as DeleteFile;
				flushSubtree(deleteOp.uri);
				ops.push({ kind: "delete", uri: deleteOp.uri });
			}
		}
	}

	// Flush text edits not followed by a resource op.
	for (const uri of [...pending.keys()]) {
		flushUri(uri);
	}

	return ops;
}

/** Every regular file that currently exists under `dirPath`, recursively, as absolute paths. */
async function listDescendantFiles(dirPath: string): Promise<string[]> {
	const entries = await fs.readdir(dirPath, { recursive: true, withFileTypes: true });
	const files: string[] = [];
	for (const entry of entries) {
		if (!entry.isFile()) continue;
		const parent = entry.parentPath ?? dirPath;
		files.push(path.join(parent, entry.name));
	}
	return files;
}

async function statIsDirectory(target: string): Promise<boolean> {
	try {
		return (await fs.stat(target)).isDirectory();
	} catch {
		// Missing, or a stat error the caller has no better way to react to here:
		// treat as "not a directory" and fall through to the single-path case,
		// same as a file rename/delete would.
		return false;
	}
}

/**
 * Path targets a `rename` op would touch, expanded to every existing
 * descendant when `oldUri` names a directory.
 *
 * A directory-scoped `RenameFile`/`DeleteFile` is valid per LSP §3.16
 * (`ResourceOperationKind`), and {@link applyWorkspaceEdit} applies it as one
 * atomic `fs.rename` on the directory — but the resource gate must still see
 * every file that move actually relocates, not just the two root paths. A
 * server that only lists the directory root would otherwise smuggle a
 * protected descendant past a rule scoped to individual files (finding under
 * review). Both endpoints of every pair are checked: the source is removed
 * and the destination is written, mirroring `lsp/tool.ts`'s
 * `enumerateRenamePairs` for the tool-initiated `rename_file` action.
 */
async function renameTargets(oldPath: string, newPath: string): Promise<PathTarget[]> {
	const targets: PathTarget[] = [
		{ raw: oldPath, access: "write", field: "workspace edit rename source" },
		{ raw: newPath, access: "write", field: "workspace edit rename destination" },
	];
	if (!(await statIsDirectory(oldPath))) return targets;
	for (const absolute of await listDescendantFiles(oldPath)) {
		const relative = path.relative(oldPath, absolute);
		targets.push({ raw: absolute, access: "write", field: "workspace edit rename source" });
		targets.push({ raw: path.join(newPath, relative), access: "write", field: "workspace edit rename destination" });
	}
	return targets;
}

/** Path targets a `delete` op would touch, expanded to every existing descendant when `uri` names a directory. */
async function deleteTargets(target: string): Promise<PathTarget[]> {
	const targets: PathTarget[] = [{ raw: target, access: "write", field: "workspace edit delete" }];
	if (!(await statIsDirectory(target))) return targets;
	for (const absolute of await listDescendantFiles(target)) {
		targets.push({ raw: absolute, access: "write", field: "workspace edit delete" });
	}
	return targets;
}

/**
 * Every path target applying `edit` would touch, with the access it would
 * take on each — for the resource permission gate.
 *
 * A `WorkspaceEdit` is *server*-supplied: a rename initiated inside an allowed
 * file can name any destination the language server chooses, including one
 * outside every workspace root. The initiating `file` argument is therefore not
 * the write surface, so callers run this through the resource permission gate
 * before applying anything (`lsp/tool.ts`'s `applyGuardedWorkspaceEdit`,
 * `lsp/client.ts`'s `guardedApplyEditDenial`).
 *
 * A `text` op is read-then-write: {@link applyTextEdits} loads the current
 * content before writing the patched result, so a rule that only sees `write`
 * (e.g. `permissions.deny.read` without a matching `deny.write`) would not
 * apply to the read half. `create`/`rename`/`delete` never read existing
 * content — a directory rename/delete moves or removes whatever is there
 * without inspecting it — so those stay write-only, expanded to every
 * existing descendant via {@link renameTargets}/{@link deleteTargets}.
 *
 * Derived from the same `planDocumentChanges`/`uriToFile` pair
 * {@link applyWorkspaceEdit} uses, so the set checked and the set written
 * cannot diverge.
 */
export async function workspaceEditPathTargets(edit: WorkspaceEdit): Promise<PathTarget[]> {
	const targets: PathTarget[] = [];
	if (edit.documentChanges) {
		for (const op of planDocumentChanges(edit.documentChanges)) {
			if (op.kind === "text") {
				const filePath = uriToFile(op.uri);
				targets.push({ raw: filePath, access: "read", field: "workspace edit text" });
				targets.push({ raw: filePath, access: "write", field: "workspace edit text" });
			} else if (op.kind === "create") {
				targets.push({ raw: uriToFile(op.uri), access: "write", field: "workspace edit create" });
			} else if (op.kind === "rename") {
				targets.push(...(await renameTargets(uriToFile(op.oldUri), uriToFile(op.newUri))));
			} else {
				targets.push(...(await deleteTargets(uriToFile(op.uri))));
			}
		}
	}
	if (edit.changes) {
		for (const uri in edit.changes) {
			if (edit.changes[uri].length === 0) continue;
			const filePath = uriToFile(uri);
			targets.push({ raw: filePath, access: "read", field: "workspace edit text" });
			targets.push({ raw: filePath, access: "write", field: "workspace edit text" });
		}
	}
	return targets;
}

/**
 * Apply a workspace edit (collection of file changes).
 * All text-edit batches are overlap-validated before anything is written so a
 * conflict throws without leaving the workspace half-applied.
 * Returns array of applied change descriptions.
 */
export async function applyWorkspaceEdit(edit: WorkspaceEdit, cwd: string): Promise<string[]> {
	const applied: string[] = [];

	if (edit.documentChanges) {
		const ops = planDocumentChanges(edit.documentChanges);
		for (const op of ops) {
			if (op.kind === "text") sortAndValidateTextEdits(op.edits);
		}
		for (const op of ops) {
			if (op.kind === "text") {
				const filePath = uriToFile(op.uri);
				await applyTextEdits(filePath, op.edits);
				applied.push(`Applied ${op.edits.length} edit(s) to ${formatPathRelativeToCwd(filePath, cwd)}`);
			} else if (op.kind === "create") {
				const filePath = uriToFile(op.uri);
				await Bun.write(filePath, "");
				applied.push(`Created ${formatPathRelativeToCwd(filePath, cwd)}`);
			} else if (op.kind === "rename") {
				const oldPath = uriToFile(op.oldUri);
				const newPath = uriToFile(op.newUri);
				await fs.mkdir(path.dirname(newPath), { recursive: true });
				await fs.rename(oldPath, newPath);
				applied.push(`Renamed ${formatPathRelativeToCwd(oldPath, cwd)} → ${formatPathRelativeToCwd(newPath, cwd)}`);
			} else {
				const filePath = uriToFile(op.uri);
				await fs.rm(filePath, { recursive: true });
				applied.push(`Deleted ${formatPathRelativeToCwd(filePath, cwd)}`);
			}
		}
	} else if (edit.changes) {
		// Legacy changes-map path: validate every file's edits before writing any.
		const changes = edit.changes;
		for (const uri in changes) {
			sortAndValidateTextEdits(changes[uri]);
		}
		for (const uri in changes) {
			const textEdits = changes[uri];
			if (textEdits.length === 0) continue;
			const filePath = uriToFile(uri);
			await applyTextEdits(filePath, textEdits);
			applied.push(`Applied ${textEdits.length} edit(s) to ${formatPathRelativeToCwd(filePath, cwd)}`);
		}
	}

	return applied;
}
