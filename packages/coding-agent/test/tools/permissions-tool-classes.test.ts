import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { Patch } from "@oh-my-pi/hashline";
import type { PermissionRoots } from "@oh-my-pi/pi-coding-agent/tools/permissions";
import {
	CLASSIFIED_TOOL_NAMES,
	classifyTool,
	extractEmbeddedEditPaths,
	TOOL_PATH_CLASSES,
} from "@oh-my-pi/pi-coding-agent/tools/permissions/tool-path-targets";

// A real, non-repository cwd — `git.repo.resolveSync` must not find a `.git`
// anywhere above it, or `security_scan`'s repo-root resolution would change
// the raw/relative expectations every other extractor test in this file
// relies on.
let nonRepoWorkspace: string;

beforeAll(() => {
	nonRepoWorkspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-tool-classes-")));
});

afterAll(() => {
	fs.rmSync(nonRepoWorkspace, { recursive: true, force: true });
});

describe("classification coverage", () => {
	it("classifies every built-in and hidden tool", () => {
		expect(CLASSIFIED_TOOL_NAMES.filter(name => !Object.hasOwn(TOOL_PATH_CLASSES, name))).toEqual([]);
	});

	it("classifies nothing that is not a real tool", () => {
		const known = new Set<string>(CLASSIFIED_TOOL_NAMES);
		expect(Object.keys(TOOL_PATH_CLASSES).filter(name => !known.has(name))).toEqual([]);
	});

	it("treats an unknown MCP tool as opaque rather than pathless", () => {
		expect(classifyTool("mcp__filesystem_read_file").kind).toBe("opaque");
	});

	it("resolves the legacy tool aliases to their structured classification", () => {
		expect(classifyTool("search")).toBe(TOOL_PATH_CLASSES.grep);
		expect(classifyTool("find")).toBe(TOOL_PATH_CLASSES.glob);
	});
});

describe("debug action-aware classification", () => {
	it("classifies exec/evaluate-shaped debug actions as opaque", () => {
		for (const action of ["launch", "attach", "evaluate", "write_memory", "custom_request"]) {
			expect(classifyTool("debug", { action }).kind).toBe("opaque");
		}
	});

	it("keeps breakpoint and inspection debug actions structured", () => {
		for (const action of ["set_breakpoint", "remove_breakpoint", "stack_trace", "variables"]) {
			expect(classifyTool("debug", { action }).kind).toBe("structured");
		}
	});

	it("falls back to structured when no action is known", () => {
		expect(classifyTool("debug").kind).toBe("structured");
	});

	it("leaves the base TOOL_PATH_CLASSES.debug entry structured for direct use", () => {
		expect(TOOL_PATH_CLASSES.debug?.kind).toBe("structured");
	});
});

describe("lsp action-aware classification", () => {
	it("classifies action: request as opaque, since a caller-chosen method/payload has no declared path", () => {
		expect(classifyTool("lsp", { action: "request", query: "workspace/executeCommand", payload: "{}" }).kind).toBe(
			"opaque",
		);
	});

	it("keeps every other lsp action structured", () => {
		for (const action of ["rename", "rename_file", "code_actions", "diagnostics", "reload", "hover"]) {
			expect(classifyTool("lsp", { action }).kind).toBe("structured");
		}
	});

	it("falls back to structured when no action is known", () => {
		expect(classifyTool("lsp").kind).toBe("structured");
	});

	it("leaves the base TOOL_PATH_CLASSES.lsp entry structured for direct use", () => {
		expect(TOOL_PATH_CLASSES.lsp?.kind).toBe("structured");
	});
});

describe("structured extraction", () => {
	function extract(tool: string, args: Record<string, unknown>, roots?: PermissionRoots) {
		const cls = TOOL_PATH_CLASSES[tool];
		if (cls?.kind !== "structured") throw new Error(`${tool} is not structured`);
		return cls.extract(args, roots ?? { cwd: nonRepoWorkspace, additionalDirectories: [] });
	}

	it("reads read/write single path arguments with the right access", () => {
		expect(extract("read", { path: "a.ts" })).toEqual([{ raw: "a.ts", access: "read", field: "path" }]);
		expect(extract("write", { path: "a.ts" })).toEqual([{ raw: "a.ts", access: "write", field: "path" }]);
	});

	it("splits the semicolon-delimited search roots grep and glob accept", () => {
		expect(extract("grep", { path: "src; test" }).map(t => t.raw)).toEqual(["src", "test"]);
	});

	it("read/write-classifies a top-level edit target based on whether every edit is a pure create", () => {
		// No `op` on any entry (the `replace` mode shape, and a `patch` entry
		// that omits `op`) - defaults to "update", which reads the file.
		const updateTargets = extract("edit", { path: "a.ts", edits: [{ rename: "b.ts" }, { diff: "x" }] });
		expect(updateTargets.map(t => `${t.access}:${t.raw}`)).toEqual(["write:a.ts", "read:a.ts", "write:b.ts"]);

		// Every entry explicitly `op: "create"` - no pre-existing content to read.
		const createTargets = extract("edit", { path: "new.ts", edits: [{ op: "create", diff: "x" }] });
		expect(createTargets).toEqual([{ raw: "new.ts", access: "write", field: "path" }]);

		// One `create` plus one `update` in the same call - still needs `read`,
		// since the `update` entry reads the file the `create` entry wrote.
		const mixedTargets = extract("edit", {
			path: "mixed.ts",
			edits: [
				{ op: "create", diff: "x" },
				{ op: "update", diff: "y" },
			],
		});
		expect(mixedTargets.map(t => `${t.access}:${t.raw}`)).toEqual(["write:mixed.ts", "read:mixed.ts"]);

		// An explicit `op: "delete"` also read the file's prior content
		// (`modes/patch.ts` populates `oldContent` for delete too).
		const deleteTargets = extract("edit", { path: "gone.ts", edits: [{ op: "delete" }] });
		expect(deleteTargets.map(t => `${t.access}:${t.raw}`)).toEqual(["write:gone.ts", "read:gone.ts"]);
	});

	// The access map inverts the tool's own LSP_READONLY_ACTIONS, so a
	// write-tier action the tool knows about cannot be missed here.
	it("classifies lsp navigation as a read and every write-tier action as a write", () => {
		for (const action of ["references", "hover", "definition", "diagnostics", "symbols", "status"]) {
			expect(extract("lsp", { action, file: "a.ts" })[0]?.access).toBe("read");
		}
		for (const action of ["rename", "rename_file", "code_actions", "request", "reload"]) {
			expect(extract("lsp", { action, file: "a.ts" })[0]?.access).toBe("write");
		}
	});

	it("ignores absent, blank, and wrongly typed arguments", () => {
		expect(extract("read", {})).toEqual([]);
		expect(extract("read", { path: "   " })).toEqual([]);
		expect(extract("read", { path: 42 })).toEqual([]);
		expect(extract("ast_edit", { paths: "not-an-array" })).toEqual([]);
	});

	it("keeps security_scan exclude_paths out — a filter is never opened", () => {
		const targets = extract("security_scan", { include_paths: ["src"], exclude_paths: [".env"], output_root: "out" });
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(["read:src", "write:out"]);
	});

	it("leaves security_scan include/knowledge-base paths relative when the session cwd is not a repository", () => {
		// `nonRepoWorkspace` has no `.git` anywhere above it, matching what
		// `createSecurityScanPlan` itself would see — the scan can never
		// happen either way, so the raw relative spelling passes through.
		const targets = extract("security_scan", { include_paths: ["src"], knowledge_base_paths: ["docs/kb.md"] });
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(["read:src", "read:docs/kb.md"]);
	});

	describe("security_scan repository-root resolution", () => {
		let repoRoot: string;
		let nestedCwd: string;

		beforeAll(() => {
			repoRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-scan-repo-")));
			fs.mkdirSync(path.join(repoRoot, ".git"), { recursive: true });
			nestedCwd = path.join(repoRoot, "packages", "app");
			fs.mkdirSync(nestedCwd, { recursive: true });
		});

		afterAll(() => {
			fs.rmSync(repoRoot, { recursive: true, force: true });
		});

		it("authorizes include_paths/knowledge_base_paths against the repository root, not the session cwd", () => {
			const roots: PermissionRoots = { cwd: nestedCwd, additionalDirectories: [] };
			const targets = extract(
				"security_scan",
				{ include_paths: ["private"], knowledge_base_paths: ["docs/kb.md"] },
				roots,
			);
			expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual([
				`read:${path.join(repoRoot, "private")}`,
				`read:${path.join(repoRoot, "docs/kb.md")}`,
			]);
		});

		it("adds the repository root as a read target when a default scan carries no include_paths", () => {
			// No `target_kind`/`include_paths` at all — the scan defaults to
			// scanning the whole repository, not just `nestedCwd`, so the gate
			// must see `repoRoot` itself or `permissions.confineReads` would never
			// catch the read once the scan actually walks the tree.
			const roots: PermissionRoots = { cwd: nestedCwd, additionalDirectories: [] };
			const targets = extract("security_scan", { output_root: "out" }, roots);
			expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual([`read:${repoRoot}`, "write:out"]);
		});

		it("omits the repository-root fallback once include_paths narrows the scan", () => {
			const roots: PermissionRoots = { cwd: nestedCwd, additionalDirectories: [] };
			const targets = extract("security_scan", { include_paths: ["private"], output_root: "out" }, roots);
			expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual([
				`read:${path.join(repoRoot, "private")}`,
				"write:out",
			]);
		});

		it("omits the repository-root fallback for a scoped_path scan, which already requires include_paths", () => {
			const roots: PermissionRoots = { cwd: nestedCwd, additionalDirectories: [] };
			const targets = extract(
				"security_scan",
				{ target_kind: "scoped_path", include_paths: ["private"], output_root: "out" },
				roots,
			);
			expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual([
				`read:${path.join(repoRoot, "private")}`,
				"write:out",
			]);
		});
	});
});

describe("embedded edit payload paths", () => {
	it("extracts a hashline section header as both a read and a write target", () => {
		// Every hashline section requires a `#TAG` snapshot hash from a prior
		// read (`assertSectionHashPresent`) - hashline has no "create" op, so
		// the section always needs `read` in addition to `write`.
		expect(extractEmbeddedEditPaths("[src/a.ts#1A2B]\nPUT 1.=1:\n+x").map(t => `${t.access}:${t.raw}`)).toEqual([
			"write:src/a.ts",
			"read:src/a.ts",
		]);
	});

	it("extracts apply_patch file and move markers, read+write for Update and write-only for Add", () => {
		const input = [
			"*** Begin Patch",
			"*** Add File: src/new.ts",
			"*** Update File: src/a.ts",
			"*** Move to: src/b.ts",
			"*** Delete File: src/old.ts",
			"*** End Patch",
		].join("\n");
		expect(extractEmbeddedEditPaths(input).map(t => `${t.access}:${t.raw}`)).toEqual([
			"write:src/new.ts",
			"write:src/a.ts",
			"read:src/a.ts",
			"write:src/b.ts",
			"write:src/old.ts",
			"read:src/old.ts",
		]);
	});

	it("does not mistake a bracketed body line for a header", () => {
		expect(extractEmbeddedEditPaths("[not a header#zz]")).toEqual([]);
	});

	it("finds a secret target hidden in a hashline payload with no top-level path", () => {
		const cls = TOOL_PATH_CLASSES.edit;
		if (cls?.kind !== "structured") throw new Error("edit is not structured");
		expect(
			cls
				.extract({ input: "[.env#00FF]\nPUT 1.=1:\n+LEAK=1" }, { cwd: nonRepoWorkspace, additionalDirectories: [] })
				.map(t => `${t.access}:${t.raw}`),
		).toEqual(["write:.env", "read:.env"]);
	});

	it("extracts a hashline MV destination, which is a write the section performs", () => {
		const input = "[src/a.ts#1A2B]\nCUT 1.=1\nMV ../../outside/escaped.ts";
		expect(extractEmbeddedEditPaths(input).map(t => t.raw)).toEqual([
			"src/a.ts",
			"src/a.ts",
			"../../outside/escaped.ts",
		]);
	});

	it("unquotes an MV destination containing spaces", () => {
		expect(extractEmbeddedEditPaths('MV "dir with spaces/a.ts"').map(t => t.raw)).toEqual(["dir with spaces/a.ts"]);
	});

	// A hand-rolled `[.+]` header regex could disagree with the real hashline
	// grammar about how a header is interpreted; deriving the target through
	// `Patch.parse` (the same section splitter `Patcher.apply` uses) rules
	// that divergence out by construction, including for a `..` traversal
	// path inside the header.
	it("extracts a `..` traversal path from a header exactly as the real parser resolves it", () => {
		const input = "[../../outside/escaped.ts#1A2B]\nPUT 1.=1:\n+x";
		expect(extractEmbeddedEditPaths(input).map(t => t.raw)).toEqual([
			"../../outside/escaped.ts",
			"../../outside/escaped.ts",
		]);
	});

	it("matches the real hashline Patch.parse section set exactly, including a multi-section input", () => {
		const input = "[a/one.ts#1A2B]\nPUT 1.=1:\n+x\n[b/two.ts#3C4D]\nPUT 1.=1:\n+y";
		const patch = Patch.parse(input);
		expect(patch.sections.map(s => s.path)).toEqual(["a/one.ts", "b/two.ts"]);
		// Each section yields a write and a read target, in that order.
		const expected = patch.sections.flatMap(s => [s.path, s.path]);
		expect(extractEmbeddedEditPaths(input).map(t => t.raw)).toEqual(expected);
	});
});
