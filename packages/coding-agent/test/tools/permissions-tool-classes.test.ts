import { describe, expect, it } from "bun:test";
import {
	CLASSIFIED_TOOL_NAMES,
	classifyTool,
	extractEmbeddedEditPaths,
	TOOL_PATH_CLASSES,
} from "@oh-my-pi/pi-coding-agent/tools/permissions/tool-path-targets";

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

describe("structured extraction", () => {
	function extract(tool: string, args: Record<string, unknown>) {
		const cls = TOOL_PATH_CLASSES[tool];
		if (cls?.kind !== "structured") throw new Error(`${tool} is not structured`);
		return cls.extract(args);
	}

	it("reads read/write single path arguments with the right access", () => {
		expect(extract("read", { path: "a.ts" })).toEqual([{ raw: "a.ts", access: "read", field: "path" }]);
		expect(extract("write", { path: "a.ts" })).toEqual([{ raw: "a.ts", access: "write", field: "path" }]);
	});

	it("splits the semicolon-delimited search roots grep and glob accept", () => {
		expect(extract("grep", { path: "src; test" }).map(t => t.raw)).toEqual(["src", "test"]);
	});

	it("takes edit rename destinations as writes alongside the target", () => {
		const targets = extract("edit", { path: "a.ts", edits: [{ rename: "b.ts" }, { diff: "x" }] });
		expect(targets.map(t => t.raw)).toEqual(["a.ts", "b.ts"]);
		expect(targets.every(t => t.access === "write")).toBe(true);
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
});

describe("embedded edit payload paths", () => {
	it("extracts hashline section headers", () => {
		expect(extractEmbeddedEditPaths("[src/a.ts#1A2B]\nPUT 1.=1:\n+x").map(t => t.raw)).toEqual(["src/a.ts"]);
	});

	it("extracts apply_patch file and move markers", () => {
		const input = ["*** Begin Patch", "*** Update File: src/a.ts", "*** Move to: src/b.ts", "*** End Patch"].join(
			"\n",
		);
		expect(extractEmbeddedEditPaths(input).map(t => t.raw)).toEqual(["src/a.ts", "src/b.ts"]);
	});

	it("does not mistake a bracketed body line for a header", () => {
		expect(extractEmbeddedEditPaths("[not a header#zz]")).toEqual([]);
	});

	it("finds a secret target hidden in a hashline payload with no top-level path", () => {
		const cls = TOOL_PATH_CLASSES.edit;
		if (cls?.kind !== "structured") throw new Error("edit is not structured");
		expect(cls.extract({ input: "[.env#00FF]\nPUT 1.=1:\n+LEAK=1" }).map(t => t.raw)).toEqual([".env"]);
	});

	it("extracts a hashline MV destination, which is a write the section performs", () => {
		const input = "[src/a.ts#1A2B]\nCUT 1.=1\nMV ../../outside/escaped.ts";
		expect(extractEmbeddedEditPaths(input).map(t => t.raw)).toEqual(["src/a.ts", "../../outside/escaped.ts"]);
	});

	it("unquotes an MV destination containing spaces", () => {
		expect(extractEmbeddedEditPaths('MV "dir with spaces/a.ts"').map(t => t.raw)).toEqual(["dir with spaces/a.ts"]);
	});
});
