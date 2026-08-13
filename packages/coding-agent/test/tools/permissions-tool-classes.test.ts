import { describe, expect, it } from "bun:test";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { getManagedSkillsDir } from "@oh-my-pi/pi-coding-agent/autolearn/managed-skills";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { loadMnemopiConfig } from "@oh-my-pi/pi-coding-agent/mnemopi/config";
import {
	getMnemopiRetainDbPath,
	getMnemopiScopedDbPaths,
	loadMnemopi,
	loadMnemopiCore,
} from "@oh-my-pi/pi-coding-agent/mnemopi/state";
import {
	CLASSIFIED_TOOL_NAMES,
	classifyTool,
	extractEmbeddedEditPaths,
	TOOL_PATH_CLASSES,
} from "@oh-my-pi/pi-coding-agent/tools/permissions/tool-path-targets";

// Mnemopi is lazy-loaded at runtime; preload it for synchronous bank-path resolution.
await Promise.all([loadMnemopi(), loadMnemopiCore()]);

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
	function extract(tool: string, args: Record<string, unknown>, context?: AgentToolContext) {
		const cls = TOOL_PATH_CLASSES[tool];
		if (cls?.kind !== "structured") throw new Error(`${tool} is not structured`);
		return cls.extract(args, context);
	}

	it("normalizes hashline write headers before extracting their target", () => {
		expect(extract("write", { path: "[../outside.txt#ABCD]" })).toEqual([
			{ raw: "../outside.txt", access: "write", field: "path" },
		]);
	});

	it("splits the semicolon-delimited search roots grep and glob accept", () => {
		expect(extract("grep", { path: "src; test" }).map(t => t.raw)).toEqual(["src", "test"]);
	});

	it("takes edit rename destinations as writes alongside the target", () => {
		const targets = extract("edit", { path: "a.ts", edits: [{ rename: "b.ts" }, { diff: "x" }] });
		// The edited file is opened to locate the edit, so it is a read as well
		// as a write; a rename destination is only produced.
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(["read:a.ts", "write:a.ts", "write:b.ts"]);
		expect(targets.filter(t => t.raw === "b.ts").every(t => t.access === "write")).toBe(true);
	});

	// The access map inverts the tool's own LSP_READONLY_ACTIONS, so a
	// write-tier action the tool knows about cannot be missed here. LSP opens
	// the source document before every request, including mutation requests.
	it("reads navigation sources and reads plus writes mutation sources", () => {
		for (const action of ["references", "hover", "definition", "diagnostics", "symbols", "status"]) {
			expect(extract("lsp", { action, file: "a.ts" })).toEqual([{ raw: "a.ts", access: "read", field: "file" }]);
		}
		for (const action of ["rename", "rename_file", "code_actions", "request", "reload"]) {
			const targets = extract("lsp", { action, file: "a.ts" });
			expect(targets.slice(0, 2)).toEqual([
				{ raw: "a.ts", access: "read", field: "file" },
				{ raw: "a.ts", access: "write", field: "file" },
			]);
		}
	});

	it("ignores absent, blank, and wrongly typed arguments", () => {
		expect(extract("read", {})).toEqual([]);
		expect(extract("read", { path: "   " })).toEqual([]);
		expect(extract("read", { path: 42 })).toEqual([]);
		expect(extract("ast_edit", { paths: "not-an-array" })).toEqual([]);
	});

	it("leaves security_scan scope filters to its canonical-root guard", () => {
		const targets = extract("security_scan", { include_paths: ["src"], exclude_paths: [".env"], output_root: "out" });
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(["write:out"]);
	});

	it("treats managed-skill storage as a write target", () => {
		expect(extract("manage_skill", { action: "create", name: "persistent-instruction" })).toEqual([
			{
				raw: `${getManagedSkillsDir()}/persistent-instruction/SKILL.md`,
				access: "write",
				field: "name",
			},
		]);
	});

	it("treats an optional learn skill as the managed write it performs", () => {
		expect(
			extract("learn", {
				skill: { action: "create", name: "persistent-instruction", description: "test", body: "body" },
			}),
		).toEqual([
			{
				raw: `${getManagedSkillsDir()}/persistent-instruction/SKILL.md`,
				access: "write",
				field: "skill.name",
			},
		]);
		expect(extract("learn", {})).toEqual([]);
	});

	it("keeps invalid managed-skill names inside the permission gate", () => {
		expect(
			extract("learn", {
				skill: { action: "create", name: "../outside", description: "test", body: "body" },
			}),
		).toEqual([
			{
				raw: path.join(getManagedSkillsDir(), "..", "outside", "SKILL.md"),
				access: "write",
				field: "skill.name",
			},
		]);
	});
});

describe("embedded edit payload paths", () => {
	it("extracts hashline section headers as both a read and a write", () => {
		// A hashline section anchors to a tag minted from the file's existing
		// content, so applying it opens the file before rewriting it.
		expect(extractEmbeddedEditPaths("[src/a.ts#1A2B]\nPUT 1.=1:\n+x").map(t => `${t.access}:${t.raw}`)).toEqual([
			"read:src/a.ts",
			"write:src/a.ts",
		]);
	});

	it("extracts apply_patch file and move markers, with access per marker", () => {
		const input = ["*** Begin Patch", "*** Update File: src/a.ts", "*** Move to: src/b.ts", "*** End Patch"].join(
			"\n",
		);
		// `Update File` opens the source; a move destination is only produced.
		expect(extractEmbeddedEditPaths(input).map(t => `${t.access}:${t.raw}`)).toEqual([
			"read:src/a.ts",
			"write:src/a.ts",
			"write:src/b.ts",
		]);
	});

	it("treats an apply_patch Add File target as a write only", () => {
		const input = ["*** Begin Patch", "*** Add File: src/new.ts", "*** End Patch"].join("\n");
		expect(extractEmbeddedEditPaths(input).map(t => `${t.access}:${t.raw}`)).toEqual(["write:src/new.ts"]);
	});

	it("treats an apply_patch Delete File target as a read and a write", () => {
		const input = ["*** Begin Patch", "*** Delete File: src/old.ts", "*** End Patch"].join("\n");
		expect(extractEmbeddedEditPaths(input).map(t => `${t.access}:${t.raw}`)).toEqual([
			"read:src/old.ts",
			"write:src/old.ts",
		]);
	});

	it("does not mistake a bracketed body line for a header", () => {
		expect(extractEmbeddedEditPaths("[not a header#zz]")).toEqual([]);
	});

	it("finds a secret target hidden in a hashline payload with no top-level path", () => {
		const cls = TOOL_PATH_CLASSES.edit;
		if (cls?.kind !== "structured") throw new Error("edit is not structured");
		expect(cls.extract({ input: "[.env#00FF]\nPUT 1.=1:\n+LEAK=1" }).map(t => `${t.access}:${t.raw}`)).toEqual([
			"read:.env",
			"write:.env",
		]);
	});

	it("extracts a hashline MV destination, which is a write the section performs", () => {
		const input = "[src/a.ts#1A2B]\nCUT 1.=1\nMV ../../outside/escaped.ts";
		expect(extractEmbeddedEditPaths(input).map(t => `${t.access}:${t.raw}`)).toEqual([
			"read:src/a.ts",
			"write:src/a.ts",
			"write:../../outside/escaped.ts",
		]);
	});

	it("unquotes an MV destination containing spaces", () => {
		expect(extractEmbeddedEditPaths('MV "dir with spaces/a.ts"').map(t => `${t.access}:${t.raw}`)).toEqual([
			"write:dir with spaces/a.ts",
		]);
	});
});

describe("mnemopi memory tool paths", () => {
	// `retain`/`memory_edit` carry no path argument; under `memory.backend:
	// mnemopi` they mutate whatever `mnemopi.dbPath` resolves to, which is not
	// the fixed default agent-memory location — it "may point anywhere"
	// (finding under review). A gate that only ever checks the default location
	// would miss a database an administrator moved.
	function mnemopiContext(overrides: Parameters<typeof Settings.isolated>[0]): AgentToolContext {
		const settings = Settings.isolated(overrides);
		return { settings } as unknown as AgentToolContext;
	}

	function extract(tool: string, context?: AgentToolContext) {
		const cls = TOOL_PATH_CLASSES[tool];
		if (cls?.kind !== "structured") throw new Error(`${tool} is not structured`);
		return cls.extract({}, context);
	}

	it("contributes no targets for a non-mnemopi backend, so hindsight-backed retain is unaffected", () => {
		const context = mnemopiContext({ "memory.backend": "hindsight" });
		expect(extract("retain", context)).toEqual([]);
		expect(extract("memory_edit", context)).toEqual([]);
	});

	it("contributes no targets when called with no context at all", () => {
		expect(extract("retain")).toEqual([]);
		expect(extract("memory_edit")).toEqual([]);
	});

	it("gates retain's write to wherever mnemopi.dbPath is configured, not a fixed default", () => {
		const customDbPath = path.join(path.sep, "vault", "elsewhere", "mnemopi.db");
		const context = mnemopiContext({
			"memory.backend": "mnemopi",
			"mnemopi.scoping": "global",
			"mnemopi.dbPath": customDbPath,
		});
		expect(extract("retain", context)).toEqual([{ raw: customDbPath, access: "write", field: "memory" }]);
	});

	it("derives retain's target the same way the tool's own execution path resolves it", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const expected = getMnemopiRetainDbPath(loadMnemopiConfig(settings, settings.getAgentDir()));
		expect(extract("retain", context)).toEqual([{ raw: expected, access: "write", field: "memory" }]);
	});

	it("gates memory_edit as a read and a write on every bank it can touch, since it looks an id up across all of them before writing", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const scopedPaths = getMnemopiScopedDbPaths(loadMnemopiConfig(settings, settings.getAgentDir()));
		expect(scopedPaths.length).toBeGreaterThan(0);
		const targets = extract("memory_edit", context);
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(scopedPaths.flatMap(p => [`read:${p}`, `write:${p}`]));
	});
});
