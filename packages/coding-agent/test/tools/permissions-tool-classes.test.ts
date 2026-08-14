import { afterEach, beforeEach, describe, expect, it, spyOn } from "bun:test";
import * as fsSync from "node:fs";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { getManagedSkillsDir } from "@oh-my-pi/pi-coding-agent/autolearn/managed-skills";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { getMemoryRoot, LEARNED_LESSONS_FILE } from "@oh-my-pi/pi-coding-agent/memories";
import { loadMnemopiConfig } from "@oh-my-pi/pi-coding-agent/mnemopi/config";
import {
	getMnemopiRetainDbPath,
	getMnemopiScopedDbPaths,
	loadMnemopi,
	loadMnemopiCore,
	type MnemopiSessionState,
} from "@oh-my-pi/pi-coding-agent/mnemopi/state";
import {
	buildPermissionPolicy,
	checkStructuredTargets,
	enforceResourcePermissions,
} from "@oh-my-pi/pi-coding-agent/tools/permissions";
import {
	CLASSIFIED_TOOL_NAMES,
	classifyTool,
	extractEmbeddedEditPaths,
	TOOL_PATH_CLASSES,
} from "@oh-my-pi/pi-coding-agent/tools/permissions/tool-path-targets";
import { removeWithRetries } from "@oh-my-pi/pi-utils";
import { getAgentDir, setAgentDir } from "@oh-my-pi/pi-utils/dirs";

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

	// The finding: `generate_image` had no entry here at all, so it fell to
	// the opaque string-scan fallback - `confineWrites` never applied to its
	// randomly-named temp output, and `confineReads` never applied to a
	// declared `input[].path` reference image.
	it("authorizes declared input images for read and the temp root for write", () => {
		const targets = extract("generate_image", {
			subject: "a cat",
			input: [{ path: "ref.png" }, { data: "aGVsbG8=", mime_type: "image/png" }],
		});
		expect(targets).toContainEqual({ raw: "ref.png", access: "read", field: "input" });
		expect(targets).toContainEqual({ raw: os.tmpdir(), access: "write", field: "input" });
		// The data-only entry has no path to authorize.
		expect(targets.filter(t => t.access === "read")).toHaveLength(1);
	});

	it("still authorizes the temp root when generate_image has no input images", () => {
		expect(extract("generate_image", { subject: "a cat" })).toEqual([
			{ raw: os.tmpdir(), access: "write", field: "input" },
		]);
	});

	// The finding: `tts` had no entry here at all, so it fell to the opaque
	// string-scan fallback - `confineWrites` never applied to `output_path`.
	it("authorizes output_path as a write target", () => {
		expect(extract("tts", { text: "hi", output_path: "speech.mp3" })).toEqual([
			{ raw: "speech.mp3", access: "write", field: "output_path" },
		]);
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

	it("authorizes directory reads and writes before deleting a managed skill", () => {
		const dir = path.join(getManagedSkillsDir(), "never-created-skill");
		expect(extract("manage_skill", { action: "delete", name: "never-created-skill" })).toEqual([
			{ raw: dir, access: "read", field: "name" },
			{ raw: dir, access: "write", field: "name" },
		]);
	});

	it("registers learned.md as read+write under a local memory backend, not write-only", () => {
		const settings = Settings.isolated({ "memory.backend": "local" });
		const context = { settings } as unknown as AgentToolContext;
		const filePath = path.join(getMemoryRoot(settings.getAgentDir(), settings.getCwd()), LEARNED_LESSONS_FILE);
		expect(extract("learn", { memory: "persist this lesson" }, context)).toEqual([
			{ raw: filePath, access: "read", field: "memory" },
			{ raw: filePath, access: "write", field: "memory" },
		]);
	});

	it("contributes no local-backend target under a non-local memory backend", () => {
		const settings = Settings.isolated({ "memory.backend": "hindsight" });
		const context = { settings } as unknown as AgentToolContext;
		expect(extract("learn", { memory: "persist this lesson" }, context)).toEqual([]);
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

	it("gates retain's read and write to wherever mnemopi.dbPath is configured, not a fixed default", () => {
		const customDbPath = path.join(path.sep, "vault", "elsewhere", "mnemopi.db");
		const context = mnemopiContext({
			"memory.backend": "mnemopi",
			"mnemopi.scoping": "global",
			"mnemopi.dbPath": customDbPath,
		});
		expect(extract("retain", context)).toEqual([
			{ raw: customDbPath, access: "read", field: "memory" },
			{ raw: customDbPath, access: "write", field: "memory" },
		]);
	});

	it("derives retain's target the same way the tool's own execution path resolves it", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const expected = getMnemopiRetainDbPath(loadMnemopiConfig(settings, settings.getAgentDir()));
		expect(extract("retain", context)).toEqual([
			{ raw: expected, access: "read", field: "memory" },
			{ raw: expected, access: "write", field: "memory" },
		]);
	});

	// `rememberScoped` opens the database through the same SQLite handle
	// `memory_edit` uses, and its underlying `remember` call reads existing
	// pages/indexes as part of the insert. A write-only target let a
	// `permissions.deny.read`/`confineReads` rule that blocks the database pass
	// `retain` while the equivalent `memory_edit` call was correctly refused —
	// register both the same way so a read-only denial cannot be bypassed by
	// retaining a value instead of editing one (finding under review).
	it("denies retain exactly where it denies memory_edit under a read-only block on the database", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const dbPath = getMnemopiRetainDbPath(loadMnemopiConfig(settings, settings.getAgentDir()));

		const policy = buildPermissionPolicy("workspace", {
			confineReads: false,
			confineWrites: false,
			denyRead: [dbPath],
			denyWrite: [],
			allowRead: [],
			allowWrite: [],
			opaqueToolScan: "deny",
		});
		const roots = { cwd: path.sep, additionalDirectories: [] };

		const retainDenial = checkStructuredTargets(extract("retain", context), policy, roots);
		const memoryEditDenial = checkStructuredTargets(extract("memory_edit", context), policy, roots);
		expect(retainDenial).not.toBeNull();
		expect(memoryEditDenial).not.toBeNull();
	});

	it("gates memory_edit as a read and a write on every bank it can touch, since it looks an id up across all of them before writing", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const scopedPaths = getMnemopiScopedDbPaths(loadMnemopiConfig(settings, settings.getAgentDir()));
		expect(scopedPaths.length).toBeGreaterThan(0);
		const targets = extract("memory_edit", context);
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual(scopedPaths.flatMap(p => [`read:${p}`, `write:${p}`]));
	});

	// The session's `MnemopiSessionState` opens its SQLite handles from the
	// config captured at backend startup and does not reopen them on a later
	// `mnemopi.dbPath`/scoping settings change (only `memory.backend` changing
	// reinitializes it — `mnemopi/backend.ts`). Authorizing from live settings
	// here would let a mid-session config change point the gate at a path the
	// tool never actually opens, while the real write lands in the untouched
	// startup database (finding under review).
	it("authorizes the session's initialized database, not settings changed after backend startup", () => {
		const startupSettings = Settings.isolated({
			"memory.backend": "mnemopi",
			"mnemopi.scoping": "global",
			"mnemopi.dbPath": path.join(path.sep, "vault", "startup", "mnemopi.db"),
		});
		const startupConfig = loadMnemopiConfig(startupSettings, startupSettings.getAgentDir());
		const initializedState = { config: startupConfig } as unknown as MnemopiSessionState;

		const driftedSettings = Settings.isolated({
			"memory.backend": "mnemopi",
			"mnemopi.scoping": "global",
			"mnemopi.dbPath": path.join(path.sep, "vault", "drifted", "mnemopi.db"),
		});
		const context = {
			settings: driftedSettings,
			getMnemopiSessionState: () => initializedState,
		} as unknown as AgentToolContext;

		expect(extract("retain", context)).toEqual([
			{ raw: getMnemopiRetainDbPath(startupConfig), access: "read", field: "memory" },
			{ raw: getMnemopiRetainDbPath(startupConfig), access: "write", field: "memory" },
		]);
		expect(extract("retain", context)).not.toEqual([
			{
				raw: getMnemopiRetainDbPath(loadMnemopiConfig(driftedSettings, driftedSettings.getAgentDir())),
				access: "write",
				field: "memory",
			},
		]);

		const scopedPaths = getMnemopiScopedDbPaths(startupConfig);
		expect(extract("memory_edit", context).map(t => `${t.access}:${t.raw}`)).toEqual(
			scopedPaths.flatMap(p => [`read:${p}`, `write:${p}`]),
		);
	});

	// `learn` had no mnemopi handling at all: `tool-path-targets.ts` only
	// special-cased `memory.backend: local`, so under mnemopi `LearnTool.execute`
	// called `state.rememberScoped` — the same call `retain` makes — while the
	// gate contributed zero targets for it, silently bypassing
	// `confineWrites`/`confineReads`/`deny` rules on the database (finding under
	// review).
	it("gates learn's mnemopi write the same way retain's is gated", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		expect(extract("learn", context)).toEqual(extract("retain", context));
	});

	it("denies learn's mnemopi write exactly where it denies retain under a read-only block on the database", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const dbPath = getMnemopiRetainDbPath(loadMnemopiConfig(settings, settings.getAgentDir()));

		const policy = buildPermissionPolicy("workspace", {
			confineReads: false,
			confineWrites: false,
			denyRead: [dbPath],
			denyWrite: [],
			allowRead: [],
			allowWrite: [],
			opaqueToolScan: "deny",
		});
		const roots = { cwd: path.sep, additionalDirectories: [] };

		const learnDenial = checkStructuredTargets(extract("learn", context), policy, roots);
		const retainDenial = checkStructuredTargets(extract("retain", context), policy, roots);
		expect(learnDenial).not.toBeNull();
		expect(retainDenial).not.toBeNull();
	});

	it("contributes no mnemopi target for learn under a non-mnemopi backend, so hindsight-backed learn is unaffected", () => {
		const context = mnemopiContext({ "memory.backend": "hindsight" });
		expect(extract("learn", context)).toEqual([]);
	});

	it("combines learn's mnemopi write target with an optional skill write, in that order", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const dbPath = getMnemopiRetainDbPath(loadMnemopiConfig(settings, settings.getAgentDir()));
		const cls = TOOL_PATH_CLASSES.learn;
		if (cls?.kind !== "structured") throw new Error("learn is not structured");
		const targets = cls.extract(
			{ skill: { action: "create", name: "persistent-instruction", description: "test", body: "body" } },
			context,
		);
		expect(targets.map(t => `${t.access}:${t.raw}`)).toEqual([
			`read:${dbPath}`,
			`write:${dbPath}`,
			`write:${path.join(getManagedSkillsDir(), "persistent-instruction", "SKILL.md")}`,
		]);
	});

	// `recall`/`reflect` were classified `pathless`, so the gate returned
	// immediately for both even though `state.recallResultsScoped` — the call
	// both tools make under mnemopi — reads every bank the session recalls from
	// and returns their content to the model, bypassing `confineReads` and
	// database-specific `deny.read` rules (finding under review).
	it("gates recall and reflect as reads across the same scoped bank set memory_edit touches", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const scopedPaths = getMnemopiScopedDbPaths(loadMnemopiConfig(settings, settings.getAgentDir()));
		expect(scopedPaths.length).toBeGreaterThan(0);
		for (const tool of ["recall", "reflect"]) {
			expect(extract(tool, context).map(t => `${t.access}:${t.raw}`)).toEqual(scopedPaths.map(p => `read:${p}`));
		}
	});

	it("denies recall and reflect exactly where a read-only deny rule blocks the scoped database", () => {
		const settings = Settings.isolated({ "memory.backend": "mnemopi" });
		const context = { settings } as unknown as AgentToolContext;
		const scopedPaths = getMnemopiScopedDbPaths(loadMnemopiConfig(settings, settings.getAgentDir()));

		const policy = buildPermissionPolicy("workspace", {
			confineReads: false,
			confineWrites: false,
			denyRead: [scopedPaths[0]],
			denyWrite: [],
			allowRead: [],
			allowWrite: [],
			opaqueToolScan: "deny",
		});
		const roots = { cwd: path.sep, additionalDirectories: [] };

		for (const tool of ["recall", "reflect"]) {
			expect(checkStructuredTargets(extract(tool, context), policy, roots)).not.toBeNull();
		}
	});

	it("contributes no targets for recall and reflect under a non-mnemopi backend or with no context at all", () => {
		const context = mnemopiContext({ "memory.backend": "hindsight" });
		expect(extract("recall", context)).toEqual([]);
		expect(extract("reflect", context)).toEqual([]);
		expect(extract("recall")).toEqual([]);
		expect(extract("reflect")).toEqual([]);
	});
});

describe("manage_skill delete recursion", () => {
	// `deleteManagedSkill` (`autolearn/managed-skills.ts`) runs
	// `fs.rm(dir, { recursive: true })` on the whole skill directory, so every
	// existing descendant - not just `SKILL.md` - must be authorized before the
	// removal proceeds (finding under review).
	let tempHome: string;
	let originalAgentDir: string;

	beforeEach(async () => {
		originalAgentDir = getAgentDir();
		tempHome = await fs.mkdtemp(path.join(os.tmpdir(), "omp-manage-skill-delete-"));
		spyOn(os, "homedir").mockReturnValue(tempHome);
		setAgentDir(path.join(tempHome, ".omp", "agent"));
	});

	afterEach(async () => {
		spyOn(os, "homedir").mockRestore();
		setAgentDir(originalAgentDir);
		await removeWithRetries(tempHome);
	});

	function postAuthorizationTargets(args: Record<string, unknown>) {
		const cls = TOOL_PATH_CLASSES.manage_skill;
		if (cls?.kind !== "structured") throw new Error("manage_skill is not structured");
		return cls.postAuthorizationTargets?.(args) ?? [];
	}

	it("authorizes every descendant found on disk after authorizing the directory", async () => {
		const dir = path.join(getManagedSkillsDir(), "demo-skill");
		await fs.mkdir(path.join(dir, "assets"), { recursive: true });
		await fs.writeFile(path.join(dir, "SKILL.md"), "---\nname: demo-skill\n---\nbody");
		await fs.writeFile(path.join(dir, ".env"), "SECRET=1");
		await fs.writeFile(path.join(dir, "assets", "logo.png"), "");

		const targets = postAuthorizationTargets({ action: "delete", name: "demo-skill" });
		expect(targets.every(t => t.access === "write" && t.field === "name")).toBe(true);
		const raws = new Set(targets.map(t => t.raw));
		expect(raws).toEqual(
			new Set([
				path.join(dir, "SKILL.md"),
				path.join(dir, ".env"),
				path.join(dir, "assets"),
				path.join(dir, "assets", "logo.png"),
			]),
		);
	});

	it("rejects a read-denied directory before enumerating its descendants", async () => {
		const dir = path.join(getManagedSkillsDir(), "denied-skill");
		await fs.mkdir(dir, { recursive: true });
		const readdirSync = spyOn(fsSync, "readdirSync");
		const context = {
			settings: Settings.isolated({
				"permissions.profile": "workspace",
				"permissions.deny.read": [dir],
			}),
			sessionManager: {
				getCwd: () => tempHome,
				getAdditionalDirectories: () => [],
			},
		} as unknown as AgentToolContext;

		expect(() =>
			enforceResourcePermissions("manage_skill", { action: "delete", name: "denied-skill" }, context),
		).toThrow(dir);
		expect(readdirSync).not.toHaveBeenCalled();
	});
});
