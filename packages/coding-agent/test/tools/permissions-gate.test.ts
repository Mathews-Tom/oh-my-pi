import { Database } from "bun:sqlite";
import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolContext, AgentToolResult } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { ExtensionToolWrapper } from "@oh-my-pi/pi-coding-agent/extensibility/extensions";
import type { ExtensionRunner } from "@oh-my-pi/pi-coding-agent/extensibility/extensions/runner";
import { applyGuardedWorkspaceEdit, guardLocationReads } from "@oh-my-pi/pi-coding-agent/lsp";
import { guardedApplyEditDenial } from "@oh-my-pi/pi-coding-agent/lsp/client";
import { workspaceEditPathTargets } from "@oh-my-pi/pi-coding-agent/lsp/edits";
import type { LspClient } from "@oh-my-pi/pi-coding-agent/lsp/types";
import type { ReadonlySessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import { ToolChoiceQueue } from "@oh-my-pi/pi-coding-agent/session/tool-choice-queue";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { collectPermittedSearchPaths, enforceResourcePathTargets } from "@oh-my-pi/pi-coding-agent/tools/permissions";
import { ReadTool } from "@oh-my-pi/pi-coding-agent/tools/read";
import { WriteTool } from "@oh-my-pi/pi-coding-agent/tools/write";
import { hashPath } from "@oh-my-pi/pi-utils";

/** A zero-width range at the start of the document, for text-edit fixtures. */
const RANGE_ZERO = { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } };

let workspace: string;
let worktree: string;
let sibling: string;
let outside: string;

/** Minimal runner: `execute` only ever asks whether handlers or a UI exist. */
const runner = {
	consumeToolCallEmitted: () => true,
	hasHandlers: () => false,
	hasUI: () => false,
	emit: async () => undefined,
	emitToolCall: async () => undefined,
	emitToolResult: async () => undefined,
} as unknown as ExtensionRunner;

function settingsOf(overrides: Record<string, unknown>): Settings {
	return {
		get(key: string): unknown {
			return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
		},
		getAgentDir: () => path.join(outside, "agent"),
		getCwd: () => workspace,
	} as unknown as Settings;
}

function contextOf(
	overrides: Record<string, unknown>,
	options: { cwd?: string; additionalDirectories?: string[]; autoApprove?: boolean } = {},
): AgentToolContext {
	const cwd = options.cwd ?? workspace;
	const sessionManager = {
		getCwd: () => cwd,
		getAdditionalDirectories: () => options.additionalDirectories ?? [sibling],
		getSessionId: () => "test-session",
	} as unknown as ReadonlySessionManager;
	return {
		sessionManager,
		settings: settingsOf(overrides),
		...(options.autoApprove ? { autoApprove: true } : {}),
	} as unknown as AgentToolContext;
}

interface Recorder {
	tool: AgentTool;
	calls: unknown[];
}

function recordingTool(name: string): Recorder {
	const calls: unknown[] = [];
	const tool = {
		name,
		description: name,
		parameters: {},
		label: name,
		strict: false,
		execute: async (_id: string, params: unknown): Promise<AgentToolResult> => {
			calls.push(params);
			return { content: [{ type: "text", text: "ok" }], details: undefined };
		},
	} as unknown as AgentTool;
	return { tool, calls };
}

async function run(toolName: string, params: unknown, context: AgentToolContext): Promise<Recorder> {
	const recorder = recordingTool(toolName);
	const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
	await wrapper.execute("call-1", params as never, undefined, undefined, context);
	return recorder;
}

async function denialOf(toolName: string, params: unknown, context: AgentToolContext): Promise<string> {
	const recorder = recordingTool(toolName);
	const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
	try {
		await wrapper.execute("call-1", params as never, undefined, undefined, context);
	} catch (err) {
		expect(recorder.calls).toEqual([]);
		return err instanceof Error ? err.message : String(err);
	}
	throw new Error(`expected ${toolName} to be denied`);
}

const STRICT = { "permissions.profile": "strict" };
const WORKSPACE = { "permissions.profile": "workspace" };

beforeAll(() => {
	const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-gate-")));
	workspace = path.join(base, "ws");
	worktree = path.join(base, "wt");
	sibling = path.join(base, "extra");
	outside = path.join(base, "outside");
	for (const dir of [path.join(workspace, "src"), worktree, sibling, outside]) {
		fs.mkdirSync(dir, { recursive: true });
	}
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export {};");
	fs.writeFileSync(path.join(sibling, "notes.md"), "notes");
	fs.writeFileSync(path.join(outside, "loot.txt"), "loot");
	fs.symlinkSync(outside, path.join(workspace, "escape"));
});

afterAll(() => {
	fs.rmSync(path.dirname(workspace), { recursive: true, force: true });
});

describe("profile off", () => {
	it("runs every call that runs today, including outside the workspace", async () => {
		const context = contextOf({ "permissions.profile": "off" });
		expect((await run("read", { path: ".env" }, context)).calls).toHaveLength(1);
		expect((await run("write", { path: path.join(outside, "x.txt") }, context)).calls).toHaveLength(1);
		expect((await run("edit", { path: "/etc/hosts", edits: [] }, context)).calls).toHaveLength(1);
	});

	it("behaves identically when permissions.* is entirely absent from settings", async () => {
		const context = contextOf({});
		expect((await run("read", { path: ".env" }, context)).calls).toHaveLength(1);
	});
});

describe("profile strict", () => {
	it("denies reading a secret and names the rule and the setting to change", async () => {
		const message = await denialOf("read", { path: ".env" }, contextOf(STRICT));
		expect(message).toContain('resource permission rule "**/.env"');
		expect(message).toContain("permissions.allow.read");
	});

	it("denies a hashline edit whose target is only named inside the payload", async () => {
		const message = await denialOf("edit", { input: "[.env#00FF]\nPUT 1.=1:\n+LEAK=1" }, contextOf(STRICT));
		expect(message).toContain("**/.env");
	});

	it("still runs ordinary workspace calls", async () => {
		expect((await run("read", { path: "src/main.ts" }, contextOf(STRICT))).calls).toHaveLength(1);
	});

	it("leaves internal URLs reachable", async () => {
		for (const url of ["local://plan.md", "memory://root/x", "xd://browser"]) {
			expect((await run("read", { path: url }, contextOf(STRICT))).calls).toHaveLength(1);
		}
	});

	it("excludes denied recursive candidates before a native search can open them", async () => {
		const allowedPaths = await collectPermittedSearchPaths(workspace, undefined, true, true, contextOf(STRICT));

		expect(allowedPaths).toEqual(["src/main.ts"]);
	});

	it("denies an explicit restricted search target before native search opens it", async () => {
		await expect(
			collectPermittedSearchPaths(path.join(workspace, ".env"), undefined, true, true, contextOf(STRICT)),
		).rejects.toThrow("resource permission rule");
	});
});

describe("subagent bypass is closed", () => {
	// `task/executor.ts` forces `tools.approvalMode: yolo` for every subagent,
	// and `resolveApproval` returns before its yolo branch only for `deny`. A
	// guard built as an approval tier would therefore vanish here.
	it("denies a subagent read of a denied path under forced yolo", async () => {
		const context = contextOf({ ...STRICT, "tools.approvalMode": "yolo" });
		const message = await denialOf("read", { path: ".env" }, context);
		expect(message).toContain("**/.env");
	});

	it("denies it even with --auto-approve on top of yolo", async () => {
		const context = contextOf({ ...STRICT, "tools.approvalMode": "yolo" }, { autoApprove: true });
		expect(await denialOf("read", { path: ".env" }, context)).toContain("**/.env");
	});

	it("denies it even when the tool is explicitly allowed by user policy", async () => {
		const context = contextOf({
			...STRICT,
			"tools.approvalMode": "yolo",
			"tools.approval": { read: "allow" },
		});
		expect(await denialOf("read", { path: ".env" }, context)).toContain("**/.env");
	});
});

describe("write confinement", () => {
	it("denies an absolute-path escape", async () => {
		const message = await denialOf("write", { path: path.join(outside, "loot.txt") }, contextOf(WORKSPACE));
		expect(message).toContain("permissions.confineWrites");
		expect(message).toContain("outside every workspace root");
	});

	it("denies a `..` traversal escape", async () => {
		expect(await denialOf("write", { path: "../outside/loot.txt" }, contextOf(WORKSPACE))).toContain(
			"permissions.confineWrites",
		);
	});

	it("denies a write through a symlink pointing out of the workspace", async () => {
		expect(await denialOf("write", { path: "escape/loot.txt" }, contextOf(WORKSPACE))).toContain(
			"permissions.confineWrites",
		);
	});

	it("denies an existing write target whose contents are read by the executor", async () => {
		const context = contextOf({
			...WORKSPACE,
			"permissions.deny.read": ["**/.env"],
		});
		const session = {
			cwd: workspace,
			hasUI: false,
			enableLsp: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: settingsOf({}),
		} as ToolSession;

		await expect(
			new WriteTool(session).execute(
				"write-existing-denied-read",
				{ path: ".env", content: "REPLACED=1" },
				undefined,
				undefined,
				context,
			),
		).rejects.toThrow("**/.env");
		expect(await Bun.file(path.join(workspace, ".env")).text()).toBe("SECRET=1");
	});

	it("permits a write into an additional workspace root", async () => {
		const calls = (await run("write", { path: path.join(sibling, "new.md") }, contextOf(WORKSPACE))).calls;
		expect(calls).toHaveLength(1);
	});

	it("leaves reads unconfined", async () => {
		expect((await run("read", { path: "/etc/hosts" }, contextOf(WORKSPACE))).calls).toHaveLength(1);
	});

	it("denies a bracketed hashline write target after normalizing it to its actual path", async () => {
		const message = await denialOf("write", { path: "[../outside/loot.txt#ABCD]" }, contextOf(WORKSPACE));
		expect(message).toContain("permissions.confineWrites");
	});

	it("authorizes a SQLite database's journal/WAL/SHM siblings, not just the database an exact rule allows", async () => {
		const dbPath = path.join(outside, "vault.db");
		const db = new Database(dbPath, { create: true, strict: true });
		db.run("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT NOT NULL)");
		db.run("INSERT INTO items (id, value) VALUES (1, 'a')");
		db.close();

		const session = {
			cwd: workspace,
			hasUI: false,
			enableLsp: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: settingsOf({}),
		} as ToolSession;
		// The exact allow rule carves out only the database itself, so
		// `permissions.confineWrites` still applies to every other outside
		// path — including the `-journal`/`-wal`/`-shm` siblings a writable
		// open can create next to it.
		const context = contextOf({
			"permissions.profile": "workspace",
			"permissions.allow.write": [dbPath],
		});

		await expect(
			new WriteTool(session).execute(
				"write-sqlite-aux-siblings",
				{ path: `${dbPath}:items:1`, content: "{ value: 'b' }" },
				undefined,
				undefined,
				context,
			),
		).rejects.toThrow("permissions.confineWrites");

		expect(fs.existsSync(`${dbPath}-journal`)).toBe(false);
		expect(fs.existsSync(`${dbPath}-wal`)).toBe(false);
		expect(fs.existsSync(`${dbPath}-shm`)).toBe(false);
	});
});

describe("worktree subagent roots", () => {
	// `task/executor.ts` clears `workspace.additionalDirectories` for an
	// isolated run, so the roots collapse to the worktree alone.
	it("refuses a write to the parent workspace once roots collapse", async () => {
		const context = contextOf(WORKSPACE, { cwd: worktree, additionalDirectories: [] });
		expect(await denialOf("write", { path: path.join(workspace, "src", "main.ts") }, context)).toContain(
			"permissions.confineWrites",
		);
		expect((await run("write", { path: path.join(worktree, "out.txt") }, context)).calls).toHaveLength(1);
	});

	it("denies managed-skill mutations outside the workspace", async () => {
		const message = await denialOf(
			"manage_skill",
			{ action: "create", name: "persistent-instruction" },
			contextOf(WORKSPACE),
		);
		expect(message).toContain("permissions.confineWrites");
	});

	it("denies learn when its optional skill would write outside the workspace", async () => {
		const message = await denialOf(
			"learn",
			{
				skill: { action: "create", name: "persistent-instruction", description: "test", body: "body" },
			},
			contextOf(WORKSPACE),
		);
		expect(message).toContain("permissions.confineWrites");
	});

	it("denies local lesson persistence outside the workspace", async () => {
		const message = await denialOf(
			"learn",
			{ memory: "persist this lesson" },
			contextOf({ ...WORKSPACE, "memory.backend": "local" }),
		);
		expect(message).toContain("permissions.confineWrites");
		expect(message).toContain("learned.md");
	});
});

describe("read confinement", () => {
	it("denies a read through a symlink escape once confineReads is on", async () => {
		const context = contextOf({ "permissions.profile": "workspace", "permissions.confineReads": true });
		expect(await denialOf("read", { path: "escape/loot.txt" }, context)).toContain("permissions.confineReads");
	});
});

describe("opaque tool scan", () => {
	it("denies a bash command naming a denied path", async () => {
		const message = await denialOf("bash", { command: "cat .env" }, contextOf(STRICT));
		expect(message).toContain('rule "**/.env"');
		expect(message).toContain("not a sandbox");
		expect(message).toContain("tools.approval.bash: deny");
	});

	it("denies an unknown MCP tool naming a denied path in a nested argument", async () => {
		const args = { params: { path: ".env" } };
		expect(await denialOf("mcp__filesystem_read_file", args, contextOf(STRICT))).toContain("**/.env");
	});

	it("lets an ordinary bash command through", async () => {
		expect((await run("bash", { command: "bun test src/main.ts" }, contextOf(STRICT))).calls).toHaveLength(1);
	});

	it("does not scan at all when opaqueToolScan is off", async () => {
		const context = contextOf({ ...STRICT, "permissions.opaqueToolScan": "off" });
		expect((await run("bash", { command: "cat .env" }, context)).calls).toHaveLength(1);
	});

	it("routes to confirmation under opaqueToolScan: prompt and keeps the rule in the message", async () => {
		// Headless runs — subagents, RPC, ACP, `-p` — have no UI, so a required
		// approval surfaces as the wrapper's no-interactive-UI refusal. The
		// contract worth defending is that the message still names the rule; a
		// generic "requires approval" tells the user nothing they can act on.
		const context = contextOf({ ...STRICT, "permissions.opaqueToolScan": "prompt" });
		const message = await denialOf("bash", { command: "cat .env" }, context);
		expect(message).toContain("requires approval but no interactive UI available");
		expect(message).toContain('rule "**/.env"');
		expect(message).toContain("permissions.opaqueToolScan");
	});

	it("leaves the task tool unscanned so a prompt may name a secret", async () => {
		const params = { task: "audit config", context: "never touch .env" };
		expect((await run("task", params, contextOf(STRICT))).calls).toHaveLength(1);
	});
});

describe("fail-closed edges", () => {
	it("denies rather than guessing when the call carries no session", async () => {
		const recorder = recordingTool("read");
		const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
		const context = { settings: settingsOf(STRICT) } as unknown as AgentToolContext;
		await expect(
			wrapper.execute("call-1", { path: "src/main.ts" } as never, undefined, undefined, context),
		).rejects.toThrow(/no session/);
		expect(recorder.calls).toEqual([]);
	});

	it("scans a structured tool whose payload is not the object its schema declares", async () => {
		expect(await denialOf("read", [".env"], contextOf(STRICT))).toContain("**/.env");
	});

	it("denies a read named with a selector suffix, which the tool would peel", async () => {
		expect(await denialOf("read", { path: ".env:raw" }, contextOf(STRICT))).toContain("**/.env");
		expect(await denialOf("grep", { pattern: "KEY", path: ".env:1-5" }, contextOf(STRICT))).toContain("**/.env");
	});

	it("names the bad value when permissions.profile is not a profile", async () => {
		// Indexing the profile table with an unrecognized value used to throw a
		// bare `TypeError: undefined is not an object` from inside the gate —
		// a crash that neither allows nor denies and names nothing to fix.
		for (const bogus of [{}, "stict", 3]) {
			const message = await denialOf("read", { path: "src/main.ts" }, contextOf({ "permissions.profile": bogus }));
			expect(message).toContain("permissions.profile is");
			expect(message).toContain('"off", "workspace", or "strict"');
		}
	});

	it("treats every falsy spelling of the profile as off rather than as an error", async () => {
		// `undefined`, `null`, `false`, and `""` all mean "not configured", and
		// `settings: { get: () => false }` is the blanket stub much of this suite
		// uses. None of them is a typo of a profile name, so none is an error.
		for (const absent of [undefined, null, false, ""]) {
			const context = contextOf({ "permissions.profile": absent });
			expect((await run("read", { path: ".env" }, context)).calls).toHaveLength(1);
		}
	});
});

describe("the layer subtracts, never grants", () => {
	it("cannot rescue a call that tools.approval already denies", async () => {
		const context = contextOf({
			"permissions.profile": "strict",
			"permissions.allow.read": ["**/*"],
			"tools.approval": { read: "deny" },
		});
		expect(await denialOf("read", { path: "src/main.ts" }, context)).toContain("blocked by user policy");
	});
});

describe("write-side settings reach the policy", () => {
	it("honours permissions.deny.write from settings", async () => {
		const context = contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/*.lock"] });
		expect(await denialOf("write", { path: "src/deps.lock" }, context)).toContain("**/*.lock");
		expect((await run("write", { path: "src/ok.ts" }, context)).calls).toHaveLength(1);
	});

	it("honours permissions.allow.write as a carve-out from a profile rule", async () => {
		const denied = contextOf({ "permissions.profile": "strict" });
		expect(await denialOf("write", { path: "svc/.env" }, denied)).toContain("**/.env");
		const allowed = contextOf({ "permissions.profile": "strict", "permissions.allow.write": ["svc/.env"] });
		expect((await run("write", { path: "svc/.env" }, allowed)).calls).toHaveLength(1);
	});
});

describe("edit reads the file it rewrites", () => {
	// A read-only denial used to be invisible to `edit`, which classified its
	// target purely as a write. Patch and replace modes open the file to locate
	// the edit, and a mismatch error quotes the closest real source line back to
	// the model, so the denied contents leak through the write-allowed path.
	const READ_DENIED = { "permissions.profile": "workspace", "permissions.deny.read": ["**/secret.txt"] };

	it("denies a patch-mode edit whose source is read-denied but write-allowed", async () => {
		const message = await denialOf("edit", { path: "secret.txt", edits: [] }, contextOf(READ_DENIED));
		expect(message).toContain("**/secret.txt");
		expect(message).toContain("Reading");
	});

	it("denies a hashline edit of a read-denied file", async () => {
		const params = { input: "[secret.txt#00FF]\nPUT 1.=1:\n+LEAK=1" };
		expect(await denialOf("edit", params, contextOf(READ_DENIED))).toContain("**/secret.txt");
	});

	it("still permits creating a new file the read rule names, which is never opened", async () => {
		// `*** Add File` produces its target rather than consulting it, so the
		// read rule does not apply — over-denying here would block a legitimate
		// create for a file that has no contents to leak.
		const params = { input: ["*** Begin Patch", "*** Add File: secret.txt", "*** End Patch"].join("\n") };
		expect((await run("edit", params, contextOf(READ_DENIED))).calls).toHaveLength(1);
	});
});

describe("post-execution recheck", () => {
	/** A tool that reports the files it visited, as `grep`/`ast_edit` do. */
	function reportingTool(name: string, files: string[], onExecute?: () => void): AgentTool {
		return {
			name,
			description: name,
			parameters: {},
			label: name,
			strict: false,
			execute: async (): Promise<AgentToolResult> => {
				onExecute?.();
				return { content: [{ type: "text", text: "ok" }], details: { files } };
			},
		} as unknown as AgentTool;
	}

	async function runReporting(tool: AgentTool, params: unknown, context: AgentToolContext): Promise<Error | null> {
		const wrapper = new ExtensionToolWrapper(tool, runner);
		try {
			await wrapper.execute("call-1", params as never, undefined, undefined, context);
			return null;
		} catch (err) {
			return err instanceof Error ? err : new Error(String(err));
		}
	}

	it("denies a recursive grep that reached a file the declared root did not name", async () => {
		// `grep({ path: "." })` clears the pre-execution gate — `.` matches no
		// secret glob — and only the reported file set exposes the `.env` it opened.
		const tool = reportingTool("grep", [".env"]);
		const error = await runReporting(tool, { path: "." }, contextOf(STRICT));
		expect(error?.message).toContain("**/.env");
	});

	it("drops a preview the denied call staged, so `xd://resolve` cannot apply it", async () => {
		// `ast_edit` registers its apply closure during execution, before the
		// recheck below runs. Left registered, a later resolve dispatch would run
		// it with no further permission check — writing the very file this denial
		// reports as blocked.
		const queue = new ToolChoiceQueue();
		queue.registerPendingInvoker("pre-existing", "write", async () => undefined);
		const context = contextOf(STRICT);
		(context as { pendingPreviews?: unknown }).pendingPreviews = {
			headId: () => queue.peekPendingHead()?.id,
			removeSince: (id: string | undefined) => queue.removePendingInvokersSince(id),
		};

		const tool = reportingTool("ast_edit", [".env"], () => {
			queue.registerPendingInvoker("pending-action:ast_edit:0", "ast_edit", async () => undefined);
		});
		const error = await runReporting(tool, { paths: ["."] }, context);

		expect(error?.message).toContain("**/.env");
		// The denied call's staged apply is gone; an unrelated one that was
		// already pending survives.
		expect(queue.peekPendingHead()).toEqual({ id: "pre-existing", sourceToolName: "write" });
	});

	it("keeps a preview staged when the recheck passes", async () => {
		const queue = new ToolChoiceQueue();
		const context = contextOf(STRICT);
		(context as { pendingPreviews?: unknown }).pendingPreviews = {
			headId: () => queue.peekPendingHead()?.id,
			removeSince: (id: string | undefined) => queue.removePendingInvokersSince(id),
		};

		const tool = reportingTool("ast_edit", ["src/main.ts"], () => {
			queue.registerPendingInvoker("pending-action:ast_edit:0", "ast_edit", async () => undefined);
		});
		expect(await runReporting(tool, { paths: ["src"] }, context)).toBeNull();
		expect(queue.peekPendingHead()?.id).toBe("pending-action:ast_edit:0");
	});
});

describe("security_scan implicit surfaces", () => {
	// The tool declares `include_paths`/`output_root`, but a default
	// `target_kind: "repository"` scan names no read path at all and an omitted
	// `output_root` is defaulted inside the coordinator. Both are resolved
	// mid-preflight, so `SecurityScanGuard` is the only point that sees them.
	// These drive the same gate entry point the guard calls.
	function scanScope(relativePaths: string[], context: AgentToolContext): void {
		enforceResourcePathTargets(
			"security_scan",
			relativePaths.map(relativePath => ({
				raw: path.resolve(workspace, relativePath),
				access: "read" as const,
				field: "scan scope",
			})),
			context,
		);
	}

	it("refuses a repository scan whose resolved scope includes a denied secret", () => {
		expect(() => scanScope(["src/main.ts", ".env"], contextOf(STRICT))).toThrow("**/.env");
	});

	it("permits a repository scan whose resolved scope holds no denied file", () => {
		expect(() => scanScope(["src/main.ts"], contextOf(STRICT))).not.toThrow();
	});

	it("refuses an effective output root outside every workspace root", () => {
		// The default is `<security state dir>/work/<uuid>`, which is outside the
		// repository by design — checking the caller's argument instead of the
		// resolved default left exactly this case unexamined.
		expect(() =>
			enforceResourcePathTargets(
				"security_scan",
				[{ raw: path.join(outside, "work", "abc"), access: "write", field: "output_root" }],
				contextOf(WORKSPACE),
			),
		).toThrow("permissions.confineWrites");
	});

	it("leaves both surfaces alone when no profile is active", () => {
		const off = contextOf({ "permissions.profile": "off" });
		expect(() => scanScope([".env"], off)).not.toThrow();
	});
});

describe("lsp result locations", () => {
	// `definition`/`references` are gated on the initiating `file`, but the
	// locations that come back are the server's choice and their surrounding
	// source lines are read and shown. Without this the rules never saw them.
	function locations(...files: string[]) {
		return files.map(file => ({
			uri: `file://${path.isAbsolute(file) ? file : path.join(workspace, file)}`,
			range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
		}));
	}

	it("refuses to read context from a location the rules deny", () => {
		expect(() => guardLocationReads(locations("src/main.ts", ".env") as never, contextOf(STRICT))).toThrow("**/.env");
	});

	it("refuses a location outside every root once reads are confined", () => {
		const confined = contextOf({ "permissions.profile": "workspace", "permissions.confineReads": true });
		expect(() => guardLocationReads(locations(path.join(outside, "loot.txt")) as never, confined)).toThrow(
			"permissions.confineReads",
		);
	});

	it("permits ordinary in-workspace locations", () => {
		expect(() => guardLocationReads(locations("src/main.ts") as never, contextOf(STRICT))).not.toThrow();
	});
});

describe("resolved read selectors", () => {
	it("rejects a SQLite selector whose resolved database container is denied", async () => {
		const databasePath = path.join(workspace, "vault.db");
		const database = new Database(databasePath);
		database.run("CREATE TABLE users (id INTEGER PRIMARY KEY)");
		database.close();
		const tool = new ReadTool({
			cwd: workspace,
			hasUI: false,
			getSessionFile: () => path.join(workspace, "session.jsonl"),
			getSessionSpawns: () => "*",
			getArtifactsDir: () => path.join(workspace, "session"),
			settings: Settings.isolated(),
		} as ToolSession);

		await expect(
			tool.execute(
				"read-selector-denied-container",
				{ path: "vault.db:users" },
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.read": [databasePath] }),
			),
		).rejects.toThrow(databasePath);
	});
});
describe("lsp workspace edits", () => {
	function fileUri(absolutePath: string): string {
		return `file://${absolutePath}`;
	}

	it("names every destination a workspace edit would touch, including both rename endpoints", async () => {
		const targets = await workspaceEditPathTargets({
			documentChanges: [
				{ kind: "rename", oldUri: fileUri(path.join(workspace, "src/a.ts")), newUri: fileUri("/tmp/b.ts") },
				{ kind: "create", uri: fileUri(path.join(workspace, "src/c.ts")) },
			],
		} as never);
		expect(targets.map(t => t.raw)).toEqual([
			path.join(workspace, "src/a.ts"),
			"/tmp/b.ts",
			path.join(workspace, "src/c.ts"),
		]);
		// Neither `src/a.ts` (a rename source that doesn't exist, so it isn't
		// treated as a directory) nor a `create` target is ever read before it's
		// written — both stay write-only.
		expect(targets.every(t => t.access === "write")).toBe(true);
	});

	it("requires both read and write authorization for a text edit target, since applyTextEdits reads before rewriting", async () => {
		const target = path.join(workspace, "src/main.ts");
		const targets = await workspaceEditPathTargets({
			changes: { [fileUri(target)]: [{ range: RANGE_ZERO, newText: "x" }] },
		} as never);
		expect(targets).toEqual([
			{ raw: target, access: "read", field: "workspace edit text" },
			{ raw: target, access: "write", field: "workspace edit text" },
		]);
	});

	it("expands a directory rename to every existing descendant, mapping each to its destination", async () => {
		const dirPath = path.join(workspace, "pkg-targets");
		fs.mkdirSync(path.join(dirPath, "nested", "empty"), { recursive: true });
		fs.writeFileSync(path.join(dirPath, "index.ts"), "export {};");
		fs.writeFileSync(path.join(dirPath, "nested", "inner.ts"), "export {};");
		const linkPath = path.join(dirPath, "nested", "secret-link");
		fs.symlinkSync("missing-target", linkPath);
		const destination = path.join(workspace, "pkg-targets-renamed");

		const targets = await workspaceEditPathTargets({
			documentChanges: [{ kind: "rename", oldUri: fileUri(dirPath), newUri: fileUri(destination) }],
		} as never);

		const raws = targets.map(target => target.raw).sort();
		expect(raws).toEqual(
			[
				dirPath,
				destination,
				path.join(dirPath, "index.ts"),
				path.join(destination, "index.ts"),
				path.join(dirPath, "nested"),
				path.join(destination, "nested"),
				path.join(dirPath, "nested", "empty"),
				path.join(destination, "nested", "empty"),
				path.join(dirPath, "nested", "inner.ts"),
				path.join(destination, "nested", "inner.ts"),
				linkPath,
				path.join(destination, "nested", "secret-link"),
			].sort(),
		);
	});

	it("refuses a server-chosen rename destination outside the workspace, and writes nothing", async () => {
		// The `file` argument the gate checks is in-workspace and allowed; the
		// destination comes from the language server, so only this check sees it.
		const destination = path.join(outside, "renamed.ts");
		const source = path.join(workspace, "src", "main.ts");
		await expect(
			applyGuardedWorkspaceEdit(
				{ documentChanges: [{ kind: "rename", oldUri: fileUri(source), newUri: fileUri(destination) }] } as never,
				workspace,
				contextOf(WORKSPACE),
			),
		).rejects.toThrow("permissions.confineWrites");
		expect(fs.existsSync(destination)).toBe(false);
		expect(fs.existsSync(source)).toBe(true);
	});

	it("refuses a server-supplied text edit against a denied file", async () => {
		await expect(
			applyGuardedWorkspaceEdit(
				{
					changes: { [fileUri(path.join(workspace, ".env"))]: [{ range: RANGE_ZERO, newText: "LEAK=1" }] },
				} as never,
				workspace,
				contextOf(STRICT),
			),
		).rejects.toThrow("**/.env");
		expect(fs.readFileSync(path.join(workspace, ".env"), "utf8")).toBe("SECRET=1");
	});

	it("applies an in-workspace edit the policy permits", async () => {
		const target = path.join(workspace, "src", "renamed.ts");
		const applied = await applyGuardedWorkspaceEdit(
			{ documentChanges: [{ kind: "create", uri: fileUri(target) }] } as never,
			workspace,
			contextOf(WORKSPACE),
		);
		expect(applied).toHaveLength(1);
		expect(fs.existsSync(target)).toBe(true);
	});

	it("refuses a server-supplied text edit the read side denies, even though nothing denies its write", async () => {
		// A read-only deny rule would have been invisible to the pre-fix,
		// write-only gate — `applyTextEdits` reads `main.ts` before rewriting it,
		// so a `deny.read` with no matching `deny.write` must still block it.
		const target = path.join(workspace, "src", "main.ts");
		await expect(
			applyGuardedWorkspaceEdit(
				{ changes: { [fileUri(target)]: [{ range: RANGE_ZERO, newText: "x" }] } } as never,
				workspace,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.read": ["**/main.ts"] }),
			),
		).rejects.toThrow("**/main.ts");
		expect(fs.readFileSync(target, "utf8")).toBe("export {};");
	});

	it("refuses a directory rename whose descendant is individually denied, leaving the tree untouched", async () => {
		const dirPath = path.join(workspace, "pkg-apply");
		fs.mkdirSync(dirPath, { recursive: true });
		fs.writeFileSync(path.join(dirPath, "index.ts"), "export {};");
		fs.writeFileSync(path.join(dirPath, "protected.txt"), "secret");
		const destination = path.join(workspace, "pkg-apply-renamed");

		await expect(
			applyGuardedWorkspaceEdit(
				{ documentChanges: [{ kind: "rename", oldUri: fileUri(dirPath), newUri: fileUri(destination) }] } as never,
				workspace,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/protected.txt"] }),
			),
		).rejects.toThrow("**/protected.txt");
		expect(fs.existsSync(dirPath)).toBe(true);
		expect(fs.existsSync(destination)).toBe(false);
	});

	it("refuses a directory delete whose symlink descendant is individually denied", async () => {
		const dirPath = path.join(workspace, "pkg-apply-symlink");
		const linkPath = path.join(dirPath, "secret-link");
		fs.mkdirSync(dirPath, { recursive: true });
		fs.symlinkSync("missing-target", linkPath);

		await expect(
			applyGuardedWorkspaceEdit(
				{ documentChanges: [{ kind: "delete", uri: fileUri(dirPath) }] } as never,
				workspace,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.confineWrites": false,
					"permissions.deny.write": ["**/secret-link"],
				}),
			),
		).rejects.toThrow("**/secret-link");
		expect(fs.existsSync(dirPath)).toBe(true);
		expect(fs.lstatSync(linkPath).isSymbolicLink()).toBe(true);
	});

	it("refuses a directory delete whose descendant is individually denied, leaving the tree untouched", async () => {
		const dirPath = path.join(workspace, "pkg-apply-del");
		fs.mkdirSync(dirPath, { recursive: true });
		fs.writeFileSync(path.join(dirPath, "index.ts"), "export {};");
		fs.writeFileSync(path.join(dirPath, "protected.txt"), "secret");

		await expect(
			applyGuardedWorkspaceEdit(
				{ documentChanges: [{ kind: "delete", uri: fileUri(dirPath) }] } as never,
				workspace,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/protected.txt"] }),
			),
		).rejects.toThrow("**/protected.txt");
		expect(fs.existsSync(dirPath)).toBe(true);
		expect(fs.existsSync(path.join(dirPath, "protected.txt"))).toBe(true);
	});

	it("refuses overwrite rename when an existing destination descendant is individually denied", async () => {
		const source = path.join(workspace, "pkg-overwrite-source");
		const destination = path.join(workspace, "pkg-overwrite-destination");
		fs.mkdirSync(source, { recursive: true });
		fs.mkdirSync(destination, { recursive: true });
		fs.writeFileSync(path.join(source, "index.ts"), "SOURCE");
		const protectedDestination = path.join(destination, "protected.txt");
		fs.writeFileSync(protectedDestination, "DESTINATION");

		await expect(
			applyGuardedWorkspaceEdit(
				{
					documentChanges: [
						{
							kind: "rename",
							oldUri: fileUri(source),
							newUri: fileUri(destination),
							options: { overwrite: true },
						},
					],
				} as never,
				workspace,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/protected.txt"] }),
			),
		).rejects.toThrow("**/protected.txt");
		expect(fs.readFileSync(path.join(source, "index.ts"), "utf8")).toBe("SOURCE");
		expect(fs.readFileSync(protectedDestination, "utf8")).toBe("DESTINATION");
	});

	it("refuses overwrite rename before creating its denied displacement sibling", async () => {
		const source = path.join(workspace, "src", "overwrite-source.ts");
		const destination = path.join(workspace, "src", "overwrite-destination.ts");
		fs.writeFileSync(source, "SOURCE");
		fs.writeFileSync(destination, "DESTINATION");

		await expect(
			applyGuardedWorkspaceEdit(
				{
					documentChanges: [
						{
							kind: "rename",
							oldUri: fileUri(source),
							newUri: fileUri(destination),
							options: { overwrite: true },
						},
					],
				} as never,
				workspace,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/.omp-displaced-*"] }),
			),
		).rejects.toThrow("**/.omp-displaced-*");
		expect(fs.readFileSync(source, "utf8")).toBe("SOURCE");
		expect(fs.readFileSync(destination, "utf8")).toBe("DESTINATION");
	});

	it("reclaims an interrupted overwrite displacement before retrying the rename", async () => {
		const source = path.join(workspace, "src", "retry-source.ts");
		const destination = path.join(workspace, "src", "retry-destination.ts");
		const holdDir = path.join(path.dirname(destination), `.omp-displaced-${hashPath(destination)}`);
		fs.mkdirSync(holdDir, { recursive: true });
		fs.writeFileSync(source, "SOURCE");
		fs.writeFileSync(destination, "DESTINATION");

		await applyGuardedWorkspaceEdit(
			{
				documentChanges: [
					{
						kind: "rename",
						oldUri: fileUri(source),
						newUri: fileUri(destination),
						options: { overwrite: true },
					},
				],
			} as never,
			workspace,
			contextOf({ "permissions.profile": "workspace" }),
		);

		expect(fs.existsSync(source)).toBe(false);
		expect(fs.readFileSync(destination, "utf8")).toBe("SOURCE");
		expect(fs.existsSync(holdDir)).toBe(false);
	});
});

describe("lsp server-initiated workspace/applyEdit", () => {
	// `guardedApplyEditDenial` is the counterpart to `applyGuardedWorkspaceEdit`
	// above for the one write surface that has no `AgentToolContext`: a
	// language server pushing `workspace/applyEdit` unsolicited. It measures
	// against `LspClient.permissionContext` instead — the calling session's
	// settings and `workspace.additionalDirectories`, stamped onto the client.
	function fileUri(absolutePath: string): string {
		return `file://${absolutePath}`;
	}

	function clientWith(overrides: Record<string, unknown> | undefined, additionalDirectories?: string[]): LspClient {
		return {
			cwd: workspace,
			permissionContext: overrides && {
				settings: settingsOf(overrides),
				getAdditionalDirectories: () => additionalDirectories ?? [sibling],
			},
		} as unknown as LspClient;
	}

	it("permits every edit when the client has no recorded permission context, same as an absent-settings caller", async () => {
		const denial = await guardedApplyEditDenial(clientWith(undefined), {
			changes: { [fileUri(path.join(outside, "loot.txt"))]: [{ range: RANGE_ZERO, newText: "x" }] },
		} as never);
		expect(denial).toBeNull();
	});

	it("refuses a server-pushed edit to a secret path under the session's strict profile", async () => {
		const denial = await guardedApplyEditDenial(clientWith(STRICT), {
			changes: { [fileUri(path.join(workspace, ".env"))]: [{ range: RANGE_ZERO, newText: "LEAK=1" }] },
		} as never);
		expect(denial).toContain("**/.env");
	});

	it("refuses a server-chosen create target outside every workspace root", async () => {
		const denial = await guardedApplyEditDenial(clientWith(WORKSPACE), {
			documentChanges: [{ kind: "create", uri: fileUri(path.join(outside, "new.ts")) }],
		} as never);
		expect(denial).toContain("permissions.confineWrites");
	});

	it("refuses a server-pushed text edit the read side denies, even though nothing denies its write", async () => {
		const denial = await guardedApplyEditDenial(clientWith(WORKSPACE), {
			changes: { [fileUri(path.join(workspace, "src", "main.ts"))]: [{ range: RANGE_ZERO, newText: "x" }] },
		} as never);
		expect(denial).toBeNull();

		const denialWithReadDeny = await guardedApplyEditDenial(
			clientWith({ "permissions.profile": "workspace", "permissions.deny.read": ["**/main.ts"] }),
			{
				changes: { [fileUri(path.join(workspace, "src", "main.ts"))]: [{ range: RANGE_ZERO, newText: "x" }] },
			} as never,
		);
		expect(denialWithReadDeny).toContain("**/main.ts");
	});

	it("carries the session's live additionalDirectories, so an edit into an /add-dir root is not falsely denied", async () => {
		const denial = await guardedApplyEditDenial(clientWith(WORKSPACE, [sibling]), {
			documentChanges: [{ kind: "create", uri: fileUri(path.join(sibling, "new.md")) }],
		} as never);
		expect(denial).toBeNull();
	});

	it("re-reads additionalDirectories on every check, so a root removed by /remove-dir is denied without another tool call re-stamping the client", async () => {
		// `LspTool.permissionContext()` closes over the live session getter
		// instead of copying its result into an array, so a client stamped
		// while `sibling` was still an allowed root sees its removal on the
		// very next push — not just the next `getOrCreateClient` call.
		let allowedDirs = [sibling];
		const client = {
			cwd: workspace,
			permissionContext: { settings: settingsOf(WORKSPACE), getAdditionalDirectories: () => allowedDirs },
		} as unknown as LspClient;
		const edit = {
			documentChanges: [{ kind: "create", uri: fileUri(path.join(sibling, "new.md")) }],
		} as never;

		expect(await guardedApplyEditDenial(client, edit)).toBeNull();

		allowedDirs = [];
		expect(await guardedApplyEditDenial(client, edit)).toContain("permissions.confineWrites");
	});

	// The finding: a single "which pending request caused this push"
	// heuristic (oldest, newest, …) can always guess wrong when two sessions
	// with different policies share one client - a long-running permissive
	// request in flight must never let a push bypass a concurrent strict
	// session's policy just because it happened to be inserted first/last.
	it("denies a push any concurrently pending session's policy would deny, not just the oldest request's", async () => {
		const permissiveContext = { settings: settingsOf({}), getAdditionalDirectories: () => [] };
		const strictContext = { settings: settingsOf(STRICT), getAdditionalDirectories: () => [] };
		const client = {
			cwd: workspace,
			permissionContext: permissiveContext,
			pendingRequests: new Map([
				[1, { permissionContext: permissiveContext }],
				[2, { permissionContext: strictContext }],
			]),
		} as unknown as LspClient;

		const denial = await guardedApplyEditDenial(client, {
			changes: { [fileUri(path.join(workspace, ".env"))]: [{ range: RANGE_ZERO, newText: "LEAK=1" }] },
		} as never);
		expect(denial).toContain("**/.env");
	});
});
