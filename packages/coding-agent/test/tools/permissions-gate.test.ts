import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentTool, AgentToolContext, AgentToolResult } from "@oh-my-pi/pi-agent-core";
import type { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { ExtensionToolWrapper } from "@oh-my-pi/pi-coding-agent/extensibility/extensions";
import type { ExtensionRunner } from "@oh-my-pi/pi-coding-agent/extensibility/extensions/runner";
import type { ReadonlySessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";

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

/** Like {@link recordingTool}, but the execution result carries caller-supplied `details` — used to simulate a recursive search/edit tool reporting the files it actually touched. */
function recordingToolWithDetails(name: string, details: unknown): Recorder {
	const calls: unknown[] = [];
	const tool = {
		name,
		description: name,
		parameters: {},
		label: name,
		strict: false,
		execute: async (_id: string, params: unknown): Promise<AgentToolResult> => {
			calls.push(params);
			return { content: [{ type: "text", text: "ok" }], details };
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

	it("denies updating an existing file under a deny.read rule with no matching deny.write rule", async () => {
		// `edit`'s update/delete ops read the target's current content to
		// compute the diff and surface it in the result - a `deny.read`-only
		// rule must still block them, even though nothing denies `write`.
		const context = contextOf({ ...WORKSPACE, "permissions.deny.read": ["**/private.ts"] });
		const message = await denialOf(
			"edit",
			{ path: "src/private.ts", edits: [{ old_text: "a", new_text: "b" }] },
			context,
		);
		expect(message).toContain('resource permission rule "**/private.ts"');
	});

	it("still allows a pure create under a deny.read rule with no matching deny.write rule", async () => {
		// An `op: "create"` edit never reads pre-existing content - it should
		// clear a read-only deny rule that a same-named update would not.
		const context = contextOf({ ...WORKSPACE, "permissions.deny.read": ["**/private.ts"] });
		expect(
			(await run("edit", { path: "src/private.ts", edits: [{ op: "create", diff: "+new" }] }, context)).calls,
		).toHaveLength(1);
	});

	it("still runs ordinary workspace calls", async () => {
		expect((await run("read", { path: "src/main.ts" }, contextOf(STRICT))).calls).toHaveLength(1);
	});

	it("leaves internal URLs reachable", async () => {
		for (const url of ["local://plan.md", "memory://root/x", "xd://browser"]) {
			expect((await run("read", { path: url }, contextOf(STRICT))).calls).toHaveLength(1);
		}
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

	it("permits a write into an additional workspace root", async () => {
		const calls = (await run("write", { path: path.join(sibling, "new.md") }, contextOf(WORKSPACE))).calls;
		expect(calls).toHaveLength(1);
	});

	it("leaves reads unconfined", async () => {
		expect((await run("read", { path: "/etc/hosts" }, contextOf(WORKSPACE))).calls).toHaveLength(1);
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

	it("denies the real target behind a JSON-encoded path list, not the literal composite string", async () => {
		// `grep`/`ast_grep`/`ast_edit` accept `path` as a JSON-encoded string
		// array (`toPathList` in `path-utils.ts`); authorizing the raw
		// `'[".env"]'` string instead of the `.env` it expands to would let a
		// denied file through under a spelling the deny glob never matches.
		expect(await denialOf("grep", { pattern: "KEY", path: '[".env"]' }, contextOf(STRICT))).toContain("**/.env");
		expect(await denialOf("glob", { path: '[".env"]' }, contextOf(STRICT))).toContain("**/.env");
	});

	it("denies the real target behind an outer-quoted path, which execution strips", async () => {
		expect(await denialOf("grep", { pattern: "KEY", path: '".env"' }, contextOf(STRICT))).toContain("**/.env");
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

describe("post-execution recheck for recursive tools", () => {
	// `grep`/`ast_grep`/`ast_edit` recurse beneath their declared scope root, so
	// the pre-execution gate only ever sees that root. This recheck evaluates
	// the files the tool actually reports it touched (`result.details.files`)
	// after execution, before the result reaches the caller.
	it("denies a grep result whose reported files include a path the declared scope never named", async () => {
		const recorder = recordingToolWithDetails("grep", { files: [".env"] });
		const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
		let message: string | undefined;
		try {
			await wrapper.execute(
				"call-1",
				{ pattern: "SECRET", path: ".", gitignore: false } as never,
				undefined,
				undefined,
				contextOf(STRICT),
			);
		} catch (err) {
			message = err instanceof Error ? err.message : String(err);
		}
		// The tool DID run — it already read `.env` locally — the gate's job is
		// keeping that result from reaching the caller, not preventing the call.
		expect(recorder.calls).toHaveLength(1);
		expect(message).toContain("**/.env");
	});

	it("denies an ast_edit result whose reported files include a denied write target", async () => {
		const recorder = recordingToolWithDetails("ast_edit", { files: [".env"] });
		const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
		let message: string | undefined;
		try {
			await wrapper.execute(
				"call-1",
				{ paths: ["."], pat: "$A", out: "$A" } as never,
				undefined,
				undefined,
				contextOf(STRICT),
			);
		} catch (err) {
			message = err instanceof Error ? err.message : String(err);
		}
		expect(recorder.calls).toHaveLength(1);
		expect(message).toContain("**/.env");
	});

	it("permits a recursive-tool result whose reported files are all in bounds", async () => {
		const recorder = recordingToolWithDetails("grep", { files: ["src/main.ts"] });
		const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
		await wrapper.execute("call-1", { pattern: "x", path: "src" } as never, undefined, undefined, contextOf(STRICT));
		expect(recorder.calls).toHaveLength(1);
	});

	it("does not recheck a tool with no resultTargets extractor", async () => {
		const recorder = recordingToolWithDetails("read", { files: [".env"] });
		const wrapper = new ExtensionToolWrapper(recorder.tool, runner);
		await wrapper.execute("call-1", { path: "src/main.ts" } as never, undefined, undefined, contextOf(STRICT));
		expect(recorder.calls).toHaveLength(1);
	});
});

describe("debug action-aware classification", () => {
	// `launch`/`attach`/`evaluate`/`write_memory`/`custom_request` reach
	// arbitrary execution beyond the declared `program`/`file`/`cwd` fields, so
	// they get the opaque literal scan instead of a false sense of structured
	// soundness (see `DEBUG_OPAQUE_ACTIONS`, `tool-path-targets.ts`).
	it("denies a launch whose args reference a denied path the declared program field never named", async () => {
		const message = await denialOf(
			"debug",
			{ action: "launch", program: "/bin/sh", args: ["-c", "cat .env"] },
			contextOf(STRICT),
		);
		expect(message).toContain("**/.env");
	});

	it("denies an evaluate expression referencing a denied path", async () => {
		const message = await denialOf(
			"debug",
			{ action: "evaluate", expression: "system('cat .env')" },
			contextOf(STRICT),
		);
		expect(message).toContain("**/.env");
	});

	it("still enforces the declared file field for a structured (breakpoint) action", async () => {
		const message = await denialOf("debug", { action: "set_breakpoint", file: ".env" }, contextOf(STRICT));
		expect(message).toContain("**/.env");
	});

	it("lets an ordinary launch through", async () => {
		const params = { action: "launch", program: "./my_app", args: ["--flag"] };
		expect((await run("debug", params, contextOf(STRICT))).calls).toHaveLength(1);
	});
});

describe("confinement cannot be bypassed by a built-in allow glob", () => {
	// The `.env.example`/`.env.sample` allow carve-out exists to override the
	// secret deny-by-name rule, not to also bypass workspace confinement.
	it("still confines a write matching the .env.example allow glob", async () => {
		const message = await denialOf("write", { path: path.join(outside, ".env.example") }, contextOf(STRICT));
		expect(message).toContain("permissions.confineWrites");
	});

	it("still permits the same allow glob inside the workspace", async () => {
		expect((await run("write", { path: "svc/.env.example" }, contextOf(STRICT))).calls).toHaveLength(1);
	});
});

describe("headless recovery guidance", () => {
	it("offers permission-specific recovery options for a permission-layer prompt, not the approval-tier ones", async () => {
		const context = contextOf({ ...STRICT, "permissions.opaqueToolScan": "prompt" });
		const message = await denialOf("bash", { command: "cat .env" }, context);
		expect(message).toContain("permissions.allow.read");
		expect(message).toContain("permissions.opaqueToolScan");
		expect(message).not.toContain("tools.approvalMode: yolo");
		expect(message).not.toContain("tools.approval.bash: allow");
	});

	it("keeps the approval-tier options for an ordinary tools.approval prompt with no permission layer involved", async () => {
		const context = contextOf({ "permissions.profile": "off", "tools.approval": { read: "prompt" } });
		const message = await denialOf("read", { path: "src/main.ts" }, context);
		expect(message).toContain("tools.approvalMode: yolo");
		expect(message).toContain("tools.approval.read: allow");
	});
});

describe("malformed glob patterns fail closed at settings load", () => {
	it("throws a clear error naming the setting instead of silently matching nothing", async () => {
		const context = contextOf({ "permissions.profile": "strict", "permissions.deny.read": ["[a-"] });
		await expect(run("read", { path: "src/main.ts" }, context)).rejects.toThrow(/invalid glob pattern/);
	});

	it("does not affect a policy with only well-formed patterns", async () => {
		const context = contextOf({ "permissions.profile": "strict", "permissions.deny.read": ["**/*.secret"] });
		expect((await run("read", { path: "src/main.ts" }, context)).calls).toHaveLength(1);
	});
});
