import { afterEach, describe, expect, it, spyOn, vi } from "bun:test";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import * as dapModule from "@oh-my-pi/pi-coding-agent/dap";
import type { DapSessionSummary } from "@oh-my-pi/pi-coding-agent/dap/types";
import type { ReadonlySessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { DebugTool } from "@oh-my-pi/pi-coding-agent/tools/debug";

const CWD = "/tmp/omp-debug-redaction";
const DENIED_PATH = "/tmp/omp-debug-redaction/secret.js";

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.map(part => (part.type === "text" ? (part.text ?? "") : "")).join("\n");
}

function makeSession(): ToolSession {
	return {
		cwd: CWD,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "debug.enabled": true }),
	};
}

function makeContext(denyRead: string[]): AgentToolContext {
	const sessionManager = {
		getCwd: () => CWD,
		getAdditionalDirectories: () => [],
	} as unknown as ReadonlySessionManager;
	return {
		settings: Settings.isolated({
			"permissions.profile": "workspace",
			"permissions.deny.read": denyRead,
		}),
		sessionManager,
	} as unknown as AgentToolContext;
}

function makeSnapshot(overrides: Partial<DapSessionSummary> = {}): DapSessionSummary {
	return {
		id: "sess-1",
		adapter: "js-debug-adapter",
		cwd: CWD,
		status: "stopped",
		launchedAt: "2026-01-01T00:00:00.000Z",
		lastUsedAt: "2026-01-01T00:00:00.000Z",
		program: DENIED_PATH,
		source: { path: DENIED_PATH, name: "secret.js" },
		line: 3,
		column: 1,
		breakpointFiles: 0,
		breakpointCount: 0,
		functionBreakpointCount: 0,
		outputBytes: 0,
		outputTruncated: false,
		needsConfigurationDone: false,
		...overrides,
	};
}

afterEach(() => {
	vi.restoreAllMocks();
});

describe("debug tool DAP path redaction", () => {
	it("redacts a denied stack frame source path while preserving the frame id and name", async () => {
		spyOn(dapModule.dapSessionManager, "stackTrace").mockResolvedValue({
			snapshot: makeSnapshot(),
			stackFrames: [{ id: 70, name: "main", line: 3, column: 1, source: { path: DENIED_PATH, name: "secret.js" } }],
		});
		const tool = new DebugTool(makeSession());

		const denied = await tool.execute(
			"call-1",
			{ action: "stack_trace" },
			undefined,
			undefined,
			makeContext([DENIED_PATH]),
		);
		const deniedText = textOf(denied);
		expect(deniedText).not.toContain(DENIED_PATH);
		expect(deniedText).toContain("#70 main");
		expect(deniedText).toContain("blocked by permissions.deny.read");
		expect(denied.details?.stackFrames?.[0]?.source?.path).not.toBe(DENIED_PATH);

		const allowed = await tool.execute("call-2", { action: "stack_trace" }, undefined, undefined, makeContext([]));
		expect(textOf(allowed)).toContain(DENIED_PATH);
	});

	it("redacts a denied module path while preserving module id and name", async () => {
		spyOn(dapModule.dapSessionManager, "getActiveSession").mockReturnValue(makeSnapshot());
		spyOn(dapModule.dapSessionManager, "getCapabilities").mockReturnValue({ supportsModulesRequest: true });
		spyOn(dapModule.dapSessionManager, "modules").mockResolvedValue({
			snapshot: makeSnapshot(),
			modules: [{ id: 1, name: "core", path: DENIED_PATH }],
		});
		const tool = new DebugTool(makeSession());

		const denied = await tool.execute(
			"call-1",
			{ action: "modules" },
			undefined,
			undefined,
			makeContext([DENIED_PATH]),
		);
		const deniedText = textOf(denied);
		expect(deniedText).not.toContain(DENIED_PATH);
		expect(deniedText).toContain("core");
		expect(denied.details?.modules?.[0]?.path).not.toBe(DENIED_PATH);

		const allowed = await tool.execute("call-2", { action: "modules" }, undefined, undefined, makeContext([]));
		expect(textOf(allowed)).toContain(DENIED_PATH);
	});

	it("redacts a denied loaded source path", async () => {
		spyOn(dapModule.dapSessionManager, "getActiveSession").mockReturnValue(makeSnapshot());
		spyOn(dapModule.dapSessionManager, "getCapabilities").mockReturnValue({ supportsLoadedSourcesRequest: true });
		spyOn(dapModule.dapSessionManager, "loadedSources").mockResolvedValue({
			snapshot: makeSnapshot(),
			sources: [{ path: DENIED_PATH, name: "secret.js" }],
		});
		const tool = new DebugTool(makeSession());

		const denied = await tool.execute(
			"call-1",
			{ action: "loaded_sources" },
			undefined,
			undefined,
			makeContext([DENIED_PATH]),
		);
		const deniedText = textOf(denied);
		expect(deniedText).not.toContain(DENIED_PATH);
		expect(deniedText).toContain("blocked by permissions.deny.read");
		expect(denied.details?.sources?.[0]?.path).not.toBe(DENIED_PATH);
		expect(denied.details?.sources?.[0]?.name).toBe("secret.js");

		const allowed = await tool.execute("call-2", { action: "loaded_sources" }, undefined, undefined, makeContext([]));
		expect(textOf(allowed)).toContain(DENIED_PATH);
	});

	it("redacts denied paths across listed sessions", async () => {
		spyOn(dapModule.dapSessionManager, "listSessions").mockReturnValue([makeSnapshot()]);
		const tool = new DebugTool(makeSession());

		const denied = await tool.execute(
			"call-1",
			{ action: "sessions" },
			undefined,
			undefined,
			makeContext([DENIED_PATH]),
		);
		const deniedText = textOf(denied);
		expect(deniedText).not.toContain(DENIED_PATH);
		expect(deniedText).toContain("sess-1");
		expect(denied.details?.sessions?.[0]?.program).not.toBe(DENIED_PATH);

		const allowed = await tool.execute("call-2", { action: "sessions" }, undefined, undefined, makeContext([]));
		expect(textOf(allowed)).toContain(DENIED_PATH);
	});

	it("redacts a denied stop location for an action never named in the review (pause) — the shared snapshot boundary", async () => {
		spyOn(dapModule.dapSessionManager, "pause").mockResolvedValue(makeSnapshot());
		const tool = new DebugTool(makeSession());

		const denied = await tool.execute(
			"call-1",
			{ action: "pause" },
			undefined,
			undefined,
			makeContext([DENIED_PATH]),
		);
		const deniedText = textOf(denied);
		expect(deniedText).not.toContain(DENIED_PATH);
		expect(denied.details?.snapshot?.program).not.toBe(DENIED_PATH);

		const allowed = await tool.execute("call-2", { action: "pause" }, undefined, undefined, makeContext([]));
		expect(textOf(allowed)).toContain(DENIED_PATH);
	});
});
