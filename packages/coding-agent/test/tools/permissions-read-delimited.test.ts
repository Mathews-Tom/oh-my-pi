import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import type { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { Settings as RealSettings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ReadonlySessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { ReadTool } from "@oh-my-pi/pi-coding-agent/tools/read";

/**
 * `read` accepts several paths flattened into one string and splits them at
 * execution time, then reads each part by re-entering its own `execute` rather
 * than the wrapper. The permission gate only ever saw the combined literal,
 * which matches no secret glob, so a denied component used to be read anyway.
 */
describe("read delimited-path permission gate", () => {
	let testDir: string;

	function contextOf(overrides: Record<string, unknown>): AgentToolContext {
		const sessionManager = {
			getCwd: () => testDir,
			getAdditionalDirectories: () => [],
			getSessionId: () => "test-session",
		} as unknown as ReadonlySessionManager;
		const settings = {
			get: (key: string): unknown => (Object.hasOwn(overrides, key) ? overrides[key] : undefined),
		} as unknown as Settings;
		return { sessionManager, settings } as unknown as AgentToolContext;
	}

	function makeTool(): ReadTool {
		return new ReadTool({
			cwd: testDir,
			hasUI: false,
			getSessionFile: () => path.join(testDir, "session.jsonl"),
			getSessionSpawns: () => "*",
			getArtifactsDir: () => path.join(testDir, "session"),
			settings: RealSettings.isolated(),
		} as ToolSession);
	}

	beforeEach(async () => {
		testDir = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "omp-read-delim-")));
		await Bun.write(path.join(testDir, "README.md"), "# readme\n");
		await Bun.write(path.join(testDir, ".env"), "SECRET=1\n");
	});

	afterEach(async () => {
		await fs.rm(testDir, { recursive: true, force: true });
	});

	it("denies a delimited read whose second component is a denied secret", async () => {
		const tool = makeTool();
		await expect(
			tool.execute(
				"call-1",
				{ path: "README.md;.env" },
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "strict",
				}),
			),
		).rejects.toThrow("**/.env");
	});

	it("still reads a delimited pair whose components are both permitted", async () => {
		await Bun.write(path.join(testDir, "NOTES.md"), "# notes\n");
		const tool = makeTool();
		const result = await tool.execute(
			"call-2",
			{ path: "README.md;NOTES.md" },
			undefined,
			undefined,
			contextOf({ "permissions.profile": "strict" }),
		);
		const text = result.content
			.filter(block => block.type === "text")
			.map(block => (block as { text: string }).text)
			.join("\n");
		expect(text).toContain("interpreted as 2 paths");
	});

	it("leaves delimited reads alone when no profile is active", async () => {
		const tool = makeTool();
		const result = await tool.execute("call-3", { path: "README.md;.env" }, undefined, undefined, contextOf({}));
		expect(result.content.length).toBeGreaterThan(0);
	});
});
