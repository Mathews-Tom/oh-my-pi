import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import type { Settings } from "../../src/config/settings";
import type { ReadonlySessionManager } from "../../src/session/session-manager";
import type { ToolSession } from "../../src/tools";
import { GlobTool } from "../../src/tools/glob";

let workspace: string;

function settingsOf(overrides: Record<string, unknown>): Settings {
	return {
		get(key: string): unknown {
			return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
		},
	} as unknown as Settings;
}

function contextOf(overrides: Record<string, unknown>): AgentToolContext {
	const sessionManager = {
		getCwd: () => workspace,
		getAdditionalDirectories: () => [],
		getSessionId: () => "test-session",
	} as unknown as ReadonlySessionManager;
	return { sessionManager, settings: settingsOf(overrides) } as unknown as AgentToolContext;
}

function sessionOf(): ToolSession {
	return {
		cwd: workspace,
		hasUI: false,
		settings: settingsOf({}),
		getSessionFile: () => null,
		getSessionSpawns: () => null,
	} as unknown as ToolSession;
}

beforeAll(() => {
	workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-glob-perm-")));
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export {};");
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
});

afterAll(() => {
	fs.rmSync(workspace, { recursive: true, force: true });
});

describe("GlobTool resource permissions", () => {
	// `glob` accepts a scope root but recurses beneath it, so the declared
	// `path` argument alone cannot make the pre-execution gate see individual
	// results — the tool itself must filter what it returns.
	test("excludes a denied file from a recursive listing under strict", async () => {
		const tool = new GlobTool(sessionOf());
		const result = await tool.execute(
			"glob-perm-1",
			{ path: "." },
			undefined,
			undefined,
			contextOf({
				"permissions.profile": "strict",
			}),
		);
		const text = result.content.map(part => ("text" in part ? part.text : "")).join("\n");
		expect(text).not.toContain(".env");
		expect(text).toContain("main.ts");
		expect(result.details?.files).not.toContain(".env");
	});

	test("keeps the denied file visible under permissions.profile: off", async () => {
		const tool = new GlobTool(sessionOf());
		const result = await tool.execute(
			"glob-perm-2",
			{ path: "." },
			undefined,
			undefined,
			contextOf({
				"permissions.profile": "off",
			}),
		);
		expect(result.details?.files).toContain(".env");
	});
});
