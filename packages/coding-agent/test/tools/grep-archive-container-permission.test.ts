import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { GrepTool } from "@oh-my-pi/pi-coding-agent/tools/grep";
import { writeArchive } from "@oh-my-pi/pi-coding-agent/utils/zip";

// `grep({ path: "bundle.zip:member.txt" })` reaches the pre-execution
// structural gate as one selector-bearing string, which a container-only
// rule like `deny.read: ["**/bundle.zip"]` does not match. Before
// `resolveArchiveSearchPaths` authorized the resolved container path, that
// selector spelling bypassed the rule entirely and the archive was opened
// and its member materialized regardless (finding under review).

let temporaryRoot = "";
let workspace: string;
let archivePath: string;
let settings: Settings;

beforeEach(async () => {
	temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-grep-archive-gate-"));
	workspace = path.join(temporaryRoot, "ws");
	await fs.mkdir(workspace, { recursive: true });
	archivePath = path.join(workspace, "bundle.zip");
	await writeArchive(archivePath, "zip", [["member.txt", "needle inside the archive\n"]]);
});

afterEach(async () => {
	settings.cancelPendingSaves();
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function session(): ToolSession {
	return {
		cwd: workspace,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings,
	} as ToolSession;
}

function contextOf(overrides: Record<string, unknown>): AgentToolContext {
	return {
		sessionManager: {
			getCwd: () => workspace,
			getAdditionalDirectories: () => [],
			getSessionId: () => "test-session",
		},
		settings: Settings.isolated(overrides),
	} as unknown as AgentToolContext;
}

describe("grep authorizes an archive's container path before opening it", () => {
	test("refuses an archive member selector when the container is denied", async () => {
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace", "permissions.deny.read": ["**/bundle.zip"] }),
			),
		).rejects.toThrow("**/bundle.zip");
	});

	test("still searches an archive member selector when nothing denies it", async () => {
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		const result = await tool.execute(
			"call-1",
			{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "workspace" }),
		);
		expect(result.isError).toBeUndefined();
	});
});
