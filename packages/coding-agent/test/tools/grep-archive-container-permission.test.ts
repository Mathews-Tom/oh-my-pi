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
			// The scratch write always stages through `tmpdir()` itself, which sits
			// above (not under) the workspace root, so `confineWrites` is relaxed
			// here to isolate this test's actual point — the container read gate —
			// from the separate write gate exercised below.
			contextOf({ "permissions.profile": "workspace", "permissions.confineWrites": false }),
		);
		expect(result.isError).toBeUndefined();
	});
});

// `resolveArchiveSearchPaths` authorized the archive's container read but never
// authorized the scratch directory (`tmpdir()`) or the extracted member file it
// creates and writes before `resolveArchiveSearchPaths` returns — so a confining
// `workspace`/`strict` profile, or an explicit `permissions.deny.write` rule,
// could not block the write side at all (finding under review).
describe("grep authorizes the archive scratch write before creating or writing it", () => {
	test("refuses an archive member selector whose scratch write falls outside the workspace under a confining profile", async () => {
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace" }),
			),
		).rejects.toThrow(/permissions\.confineWrites/);
	});

	test("does not leave a scratch directory behind after refusing", async () => {
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		const tmpEntriesBefore = await fs.readdir(os.tmpdir());

		await expect(
			tool.execute(
				"call-1",
				{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace" }),
			),
		).rejects.toThrow();

		const tmpEntriesAfter = await fs.readdir(os.tmpdir());
		const leaked = tmpEntriesAfter
			.filter(name => !tmpEntriesBefore.includes(name))
			.filter(name => name.startsWith("omp-search-archive-"));
		expect(leaked).toEqual([]);
	});

	test("refuses an archive member selector when permissions.deny.write denies the scratch destination", async () => {
		// `confineWrites: false` isolates this from the confinement denial the
		// previous test exercises, so this proves `deny.write` alone is
		// consulted too, not just workspace containment.
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.confineWrites": false,
					"permissions.deny.write": [path.join(os.tmpdir(), "**")],
				}),
			),
		).rejects.toThrow(/resource permission rule/);
	});

	test("still searches an archive member selector when the scratch write is explicitly allowed", async () => {
		settings = Settings.isolated({});
		const tool = new GrepTool(session());
		const result = await tool.execute(
			"call-1",
			{ pattern: "needle", path: "bundle.zip:member.txt" } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "workspace", "permissions.allow.write": ["**"] }),
		);
		expect(result.isError).toBeUndefined();
	});
});
