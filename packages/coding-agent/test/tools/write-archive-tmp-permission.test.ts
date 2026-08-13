import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { WriteTool } from "@oh-my-pi/pi-coding-agent/tools/write";
import { writeArchive } from "@oh-my-pi/pi-coding-agent/utils/zip";

// `write` authorizes the archive's own path before `#writeArchiveEntry` runs,
// but the whole-archive rewrite actually lands its bytes at
// `${finalPath}.tmp-${process.pid}` and renames that sibling over the archive.
// An exact `permissions.allow.write` entry scoped to the archive path does not
// cover that distinct sibling path, so it must clear the resource gate on its
// own rather than silently inheriting the archive's grant (finding under
// review).

let temporaryRoot = "";
let workspace: string;
let outsideDir: string;
let archivePath: string;

beforeEach(async () => {
	// Resolve through macOS's `/var` -> `/private/var` symlink up front so the
	// path this test authorizes matches the realpath-resolved spelling
	// `#writeArchiveEntry` re-derives before writing the tmp sibling.
	temporaryRoot = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "omp-write-archive-tmp-gate-")));
	workspace = path.join(temporaryRoot, "ws");
	outsideDir = path.join(temporaryRoot, "outside");
	await fs.mkdir(workspace, { recursive: true });
	await fs.mkdir(outsideDir, { recursive: true });
	archivePath = path.join(outsideDir, "bundle.zip");
	await writeArchive(archivePath, "zip", [["existing.txt", "old\n"]]);
});

afterEach(async () => {
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function session(): ToolSession {
	return {
		cwd: workspace,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({}),
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

describe("write authorizes an archive rewrite's temporary sibling", () => {
	test("refuses the rewrite when only the archive's exact path is allowed, not its .tmp sibling", async () => {
		const tool = new WriteTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ path: `${archivePath}:new.txt`, content: "hi" } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace", "permissions.allow.write": [archivePath] }),
			),
		).rejects.toThrow(/permissions\.confineWrites/);

		// The archive itself must be untouched — the tmp write never happened,
		// so the rename that would clobber it never ran either.
		expect(await Bun.file(archivePath).text()).not.toBe("");
	});

	test("still rewrites the archive when the allow rule covers the tmp sibling too", async () => {
		const tool = new WriteTool(session());
		const result = await tool.execute(
			"call-1",
			{ path: `${archivePath}:new.txt`, content: "hi" } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "workspace", "permissions.allow.write": [`${archivePath}*`] }),
		);
		expect(result.isError).toBeUndefined();
	});
});
