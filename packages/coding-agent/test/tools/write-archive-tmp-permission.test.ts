import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { WriteTool } from "@oh-my-pi/pi-coding-agent/tools/write";
import { type ArchiveMemberContent, readArchiveEntries, writeArchive } from "@oh-my-pi/pi-coding-agent/utils/zip";

/** `readArchiveEntries` returns member bytes as `string | Uint8Array | Blob`,
 * regardless of which of those an entry was originally written as; decode to
 * text so assertions can compare against the plain strings the fixtures were
 * written with. */
async function decodeMember(content: ArchiveMemberContent): Promise<string> {
	if (typeof content === "string") return content;
	if (content instanceof Blob) return content.text();
	return new TextDecoder().decode(content);
}

async function readEntryTexts(archivePath: string): Promise<Record<string, string>> {
	const entries = await readArchiveEntries({ path: archivePath, format: "zip" });
	const out: Record<string, string> = {};
	for (const [name, content] of entries) {
		out[name] = await decodeMember(content);
	}
	return out;
}

// `write` authorizes the archive's own path before `#writeArchiveEntry` runs,
// but the whole-archive rewrite actually reads and rewrites `finalPath` — the
// archive path after `fs.realpath` resolves any symlink — and lands its bytes
// at `${finalPath}.tmp-${process.pid}` before renaming that sibling over
// `finalPath`. An exact `permissions.allow.write` entry scoped only to the
// archive's pre-realpath spelling covers neither the distinct tmp sibling nor
// (when the archive is a symlink) the real target `readArchiveEntries` and
// `fs.rename` actually touch, so both must clear the resource gate on their
// own rather than silently inheriting the archive's grant (finding under
// review).

let temporaryRoot = "";
let workspace: string;
let outsideDir: string;
let archivePath: string;
let archiveBytesBefore: Uint8Array<ArrayBuffer>;

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
	archiveBytesBefore = await Bun.file(archivePath).bytes();
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

		// The archive itself must be untouched, byte-for-byte: the tmp write
		// never happened, so the rename that would clobber it never ran either.
		expect(await Bun.file(archivePath).bytes()).toEqual(archiveBytesBefore);
		expect(await readEntryTexts(archivePath)).toEqual({ "existing.txt": "old\n" });
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
		expect(await readEntryTexts(archivePath)).toEqual({ "existing.txt": "old\n", "new.txt": "hi" });
	});
});

describe("write authorizes the realpath-resolved archive an allowed symlink points at", () => {
	let targetArchivePath: string;
	let targetBytesBefore: Uint8Array<ArrayBuffer>;

	beforeEach(async () => {
		// `archivePath` (already granted above) is a symlink; the archive bytes
		// `readArchiveEntries` reads and `fs.rename` overwrites live at
		// `targetArchivePath`, which sits in a directory the caller was never
		// granted access to. Authorizing only the symlink spelling — plus its
		// own `.tmp-*` sibling, which is irrelevant once `finalPath` diverges —
		// must not be enough to read or clobber the real target.
		const targetDir = path.join(temporaryRoot, "target");
		await fs.mkdir(targetDir, { recursive: true });
		targetArchivePath = path.join(targetDir, "real.zip");
		await writeArchive(targetArchivePath, "zip", [["secret.txt", "protected\n"]]);
		await fs.unlink(archivePath);
		await fs.symlink(targetArchivePath, archivePath);
		targetBytesBefore = await Bun.file(targetArchivePath).bytes();
	});

	test("refuses the rewrite when only the symlink spelling and its own .tmp sibling are allowed", async () => {
		const tool = new WriteTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ path: `${archivePath}:new.txt`, content: "hi" } as never,
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.allow.write": [archivePath, `${archivePath}.tmp-*`],
				}),
			),
		).rejects.toThrow(/permissions\.confineWrites/);

		// The real target the symlink points at must be untouched, byte-for-byte.
		expect(await Bun.file(targetArchivePath).bytes()).toEqual(targetBytesBefore);
		expect(await readEntryTexts(targetArchivePath)).toEqual({ "secret.txt": "protected\n" });
	});

	test("still rewrites the archive when the allow rule covers the realpath-resolved target too", async () => {
		const tool = new WriteTool(session());
		const result = await tool.execute(
			"call-1",
			{ path: `${archivePath}:new.txt`, content: "hi" } as never,
			undefined,
			undefined,
			contextOf({
				"permissions.profile": "workspace",
				"permissions.allow.write": [archivePath, `${targetArchivePath}*`],
			}),
		);
		expect(result.isError).toBeUndefined();
		expect(await readEntryTexts(targetArchivePath)).toEqual({ "secret.txt": "protected\n", "new.txt": "hi" });
	});
});
