import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { ReadTool } from "@oh-my-pi/pi-coding-agent/tools/read";
import * as markit from "@oh-my-pi/pi-coding-agent/utils/markit";
import { removeSyncWithRetries, Snowflake } from "@oh-my-pi/pi-utils";

// PDF image extraction (`read-pdf-images.ts`) only had its PDF *source* read
// gated by the caller (`read.ts`'s `enforceResourcePathTargets("read", ...)`
// on the pdf path itself) — the tool's own context never reached
// `readPdfImageMember`, so the snapshot it copies the pdf bytes into (an
// `os.tmpdir()` scratch directory) and the cache directory it extracts images
// and writes a `.extracted` marker into (a session-artifacts sibling, or
// `os.tmpdir()/omp-read-pdf-images` when there is no session file) were never
// authorized at all. Fixed by threading the context through and authorizing
// each destination before it is created or written (finding under review).

const TINY_PNG = Buffer.from(
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
	"base64",
);

function mockExtraction() {
	return vi.spyOn(markit, "convertFileWithMarkit").mockImplementation(async (_filePath, _signal, options) => {
		if (options?.imageDir) {
			fs.mkdirSync(options.imageDir, { recursive: true });
			fs.writeFileSync(path.join(options.imageDir, "p11-img0.png"), TINY_PNG);
		}
		return { ok: true, content: "" };
	});
}

let testDir: string;
let pdfPath: string;

beforeEach(() => {
	testDir = path.join(os.tmpdir(), `read-pdf-img-gate-${Snowflake.next()}`);
	fs.mkdirSync(testDir, { recursive: true });
	pdfPath = path.join(testDir, "doc.pdf");
	fs.writeFileSync(pdfPath, "%PDF-stub");
});

afterEach(() => {
	vi.restoreAllMocks();
	removeSyncWithRetries(testDir);
});

/** No session file — `pdfImageCacheDir` falls back to `os.tmpdir()/omp-read-pdf-images`, outside `testDir`. */
function ephemeralSession(): ToolSession {
	return {
		cwd: testDir,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({ "images.autoResize": false }),
	} as unknown as ToolSession;
}

function contextOf(overrides: Record<string, unknown>): AgentToolContext {
	return {
		sessionManager: {
			getCwd: () => testDir,
			getAdditionalDirectories: () => [],
			getSessionId: () => "test-session",
		},
		settings: Settings.isolated(overrides),
	} as unknown as AgentToolContext;
}

describe("read authorizes PDF image extraction's write destinations", () => {
	it("refuses extraction whose cache directory falls outside the workspace under a confining profile", async () => {
		mockExtraction();
		const tool = new ReadTool(ephemeralSession());

		await expect(
			tool.execute(
				"call-1",
				{ path: `${pdfPath}:p11-img0.png` } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace" }),
			),
		).rejects.toThrow(/permissions\.confineWrites/);
	});

	it("does not leave a snapshot or cache directory behind after refusing", async () => {
		mockExtraction();
		const tool = new ReadTool(ephemeralSession());
		const tmpEntriesBefore = fs.readdirSync(os.tmpdir());

		await expect(
			tool.execute(
				"call-1",
				{ path: `${pdfPath}:p11-img0.png` } as never,
				undefined,
				undefined,
				contextOf({ "permissions.profile": "workspace" }),
			),
		).rejects.toThrow();

		const leaked = fs
			.readdirSync(os.tmpdir())
			.filter(name => !tmpEntriesBefore.includes(name))
			.filter(name => name.startsWith("omp-read-pdf-"));
		expect(leaked).toEqual([]);
	});

	it("does not merely block every extraction — an explicit allow rule still lets it through", async () => {
		mockExtraction();
		const tool = new ReadTool(ephemeralSession());

		const result = await tool.execute(
			"call-1",
			{ path: `${pdfPath}:p11-img0.png` } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "workspace", "permissions.allow.write": ["**"] }),
		);

		expect(result.content.some(content => content.type === "image")).toBe(true);
	});

	it("leaves extraction unaffected when the permission profile is off (the default)", async () => {
		mockExtraction();
		const tool = new ReadTool(ephemeralSession());

		const result = await tool.execute(
			"call-1",
			{ path: `${pdfPath}:p11-img0.png` } as never,
			undefined,
			undefined,
			contextOf({}),
		);

		expect(result.content.some(content => content.type === "image")).toBe(true);
	});

	it("refuses extraction whose snapshot directory matches an explicit deny.write rule", async () => {
		// `confineWrites: false` isolates this from the confinement denial the
		// other tests exercise, so this proves `deny.write` alone is consulted
		// too, not just containment.
		mockExtraction();
		const tool = new ReadTool(ephemeralSession());

		await expect(
			tool.execute(
				"call-1",
				{ path: `${pdfPath}:p11-img0.png` } as never,
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

	it("does not additionally block extraction just because the cache directory resolves inside the workspace", async () => {
		// The persistent cache directory (`imageDir`) sits beside the session
		// file when one exists, so it can legitimately land inside the
		// workspace — but the snapshot step always stages through `os.tmpdir()`
		// regardless, so this still needs `confineWrites` relaxed (or an allow
		// rule covering system temp) under a confining profile. The point of
		// this test is that having `imageDir` land inside the workspace doesn't
		// impose some *additional* restriction on top of that.
		const sessionFile = path.join(testDir, "session.jsonl");
		const session = {
			cwd: testDir,
			hasUI: false,
			getSessionFile: () => sessionFile,
			getArtifactsDir: () => sessionFile.slice(0, -6),
			getSessionSpawns: () => "*",
			settings: Settings.isolated({ "images.autoResize": false }),
		} as unknown as ToolSession;
		mockExtraction();
		const tool = new ReadTool(session);

		const result = await tool.execute(
			"call-1",
			{ path: `${pdfPath}:p11-img0.png` } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "strict", "permissions.confineWrites": false }),
		);

		expect(result.content.some(content => content.type === "image")).toBe(true);
	});
});
