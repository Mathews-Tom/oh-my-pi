import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { type SettingPath, Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { materializeReadUrlToFile } from "@oh-my-pi/pi-coding-agent/tools/fetch";
import * as scrapers from "@oh-my-pi/pi-coding-agent/web/scrapers/types";
import { removeSyncWithRetries, Snowflake } from "@oh-my-pi/pi-utils";

// Regression for the finding: `grep`/`ast_grep`'s wrapper gate declares only a
// read target for a searched URL (the URL itself is scheme-exempt), so
// `materializeReadUrlToFile` wrote the fetched body under
// `<session-artifacts>/url-search` with no write authorization at all -
// bypassing `confineWrites`/`deny.write` on the artifacts directory.
describe("URL search materialization permission gate", () => {
	let testDir: string;

	beforeEach(() => {
		testDir = path.join(os.tmpdir(), `url-search-permission-gate-${Snowflake.next()}`);
		fs.mkdirSync(testDir, { recursive: true });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		removeSyncWithRetries(testDir);
	});

	const createSession = (overrides: Partial<Record<SettingPath, unknown>> = {}): ToolSession => {
		const sessionFile = path.join(testDir, "session.jsonl");
		const artifactsDir = sessionFile.slice(0, -6);
		return {
			cwd: testDir,
			hasUI: false,
			getSessionFile: () => sessionFile,
			getArtifactsDir: () => artifactsDir,
			getSessionSpawns: () => null,
			settings: Settings.isolated({ "fetch.enabled": true, ...overrides }),
		};
	};

	function mockPage(): void {
		vi.spyOn(scrapers, "loadPage").mockResolvedValue({
			ok: true,
			status: 200,
			contentType: "text/plain",
			finalUrl: "https://example.com/doc",
			content: "search me",
		});
	}

	it("denies materializing the searched URL body under a denied artifacts directory", async () => {
		mockPage();
		const session = createSession({
			"permissions.profile": "strict",
			"permissions.deny.write": ["**/url-search/**"],
		});

		await expect(materializeReadUrlToFile(session, { path: "https://example.com/doc" })).rejects.toThrow(
			"**/url-search/**",
		);

		const artifactsDir = session.getArtifactsDir?.();
		expect(artifactsDir).toBeDefined();
		expect(fs.existsSync(path.join(artifactsDir!, "url-search"))).toBe(false);
	});

	it("materializes the searched URL body when the policy permits it", async () => {
		mockPage();
		const session = createSession();

		const { path: contentPath } = await materializeReadUrlToFile(session, { path: "https://example.com/doc" });

		expect(fs.existsSync(contentPath)).toBe(true);
		expect(fs.readFileSync(contentPath, "utf8")).toContain("search me");
	});
});
