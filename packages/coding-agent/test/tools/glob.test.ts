import { describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "../../src/config/settings";
import type { ReadonlySessionManager } from "../../src/session/session-manager";
import type { ToolSession } from "../../src/tools";
import { GlobTool, type GlobToolDetails } from "../../src/tools/glob";
import { ToolError } from "../../src/tools/tool-errors";

const ROOT_SEARCH_ERROR = "Searching from root directory '/' is not allowed";

async function expectRootSearchRejected(searchPath: string): Promise<void> {
	const session: ToolSession = {
		cwd: process.cwd(),
		hasUI: false,
		settings: Settings.isolated({}),
		getSessionFile: () => null,
		getSessionSpawns: () => null,
	};
	const tool = new GlobTool(session);
	let thrown: unknown;
	try {
		await tool.execute("glob-root-regression", { path: searchPath });
	} catch (error) {
		thrown = error;
	}

	if (!(thrown instanceof Error)) {
		throw new Error(`Expected glob path ${JSON.stringify(searchPath)} to reject`);
	}

	expect(thrown).toBeInstanceOf(ToolError);
	expect(thrown.message).toBe(ROOT_SEARCH_ERROR);
}

describe("GlobTool.execute", () => {
	test.each(["/", "//"])("rejects bare root search path %s", async searchPath => {
		await expectRootSearchRejected(searchPath);
	});

	test("returns permitted matches when denied files saturate the native result page", async () => {
		const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-glob-perm-")));
		try {
			const limit = 3;
			const denyDir = path.join(base, "deny");
			const allowDir = path.join(base, "allow");
			fs.mkdirSync(denyDir);
			fs.mkdirSync(allowDir);

			// `limit` denied files, most-recently modified, so an mtime-ranked
			// native page truncated at `limit` is saturated entirely with denied
			// entries. Older, permitted files sit further down the ranked list.
			const now = Date.now() / 1000;
			for (let i = 0; i < limit; i++) {
				const file = path.join(denyDir, `d${i}.txt`);
				fs.writeFileSync(file, "denied");
				fs.utimesSync(file, now + 1000, now + 1000);
			}
			const allowedNames: string[] = [];
			for (let i = 0; i < limit; i++) {
				const file = path.join(allowDir, `a${i}.txt`);
				fs.writeFileSync(file, "allowed");
				fs.utimesSync(file, now - 1000, now - 1000);
				allowedNames.push(`allow/a${i}.txt`);
			}

			const sessionManager = {
				getCwd: () => base,
				getAdditionalDirectories: () => [],
				getSessionId: () => "test-session",
			} as unknown as ReadonlySessionManager;
			const toolContext = {
				sessionManager,
				settings: Settings.isolated({
					"permissions.profile": "workspace",
					"permissions.deny.read": ["deny/**"],
				}),
			} as unknown as AgentToolContext;

			const session: ToolSession = {
				cwd: base,
				hasUI: false,
				settings: Settings.isolated({}),
				getSessionFile: () => null,
				getSessionSpawns: () => null,
			};
			const tool = new GlobTool(session);
			const result = await tool.execute(
				"glob-perm-limit-regression",
				{ path: "**/*.txt", limit },
				undefined,
				undefined,
				toolContext,
			);

			const details = result.details as GlobToolDetails | undefined;
			expect((details?.files ?? []).slice().sort()).toEqual(allowedNames.slice().sort());
		} finally {
			fs.rmSync(base, { recursive: true, force: true });
		}
	});
});
