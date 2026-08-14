import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import {
	type InternalResource,
	type InternalUrl,
	InternalUrlRouter,
	type ProtocolHandler,
} from "@oh-my-pi/pi-coding-agent/internal-urls";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { GrepTool } from "@oh-my-pi/pi-coding-agent/tools/grep";
import { writeArchive } from "@oh-my-pi/pi-coding-agent/utils/zip";
import { removeWithRetries } from "@oh-my-pi/pi-utils";

// Regression for the finding: `grep`'s wrapper gate classifies `path` as
// read-only (tool-path-targets.ts), but an archive-member or virtual-URL
// search materializes the searched text to a scratch file under
// `os.tmpdir()` (an `omp-search-archive-*`/`omp-search-virtual-*` directory,
// normally outside every workspace root) with no write authorization at
// all — bypassing `confineWrites` and any `deny.write` rule on that scratch
// directory entirely.
describe("grep scratch-file permission gate", () => {
	let tmpDir: string;

	function registerVirtualDoc(name: string, content: string): void {
		const handler: ProtocolHandler = {
			scheme: "virtual",
			immutable: true,
			async resolve(url: InternalUrl): Promise<InternalResource> {
				const host = url.rawHost || url.hostname;
				const pathname = url.rawPathname ?? url.pathname;
				const docName = host ? (pathname && pathname !== "/" ? host + pathname : host) : "";
				if (docName !== name) throw new Error(`Virtual doc not found: ${docName}`);
				return { url: url.href, content, contentType: "text/plain", size: Buffer.byteLength(content, "utf-8") };
			},
		};
		InternalUrlRouter.instance().register(handler);
	}

	beforeEach(async () => {
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "grep-scratch-gate-"));
		InternalUrlRouter.resetForTests();
	});

	afterEach(async () => {
		InternalUrlRouter.resetForTests();
		await removeWithRetries(tmpDir);
	});

	function createSession(overrides: Record<string, unknown> = {}): ToolSession {
		return {
			cwd: tmpDir,
			hasUI: false,
			getSessionFile: () => null,
			getSessionSpawns: () => "*",
			settings: Settings.isolated({ "grep.contextBefore": 0, "grep.contextAfter": 0, ...overrides }),
		};
	}

	describe("archive member extraction", () => {
		async function makeArchive(): Promise<string> {
			const archivePath = path.join(tmpDir, "bundle.zip");
			await writeArchive(archivePath, "zip", [["src/foo.ts", "needle in archive member\n"]]);
			return archivePath;
		}

		it("denies extracting an archive member to scratch when confineWrites blocks the tmpdir scratch directory", async () => {
			const archivePath = await makeArchive();
			const session = createSession({ "permissions.profile": "workspace" });
			const tool = new GrepTool(session);
			await expect(
				tool.execute("archive-confine", { pattern: "needle", path: `${archivePath}:src/foo.ts` }),
			).rejects.toThrow(/confineWrites/);
		});

		it("denies extracting an archive member whose scratch filename matches a deny.write basename rule", async () => {
			const archivePath = path.join(tmpDir, "bundle.zip");
			await writeArchive(archivePath, "zip", [["secret.key", "needle in denied member\n"]]);
			const session = createSession({
				"permissions.profile": "workspace",
				"permissions.confineWrites": false,
				"permissions.deny.write": ["**/*.key"],
			});
			const tool = new GrepTool(session);
			await expect(
				tool.execute("archive-deny", { pattern: "needle", path: `${archivePath}:secret.key` }),
			).rejects.toThrow(/\*\*\/\*\.key/);
		});

		it("permits extracting an archive member to scratch when the policy allows it", async () => {
			const archivePath = await makeArchive();
			const session = createSession();
			const tool = new GrepTool(session);
			const result = await tool.execute("archive-ok", { pattern: "needle", path: `${archivePath}:src/foo.ts` });
			const text = result.content
				.filter(c => c.type === "text")
				.map(c => c.text ?? "")
				.join("\n");
			expect(text).toContain("needle in archive member");
		});
	});

	describe("virtual resource search", () => {
		it("denies searching a virtual resource when confineWrites blocks the tmpdir scratch directory", async () => {
			registerVirtualDoc("doc.md", "needle in virtual content\n");
			const session = createSession({ "permissions.profile": "workspace" });
			const tool = new GrepTool(session);
			await expect(tool.execute("virtual-confine", { pattern: "needle", path: "virtual://doc.md" })).rejects.toThrow(
				/confineWrites/,
			);
		});

		it("permits searching a virtual resource when the policy allows it", async () => {
			registerVirtualDoc("doc.md", "needle in virtual content\n");
			const session = createSession();
			const tool = new GrepTool(session);
			const result = await tool.execute("virtual-ok", { pattern: "needle", path: "virtual://doc.md" });
			const text = result.content
				.filter(c => c.type === "text")
				.map(c => c.text ?? "")
				.join("\n");
			expect(text).toContain("needle in virtual content");
		});
	});
});
