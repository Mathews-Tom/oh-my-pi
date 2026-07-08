import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { clearCache as clearFsCache } from "@oh-my-pi/pi-coding-agent/capability/fs";
import { type MCPServer, mcpCapability } from "@oh-my-pi/pi-coding-agent/capability/mcp";
import { resetSettingsForTest } from "@oh-my-pi/pi-coding-agent/config/settings";
import { loadCapability } from "@oh-my-pi/pi-coding-agent/discovery";
import { removeWithRetries } from "@oh-my-pi/pi-utils";

async function writeFile(filePath: string, content: string): Promise<void> {
	await fs.mkdir(path.dirname(filePath), { recursive: true });
	await fs.writeFile(filePath, content);
}

describe("Claude Code MCP server discovery", () => {
	let root = "";
	let home = "";
	let project = "";
	let originalHome: string | undefined;
	let originalClaudeConfigDir: string | undefined;

	beforeEach(async () => {
		clearFsCache();
		resetSettingsForTest();
		originalHome = process.env.HOME;
		originalClaudeConfigDir = process.env.CLAUDE_CONFIG_DIR;
		root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-claude-mcp-"));
		home = path.join(root, "home");
		project = path.join(root, "project");
		process.env.HOME = home;
		delete process.env.CLAUDE_CONFIG_DIR;
		vi.spyOn(os, "homedir").mockReturnValue(home);
		await fs.mkdir(path.join(project, ".git"), { recursive: true });
	});

	afterEach(async () => {
		clearFsCache();
		resetSettingsForTest();
		vi.restoreAllMocks();
		if (originalHome === undefined) {
			delete process.env.HOME;
		} else {
			process.env.HOME = originalHome;
		}
		if (originalClaudeConfigDir === undefined) {
			delete process.env.CLAUDE_CONFIG_DIR;
		} else {
			process.env.CLAUDE_CONFIG_DIR = originalClaudeConfigDir;
		}
		await removeWithRetries(root);
	});

	test("loads user MCP servers from ~/.claude.json by default", async () => {
		await writeFile(
			path.join(home, ".claude.json"),
			JSON.stringify({ mcpServers: { github: { command: "github-mcp", args: ["--stdio"] } } }),
		);

		const result = await loadCapability<MCPServer>(mcpCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(server => server.name)).toContain("github");
	});

	test("loads user MCP servers from CLAUDE_CONFIG_DIR/.claude.json when overridden", async () => {
		// Regression: loadMCPServers previously read `.claude.json` from `ctx.home`
		// unconditionally, ignoring CLAUDE_CONFIG_DIR even though the rest of the
		// user-level Claude config (settings.json, CLAUDE.md, hooks, etc.) already moves
		// under the override. A user running a separate Claude profile would silently
		// lose their profile's user-scoped MCP servers.
		const claudeConfigDir = path.join(root, "claude-config");
		process.env.CLAUDE_CONFIG_DIR = claudeConfigDir;
		await writeFile(
			path.join(claudeConfigDir, ".claude.json"),
			JSON.stringify({ mcpServers: { github: { command: "github-mcp", args: ["--stdio"] } } }),
		);
		// A stray ~/.claude.json (the unset-override default location) must not be read
		// once CLAUDE_CONFIG_DIR is set, or a stale/foreign profile could leak in.
		await writeFile(
			path.join(home, ".claude.json"),
			JSON.stringify({ mcpServers: { stale: { command: "stale-mcp" } } }),
		);

		const result = await loadCapability<MCPServer>(mcpCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(server => server.name);
		expect(names).toContain("github");
		expect(names).not.toContain("stale");
	});
});
