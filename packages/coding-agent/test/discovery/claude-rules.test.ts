import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { clearCache as clearFsCache } from "@oh-my-pi/pi-coding-agent/capability/fs";
import { type Rule, ruleCapability } from "@oh-my-pi/pi-coding-agent/capability/rule";
import { resetSettingsForTest } from "@oh-my-pi/pi-coding-agent/config/settings";
import { loadCapability } from "@oh-my-pi/pi-coding-agent/discovery";

async function writeFile(filePath: string, content: string): Promise<void> {
	await fs.mkdir(path.dirname(filePath), { recursive: true });
	await fs.writeFile(filePath, content);
}

describe("Claude Code rule discovery", () => {
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
		root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-claude-rules-"));
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
		await fs.rm(root, { recursive: true, force: true });
	});

	test("loads user rules from CLAUDE_CONFIG_DIR", async () => {
		const claudeConfigDir = path.join(root, "claude-config");
		process.env.CLAUDE_CONFIG_DIR = claudeConfigDir;
		await writeFile(path.join(claudeConfigDir, "rules", "global.md"), "Global rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toEqual(["global", "local"]);
		expect(result.items.find(rule => rule.name === "global")?.path).toBe(
			path.join(claudeConfigDir, "rules", "global.md"),
		);
		expect(result.items.find(rule => rule.name === "local")?.path).toBe(
			path.join(project, ".claude", "rules", "local.md"),
		);
	});

	test("keeps rules when unrelated directory-only ignores exist", async () => {
		await writeFile(path.join(project, ".gitignore"), "node_modules/\ndist/\n");
		await writeFile(path.join(project, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("local");
	});

	test("keeps linked rules ignored when a parent remains ignored", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), "*\n!.claude/\n!.claude/rules/shared/keep.md\n");
		const sharedRules = path.join(root, "shared-rules");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:keep");
	});
});
