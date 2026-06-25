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

async function runGit(cwd: string, args: string[]): Promise<string> {
	const proc = Bun.spawn(["git", ...args], { cwd, stdout: "pipe", stderr: "pipe" });
	const [exitCode, stdout, stderr] = await Promise.all([
		proc.exited,
		new Response(proc.stdout as ReadableStream<Uint8Array>).text(),
		new Response(proc.stderr as ReadableStream<Uint8Array>).text(),
	]);
	if (exitCode !== 0) {
		throw new Error(`git ${args.join(" ")} failed (${exitCode}): ${stderr || stdout}`);
	}
	return stdout.trim();
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

	test("loads project rules from ancestor .claude directories", async () => {
		const nestedCwd = path.join(project, "packages", "app");
		await fs.mkdir(nestedCwd, { recursive: true });
		await writeFile(path.join(project, ".claude", "rules", "root.md"), "Root rule.\n");
		await writeFile(path.join(nestedCwd, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: nestedCwd,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toEqual(["root", "local"]);
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

	test("keeps rules when their ignored parent is re-included", async () => {
		await writeFile(path.join(project, ".gitignore"), ".claude/\n!.claude/\n");
		await writeFile(path.join(project, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("local");
	});

	test("keeps rules when nested ignore files re-include a parent", async () => {
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/\n");
		await writeFile(path.join(project, ".claude", ".gitignore"), "!rules/\n");
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

	test("keeps linked rules ignored when a file ignore remains", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), "*.md\n!.claude/rules/shared/\n");
		const sharedRules = path.join(root, "shared-rules");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:private");
	});

	test("skips ignored linked rule directories", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/vendor/\n");
		const vendorRules = path.join(root, "vendor-rules");
		await writeFile(path.join(vendorRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(vendorRules, path.join(project, ".claude", "rules", "vendor"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("vendor:private");
	});

	test("keeps project ignores when the rules root is a symlinked checkout", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/private.md\n");
		const sharedRules = path.join(root, "shared-rules-checkout");
		await writeFile(path.join(sharedRules, ".git", "HEAD"), "ref: refs/heads/main\n");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(project, ".claude"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("private");
	});

	test("skips node_modules under linked rule directories", async () => {
		if (process.platform === "win32") return;
		const sharedRules = path.join(root, "shared-rules-with-deps");
		await writeFile(path.join(sharedRules, "node_modules", "pkg", "README.md"), "Dependency docs.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:node_modules:pkg:README");
	});

	test("honors git excludes from a symlinked project checkout", async () => {
		if (process.platform === "win32") return;
		const realProject = path.join(root, "real-project");
		await fs.rm(project, { recursive: true, force: true });
		await writeFile(path.join(realProject, ".git", "info", "exclude"), ".claude/rules/shared/private.md\n");
		const sharedRules = path.join(root, "shared-rules-for-symlinked-project");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(realProject, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(realProject, ".claude", "rules", "shared"), "dir");
		await fs.symlink(realProject, project, "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:private");
	});

	test("honors merged claudeMdExcludes when loading rules", async () => {
		const privateRule = path.join(project, ".claude", "rules", "private.md");
		await writeFile(
			path.join(project, ".claude", "settings.json"),
			JSON.stringify({ claudeMdExcludes: [privateRule] }),
		);
		await writeFile(
			path.join(project, ".claude", "settings.local.json"),
			JSON.stringify({ claudeMdExcludes: ["**/.claude/rules/vendor/**"] }),
		);
		await writeFile(privateRule, "Private rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "keep.md"), "Keep rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "vendor", "skip.md"), "Skip rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
		expect(result.items.map(rule => rule.name)).not.toContain("private");
		expect(result.items.map(rule => rule.name)).not.toContain("vendor:skip");
	});

	test("honors project-relative claudeMdExcludes when loading rules", async () => {
		await writeFile(
			path.join(project, ".claude", "settings.json"),
			JSON.stringify({ claudeMdExcludes: [".claude/rules/private.md"] }),
		);
		await writeFile(path.join(project, ".claude", "rules", "private.md"), "Private rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "keep.md"), "Keep rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
		expect(result.items.map(rule => rule.name)).not.toContain("private");
	});

	test("honors git excludes from a symlinked worktree checkout", async () => {
		if (process.platform === "win32") return;
		const repo = path.join(root, "worktree-repo");
		const worktree = path.join(root, "worktree-checkout");
		const sharedRules = path.join(root, "shared-rules-for-worktree");
		await fs.rm(project, { recursive: true, force: true });
		await fs.mkdir(repo, { recursive: true });
		await runGit(repo, ["init"]);
		await runGit(repo, ["config", "user.email", "test@example.com"]);
		await runGit(repo, ["config", "user.name", "Test User"]);
		await writeFile(path.join(repo, "tracked.txt"), "tracked\n");
		await runGit(repo, ["add", "tracked.txt"]);
		await runGit(repo, ["commit", "-m", "init"]);
		await runGit(repo, ["worktree", "add", worktree, "-b", "feature"]);
		const excludeFile = await runGit(worktree, ["rev-parse", "--git-path", "info/exclude"]);
		await writeFile(
			path.isAbsolute(excludeFile) ? excludeFile : path.join(worktree, excludeFile),
			".claude/rules/shared/private.md\n",
		);
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(worktree, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(worktree, ".claude", "rules", "shared"), "dir");
		await fs.symlink(worktree, project, "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:private");
	});

	test("honors escaped gitignore patterns for linked rules", async () => {
		if (process.platform === "win32") return;
		await writeFile(
			path.join(project, ".gitignore"),
			".claude/rules/shared/Private\\ Rule.md\n.claude/rules/shared/\\!secret.md\n",
		);
		const sharedRules = path.join(root, "shared-rules-escaped-ignores");
		await writeFile(path.join(sharedRules, "Private Rule.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "!secret.md"), "Secret rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:Private Rule");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:!secret");
	});

	test("keeps re-included files under otherwise ignored linked directories", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/vendor/*\n!.claude/rules/vendor/keep.md\n");
		const sharedRules = path.join(root, "shared-rules-content-ignored");
		await writeFile(path.join(sharedRules, "drop.md"), "Drop rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "vendor"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("vendor:keep");
		expect(result.items.map(rule => rule.name)).not.toContain("vendor:drop");
	});
	test("keeps root .ignore precedence over nested .gitignore for linked rules", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".ignore"), ".claude/rules/shared/private.md\n");
		await writeFile(path.join(project, ".claude", "rules", ".gitignore"), "!shared/private.md\n");
		const sharedRules = path.join(root, "shared-rules-ignore-precedence");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:private");
	});
	test("honors POSIX character classes in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[[:upper:]]*.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-classes");
		await writeFile(path.join(sharedRules, "Private.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:Private");
	});
	test("honors space and punctuation POSIX classes in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		await writeFile(
			path.join(project, ".gitignore"),
			".claude/rules/shared/*[[:space:]]*.md\n.claude/rules/shared/[[:punct:]]*.md\n",
		);
		const sharedRules = path.join(root, "shared-rules-posix-space-punct");
		await writeFile(path.join(sharedRules, "Private Rule.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "!secret.md"), "Secret rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:Private Rule");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:!secret");
	});
});
