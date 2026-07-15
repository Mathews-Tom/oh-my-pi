import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import * as capabilityFs from "@oh-my-pi/pi-coding-agent/capability/fs";
import { clearCache as clearFsCache } from "@oh-my-pi/pi-coding-agent/capability/fs";
import {
	type Rule,
	resetActiveRulesForTests,
	ruleCapability,
	setActiveRules,
} from "@oh-my-pi/pi-coding-agent/capability/rule";
import { bucketRules } from "@oh-my-pi/pi-coding-agent/capability/rule-buckets";
import { resetSettingsForTest } from "@oh-my-pi/pi-coding-agent/config/settings";
import { loadCapability } from "@oh-my-pi/pi-coding-agent/discovery";
import { TtsrManager } from "@oh-my-pi/pi-coding-agent/export/ttsr";
import { parseInternalUrl } from "@oh-my-pi/pi-coding-agent/internal-urls/parse";
import { RuleProtocolHandler } from "@oh-my-pi/pi-coding-agent/internal-urls/rule-protocol";
import { splitInternalUrlSel } from "@oh-my-pi/pi-coding-agent/tools/path-utils";

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

function managedSettingsPath(): string {
	switch (process.platform) {
		case "darwin":
			return "/Library/Application Support/ClaudeCode/managed-settings.json";
		case "win32":
			return path.join(process.env.ProgramFiles || "C:\\Program Files", "ClaudeCode", "managed-settings.json");
		default:
			return "/etc/claude-code/managed-settings.json";
	}
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
		resetActiveRulesForTests();
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
		resetActiveRulesForTests();
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

	test("does not apply home gitignore rules to user rules", async () => {
		await writeFile(path.join(home, ".gitignore"), "*.md\n");
		await writeFile(path.join(home, ".claude", "rules", "global.md"), "Global rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toEqual(["global"]);
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

	test("does not leak ancestor .claude/rules when cwd has no repo root and is outside home", async () => {
		// No git anchor and cwd outside $HOME (a scratch checkout under /tmp, e.g.) means
		// getProjectClaudePathCandidates has no safe upper bound for the ancestor walk.
		// It must stop at cwd itself instead of climbing toward the filesystem root and
		// loading unrelated parent-directory rules.
		const outsideDir = path.join(root, "outside");
		const nestedCwd = path.join(outsideDir, "nested", "deep");
		await fs.mkdir(nestedCwd, { recursive: true });
		await writeFile(path.join(outsideDir, ".claude", "rules", "parent.md"), "Leaked parent rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: nestedCwd,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("parent");
	});

	test("does not apply parent ignores to non-repo project rules", async () => {
		const scratchRoot = path.join(root, "scratch");
		const scratchProject = path.join(scratchRoot, "project");
		await writeFile(path.join(scratchRoot, ".gitignore"), "*.md\n");
		await writeFile(path.join(scratchProject, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: scratchProject,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("local");
	});

	test("does not leak parent .claude/rules when repo-root cwd has a trailing separator", async () => {
		const parentDir = path.join(root, "trailing-parent");
		const projectDir = path.join(parentDir, "project");
		await fs.mkdir(path.join(projectDir, ".git"), { recursive: true });
		await writeFile(path.join(parentDir, ".claude", "rules", "parent.md"), "Leaked parent rule.\n");
		await writeFile(path.join(projectDir, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: `${projectDir}${path.sep}`,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("local");
		expect(names).not.toContain("parent");
	});

	test("honors the repo .gitignore for ancestor rules when cwd is nested below a symlinked checkout", async () => {
		if (process.platform === "win32") return;
		// cwd is nested below a symlinked checkout (link -> realRepo) and the rule dir is an
		// ancestor `.claude/rules` that is NOT under cwd. The symlink boundary must be the
		// repo root (link), not the nested cwd, so the repo `.gitignore` still suppresses
		// `secret.md` instead of the walk skipping past the checkout symlink and missing it.
		const realRepo = path.join(root, "real-repo");
		await fs.mkdir(path.join(realRepo, ".git"), { recursive: true });
		await writeFile(path.join(realRepo, ".gitignore"), ".claude/rules/secret.md\n");
		await writeFile(path.join(realRepo, ".claude", "rules", "secret.md"), "Secret rule.\n");
		await writeFile(path.join(realRepo, ".claude", "rules", "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(realRepo, "packages", "app"), { recursive: true });
		const link = path.join(root, "link");
		await fs.symlink(realRepo, link, "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: path.join(link, "packages", "app"),
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("keep");
		expect(names).not.toContain("secret");
	});

	test("keeps Claude rule names human-readable; encoding applies only at the rule:// URL boundary", async () => {
		await writeFile(path.join(project, ".claude", "rules", "C#.md"), '---\npaths:\n  - "**/*.cs"\n---\nC# rule.\n');

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.find(rule => rule.path.endsWith("C#.md"))?.name).toBe("C#");
		setActiveRules(result.items);
		const resource = await new RuleProtocolHandler().resolve(parseInternalUrl("rule://C%23"));
		expect(resource.content.trim()).toBe("C# rule.");
	});

	test("keeps Claude rule identity distinct from a colliding literal percent-encoded filename", async () => {
		await writeFile(path.join(project, ".claude", "rules", "C#.md"), "Decoded C# rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "C%23.md"), "Literal percent rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.find(rule => rule.path.endsWith("C#.md"))?.name).toBe("C#");
		expect(result.items.find(rule => rule.path.endsWith("C%23.md"))?.name).toBe("C%23");
		setActiveRules(result.items);
		const completions = await new RuleProtocolHandler().complete();
		expect(completions.map(completion => completion.value)).toEqual(["C%23", "C%2523"]);
		expect(completions.map(completion => completion.label ?? null)).toEqual(["C#", "C%23"]);
		const resource = await new RuleProtocolHandler().resolve(parseInternalUrl("rule://C%2523"));
		expect(resource.content.trim()).toBe("Literal percent rule.");
	});
	test("does not let a Claude rule with reserved characters silently shadow another provider's literal-named rule", async () => {
		// Regression: claudeRuleNameFromPath used to percent-encode segments, so
		// `.claude/rules/C#.md` (name "C#") produced the same `rule.name` ("C%23")
		// as a literal `.agent/rules/C%23.md` file from a lower-priority provider,
		// silently shadowing it via ruleCapability's name-keyed dedupe.
		await writeFile(path.join(project, ".claude", "rules", "C#.md"), "Claude C# rule.\n");
		await writeFile(path.join(project, ".agent", "rules", "C%23.md"), "Agents literal-percent rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude", "agents"],
		});

		const claudeRule = result.items.find(rule => rule.path.endsWith(path.join(".claude", "rules", "C#.md")));
		const agentsRule = result.items.find(rule => rule.path.endsWith(path.join(".agent", "rules", "C%23.md")));
		expect(claudeRule?.name).toBe("C#");
		expect(agentsRule?.name).toBe("C%23");
		expect(claudeRule?.name).not.toBe(agentsRule?.name);
	});
	test("treats Claude rules with globs the same as paths: both stay path-scoped", async () => {
		// buildRuleFromMarkdown's shared `globs ?? paths` precedence applies to Claude
		// rules too, so a Cursor-style `globs:` key scopes a Claude rule exactly like
		// `paths:` does — both stay path-scoped rather than one silently becoming an
		// always-on launch rule.
		await writeFile(
			path.join(project, ".claude", "rules", "globs-only.md"),
			'---\nglobs:\n  - "**/*.ts"\n---\nGlobs-only rule.\n',
		);
		await writeFile(
			path.join(project, ".claude", "rules", "paths-scoped.md"),
			'---\npaths:\n  - "**/*.ts"\n---\nPaths rule.\n',
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const globsOnly = result.items.find(rule => rule.name === "globs-only");
		const pathsScoped = result.items.find(rule => rule.name === "paths-scoped");
		expect(globsOnly?.alwaysApply).not.toBe(true);
		expect(globsOnly?.globs).toEqual(["**/*.ts"]);
		expect(pathsScoped?.alwaysApply).not.toBe(true);
		expect(pathsScoped?.globs).toEqual(["**/*.ts"]);
	});
	test("scopes a Claude rule to its paths even when alwaysApply: true is also set", async () => {
		// Regression: `alwaysApply: true` combined with `paths:` used to short-circuit
		// transformClaudeRule BEFORE the globs branch ran. Even after fixing that
		// ordering, bucketRules itself also checks `alwaysApply` before `description`,
		// so the fix must actively clear the stray flag, not just reorder the checks.
		await writeFile(
			path.join(project, ".claude", "rules", "paths-and-always.md"),
			'---\npaths:\n  - "**/*.ts"\nalwaysApply: true\n---\nCombined paths and alwaysApply rule.\n',
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const rule = result.items.find(r => r.name === "paths-and-always");
		expect(rule?.globs).toEqual(["**/*.ts"]);
		expect(rule?.alwaysApply).not.toBe(true);

		if (!rule) throw new Error("expected paths-and-always rule to be loaded");
		const mgr = new TtsrManager();
		const { rulebookRules, alwaysApplyRules } = bucketRules([rule], mgr);
		expect(alwaysApplyRules).not.toContain(rule);
		expect(rulebookRules).toContain(rule);
	});
	test("preserves globs on conditional (TTSR) Claude rules so the condition stays path-scoped", async () => {
		// A Claude rule that combines OMP TTSR metadata (`condition:`) with a `globs:`
		// path filter must keep its globs — TtsrManager uses rule.globs as the global
		// path filter, so dropping it would fire the condition for unrelated files.
		await writeFile(
			path.join(project, ".claude", "rules", "ttsr-globs.md"),
			'---\ncondition: TODO\nglobs:\n  - "**/*.ts"\n---\nTTSR rule.\n',
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const ttsr = result.items.find(rule => rule.name === "ttsr-globs");
		expect(ttsr?.condition).toEqual(["TODO"]);
		expect(ttsr?.globs).toEqual(["**/*.ts"]);
	});
	test("treats modifier-only Claude rules (no condition/paths) as launch rules", async () => {
		// scope/interruptMode without a condition does not make a rule TTSR (TtsrManager
		// rejects it) and it is not path-scoped, so it must still launch at startup
		// rather than silently disappear.
		await writeFile(
			path.join(project, ".claude", "rules", "modifier-only.md"),
			"---\ninterruptMode: never\n---\nModifier-only rule.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const modifierOnly = result.items.find(rule => rule.name === "modifier-only");
		expect(modifierOnly?.alwaysApply).toBe(true);
	});
	test("forces launch for a pathless Claude rule with alwaysApply: false and no description", async () => {
		// Regression: a shared rule collection (e.g. reused Cursor .mdc frontmatter)
		// can set `alwaysApply: false` with no `paths:` and no `description`. Claude
		// path-specificity comes only from `paths:`, so a pathless rule must still
		// launch — otherwise bucketRules drops it entirely (no condition, not
		// always-apply, no description to route it to the rulebook bucket).
		await writeFile(
			path.join(project, ".claude", "rules", "pathless-opt-out.md"),
			"---\nalwaysApply: false\n---\nShared rule with no paths.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const rule = result.items.find(r => r.name === "pathless-opt-out");
		expect(rule?.alwaysApply).toBe(true);
	});
	test("honors alwaysApply: false on a pathless Claude rule that has a description", async () => {
		// A description gives the rule an on-demand rulebook home, so an explicit
		// `alwaysApply: false` is respected instead of being forced to launch.
		await writeFile(
			path.join(project, ".claude", "rules", "on-demand.md"),
			"---\nalwaysApply: false\ndescription: Fetch on demand.\n---\nOn-demand rule.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const rule = result.items.find(r => r.name === "on-demand");
		expect(rule?.alwaysApply).toBe(false);
		expect(rule?.description).toBe("Fetch on demand.");
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

	test("skips non-regular gitignore sources when loading rules", async () => {
		await fs.mkdir(path.join(home, ".config", "git", "ignore"), { recursive: true });
		await fs.mkdir(path.join(project, ".gitignore"), { recursive: true });
		await fs.mkdir(path.join(project, ".ignore"), { recursive: true });
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

	// Under the old code, the custom Git-compatible ignore re-filter (which correctly
	// normalizes POSIX character classes like `[[:upper:]]`) only ran for symlinked rule
	// directories. For an ordinary directory, the native glob's own gitignore handling does
	// not understand POSIX character classes, so a matching rule file was silently kept.
	test("drops rules matched by a POSIX character class gitignore pattern in an ordinary (non-symlinked) rules directory", async () => {
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/[[:upper:]]*.md\n");
		await writeFile(path.join(project, ".claude", "rules", "A.md"), "Uppercase rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "local.md"), "Local rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("local");
		expect(result.items.map(rule => rule.name)).not.toContain("A");
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

	test("honors project ignores when the whole .claude directory is symlinked", async () => {
		if (process.platform === "win32") return;
		// `.claude` itself is the symlink (not just `.claude/rules`), so lstat on the
		// rules dir resolves the parent link and reports a real directory. A symlink in
		// any ancestor must still trigger the project-logical re-filter; otherwise the
		// native glob walks the target and the project `.gitignore` entry for
		// `.claude/rules/private.md` is bypassed.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/private.md\n");
		const sharedClaude = path.join(root, "shared-claude-dir");
		await writeFile(path.join(sharedClaude, "rules", "private.md"), "Private rule.\n");
		await writeFile(path.join(sharedClaude, "rules", "keep.md"), "Keep rule.\n");
		await fs.symlink(sharedClaude, path.join(project, ".claude"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("keep");
		expect(names).not.toContain("private");
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

	test("honors managed-policy claudeMdExcludes when loading rules", async () => {
		const managedRule = path.join(project, ".claude", "rules", "managed-private.md");
		await writeFile(managedRule, "Managed private rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "keep.md"), "Keep rule.\n");
		const originalReadFile = capabilityFs.readFile;
		const managedPath = managedSettingsPath();
		vi.spyOn(capabilityFs, "readFile").mockImplementation(filePath => {
			if (filePath === managedPath) {
				return Promise.resolve(JSON.stringify({ claudeMdExcludes: [managedRule] }));
			}
			return originalReadFile(filePath);
		});

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
		expect(result.items.map(rule => rule.name)).not.toContain("managed-private");
	});

	test("does not exclude via a relative literal claudeMdExcludes pattern", async () => {
		// Claude Code matches every claudeMdExcludes entry — literal or glob — only
		// against absolute file paths, so a project-relative literal like
		// `.claude/rules/private.md` never matches `/repo/.claude/rules/private.md`.
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
		expect(result.items.map(rule => rule.name)).toContain("private");
	});

	test("excludes an absolute literal path whose parent directory name contains glob metacharacters", async () => {
		// Under the old code, any pattern containing `[`/`]`/`*`/`?`/`{`/`}` was sent
		// straight to Bun.Glob without ever checking exact absolute equality first.
		// Bun.Glob parses `[1]` in `repo[1]` as a single-character class matching only
		// the literal character "1", so this literal absolute path would never match
		// itself and `private.md` would have loaded instead of being excluded.
		const bracketedRoot = path.join(project, "repo[1]");
		const privateRule = path.join(bracketedRoot, ".claude", "rules", "private.md");
		await writeFile(
			path.join(bracketedRoot, ".claude", "settings.json"),
			JSON.stringify({ claudeMdExcludes: [privateRule] }),
		);
		await writeFile(privateRule, "Private rule.\n");
		await writeFile(path.join(bracketedRoot, ".claude", "rules", "keep.md"), "Keep rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: bracketedRoot,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
		expect(result.items.map(rule => rule.name)).not.toContain("private");
	});

	test("does not exclude via a relative glob claudeMdExcludes pattern lacking a ** prefix", async () => {
		await writeFile(
			path.join(project, ".claude", "settings.json"),
			JSON.stringify({ claudeMdExcludes: [".claude/rules/*.md"] }),
		);
		await writeFile(path.join(project, ".claude", "rules", "private.md"), "Private rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "keep.md"), "Keep rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
		expect(result.items.map(rule => rule.name)).toContain("private");
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

	test("honors repo-local excludesFile from a symlinked worktree checkout", async () => {
		if (process.platform === "win32") return;
		const repo = path.join(root, "local-excludes-repo");
		const worktree = path.join(root, "local-excludes-worktree");
		const sharedRules = path.join(root, "shared-rules-local-excludes");
		const excludesFile = path.join(worktree, ".gitignore-local");
		await fs.rm(project, { recursive: true, force: true });
		await fs.mkdir(repo, { recursive: true });
		await runGit(repo, ["init"]);
		await runGit(repo, ["config", "user.email", "test@example.com"]);
		await runGit(repo, ["config", "user.name", "Test User"]);
		await writeFile(path.join(repo, "tracked.txt"), "tracked\n");
		await runGit(repo, ["add", "tracked.txt"]);
		await runGit(repo, ["commit", "-m", "init"]);
		await runGit(repo, ["worktree", "add", worktree, "-b", "feature"]);
		await runGit(worktree, ["config", "core.excludesFile", excludesFile]);
		await writeFile(excludesFile, ".claude/rules/shared/private.md\n");
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

	test("treats empty core.excludesFile as disabling the global ignore file", async () => {
		if (process.platform === "win32") return;
		const repo = path.join(root, "empty-excludes-repo");
		const worktree = path.join(root, "empty-excludes-worktree");
		const sharedRules = path.join(root, "shared-rules-empty-excludes");
		await fs.rm(project, { recursive: true, force: true });
		await fs.mkdir(repo, { recursive: true });
		await runGit(repo, ["init"]);
		await runGit(repo, ["config", "user.email", "test@example.com"]);
		await runGit(repo, ["config", "user.name", "Test User"]);
		await writeFile(path.join(repo, "tracked.txt"), "tracked\n");
		await runGit(repo, ["add", "tracked.txt"]);
		await runGit(repo, ["commit", "-m", "init"]);
		await runGit(repo, ["worktree", "add", worktree, "-b", "feature"]);
		await writeFile(path.join(home, ".gitconfig"), "[core]\n\texcludesFile = ~/.config/git/ignore\n");
		await writeFile(path.join(home, ".config", "git", "ignore"), "*.md\n");
		await runGit(worktree, ["config", "core.excludesFile", ""]);
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(worktree, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(worktree, ".claude", "rules", "shared"), "dir");
		await fs.symlink(worktree, project, "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
	});

	test("does not apply a globally configured core.excludesFile outside a Git worktree", async () => {
		if (process.platform === "win32") return;
		// Regression: computeGitignoreRules previously read core.excludesFile (falling back
		// to ~/.config/git/ignore) unconditionally, even when the scanned directory tree has
		// no `.git` anywhere in its ancestry. Git itself only applies that global excludes
		// file inside a real worktree, so an unrelated global ignore (e.g. `*.md`) must not
		// suppress Claude rules in a non-repo project.
		await fs.rm(path.join(project, ".git"), { recursive: true, force: true });
		await writeFile(path.join(home, ".gitconfig"), "[core]\n\texcludesFile = ~/.config/git/ignore\n");
		await writeFile(path.join(home, ".config", "git", "ignore"), "*.md\n");
		await writeFile(path.join(project, ".claude", "rules", "keep.md"), "Keep rule.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
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

	test("treats an anchored literal bang gitignore pattern as root-only for linked rules", async () => {
		if (process.platform === "win32") return;
		// `/!secret.md` is an anchored ignore of the literal root file `!secret.md`.
		// The leading `!` is negation only as a bare line prefix; after the `/` anchor
		// it is a literal path character. If Bun.Glob reads it as negation the pattern
		// becomes "match anything but secret.md" and drops every unrelated linked rule.
		await writeFile(path.join(project, ".gitignore"), "/!secret.md\n");
		const sharedRules = path.join(root, "shared-rules-anchored-bang");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await writeFile(path.join(sharedRules, "!secret.md"), "Secret rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:keep");
		expect(names).toContain("shared:!secret");
	});

	test("unescapes arbitrary backslash escapes in gitignore patterns for linked rules", async () => {
		if (process.platform === "win32") return;
		// Git lets a backslash escape ANY character, so `foo\bar.md` is the logical
		// file `foobar.md`. Leaving `\b` in the Bun.Glob pattern would match nothing
		// and wrongly keep a rule Git/native discovery suppresses.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/foo\\bar.md\n");
		const sharedRules = path.join(root, "shared-rules-arbitrary-escape");
		await writeFile(path.join(sharedRules, "foobar.md"), "Escaped rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:keep");
		expect(names).not.toContain("shared:foobar");
	});

	test("preserves bracket-local escapes in gitignore patterns for linked rules", async () => {
		if (process.platform === "win32") return;
		// Inside a `[...]` class, `\-` is a literal hyphen, so `[a\-z]` matches the
		// literals a, -, z — not the range a-z. Dropping the backslash would form the
		// range `[a-z]` and wrongly suppress unrelated rules like `bsecret.md`.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[a\\-z]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-bracket-escape");
		await writeFile(path.join(sharedRules, "asecret.md"), "A rule.\n");
		await writeFile(path.join(sharedRules, "-secret.md"), "Hyphen rule.\n");
		await writeFile(path.join(sharedRules, "bsecret.md"), "B rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:keep");
		expect(names).toContain("shared:bsecret");
		expect(names).not.toContain("shared:asecret");
		expect(names).not.toContain("shared:-secret");
	});

	test("honors core.ignoreCase for linked gitignore matches", async () => {
		if (process.platform === "win32") return;
		await fs.rm(path.join(project, ".git"), { recursive: true, force: true });
		await runGit(project, ["init"]);
		await runGit(project, ["config", "core.ignoreCase", "true"]);
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/private.md\n");
		const sharedRules = path.join(root, "shared-rules-ignore-case");
		await writeFile(path.join(sharedRules, "Private.md"), "Private rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).not.toContain("shared:Private");
	});

	test("treats leading-space bang lines as literal ignore patterns", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), "*.md\n !.claude/rules/shared/private.md\n");
		const sharedRules = path.join(root, "shared-rules-leading-space-bang");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "keep.mdc"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:private");
	});

	test("treats gitignore braces as literals for linked rules", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/{private,secret}.md\n");
		const sharedRules = path.join(root, "shared-rules-brace-literals");
		await writeFile(path.join(sharedRules, "{private,secret}.md"), "Literal brace rule.\n");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "secret.md"), "Secret rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:private");
		expect(result.items.map(rule => rule.name)).toContain("shared:secret");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:{private,secret}");
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

	test("keeps linked allow-list files when parents are re-included later", async () => {
		if (process.platform === "win32") return;
		await writeFile(
			path.join(project, ".gitignore"),
			"*\n!.claude/rules/vendor/keep.md\n!.claude/\n!.claude/rules/\n!.claude/rules/vendor/\n",
		);
		const sharedRules = path.join(root, "shared-rules-allow-list-order");
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

	test("honors POSIX print classes in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[[:print:]]rivate.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-print");
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
		const backslashRule = String.raw`\secret.md`;
		await writeFile(path.join(sharedRules, "Private Rule.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "!secret.md"), "Secret rule.\n");
		await writeFile(path.join(sharedRules, "[secret.md"), "Bracket rule.\n");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket-close rule.\n");
		await writeFile(path.join(sharedRules, backslashRule), "Backslash rule.\n");
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
		expect(result.items.map(rule => rule.name)).not.toContain("shared:[secret");
		expect(result.items.map(rule => rule.name)).not.toContain("shared:]secret");
		expect(result.items.map(rule => rule.name)).not.toContain(String.raw`shared:\secret`);
	});
	test("honors the POSIX graph class in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// `[[:graph:]]` is the `!`-to-`~` range. Mapped naively to `[!-~]`, Bun.Glob reads the
		// leading `!` as negation and would keep names git ignores (e.g. `-secret.md`).
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[[:graph:]]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-graph");
		await writeFile(path.join(sharedRules, "-secret.md"), "Dash secret rule.\n");
		await writeFile(path.join(sharedRules, "~secret.md"), "Tilde secret rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:keep");
		expect(names).not.toContain("shared:-secret");
		expect(names).not.toContain("shared:~secret");
	});
	test("matches every POSIX space character in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// Git's [[:space:]] also matches newline/CR/VT/FF in filenames, not just space/tab.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/*[[:space:]]*.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-space-control");
		await writeFile(path.join(sharedRules, "tab\tname.md"), "Tab rule.\n");
		await writeFile(path.join(sharedRules, "line\nbreak.md"), "Newline rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("break.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("name.md"))).toBe(false);
	});
	test("preserves a punct class inside a mixed bracket expression in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// The [:punct:] expansion's leading ] is literal only at the bracket start; after another
		// token (e.g. [a[:punct:]]) it must be escaped or Bun.Glob ends the class early and keeps
		// rules git ignores.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[a[:punct:]]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-punct-mixed");
		await writeFile(path.join(sharedRules, "asecret.md"), "A secret.\n");
		await writeFile(path.join(sharedRules, "!secret.md"), "Bang secret.\n");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket secret.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("asecret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("!secret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("]secret.md"))).toBe(false);
	});
	test("escapes the punct class trailing hyphen when followed by another bracket member in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// Regression: the [:punct:] expansion ends in a literal trailing `-`, safe
		// unescaped only when it sits right before the bracket closes. Followed by
		// another member (e.g. [[:punct:]a]), that `-` lands mid-bracket and forms
		// an invalid range with the next char, silently rejecting the whole bracket
		// in Bun.Glob and leaking rules Git ignores.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[[:punct:]a]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-punct-hyphen-mid-bracket");
		await writeFile(path.join(sharedRules, "-secret.md"), "Hyphen secret.\n");
		await writeFile(path.join(sharedRules, "asecret.md"), "A secret.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("-secret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("asecret.md"))).toBe(false);
	});
	test("does not let a POSIX class or negated bracket cross the path separator into a symlinked rules directory", async () => {
		if (process.platform === "win32") return;
		// Regression: gitignore matches with FNM_PATHNAME semantics — a bracket
		// expression (POSIX-class-derived or hand-written, negated or not) never
		// matches `/`. Bun.Glob has no such notion by default, so a pattern like
		// `shared[[:punct:]]private.md` must not also match `shared/private.md`
		// through a symlinked `shared` directory (real Git: `git check-ignore -v`
		// never matches it there either — verified separately against real Git).
		//
		// The negated-bracket sibling (`shared[^x]negated.md` vs literal
		// `sharedZnegated.md`) is asserted end-to-end since globset (the native,
		// non-symlinked ignore path) understands plain negated brackets, unlike
		// POSIX classes — so both the native and supplemental paths are exercised
		// there, while the POSIX-class case only exercises the supplemental path
		// this fix targets (globset has no `[:punct:]` support at all).
		await writeFile(
			path.join(project, ".gitignore"),
			".claude/rules/shared[[:punct:]]private.md\n.claude/rules/shared[^x]negated.md\n",
		);
		await writeFile(path.join(project, ".claude", "rules", "sharedZnegated.md"), "Sibling negated rule.\n");
		const sharedRules = path.join(root, "shared-rules-no-bracket-slash-cross");
		await writeFile(path.join(sharedRules, "private.md"), "Linked private rule.\n");
		await writeFile(path.join(sharedRules, "negated.md"), "Linked negated rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		// The negated-bracket sibling IS ignored (pattern works as intended via
		// the native, non-symlinked path).
		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("sharedZnegated.md"))).toBe(false);
		// Files reached only by crossing the symlinked "shared/" directory boundary
		// are NOT ignored — the bracket must not have matched across "/".
		expect(result.items.some(rule => rule.name === "shared:private")).toBe(true);
		expect(result.items.some(rule => rule.name === "shared:negated")).toBe(true);
	});
	test("does not let a hand-written range that numerically spans the path separator cross into a symlinked rules directory", async () => {
		if (process.platform === "win32") return;
		// Regression: `[.-0]` numerically spans `/` (0x2E-0x30, and `/` is 0x2F) but
		// under FNM_PATHNAME semantics still never matches `/` — real Git:
		// `.claude/rules/shared[.-0]private.md` ignores literal `shared.private.md`
		// and `shared0private.md` but never `shared/private.md`. Bun.Glob's ranges
		// have no such notion, so a hand-written (non-POSIX-class) range must be
		// split around `/` the same way a POSIX-class-derived range is.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared[.-0]private.md\n");
		await writeFile(path.join(project, ".claude", "rules", "shared.private.md"), "Sibling dot rule.\n");
		await writeFile(path.join(project, ".claude", "rules", "shared0private.md"), "Sibling zero rule.\n");
		const sharedRules = path.join(root, "shared-rules-hand-range-slash-cross");
		await writeFile(path.join(sharedRules, "private.md"), "Linked private rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		// The sibling files matching the range literally ARE ignored (native path).
		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("shared.private.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("shared0private.md"))).toBe(false);
		// The file reached only by crossing the symlinked "shared/" directory
		// boundary is NOT ignored — the range must not have matched across "/".
		expect(result.items.some(rule => rule.name === "shared:private")).toBe(true);
	});
	test("keeps a leading ] literal before a POSIX class in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// In `[][:upper:]]`, the first `]` is a literal class member and `[:upper:]` is a
		// POSIX class. Closing the class on the leading `]` would drop the expansion, so
		// Bun.Glob would match neither `]secret.md` nor an uppercase name git ignores.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[][:upper:]]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-posix-leading-bracket");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket secret.\n");
		await writeFile(path.join(sharedRules, "Asecret.md"), "Upper secret.\n");
		await writeFile(path.join(sharedRules, "bsecret.md"), "Lower keep.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("bsecret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("]secret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("Asecret.md"))).toBe(false);
	});
	test("keeps a leading ] literal before braces in a linked rule ignore class", async () => {
		if (process.platform === "win32") return;
		// In `[]{}]`, the first `]` is a literal class member, so the class matches `]`,
		// `{`, `}`. Closing the class on that leading `]` exposes the later `{`/`}` to brace
		// escaping, so Bun.Glob would match none of those names git ignores and leak the
		// symlinked rules into the prompt.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[]{}]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-leading-bracket-braces");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket secret.\n");
		await writeFile(path.join(sharedRules, "{secret.md"), "Brace-open secret.\n");
		await writeFile(path.join(sharedRules, "}secret.md"), "Brace-close secret.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("]secret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("{secret.md"))).toBe(false);
		expect(paths.some(rulePath => rulePath.endsWith("}secret.md"))).toBe(false);
	});
	test("closes a bracket class after one negation prefix in a linked rule ignore", async () => {
		if (process.platform === "win32") return;
		// In `[!!]`, the first `!` is the negation prefix and the second `!` is an ordinary
		// member, so the class is "any char except `!`" and the following `]` closes it. The
		// trailing `{private,secret}` are then literal braces. Keeping the leading slot open
		// past the first `!` would leave the class unclosed, so Bun.Glob would brace-expand
		// `{private,secret}` — dropping `aprivate.md`/`asecret.md` git keeps and keeping the
		// literal braced rule git suppresses.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[!!]{private,secret}.md\n");
		const sharedRules = path.join(root, "shared-rules-negation-prefix-braces");
		await writeFile(path.join(sharedRules, "a{private,secret}.md"), "Literal braced secret.\n");
		await writeFile(path.join(sharedRules, "aprivate.md"), "Private keep.\n");
		await writeFile(path.join(sharedRules, "asecret.md"), "Secret keep.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("aprivate.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("asecret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("a{private,secret}.md"))).toBe(false);
	});
	test("keeps a leading ] literal after a negation prefix in a linked rule ignore", async () => {
		if (process.platform === "win32") return;
		// In `[!]\-z]`, the `]` right after the `[!` negation prefix is a literal class
		// member, so the class is the negated set of `]`, `-`, `z` (git/fnmatch: it ignores
		// `asecret.md` but keeps `-secret.md`, `zsecret.md`, `]secret.md`). Closing the class
		// on that leading `]` would turn `\-` into an outside-bracket escape and match the
		// wrong names, leaking or suppressing the wrong linked rules.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[!]\\-z]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-negated-leading-bracket");
		await writeFile(path.join(sharedRules, "asecret.md"), "A secret.\n");
		await writeFile(path.join(sharedRules, "-secret.md"), "Hyphen keep.\n");
		await writeFile(path.join(sharedRules, "zsecret.md"), "Z keep.\n");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket keep.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("-secret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("zsecret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("]secret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("asecret.md"))).toBe(false);
	});
	test("keeps a leading ] literal before a POSIX class after a negation prefix", async () => {
		if (process.platform === "win32") return;
		// In `[!][:upper:]]`, the `]` right after the `[!` negation prefix is a literal class
		// member and `[:upper:]` is a POSIX class, so the class is the negated set of `]` and
		// A-Z (git/fnmatch: it ignores `bsecret.md` but keeps `Csecret.md` and `]secret.md`).
		// Closing the class on that leading `]` would drop the POSIX expansion and the symlink
		// fallback would load rules git suppresses. Distinct base letters (not `a`/`A`) keep
		// the suppressed and kept fixtures separate files on case-insensitive filesystems.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/[!][:upper:]]secret.md\n");
		const sharedRules = path.join(root, "shared-rules-negated-posix-leading-bracket");
		await writeFile(path.join(sharedRules, "bsecret.md"), "Lower secret.\n");
		await writeFile(path.join(sharedRules, "Csecret.md"), "Upper keep.\n");
		await writeFile(path.join(sharedRules, "]secret.md"), "Bracket keep.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const paths = result.items.map(rule => rule.path);
		expect(paths.some(rulePath => rulePath.endsWith("keep.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("Csecret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("]secret.md"))).toBe(true);
		expect(paths.some(rulePath => rulePath.endsWith("bsecret.md"))).toBe(false);
	});
	test("does not follow .gitignore reached through a symlinked rule directory", async () => {
		if (process.platform === "win32") return;
		// Git does not follow symlinks when reading .gitignore files, so a target-side
		// ignore file inside the linked checkout must not suppress linked rules.
		const sharedRules = path.join(root, "shared-rules-symlinked-gitignore");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await writeFile(path.join(sharedRules, ".gitignore"), "*.md\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("shared:keep");
	});
	test("treats single-bracket POSIX-like classes as literal in linked rule ignores", async () => {
		if (process.platform === "win32") return;
		// `[:upper:]` (single brackets) is not a POSIX class: git treats it as a bracket
		// expression of the literal characters `:uper`, so it must not become an A-Z range.
		await writeFile(path.join(project, ".gitignore"), ".claude/rules/shared/foo[:upper:].md\n");
		const sharedRules = path.join(root, "shared-rules-single-bracket");
		await writeFile(path.join(sharedRules, "foou.md"), "Matches the literal class.\n");
		await writeFile(path.join(sharedRules, "fooA-Z.md"), "Must stay loaded.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).not.toContain("shared:foou");
		expect(names).toContain("shared:fooA-Z");
	});
	test("honors root .gitignore when the project root is reached through a symlink", async () => {
		if (process.platform === "win32") return;
		// Opening a checkout via a symlinked path (e.g. /tmp/link -> /real/repo) must still
		// honor the repo-root .gitignore for linked rules.
		const realProject = path.join(root, "real-project");
		await fs.mkdir(path.join(realProject, ".git"), { recursive: true });
		await writeFile(path.join(realProject, ".gitignore"), ".claude/rules/shared/private.md\n");
		const sharedRules = path.join(root, "shared-rules-root-symlink");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(realProject, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(realProject, ".claude", "rules", "shared"), "dir");
		const linkedProject = path.join(root, "linked-project");
		await fs.symlink(realProject, linkedProject, "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: linkedProject,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:keep");
		expect(names).not.toContain("shared:private");
	});
	test("recovers symlink-root rules dropped by a target-side .gitignore", async () => {
		if (process.platform === "win32") return;
		// `.claude/rules` is a symlink to a checkout whose own .gitignore ignores *.md.
		// Git does not follow symlinks for .gitignore, so those root rules must still load.
		const sharedRules = path.join(root, "shared-rules-root-target-gitignore");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await writeFile(path.join(sharedRules, ".gitignore"), "*.md\n");
		await fs.mkdir(path.join(project, ".claude"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
	});
	test("recovers symlink-root rules in a no-Git workspace with a target-side .gitignore", async () => {
		if (process.platform === "win32") return;
		// Regression: with no project `.git` or parent ignore file, the ignore-root walk
		// must not follow the symlinked `.claude/rules` into the target checkout and adopt
		// its `.gitignore` (*.md) as the project root, which would silently drop the linked
		// rules. Git never follows symlinks for ignore files, so the rules must still load.
		await fs.rm(path.join(project, ".git"), { recursive: true, force: true });
		const sharedRules = path.join(root, "shared-rules-no-git-target-gitignore");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await writeFile(path.join(sharedRules, ".gitignore"), "*.md\n");
		await fs.mkdir(path.join(project, ".claude"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
	});
	test("ignores target-side .gitignore when the whole .claude dir is symlinked in a no-Git workspace", async () => {
		if (process.platform === "win32") return;
		// `.claude` itself is the symlink (rules live under the target) and the project has
		// no `.git` or project ignore file. The ignore-root walk must skip the symlinked
		// ancestor instead of adopting the target checkout's `.gitignore` (*.md) as the
		// root, which would drop linked rules git would keep.
		await fs.rm(path.join(project, ".git"), { recursive: true, force: true });
		const sharedClaude = path.join(root, "shared-claude-no-git");
		await writeFile(path.join(sharedClaude, "rules", "keep.md"), "Keep rule.\n");
		await writeFile(path.join(sharedClaude, "rules", ".gitignore"), "*.md\n");
		await fs.symlink(sharedClaude, path.join(project, ".claude"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		expect(result.items.map(rule => rule.name)).toContain("keep");
	});
	test("does not follow a symlinked .gitignore file for linked rules", async () => {
		if (process.platform === "win32") return;
		// Git never follows a symlinked working-tree .gitignore (it reports the link as
		// inaccessible), so a rule the symlink target would ignore must stay visible.
		await writeFile(path.join(project, "shared-ignore"), ".claude/rules/shared/private.md\n");
		await fs.symlink("shared-ignore", path.join(project, ".gitignore"));
		const sharedRules = path.join(root, "shared-rules-symlinked-ignore-file");
		await writeFile(path.join(sharedRules, "private.md"), "Private rule.\n");
		await writeFile(path.join(sharedRules, "keep.md"), "Keep rule.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRules, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});

		const names = result.items.map(rule => rule.name);
		expect(names).toContain("shared:private");
		expect(names).toContain("shared:keep");
	});
	test("resolves and peels rule URLs with the caller's session rules", async () => {
		await writeFile(path.join(project, ".claude", "rules", "api.md"), "Session A rule.\n");
		const result = await loadCapability<Rule>(ruleCapability.id, {
			cwd: project,
			providers: ["claude"],
		});
		const sessionARules = result.items;
		const sessionBRule: Rule = { ...sessionARules[0], content: "Session B rule.\n" };
		setActiveRules([sessionBRule]);

		const handler = new RuleProtocolHandler();
		const resource = await handler.resolve(parseInternalUrl("rule://api"), { rules: sessionARules });
		expect(resource.content.trim()).toBe("Session A rule.");
		expect(await handler.complete("", { rules: sessionARules })).toMatchObject([{ value: "api" }]);
		expect(splitInternalUrlSel("rule://api:80", sessionARules)).toEqual({ path: "rule://api", sel: "80" });
		await expect(handler.resolve(parseInternalUrl("rule://api:80"), { rules: sessionARules })).rejects.toThrow(
			"Unknown rule: api:80",
		);
		const disabledManager = new TtsrManager();
		const { rulebookRules, alwaysApplyRules } = bucketRules(sessionARules, disabledManager, {
			disabledRules: ["api"],
		});
		const visibleRules = [...rulebookRules, ...alwaysApplyRules, ...disabledManager.getRules()];
		await expect(handler.resolve(parseInternalUrl("rule://api"), { rules: visibleRules })).rejects.toThrow(
			"Unknown rule: api",
		);
	});
});
