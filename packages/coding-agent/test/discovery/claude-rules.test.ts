import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { getCapability, loadCapability } from "@oh-my-pi/pi-coding-agent/capability";
import { clearCache as clearFsCache } from "@oh-my-pi/pi-coding-agent/capability/fs";
import { type Rule, ruleCapability } from "@oh-my-pi/pi-coding-agent/capability/rule";
import { bucketRules } from "@oh-my-pi/pi-coding-agent/capability/rule-buckets";
import type { LoadContext, Provider } from "@oh-my-pi/pi-coding-agent/capability/types";
import { TtsrManager } from "@oh-my-pi/pi-coding-agent/export/ttsr";
import "@oh-my-pi/pi-coding-agent/discovery";

async function writeFile(filePath: string, content: string): Promise<void> {
	await fs.mkdir(path.dirname(filePath), { recursive: true });
	await fs.writeFile(filePath, content);
}

function claudeRulesProvider(): Provider<Rule> {
	const capability = getCapability(ruleCapability.id);
	if (!capability) throw new Error("rules capability missing");
	const provider = capability.providers.find(p => p.id === "claude");
	if (!provider) throw new Error("claude rules provider missing");
	return provider as Provider<Rule>;
}

describe("Claude Code rule discovery", () => {
	let root = "";
	let home = "";
	let project = "";
	let originalHome: string | undefined;

	beforeEach(async () => {
		clearFsCache();
		root = await fs.mkdtemp(path.join(os.tmpdir(), "omp-claude-rules-"));
		home = path.join(root, "home");
		project = path.join(root, "project");
		originalHome = process.env.HOME;
		process.env.HOME = home;
		vi.spyOn(os, "homedir").mockReturnValue(home);
		await fs.mkdir(path.join(project, ".git"), { recursive: true });
	});

	afterEach(async () => {
		clearFsCache();
		vi.restoreAllMocks();
		if (originalHome === undefined) {
			delete process.env.HOME;
		} else {
			process.env.HOME = originalHome;
		}
		await fs.rm(root, { recursive: true, force: true });
	});

	function ctx(): LoadContext {
		return { cwd: project, home, repoRoot: project };
	}

	test("loads user and project .claude/rules markdown files recursively", async () => {
		await writeFile(
			path.join(home, ".claude", "rules", "style.md"),
			"---\ndescription: Prefer explicit names\nglobs:\n  - '**/*.ts'\nalwaysApply: true\n---\nUse explicit names.\n",
		);
		await writeFile(
			path.join(project, ".claude", "rules", "nested", "security.mdc"),
			"---\ndescription: Validate inputs\nglobs: '**/*.tsx'\nalwaysApply: false\n---\nValidate user input.\n",
		);
		await writeFile(path.join(project, ".claude", "rules", "ignored.txt"), "Do not load this.\n");

		const result = await claudeRulesProvider().load(ctx());
		const rules = result.items;

		expect(result.warnings).toEqual([]);
		expect(rules.map(rule => rule.name).sort()).toEqual(["nested:security", "style"]);
		expect(rules.find(rule => rule.name === "style")).toMatchObject({
			content: "Use explicit names.",
			description: "Prefer explicit names",
			globs: ["**/*.ts"],
			alwaysApply: true,
			_source: { level: "user", provider: "claude" },
		});
		expect(rules.find(rule => rule.name === "nested:security")).toMatchObject({
			content: "Validate user input.",
			description: "Validate inputs",
			globs: ["**/*.tsx"],
			alwaysApply: false,
			_source: { level: "project", provider: "claude" },
		});
	});

	test("plain Claude rules are always applied instead of dropped", async () => {
		await writeFile(path.join(project, ".claude", "rules", "plain.md"), "Use short names for test fixtures.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });
		const buckets = bucketRules(result.items, new TtsrManager());

		expect(buckets.alwaysApplyRules.map(rule => rule.name)).toEqual(["plain"]);
		expect(buckets.alwaysApplyRules[0]?.content).toBe("Use short names for test fixtures.\n");
		expect(buckets.rulebookRules).toEqual([]);
	});

	test("glob-only Claude rules stay addressable through the rulebook", async () => {
		await writeFile(
			path.join(project, ".claude", "rules", "typescript.md"),
			"---\nglobs: '**/*.ts'\n---\nUse strict types.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });
		const buckets = bucketRules(result.items, new TtsrManager());

		expect(buckets.alwaysApplyRules).toEqual([]);
		expect(buckets.rulebookRules).toHaveLength(1);
		expect(buckets.rulebookRules[0]).toMatchObject({
			name: "typescript",
			description: "Claude Code rule scoped to **/*.ts",
			globs: ["**/*.ts"],
		});
	});

	test("paths-only Claude rules stay path scoped instead of always applying", async () => {
		await writeFile(
			path.join(project, ".claude", "rules", "api.md"),
			"---\npaths:\n  - 'src/api/**/*.ts'\n---\nValidate API inputs.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });
		const buckets = bucketRules(result.items, new TtsrManager());

		expect(buckets.alwaysApplyRules).toEqual([]);
		expect(buckets.rulebookRules).toHaveLength(1);
		expect(buckets.rulebookRules[0]).toMatchObject({
			name: "api",
			description: "Claude Code rule scoped to src/api/**/*.ts",
			globs: ["src/api/**/*.ts"],
		});
	});

	test("preserves brace expansions in single-string Claude rule globs", async () => {
		await writeFile(
			path.join(project, ".claude", "rules", "typescript.md"),
			"---\npaths: '**/*.{ts,tsx}'\n---\nUse strict types.\n",
		);

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });
		const rule = result.items.find(item => item.name === "typescript");

		expect(rule).toMatchObject({
			globs: ["**/*.{ts,tsx}"],
			description: "Claude Code rule scoped to **/*.{ts,tsx}",
		});
	});

	test("nested Claude rules keep path-qualified names", async () => {
		await writeFile(path.join(project, ".claude", "rules", "frontend", "style.md"), "Frontend style.\n");
		await writeFile(path.join(project, ".claude", "rules", "backend", "style.md"), "Backend style.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });

		expect(result.items.map(rule => rule.name).sort()).toEqual(["backend:style", "frontend:style"]);
		expect(result.items.find(rule => rule.name === "frontend:style")?.content).toBe("Frontend style.\n");
		expect(result.items.find(rule => rule.name === "backend:style")?.content).toBe("Backend style.\n");
	});

	test("loads Claude rules from symlinked directories", async () => {
		const sharedRulesDir = path.join(root, "shared-claude-rules");
		await writeFile(path.join(sharedRulesDir, "api.md"), "Shared API standards.\n");
		await fs.mkdir(path.join(project, ".claude", "rules"), { recursive: true });
		await fs.symlink(sharedRulesDir, path.join(project, ".claude", "rules", "shared"), "dir");

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });

		expect(result.items).toHaveLength(1);
		expect(result.items[0]).toMatchObject({
			name: "shared:api",
			content: "Shared API standards.\n",
			_source: { level: "project", provider: "claude" },
		});
	});

	test("project Claude rules override same-named user rules", async () => {
		await writeFile(path.join(home, ".claude", "rules", "style.md"), "User style.\n");
		await writeFile(path.join(project, ".claude", "rules", "style.md"), "Project style.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });

		expect(result.items).toHaveLength(1);
		expect(result.items[0]).toMatchObject({
			name: "style",
			content: "Project style.\n",
			_source: { level: "project", provider: "claude" },
		});
	});

	test("keeps user rules before project rules except same-name project overrides", async () => {
		await writeFile(path.join(home, ".claude", "rules", "personal.md"), "Personal style.\n");
		await writeFile(path.join(home, ".claude", "rules", "shared.md"), "User shared style.\n");
		await writeFile(path.join(project, ".claude", "rules", "project.md"), "Project style.\n");
		await writeFile(path.join(project, ".claude", "rules", "shared.md"), "Project shared style.\n");

		const result = await loadCapability<Rule>(ruleCapability.id, { cwd: project, providers: ["claude"] });

		expect(result.items.map(rule => `${rule._source.level}:${rule.name}`)).toEqual([
			"user:personal",
			"project:project",
			"project:shared",
		]);
		expect(result.items.find(rule => rule.name === "shared")?.content).toBe("Project shared style.\n");
	});
});
