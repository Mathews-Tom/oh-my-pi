import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { getCapability, loadCapability } from "@oh-my-pi/pi-coding-agent/capability";
import { clearCache as clearFsCache } from "@oh-my-pi/pi-coding-agent/capability/fs";
import { type Rule, ruleCapability } from "@oh-my-pi/pi-coding-agent/capability/rule";
import type { LoadContext, Provider } from "@oh-my-pi/pi-coding-agent/capability/types";
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
		expect(rules.map(rule => rule.name).sort()).toEqual(["security", "style"]);
		expect(rules.find(rule => rule.name === "style")).toMatchObject({
			content: "Use explicit names.",
			description: "Prefer explicit names",
			globs: ["**/*.ts"],
			alwaysApply: true,
			_source: { level: "user", provider: "claude" },
		});
		expect(rules.find(rule => rule.name === "security")).toMatchObject({
			content: "Validate user input.",
			description: "Validate inputs",
			globs: ["**/*.tsx"],
			alwaysApply: false,
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
});
