/**
 * Claude Code Provider
 *
 * Loads configuration from .claude directories.
 * Priority: 80 (tool-specific, below builtin but above shared standards)
 */
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { hasFsCode, tryParseJson } from "@oh-my-pi/pi-utils";
import { registerProvider } from "../capability";
import { type ContextFile, contextFileCapability } from "../capability/context-file";
import { type ExtensionModule, extensionModuleCapability } from "../capability/extension-module";
import { readFile } from "../capability/fs";
import { type Hook, hookCapability } from "../capability/hook";
import { type MCPServer, mcpCapability } from "../capability/mcp";
import { type Rule, ruleCapability } from "../capability/rule";
import { type Settings, settingsCapability } from "../capability/settings";
import { type Skill, skillCapability } from "../capability/skill";
import { type SlashCommand, slashCommandCapability } from "../capability/slash-command";
import { type SystemPrompt, systemPromptCapability } from "../capability/system-prompt";
import { type CustomTool, toolCapability } from "../capability/tool";
import type { LoadContext, LoadResult, SourceMeta } from "../capability/types";
import { settings } from "../config/settings";
import {
	buildRuleFromMarkdown,
	calculateDepth,
	createSourceMeta,
	discoverExtensionModulePaths,
	expandEnvVarsDeep,
	getExtensionNameFromPath,
	loadFilesFromDir,
	scanSkillsFromDir,
} from "./helpers";

const PROVIDER_ID = "claude";
const DISPLAY_NAME = "Claude Code";
const PRIORITY = 80;
const CONFIG_DIR = ".claude";

/**
 * Get user-level .claude path.
 */
function getUserClaude(ctx: LoadContext): string {
	return process.env.CLAUDE_CONFIG_DIR || path.join(ctx.home, CONFIG_DIR);
}

/**
 * Get project-level .claude path (cwd only).
 */
function getProjectClaude(ctx: LoadContext): string {
	return path.join(ctx.cwd, CONFIG_DIR);
}

function getProjectClaudePathCandidates(ctx: LoadContext, ...segments: string[]): string[] {
	const paths: string[] = [];
	let current = ctx.cwd;
	while (true) {
		if (current !== ctx.home) {
			paths.push(path.join(current, CONFIG_DIR, ...segments));
		}
		if (current === (ctx.repoRoot ?? ctx.home)) break;
		const parent = path.dirname(current);
		if (parent === current) break;
		current = parent;
	}
	return paths.reverse();
}

function isMissingDirectoryError(error: unknown): boolean {
	return hasFsCode(error, "ENOENT") || hasFsCode(error, "ENOTDIR");
}

// =============================================================================
// MCP Servers
// =============================================================================

async function loadMCPServers(ctx: LoadContext): Promise<LoadResult<MCPServer>> {
	const items: MCPServer[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userClaudeJson = path.join(ctx.home, ".claude.json");
	const userMcpJson = path.join(userBase, "mcp.json");

	const projectBase = path.join(ctx.cwd, CONFIG_DIR);
	const projectMcpJson = path.join(projectBase, ".mcp.json");
	const projectMcpJsonAlt = path.join(projectBase, "mcp.json");

	const userPaths = [
		{ path: userClaudeJson, level: "user" as const },
		{ path: userMcpJson, level: "user" as const },
	];
	const projectPaths = [
		{ path: projectMcpJson, level: "project" as const },
		{ path: projectMcpJsonAlt, level: "project" as const },
	];

	const allPaths = [...userPaths, ...projectPaths];
	const contents = await Promise.all(allPaths.map(({ path }) => readFile(path)));

	const parseMcpServers = (content: string | null, path: string, level: "user" | "project"): MCPServer[] => {
		if (!content) return [];
		const json = tryParseJson<{ mcpServers?: Record<string, unknown> }>(content);
		if (!json?.mcpServers) return [];

		const mcpServers = expandEnvVarsDeep(json.mcpServers);
		return Object.entries(mcpServers).map(([name, config]) => {
			const serverConfig = config as Record<string, unknown>;
			return {
				name,
				timeout: typeof serverConfig.timeout === "number" ? serverConfig.timeout : undefined,
				command: serverConfig.command as string | undefined,
				args: serverConfig.args as string[] | undefined,
				env: serverConfig.env as Record<string, string> | undefined,
				url: serverConfig.url as string | undefined,
				headers: serverConfig.headers as Record<string, string> | undefined,
				transport: serverConfig.type as "stdio" | "sse" | "http" | undefined,
				_source: createSourceMeta(PROVIDER_ID, path, level),
			};
		});
	};

	for (let i = 0; i < userPaths.length; i++) {
		const servers = parseMcpServers(contents[i], userPaths[i].path, userPaths[i].level);
		if (servers.length > 0) {
			items.push(...servers);
			break;
		}
	}

	const projectOffset = userPaths.length;
	for (let i = 0; i < projectPaths.length; i++) {
		const servers = parseMcpServers(contents[projectOffset + i], projectPaths[i].path, projectPaths[i].level);
		if (servers.length > 0) {
			items.push(...servers);
			break;
		}
	}

	return { items, warnings };
}

// =============================================================================
// Context Files (CLAUDE.md)
// =============================================================================

async function loadContextFiles(ctx: LoadContext): Promise<LoadResult<ContextFile>> {
	const items: ContextFile[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userClaudeMd = path.join(userBase, "CLAUDE.md");

	const userContent = await readFile(userClaudeMd);
	if (userContent !== null) {
		items.push({
			path: userClaudeMd,
			content: userContent,
			level: "user",
			_source: createSourceMeta(PROVIDER_ID, userClaudeMd, "user"),
		});
	}

	const projectBase = getProjectClaude(ctx);
	const projectClaudeMd = path.join(projectBase, "CLAUDE.md");
	const projectContent = await readFile(projectClaudeMd);
	if (projectContent !== null) {
		const depth = calculateDepth(ctx.cwd, path.dirname(projectBase), path.sep);
		items.push({
			path: projectClaudeMd,
			content: projectContent,
			level: "project",
			depth,
			_source: createSourceMeta(PROVIDER_ID, projectClaudeMd, "project"),
		});
	}

	return { items, warnings };
}

// =============================================================================
// Rules
// =============================================================================

function hasTtsrMetadata(rule: Rule): boolean {
	return Boolean(
		(rule.condition && rule.condition.length > 0) ||
			(rule.astCondition && rule.astCondition.length > 0) ||
			rule.scope ||
			rule.interruptMode,
	);
}

function scopedClaudeRuleDescription(globs: string[]): string {
	return `Claude Code rule scoped to ${globs.join(", ")}`;
}

function claudeRuleNameFromPath(rulesDir: string, filePath: string): string {
	const relativePath = path.relative(rulesDir, filePath);
	const withoutExtension = relativePath.replace(/\.(md|mdc)$/, "");
	return withoutExtension
		.split(path.sep)
		.map(segment => encodeURIComponent(segment))
		.join(":");
}

function transformClaudeRule(rulesDir: string, content: string, filePath: string, source: SourceMeta): Rule {
	const ruleName = claudeRuleNameFromPath(rulesDir, filePath);
	const rule = buildRuleFromMarkdown(ruleName, content, filePath, source, { ruleName });
	if (rule.alwaysApply === true) return rule;
	if (rule.globs && rule.globs.length > 0) {
		return rule.description ? rule : { ...rule, description: scopedClaudeRuleDescription(rule.globs) };
	}
	if (rule.alwaysApply === false || hasTtsrMetadata(rule)) return rule;
	return { ...rule, alwaysApply: true };
}

interface ClaudeMdExclude {
	pattern: string;
	baseDir: string;
}

function normalizeClaudeExcludePattern(pattern: string, home: string): string {
	const expandedHome = pattern === "~" ? home : pattern.startsWith("~/") ? path.join(home, pattern.slice(2)) : pattern;
	return expandedHome.split(path.sep).join("/");
}

function normalizePathForGlob(filePath: string): string {
	return filePath.split(path.sep).join("/");
}

function matchesClaudeMdExclude(filePath: string, excludes: ClaudeMdExclude[], home: string): boolean {
	const normalizedFilePath = normalizePathForGlob(path.resolve(filePath));
	return excludes.some(({ pattern, baseDir }) => {
		const normalizedPattern = normalizeClaudeExcludePattern(pattern, home);
		const normalizedBaseDir = path.resolve(baseDir);
		const relativeFilePath = normalizePathForGlob(path.relative(normalizedBaseDir, path.resolve(filePath)));
		const isRelativeToBase =
			relativeFilePath.length > 0 && relativeFilePath !== ".." && !relativeFilePath.startsWith("../");

		if (!/[*?[\]{}]/.test(normalizedPattern)) {
			if (path.isAbsolute(normalizedPattern)) {
				return normalizedFilePath === normalizePathForGlob(path.resolve(normalizedPattern));
			}
			return isRelativeToBase && relativeFilePath === normalizedPattern;
		}

		const glob = new Bun.Glob(normalizedPattern);
		// Mirror the literal branch above: an absolute (or `~/`-expanded) pattern matches the
		// absolute path, while a relative pattern is scoped to its settings baseDir. Without this
		// a relative project exclude (e.g. `**/private.md`) would match the absolute path and could
		// suppress unrelated user rules under ~/.claude, since the merged list is reused there too.
		if (path.isAbsolute(normalizedPattern)) return glob.match(normalizedFilePath);
		return isRelativeToBase && glob.match(relativeFilePath);
	});
}

async function readClaudeMdExcludesFromFile(filePath: string, baseDir: string): Promise<ClaudeMdExclude[]> {
	const content = await readFile(filePath);
	if (!content) return [];
	const data = tryParseJson<Record<string, unknown>>(content);
	const excludes = data?.claudeMdExcludes;
	if (!Array.isArray(excludes)) return [];
	return excludes.filter((value): value is string => typeof value === "string").map(pattern => ({ pattern, baseDir }));
}

function getManagedClaudeSettingsDir(): string {
	switch (process.platform) {
		case "darwin":
			return "/Library/Application Support/ClaudeCode";
		case "win32":
			return path.join(process.env.ProgramFiles || "C:\\Program Files", "ClaudeCode");
		default:
			return "/etc/claude-code";
	}
}

async function listManagedClaudeSettingsFiles(): Promise<string[]> {
	const managedDir = getManagedClaudeSettingsDir();
	const files = [path.join(managedDir, "managed-settings.json")];
	const dropInDir = path.join(managedDir, "managed-settings.d");
	try {
		const entries = await fs.readdir(dropInDir, { withFileTypes: true });
		files.push(
			...entries
				.filter(
					entry =>
						!entry.name.startsWith(".") &&
						entry.name.endsWith(".json") &&
						(entry.isFile() || entry.isSymbolicLink()),
				)
				.map(entry => path.join(dropInDir, entry.name))
				.sort((left, right) => left.localeCompare(right)),
		);
	} catch {}
	return files;
}

async function getClaudeMdExcludes(ctx: LoadContext): Promise<ClaudeMdExclude[]> {
	const userBase = getUserClaude(ctx);
	const managedBase = getManagedClaudeSettingsDir();
	const managedSettings = await listManagedClaudeSettingsFiles();
	const projectSettings = getProjectClaudePathCandidates(ctx, "settings.json");
	const projectLocalSettings = getProjectClaudePathCandidates(ctx, "settings.local.json");
	const projectSettingPaths = [...projectSettings, ...projectLocalSettings];
	const [managed, user, ...project] = await Promise.all([
		Promise.all(managedSettings.map(filePath => readClaudeMdExcludesFromFile(filePath, managedBase))),
		readClaudeMdExcludesFromFile(path.join(userBase, "settings.json"), userBase),
		...projectSettingPaths.map(filePath =>
			readClaudeMdExcludesFromFile(filePath, path.dirname(path.dirname(filePath))),
		),
	]);
	return [...managed.flat(), ...user, ...project.flat()];
}

function shouldExcludeClaudeRule(filePath: string, excludes: ClaudeMdExclude[], home: string): boolean {
	return excludes.length > 0 && matchesClaudeMdExclude(filePath, excludes, home);
}

async function loadClaudeRulesFromDir(
	ctx: LoadContext,
	rulesDir: string,
	level: "user" | "project",
	excludes: ClaudeMdExclude[],
): Promise<LoadResult<Rule>> {
	return loadFilesFromDir<Rule>(ctx, rulesDir, PROVIDER_ID, level, {
		extensions: ["md", "mdc"],
		recursive: true,
		followSymlinkDirectories: true,
		excludePath: filePath => shouldExcludeClaudeRule(filePath, excludes, ctx.home),
		transform: (_name, content, filePath, source) => transformClaudeRule(rulesDir, content, filePath, source),
	});
}
async function loadRules(ctx: LoadContext): Promise<LoadResult<Rule>> {
	const items: Rule[] = [];
	const warnings: string[] = [];
	const userRulesDir = path.join(getUserClaude(ctx), "rules");
	const projectRuleDirs = getProjectClaudePathCandidates(ctx, "rules");
	const claudeMdExcludes = await getClaudeMdExcludes(ctx);
	const [userResult, ...projectResults] = await Promise.all([
		loadClaudeRulesFromDir(ctx, userRulesDir, "user", claudeMdExcludes),
		...projectRuleDirs.map(rulesDir => loadClaudeRulesFromDir(ctx, rulesDir, "project", claudeMdExcludes)),
	]);

	const projectItemsFlat = projectResults.flatMap(result => result.items);
	const lastProjectRuleByName = new Map(projectItemsFlat.map(rule => [rule.name, rule]));
	const projectItems = projectItemsFlat.filter(rule => lastProjectRuleByName.get(rule.name) === rule);
	const projectNames = new Set(projectItems.map(rule => rule.name));
	items.push(...userResult.items.filter(rule => !projectNames.has(rule.name)), ...projectItems);
	warnings.push(...(userResult.warnings ?? []), ...projectResults.flatMap(result => result.warnings ?? []));

	return { items, warnings };
}

// =============================================================================
// Skills
// =============================================================================

async function loadSkills(ctx: LoadContext): Promise<LoadResult<Skill>> {
	const userSkillsDir = path.join(getUserClaude(ctx), "skills");

	// Walk up from cwd finding .claude/skills/ in ancestors
	const projectScans: Promise<LoadResult<Skill>>[] = [];
	let current = ctx.cwd;
	while (true) {
		projectScans.push(
			scanSkillsFromDir(ctx, {
				dir: path.join(current, CONFIG_DIR, "skills"),
				providerId: PROVIDER_ID,
				level: "project",
			}),
		);
		if (current === (ctx.repoRoot ?? ctx.home)) break;
		const parent = path.dirname(current);
		if (parent === current) break; // filesystem root
		current = parent;
	}

	const [userResult, ...projectResults] = await Promise.allSettled([
		scanSkillsFromDir(ctx, { dir: userSkillsDir, providerId: PROVIDER_ID, level: "user" }),
		...projectScans,
	]);

	const items: Skill[] = [];
	const warnings: string[] = [];

	if (userResult.status === "fulfilled") {
		items.push(...userResult.value.items);
		warnings.push(...(userResult.value.warnings ?? []));
	} else if (!isMissingDirectoryError(userResult.reason)) {
		warnings.push(`Failed to scan Claude user skills in ${userSkillsDir}: ${String(userResult.reason)}`);
	}

	for (const projectResult of projectResults) {
		if (projectResult.status === "fulfilled") {
			items.push(...projectResult.value.items);
			warnings.push(...(projectResult.value.warnings ?? []));
		} else if (!isMissingDirectoryError(projectResult.reason)) {
			warnings.push(`Failed to scan Claude project skills: ${String(projectResult.reason)}`);
		}
	}

	return { items, warnings };
}

// =============================================================================
// Extension Modules
// =============================================================================

async function loadExtensionModules(ctx: LoadContext): Promise<LoadResult<ExtensionModule>> {
	const items: ExtensionModule[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userExtensionsDir = path.join(userBase, "extensions");
	const projectExtensionsDir = path.join(ctx.cwd, CONFIG_DIR, "extensions");

	const dirsToDiscover: { dir: string; level: "user" | "project" }[] = [
		{ dir: userExtensionsDir, level: "user" },
		{ dir: projectExtensionsDir, level: "project" },
	];

	const pathsByLevel = await Promise.all(
		dirsToDiscover.map(async ({ dir, level }) => {
			const paths = await discoverExtensionModulePaths(ctx, dir);
			return paths.map(extPath => ({ extPath, level }));
		}),
	);

	for (const extensions of pathsByLevel) {
		for (const { extPath, level } of extensions) {
			items.push({
				name: getExtensionNameFromPath(extPath),
				path: extPath,
				level,
				_source: createSourceMeta(PROVIDER_ID, extPath, level),
			});
		}
	}

	return { items, warnings };
}

// =============================================================================
// Slash Commands
// =============================================================================

/**
 * Read the Claude command-loading toggles from settings.
 * Falls back to true (current behavior) when settings are not initialized,
 * e.g. inside discovery unit tests that run without Settings.init().
 */
function readClaudeCommandToggles(): { enableUser: boolean; enableProject: boolean } {
	try {
		return {
			enableUser: settings.get("commands.enableClaudeUser") ?? true,
			enableProject: settings.get("commands.enableClaudeProject") ?? true,
		};
	} catch {
		return { enableUser: true, enableProject: true };
	}
}

function getClaudeRelativeCommandName(commandsDir: string, filePath: string): string {
	return path.relative(commandsDir, filePath).replace(/\.md$/, "");
}

function addClaudeCommandNamespaceAliases(commands: SlashCommand[], commandsDir: string): SlashCommand[] {
	const rootCommands: SlashCommand[] = [];
	const nestedCommands: SlashCommand[] = [];
	const aliases: SlashCommand[] = [];

	for (const command of commands) {
		const relativeName = getClaudeRelativeCommandName(commandsDir, command.path);
		if (!/[\\/]/.test(relativeName)) {
			rootCommands.push(command);
			continue;
		}

		nestedCommands.push(command);
		aliases.push({ ...command, name: relativeName.replace(/[\\/]+/g, ":") });
	}

	return nestedCommands.length === 0 ? commands : [...rootCommands, ...nestedCommands, ...aliases];
}

async function loadSlashCommands(ctx: LoadContext): Promise<LoadResult<SlashCommand>> {
	const items: SlashCommand[] = [];
	const warnings: string[] = [];
	const { enableUser, enableProject } = readClaudeCommandToggles();

	if (enableUser) {
		const userBase = getUserClaude(ctx);
		const userCommandsDir = path.join(userBase, "commands");

		const userResult = await loadFilesFromDir<SlashCommand>(ctx, userCommandsDir, PROVIDER_ID, "user", {
			extensions: ["md"],
			recursive: true,
			transform: (name, content, filePath, source) => ({
				name: name.replace(/\.md$/, ""),
				path: filePath,
				content,
				level: "user",
				_source: source,
			}),
		});

		items.push(...addClaudeCommandNamespaceAliases(userResult.items, userCommandsDir));
		if (userResult.warnings) warnings.push(...userResult.warnings);
	}

	if (enableProject) {
		const projectCommandsDir = path.join(ctx.cwd, CONFIG_DIR, "commands");

		const projectResult = await loadFilesFromDir<SlashCommand>(ctx, projectCommandsDir, PROVIDER_ID, "project", {
			extensions: ["md"],
			recursive: true,
			transform: (name, content, filePath, source) => ({
				name: name.replace(/\.md$/, ""),
				path: filePath,
				content,
				level: "project",
				_source: source,
			}),
		});

		items.push(...addClaudeCommandNamespaceAliases(projectResult.items, projectCommandsDir));
		if (projectResult.warnings) warnings.push(...projectResult.warnings);
	}

	return { items, warnings };
}

// =============================================================================
// Hooks
// =============================================================================

async function loadHooks(ctx: LoadContext): Promise<LoadResult<Hook>> {
	const items: Hook[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userHooksDir = path.join(userBase, "hooks");
	const projectBase = getProjectClaude(ctx);
	const projectHooksDir = path.join(projectBase, "hooks");

	const hookTypes = ["pre", "post"] as const;

	const loadTasks: { dir: string; hookType: "pre" | "post"; level: "user" | "project" }[] = [];
	for (const hookType of hookTypes) {
		loadTasks.push({ dir: path.join(userHooksDir, hookType), hookType, level: "user" });
	}
	for (const hookType of hookTypes) {
		loadTasks.push({ dir: path.join(projectHooksDir, hookType), hookType, level: "project" });
	}

	const results = await Promise.all(
		loadTasks.map(({ dir, hookType, level }) =>
			loadFilesFromDir<Hook>(ctx, dir, PROVIDER_ID, level, {
				transform: (name, _content, path, source) => {
					const toolName = name.replace(/\.(sh|bash|zsh|fish)$/, "");
					return {
						name,
						path,
						type: hookType,
						tool: toolName,
						level,
						_source: source,
					};
				},
			}),
		),
	);

	for (const result of results) {
		items.push(...result.items);
		if (result.warnings) warnings.push(...result.warnings);
	}

	return { items, warnings };
}

// =============================================================================
// Custom Tools
// =============================================================================

async function loadTools(ctx: LoadContext): Promise<LoadResult<CustomTool>> {
	const items: CustomTool[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userToolsDir = path.join(userBase, "tools");

	const userResult = await loadFilesFromDir<CustomTool>(ctx, userToolsDir, PROVIDER_ID, "user", {
		transform: (name, _content, path, source) => {
			const toolName = name.replace(/\.(ts|js|sh|bash|py)$/, "");
			return {
				name: toolName,
				path,
				description: `${toolName} custom tool`,
				level: "user",
				_source: source,
			};
		},
	});

	items.push(...userResult.items);
	if (userResult.warnings) warnings.push(...userResult.warnings);

	const projectBase = getProjectClaude(ctx);
	const projectToolsDir = path.join(projectBase, "tools");

	const projectResult = await loadFilesFromDir<CustomTool>(ctx, projectToolsDir, PROVIDER_ID, "project", {
		transform: (name, _content, path, source) => {
			const toolName = name.replace(/\.(ts|js|sh|bash|py)$/, "");
			return {
				name: toolName,
				path,
				description: `${toolName} custom tool`,
				level: "project",
				_source: source,
			};
		},
	});

	items.push(...projectResult.items);
	if (projectResult.warnings) warnings.push(...projectResult.warnings);

	return { items, warnings };
}

// =============================================================================
// System Prompts
// =============================================================================

async function loadSystemPrompts(ctx: LoadContext): Promise<LoadResult<SystemPrompt>> {
	const items: SystemPrompt[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userSystemMd = path.join(userBase, "SYSTEM.md");

	const content = await readFile(userSystemMd);
	if (content !== null) {
		items.push({
			path: userSystemMd,
			content,
			level: "user",
			_source: createSourceMeta(PROVIDER_ID, userSystemMd, "user"),
		});
	}

	return { items, warnings };
}

// =============================================================================
// Settings
// =============================================================================

async function loadSettings(ctx: LoadContext): Promise<LoadResult<Settings>> {
	const items: Settings[] = [];
	const warnings: string[] = [];

	const userBase = getUserClaude(ctx);
	const userSettingsJson = path.join(userBase, "settings.json");

	const userContent = await readFile(userSettingsJson);
	if (userContent) {
		const data = tryParseJson<Record<string, unknown>>(userContent);
		if (data) {
			items.push({
				path: userSettingsJson,
				data,
				level: "user",
				_source: createSourceMeta(PROVIDER_ID, userSettingsJson, "user"),
			});
		} else {
			warnings.push(`Failed to parse JSON in ${userSettingsJson}`);
		}
	}

	const projectBase = getProjectClaude(ctx);
	const projectSettingsJson = path.join(projectBase, "settings.json");
	const projectContent = await readFile(projectSettingsJson);
	if (projectContent) {
		const data = tryParseJson<Record<string, unknown>>(projectContent);
		if (data) {
			items.push({
				path: projectSettingsJson,
				data,
				level: "project",
				_source: createSourceMeta(PROVIDER_ID, projectSettingsJson, "project"),
			});
		} else {
			warnings.push(`Failed to parse JSON in ${projectSettingsJson}`);
		}
	}

	return { items, warnings };
}

// =============================================================================
// Provider Registration
// =============================================================================

registerProvider<MCPServer>(mcpCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load MCP servers from .claude.json and .claude/mcp.json",
	priority: PRIORITY,
	load: loadMCPServers,
});

registerProvider<ContextFile>(contextFileCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load CLAUDE.md files from .claude/ directories",
	priority: PRIORITY,
	load: loadContextFiles,
});

registerProvider<Skill>(skillCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load skills from .claude/skills/*/SKILL.md",
	priority: PRIORITY,
	load: loadSkills,
});

registerProvider<Rule>(ruleCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load rules from .claude/rules/**/*.{md,mdc}",
	priority: PRIORITY,
	load: loadRules,
});

registerProvider<ExtensionModule>(extensionModuleCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load extension modules from .claude/extensions",
	priority: PRIORITY,
	load: loadExtensionModules,
});

registerProvider<SlashCommand>(slashCommandCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load slash commands from .claude/commands/*.md",
	priority: PRIORITY,
	load: loadSlashCommands,
});

registerProvider<Hook>(hookCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load hooks from .claude/hooks/pre/ and .claude/hooks/post/",
	priority: PRIORITY,
	load: loadHooks,
});

registerProvider<CustomTool>(toolCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load custom tools from .claude/tools/",
	priority: PRIORITY,
	load: loadTools,
});

registerProvider<Settings>(settingsCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load settings from .claude/settings.json",
	priority: PRIORITY,
	load: loadSettings,
});

registerProvider<SystemPrompt>(systemPromptCapability.id, {
	id: PROVIDER_ID,
	displayName: DISPLAY_NAME,
	description: "Load system prompt from .claude/SYSTEM.md",
	priority: PRIORITY,
	load: loadSystemPrompts,
});
