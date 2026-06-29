import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { ThinkingLevel } from "@oh-my-pi/pi-agent-core";
import { FileType, glob } from "@oh-my-pi/pi-natives";
import {
	CONFIG_DIR_NAME,
	getAgentDir,
	getConfigDirName,
	getPluginsDir,
	getProjectDir,
	parseFrontmatter,
	tryParseJson,
} from "@oh-my-pi/pi-utils";
import type { ExtensionModule } from "../capability/extension-module";
import { invalidate as invalidateFsCache, readDirEntries, readFile } from "../capability/fs";
import { parseRuleConditionAndScope, type Rule, type RuleFrontmatter } from "../capability/rule";
import type { Skill, SkillFrontmatter } from "../capability/skill";
import type { LoadContext, LoadResult, SourceMeta } from "../capability/types";
import { parseThinkingLevel } from "../thinking";
import { normalizeToolNames } from "../tools/builtin-names";

import { buildPluginDirRoot } from "./plugin-dir-roots";

/**
 * Standard paths for each config source.
 */
export const SOURCE_PATHS = {
	native: {
		get userBase() {
			return getConfigDirName();
		},
		get userAgent() {
			return `${getConfigDirName()}/agent`;
		},
		projectDir: CONFIG_DIR_NAME,
	},
	claude: {
		userBase: ".claude",
		userAgent: ".claude",
		projectDir: ".claude",
	},
	codex: {
		userBase: ".codex",
		userAgent: ".codex",
		projectDir: ".codex",
	},
	gemini: {
		userBase: ".gemini",
		userAgent: ".gemini",
		projectDir: ".gemini",
	},
	opencode: {
		userBase: ".config/opencode",
		userAgent: ".config/opencode",
		projectDir: ".opencode",
	},
	cursor: {
		userBase: ".cursor",
		userAgent: ".cursor",
		projectDir: ".cursor",
	},
	windsurf: {
		userBase: ".codeium/windsurf",
		userAgent: ".codeium/windsurf",
		projectDir: ".windsurf",
	},
	cline: {
		userBase: ".cline",
		userAgent: ".cline",
		projectDir: null, // Cline uses root-level .clinerules
	},
	github: {
		userBase: null,
		userAgent: null,
		projectDir: ".github",
	},
	vscode: {
		userBase: ".vscode",
		userAgent: ".vscode",
		projectDir: ".vscode",
	},
} as const;

export type SourceId = keyof typeof SOURCE_PATHS;

/**
 * Get user-level path for a source.
 */
export function getUserPath(ctx: LoadContext, source: SourceId, subpath: string): string | null {
	// Native user config is profile-scoped via getAgentDir() (the active profile's
	// agent dir), matching builtin.ts and getMCPConfigPath("user"). External tools
	// (~/.claude, ~/.gemini, …) are intentionally not profile-scoped, so they keep
	// resolving against ctx.home below.
	if (source === "native") return path.join(getAgentDir(), subpath);
	const paths = SOURCE_PATHS[source];
	if (!paths.userAgent) return null;
	return path.join(ctx.home, paths.userAgent, subpath);
}

/**
 * Get project-level path for a source (cwd only).
 */
export function getProjectPath(ctx: LoadContext, source: SourceId, subpath: string): string | null {
	const paths = SOURCE_PATHS[source];
	if (!paths.projectDir) return null;

	return path.join(ctx.cwd, paths.projectDir, subpath);
}

/**
 * Resolve GitHub Copilot CLI's user-global config root. Copilot stores per-user
 * instructions/prompts/agents/MCP under `~/.copilot`, relocatable via the
 * `COPILOT_HOME` env var (mirrors Copilot CLI's `--config-dir`). Falls back to
 * `<home>/.copilot` when the override is unset.
 */
export function resolveCopilotHome(home: string): string {
	const override = process.env.COPILOT_HOME?.trim();
	return override ? override : path.join(home, ".copilot");
}

/**
 * Create source metadata for an item.
 */
export function createSourceMeta(provider: string, filePath: string, level: "user" | "project"): SourceMeta {
	return {
		provider,
		providerName: "", // Filled in by registry
		path: path.resolve(filePath),
		level,
	};
}

export function parseBoolean(value: unknown): boolean | undefined {
	if (typeof value === "boolean") return value;
	if (typeof value === "string") {
		const normalized = value.trim().toLowerCase();
		if (normalized === "true") return true;
		if (normalized === "false") return false;
	}
	return undefined;
}

/**
 * Parse a comma-separated string into an array of trimmed, non-empty strings.
 */
export function parseCSV(value: string): string[] {
	return value
		.split(",")
		.map(s => s.trim())
		.filter(Boolean);
}

/**
 * Parse a value that may be an array of strings or a comma-separated string.
 * Returns undefined if the result would be empty.
 */
export function parseArrayOrCSV(value: unknown): string[] | undefined {
	if (Array.isArray(value)) {
		const filtered = value.filter((item): item is string => typeof item === "string");
		return filtered.length > 0 ? filtered : undefined;
	}
	if (typeof value === "string") {
		const parsed = parseCSV(value);
		return parsed.length > 0 ? parsed : undefined;
	}
	return undefined;
}

function parseRuleGlobs(value: unknown): string[] | undefined {
	if (Array.isArray(value)) {
		const filtered = value.filter((item): item is string => typeof item === "string");
		return filtered.length > 0 ? filtered : undefined;
	}
	return typeof value === "string" ? [value] : undefined;
}

/**
 * Build a canonical rule item from a markdown/markdown-frontmatter document.
 */
export function buildRuleFromMarkdown(
	name: string,
	content: string,
	filePath: string,
	source: SourceMeta,
	options?: {
		ruleName?: string;
		stripNamePattern?: RegExp;
		// When set, path-scope only off the `paths:` field and ignore Cursor-style
		// `globs:`. Claude Code treats only `paths:` as path-specific; a rule without
		// `paths:` loads unconditionally, so a `globs:`-only rule must not be scoped.
		scopeFromPathsOnly?: boolean;
	},
): Rule {
	const { frontmatter, body } = parseFrontmatter(content, { source: filePath });
	const { condition, astCondition, scope } = parseRuleConditionAndScope(frontmatter as RuleFrontmatter);

	// `scopeFromPathsOnly` makes Claude rules path-scope off `paths:` only, ignoring
	// Cursor-style `globs:`. But a TTSR rule (condition/astCondition) uses `globs` as
	// its global path filter (TtsrManager.addRule), so keep `globs:` whenever the rule
	// is conditional — otherwise the condition would fire for unrelated files.
	const isTtsrRule = (condition?.length ?? 0) > 0 || (astCondition?.length ?? 0) > 0;
	const globs =
		options?.scopeFromPathsOnly && !isTtsrRule
			? parseRuleGlobs(frontmatter.paths)
			: (parseRuleGlobs(frontmatter.globs) ?? parseRuleGlobs(frontmatter.paths));

	const resolvedName = options?.ruleName ?? name.replace(options?.stripNamePattern ?? /\.(md|mdc)$/, "");
	const rawMode = frontmatter.interruptMode;
	const interruptMode: Rule["interruptMode"] =
		rawMode === "never" || rawMode === "prose-only" || rawMode === "tool-only" || rawMode === "always"
			? rawMode
			: undefined;
	return {
		name: resolvedName,
		path: filePath,
		content: body,
		globs,
		alwaysApply: parseBoolean(frontmatter.alwaysApply),
		description: typeof frontmatter.description === "string" ? frontmatter.description : undefined,
		condition,
		astCondition,
		scope,
		interruptMode,
		_source: source,
	};
}

/**
 * Parse model field into a prioritized list.
 */
export function parseModelList(value: unknown): string[] | undefined {
	const parsed = parseArrayOrCSV(value);
	if (!parsed) return undefined;
	const normalized = parsed.map(entry => entry.trim()).filter(Boolean);
	return normalized.length > 0 ? normalized : undefined;
}

/** Parsed agent fields from frontmatter (excludes source/filePath/systemPrompt) */
export interface ParsedAgentFields {
	name: string;
	description: string;
	tools?: string[];
	spawns?: string[] | "*";
	model?: string[];
	output?: unknown;
	thinkingLevel?: ThinkingLevel;
	autoloadSkills?: string[];
	readSummarize?: boolean;
	blocking?: boolean;
}

/**
 * Parse agent fields from frontmatter.
 * Returns null if required fields (name, description) are missing.
 */
export function parseAgentFields(frontmatter: Record<string, unknown>): ParsedAgentFields | null {
	const name = typeof frontmatter.name === "string" ? frontmatter.name : undefined;
	const description = typeof frontmatter.description === "string" ? frontmatter.description : undefined;

	if (!name || !description) {
		return null;
	}

	let tools = parseArrayOrCSV(frontmatter.tools);
	if (tools) tools = normalizeToolNames(tools);

	// Subagents with explicit tool lists always need yield
	if (tools && !tools.includes("yield")) {
		tools = [...tools, "yield"];
	}

	// Parse spawns field (array, "*", or CSV)
	let spawns: string[] | "*" | undefined;
	if (frontmatter.spawns === "*") {
		spawns = "*";
	} else if (typeof frontmatter.spawns === "string") {
		const trimmed = frontmatter.spawns.trim();
		if (trimmed === "*") {
			spawns = "*";
		} else {
			spawns = parseArrayOrCSV(trimmed);
		}
	} else {
		spawns = parseArrayOrCSV(frontmatter.spawns);
	}

	// Backward compat: infer spawns: "*" when tools includes "task"
	if (spawns === undefined && tools?.includes("task")) {
		spawns = "*";
	}

	const output = frontmatter.output !== undefined ? frontmatter.output : undefined;
	const rawThinkingLevel =
		typeof frontmatter.thinkingLevel === "string"
			? frontmatter.thinkingLevel
			: typeof frontmatter.thinking === "string"
				? frontmatter.thinking
				: undefined;

	const thinkingLevel = parseThinkingLevel(rawThinkingLevel);
	const model = parseModelList(frontmatter.model);
	const blocking = parseBoolean(frontmatter.blocking);
	const readSummarize = parseBoolean(frontmatter.readSummarize);
	const autoloadSkills = parseArrayOrCSV(frontmatter.autoloadSkills)
		?.map(s => s.trim())
		.filter(Boolean);
	return { name, description, tools, spawns, model, output, thinkingLevel, blocking, autoloadSkills, readSummarize };
}

async function globIf(
	dir: string,
	pattern: string,
	fileType: FileType,
	recursive: boolean = true,
): Promise<Array<{ path: string }>> {
	try {
		const result = await glob({ pattern, path: dir, gitignore: true, hidden: false, fileType, recursive });
		return result.matches;
	} catch {
		return [];
	}
}

export interface ScanSkillsFromDirOptions {
	dir: string;
	providerId: string;
	level: "user" | "project";
	requireDescription?: boolean;
}

// Stable ordering used for skill lists in prompts: name (case-insensitive), then name, then path.
export function compareSkillOrder(aName: string, aPath: string, bName: string, bPath: string): number {
	const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
	const lowerCompare = cmp(aName.toLowerCase(), bName.toLowerCase());
	if (lowerCompare !== 0) return lowerCompare;
	const nameCompare = cmp(aName, bName);
	if (nameCompare !== 0) return nameCompare;
	return cmp(aPath, bPath);
}

export async function scanSkillsFromDir(
	_ctx: LoadContext,
	options: ScanSkillsFromDirOptions,
): Promise<LoadResult<Skill>> {
	const items: Skill[] = [];
	const warnings: string[] = [];
	const { dir, level, providerId, requireDescription = false } = options;

	let entries: fs.Dirent[];
	try {
		entries = await fs.promises.readdir(dir, { withFileTypes: true });
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
			warnings.push(`Failed to read skills directory: ${dir} (${String(error)})`);
		}
		return { items, warnings };
	}
	const loadSkill = async (skillPath: string) => {
		try {
			const content = await readFile(skillPath);
			if (!content) return;
			const { frontmatter, body } = parseFrontmatter(content, { source: skillPath });
			if (frontmatter.enabled === false) {
				return;
			}
			if (requireDescription && !frontmatter.description) {
				return;
			}
			const skillDirName = path.basename(path.dirname(skillPath));
			const rawName = frontmatter.name;
			const name = typeof rawName === "string" ? rawName.trim() || skillDirName : skillDirName;
			items.push({
				name,
				path: skillPath,
				content: body,
				frontmatter: frontmatter as SkillFrontmatter,
				level,
				_source: createSourceMeta(providerId, skillPath, level),
			});
		} catch {
			warnings.push(`Failed to read skill file: ${skillPath}`);
		}
	};

	const work = [];
	for (const entry of entries) {
		if (entry.name.startsWith(".")) continue;
		if (!entry.isDirectory() && !entry.isSymbolicLink()) continue;
		const skillPath = path.join(dir, entry.name, "SKILL.md");
		if (fs.existsSync(skillPath)) {
			work.push(loadSkill(skillPath));
		}
	}
	await Promise.all(work);

	// Deterministic ordering: async file reads complete nondeterministically, so sort after loading.
	items.sort((a, b) => compareSkillOrder(a.name, a.path, b.name, b.path));

	return { items, warnings };
}

/**
 * Expand environment variables in a string.
 * Supports ${VAR} and ${VAR:-default} syntax.
 */
function expandEnvVars(value: string, extraEnv?: Record<string, string>): string {
	return value.replace(/\$\{([^}:]+)(?::-([^}]*))?\}/g, (_, varName: string, defaultValue?: string) => {
		const envValue = extraEnv?.[varName] ?? Bun.env[varName];
		if (envValue !== undefined) return envValue;
		if (defaultValue !== undefined) return defaultValue;
		return `\${${varName}}`;
	});
}

/**
 * Recursively expand environment variables in an object.
 */
export function expandEnvVarsDeep<T>(obj: T, extraEnv?: Record<string, string>): T {
	if (typeof obj === "string") {
		return expandEnvVars(obj, extraEnv) as T;
	}
	if (Array.isArray(obj)) {
		return obj.map(item => expandEnvVarsDeep(item, extraEnv)) as T;
	}
	if (obj !== null && typeof obj === "object") {
		const result: Record<string, unknown> = {};
		for (const [key, value] of Object.entries(obj)) {
			result[key] = expandEnvVarsDeep(value, extraEnv);
		}
		return result as T;
	}
	return obj;
}

function matchesExtension(filePath: string, extensions: string[] | undefined): boolean {
	if (!extensions || extensions.length === 0) return true;
	const extension = path.extname(filePath).slice(1);
	return extensions.includes(extension);
}

async function isDirectoryPath(filePath: string): Promise<boolean> {
	const stat = await fs.promises.stat(filePath).catch(() => null);
	return stat?.isDirectory() ?? false;
}

interface GitignoreRule {
	baseDir: string;
	pattern: string;
	negated: boolean;
	ignoreCase: boolean;
}

interface GitignoreMatch {
	matchedPath: boolean;
	matchedAncestors: string[];
}

async function pathExists(filePath: string): Promise<boolean> {
	return (await fs.promises.lstat(filePath).catch(() => null)) !== null;
}

function normalizedRelativePath(from: string, to: string): string {
	return path.relative(from, to).split(path.sep).join("/");
}

async function findGitignoreRoot(dir: string, base?: string): Promise<string> {
	const startDir = path.resolve(dir);
	// Where to begin the upward search. A symlinked rules dir — or, when the workspace
	// `base` is known, any symlinked ancestor strictly below it (e.g. a symlinked
	// `.claude`) — resolves into a target checkout whose .git/ignore files git never
	// follows. Start at the project-side parent of the highest such symlink so the
	// target's metadata neither anchors the gitignore root nor records target-side ignore
	// files. A symlink AT or above the base (a checkout reached through a symlinked path)
	// stays authoritative, so it is left in the search. Without a `base`, only the start
	// dir itself is checked, preserving the original single-component behavior.
	let walkStart = startDir;
	const boundary = base !== undefined ? path.resolve(base) : undefined;
	let probe = startDir;
	while (true) {
		const probeStat = await fs.promises.lstat(probe).catch(() => null);
		if (probeStat?.isSymbolicLink() === true) {
			walkStart = path.dirname(probe);
		}
		if (boundary === undefined) break;
		const probeParent = path.dirname(probe);
		if (probeParent === probe || probeParent === boundary) break;
		probe = probeParent;
	}
	let current = walkStart;
	let highestIgnoreDir: string | undefined;
	while (true) {
		if (await pathExists(path.join(current, ".git"))) {
			return current;
		}
		if (
			(await Bun.file(path.join(current, ".gitignore")).exists()) ||
			(await Bun.file(path.join(current, ".ignore")).exists())
		) {
			highestIgnoreDir = current;
		}
		const parent = path.dirname(current);
		if (parent === current) return highestIgnoreDir ?? walkStart;
		current = parent;
	}
}

// Bun.Glob metacharacters: outside a bracket expression a gitignore `\X` of one of
// these must STAY escaped so Bun.Glob keeps it literal. Git lets a backslash escape
// ANY character, so every other `\X` outside brackets is a plain literal — drop the
// backslash (e.g. `foo\bar.md` is the logical file `foobar.md`, and leaving `\b` in
// the glob would match nothing).
const GLOB_METACHARACTERS: Record<string, true> = {
	"\\": true,
	"*": true,
	"?": true,
	"[": true,
	"]": true,
	"{": true,
	"}": true,
	"(": true,
	")": true,
	"!": true,
	"+": true,
	"@": true,
	"|": true,
};
function unescapeGitignorePattern(pattern: string): string {
	let result = "";
	let inBracket = false;
	// `]` closes a class only when not in the leading slot; right after `[` it is a
	// literal member (e.g. `[]...]`), so the class keeps parsing past it.
	let atBracketStart = false;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\" && i + 1 < pattern.length) {
			const next = pattern[i + 1] as string;
			// Inside a `[...]` class, backslash escapes carry bracket-local meaning
			// (e.g. `[a\-z]` is the literals a, -, z — not the range a-z), so keep them
			// verbatim for Bun.Glob's class parser. Outside brackets, keep the escape
			// only for glob metacharacters; otherwise drop it.
			result += inBracket || GLOB_METACHARACTERS[next] ? `\\${next}` : next;
			i++;
			if (inBracket) atBracketStart = false;
			continue;
		}
		if (!inBracket) {
			if (ch === "[") {
				inBracket = true;
				atBracketStart = true;
			}
			result += ch;
			continue;
		}
		if (ch === "]" && !atBracketStart) inBracket = false;
		result += ch;
		atBracketStart = false;
	}
	return result;
}

function trimGitignoreTrailingSpaces(pattern: string): string {
	let end = pattern.length;
	while (end > 0 && pattern[end - 1] === " ") {
		let backslashCount = 0;
		for (let i = end - 2; i >= 0 && pattern[i] === "\\"; i--) {
			backslashCount++;
		}
		if (backslashCount % 2 === 1) break;
		end--;
	}
	return pattern.slice(0, end);
}
async function loadIgnoreFile(
	rules: GitignoreRule[],
	filePath: string,
	baseDir: string,
	ignoreCase: boolean,
	skipSymlink = false,
): Promise<void> {
	// Git never follows a symlinked working-tree .gitignore/.ignore file
	// (https://git-scm.com/docs/gitignore#_notes); skip it so a linked rule tree filtered
	// by a symlinked ignore file keeps the rules git would leave visible. Configured
	// ignore sources (core.excludesFile, .git/info/exclude) are read by path and remain
	// followed.
	if (skipSymlink && (await fs.promises.lstat(filePath).catch(() => null))?.isSymbolicLink()) {
		return;
	}
	const ignoreFile = Bun.file(filePath);
	if (!(await ignoreFile.exists())) return;
	const lines = (await ignoreFile.text()).split(/\r?\n/);
	for (const line of lines) {
		if (line.trim().length === 0 || line.startsWith("#")) continue;
		const negated = line.startsWith("!");
		const pattern = unescapeGitignorePattern(trimGitignoreTrailingSpaces(negated ? line.slice(1) : line));
		if (pattern) rules.push({ baseDir, pattern, negated, ignoreCase });
	}
}

async function resolveGitDir(rootDir: string): Promise<string | undefined> {
	const dotGitPath = path.join(rootDir, ".git");
	const stat = await fs.promises.lstat(dotGitPath).catch(() => null);
	if (stat?.isDirectory()) return dotGitPath;
	if (!stat?.isFile()) return undefined;
	const text = await Bun.file(dotGitPath)
		.text()
		.catch(() => null);
	const match = text ? /^gitdir:\s*(.+)\s*$/im.exec(text) : null;
	if (!match?.[1]) return undefined;
	return path.resolve(rootDir, match[1].trim());
}

async function resolveGitExcludeFile(rootDir: string): Promise<string | undefined> {
	try {
		const child = Bun.spawn(["git", "-C", rootDir, "rev-parse", "--git-path", "info/exclude"], {
			stdout: "pipe",
			stderr: "pipe",
		});
		const [exitCode, text] = await Promise.all([
			child.exited,
			new Response(child.stdout as ReadableStream<Uint8Array>).text(),
		]);
		if (exitCode === 0) {
			const gitPath = text.trim();
			if (gitPath) return path.isAbsolute(gitPath) ? gitPath : path.resolve(rootDir, gitPath);
		}
	} catch {}
	const gitDir = await resolveGitDir(rootDir);
	return gitDir ? path.join(gitDir, "info", "exclude") : undefined;
}

function expandHomePath(filePath: string): string {
	if (filePath === "~") return os.homedir();
	if (filePath.startsWith("~/")) return path.join(os.homedir(), filePath.slice(2));
	return filePath;
}

async function configuredGlobalGitignorePath(): Promise<string | undefined> {
	const configCandidates = [
		path.join(os.homedir(), ".gitconfig"),
		path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "git", "config"),
	];
	for (const configPath of configCandidates) {
		const text = await Bun.file(configPath)
			.text()
			.catch(() => null);
		if (!text) continue;
		let inCore = false;
		for (const rawLine of text.split(/\r?\n/)) {
			const line = rawLine.trim();
			if (!line || line.startsWith("#") || line.startsWith(";")) continue;
			const sectionMatch = /^\[(.+)\]$/.exec(line);
			if (sectionMatch) {
				inCore = sectionMatch[1]?.trim().toLowerCase() === "core";
				continue;
			}
			if (!inCore) continue;
			const match = /^excludesFile\s*=\s*(.+)$/.exec(line);
			if (match?.[1]) return expandHomePath(match[1].trim());
		}
	}
	return undefined;
}
async function gitignorePath(rootDir: string): Promise<string | null> {
	try {
		const child = Bun.spawn(["git", "-C", rootDir, "config", "--path", "core.excludesFile"], {
			stdout: "pipe",
			stderr: "pipe",
		});
		const [exitCode, text] = await Promise.all([
			child.exited,
			new Response(child.stdout as ReadableStream<Uint8Array>).text(),
		]);
		if (exitCode === 0) {
			const configured = text.trim();
			if (!configured) return null;
			const expanded = expandHomePath(configured);
			return path.isAbsolute(expanded) ? expanded : path.resolve(rootDir, expanded);
		}
	} catch {}
	const configured = await configuredGlobalGitignorePath();
	if (configured) return configured;
	const configHome = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
	return path.join(configHome, "git", "ignore");
}

async function resolveGitIgnoreCase(rootDir: string): Promise<boolean> {
	try {
		const child = Bun.spawn(["git", "-C", rootDir, "config", "--bool", "core.ignoreCase"], {
			stdout: "pipe",
			stderr: "pipe",
		});
		const [exitCode, text] = await Promise.all([
			child.exited,
			new Response(child.stdout as ReadableStream<Uint8Array>).text(),
		]);
		if (exitCode !== 0) return false;
		const normalized = text.trim().toLowerCase();
		return normalized === "true" || normalized === "yes" || normalized === "on" || normalized === "1";
	} catch {
		return false;
	}
}

type GitignoreRulesCache = Map<string, Promise<GitignoreRule[]>>;

async function loadGitignoreRules(
	rootDir: string,
	targetDir: string,
	cache?: GitignoreRulesCache,
): Promise<GitignoreRule[]> {
	if (!cache) return computeGitignoreRules(rootDir, targetDir);
	const key = `${path.resolve(rootDir)}\u0000${path.resolve(targetDir)}`;
	const existing = cache.get(key);
	if (existing) return existing;
	const promise = computeGitignoreRules(rootDir, targetDir);
	cache.set(key, promise);
	return promise;
}

async function computeGitignoreRules(rootDir: string, targetDir: string): Promise<GitignoreRule[]> {
	const rules: GitignoreRule[] = [];
	const ignoreCase = await resolveGitIgnoreCase(rootDir);
	const globalIgnore = await gitignorePath(rootDir);
	if (globalIgnore) await loadIgnoreFile(rules, globalIgnore, rootDir, ignoreCase);
	const gitExcludeFile = await resolveGitExcludeFile(rootDir);
	if (gitExcludeFile) await loadIgnoreFile(rules, gitExcludeFile, rootDir, ignoreCase);
	const directories: string[] = [];
	let current = rootDir;
	while (true) {
		directories.push(current);
		if (path.resolve(current) === path.resolve(targetDir)) break;
		const nextSegment = path.relative(current, targetDir).split(path.sep)[0] ?? "";
		const next = path.join(current, nextSegment);
		if (next === current || !path.relative(current, targetDir)) break;
		current = next;
	}
	// Git does not follow symbolic links when reading .gitignore/.ignore files
	// (https://git-scm.com/docs/gitignore#_notes). A per-directory ignore file below a
	// symlinked directory is only reachable through that symlink, so stop the walk
	// there to match native ignore semantics for linked rule directories. The ignore
	// root itself may legitimately be reached through a symlinked checkout path
	// (e.g. /tmp/link -> /real/repo); its own ignore files are still authoritative.
	const realDirectories: string[] = [];
	for (let i = 0; i < directories.length; i++) {
		const dir = directories[i];
		if (i > 0) {
			const stat = await fs.promises.lstat(dir).catch(() => null);
			if (stat?.isSymbolicLink()) break;
		}
		realDirectories.push(dir);
	}
	for (const dir of realDirectories) {
		await loadIgnoreFile(rules, path.join(dir, ".gitignore"), dir, ignoreCase, true);
	}
	for (const dir of realDirectories) {
		await loadIgnoreFile(rules, path.join(dir, ".ignore"), dir, ignoreCase, true);
	}
	return rules;
}

const POSIX_CHARACTER_CLASS_MAP: Record<string, string> = {
	alnum: "A-Za-z0-9",
	alpha: "A-Za-z",
	blank: " \t",
	digit: "0-9",
	graph: "!-~",
	lower: "a-z",
	print: " -~",
	punct: "][\\\\!\"#$%&'()*+,./:;<=>?@\\[^_`{|}~-",
	// POSIX space = space, tab, newline, vertical tab, form feed, carriage return; Git's
	// [[:space:]] matches all of them in filenames, so emit the full set (not just space/tab).
	space: " \t\n\u000b\f\r",
	upper: "A-Z",
	cntrl: "\u0000-\u001F\u007F",
	xdigit: "A-Fa-f0-9",
};

function normalizePosixCharacterClasses(pattern: string): string {
	// POSIX bracket classes are only meaningful inside a bracket expression, e.g.
	// `[[:upper:]]`. A bare `[:upper:]` is an ordinary bracket expression matching one
	// of the literal characters `:uper`, so it must be left untranslated to match
	// git/fnmatch semantics.
	let result = "";
	let inBracket = false;
	// Track the bracket negation slot: `!`/`^` negate only as the first character, and
	// `]` is literal only there, so a class expansion's leading char may need escaping.
	let atBracketStart = false;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\" && i + 1 < pattern.length) {
			result += ch + pattern[i + 1];
			i++;
			if (inBracket) atBracketStart = false;
			continue;
		}
		if (!inBracket) {
			if (ch === "[") {
				inBracket = true;
				atBracketStart = true;
			}
			result += ch;
			continue;
		}
		if (ch === "[" && pattern[i + 1] === ":") {
			const end = pattern.indexOf(":]", i + 2);
			if (end !== -1) {
				const className = pattern.slice(i + 2, end);
				const replacement = POSIX_CHARACTER_CLASS_MAP[className];
				if (replacement !== undefined) {
					// Position-sensitive bracket metacharacters: `!`/`^` negate only at the bracket
					// start, while `]` is a literal only at the start (elsewhere it closes the class).
					// Escape a class expansion's leading char when its slot would make it special so
					// Bun.Glob keeps it literal (e.g. `[[:graph:]]` -> `!-~`, `[a[:punct:]]` -> `]...`).
					const firstChar = replacement[0];
					const needsEscape = atBracketStart ? firstChar === "!" || firstChar === "^" : firstChar === "]";
					result += needsEscape ? `\\${replacement}` : replacement;
					atBracketStart = false;
					i = end + 1;
					continue;
				}
			}
			result += ch;
			atBracketStart = false;
			continue;
		}
		// A `]` is the class close only when it is NOT in the leading slot; right after
		// `[` it is a literal member (e.g. `[]...]`), so the class — and any later
		// `[:posix:]` token — keeps parsing.
		if (ch === "]" && !atBracketStart) inBracket = false;
		result += ch;
		atBracketStart = false;
	}
	return result;
}

function escapeGitignoreLiteralBraces(pattern: string): string {
	let escaped = "";
	let inCharacterClass = false;
	for (let i = 0; i < pattern.length; i++) {
		const ch = pattern[i];
		if (ch === "\\" && i + 1 < pattern.length) {
			escaped += ch + pattern[i + 1];
			i++;
			continue;
		}
		if (ch === "[" && !inCharacterClass) {
			inCharacterClass = true;
			escaped += ch;
			continue;
		}
		if (ch === "]" && inCharacterClass) {
			inCharacterClass = false;
			escaped += ch;
			continue;
		}
		if (!inCharacterClass && ch === "{") {
			escaped += "[{]";
			continue;
		}
		if (!inCharacterClass && ch === "}") {
			escaped += "[}]";
			continue;
		}
		escaped += ch;
	}
	return escaped;
}

// A leading `!` in a gitignore pattern is the negation prefix, consumed at parse
// time into `GitignoreRule.negated`. Any `!` that survives into the glob is a
// literal path character — an anchored `/!name`, an escaped `\!name`, or a
// slash-bearing `!dir/x` — but `Bun.Glob` treats a leading `!` as negation and
// would then match every unrelated path. Escape it so the glob stays literal. A
// `!` after a `**/` prefix (or anywhere but the start) is already literal to
// `Bun.Glob` and is left untouched.
function escapeGlobLeadingBang(pattern: string): string {
	return pattern.startsWith("!") ? `\\${pattern}` : pattern;
}

function gitignoreRuleMatch(
	rule: GitignoreRule,
	filePath: string,
	options?: { treatAsDirectory?: boolean },
): GitignoreMatch | undefined {
	const relativePath = normalizedRelativePath(rule.baseDir, filePath);
	if (!relativePath || relativePath.startsWith("../")) return undefined;

	const anchored = rule.pattern.startsWith("/");
	const rawPattern = anchored ? rule.pattern.slice(1) : rule.pattern;
	const directoryOnly = rawPattern.endsWith("/");
	const normalizedPattern = rawPattern.replace(/\/+$/, "");
	const basePattern = escapeGlobLeadingBang(
		escapeGitignoreLiteralBraces(
			normalizePosixCharacterClasses(
				normalizedPattern.includes("/") || anchored ? normalizedPattern : `**/${normalizedPattern}`,
			),
		),
	);
	const globPattern = rule.ignoreCase ? basePattern.toLowerCase() : basePattern;
	const candidatePath = rule.ignoreCase ? relativePath.toLowerCase() : relativePath;
	const pathGlob = new Bun.Glob(globPattern);
	const ancestorGlob = new Bun.Glob(globPattern);
	const parts = candidatePath.split("/");
	const matchedAncestors: string[] = [];
	for (let i = 1; i < parts.length; i++) {
		const ancestor = parts.slice(0, i).join("/");
		if (ancestorGlob.match(ancestor)) {
			matchedAncestors.push(path.resolve(rule.baseDir, ancestor));
		}
	}
	const matchedPath = (options?.treatAsDirectory ? true : !directoryOnly) && pathGlob.match(candidatePath);
	if (matchedPath || matchedAncestors.length > 0) return { matchedPath, matchedAncestors };
	return undefined;
}
async function getGitignoreState(
	dir: string,
	relativePath: string,
	options?: { treatAsDirectory?: boolean },
	cache?: GitignoreRulesCache,
	base?: string,
): Promise<{ ignoredPath: boolean; ignoredAncestors: Set<string> }> {
	const filePath = path.join(dir, relativePath);
	const rootDir = await findGitignoreRoot(dir, base);
	const rules = await loadGitignoreRules(rootDir, path.dirname(filePath), cache);
	let ignoredPath = false;
	const ignoredAncestors = new Set<string>();
	for (const rule of rules) {
		const match = gitignoreRuleMatch(rule, filePath, options);
		if (!match) continue;
		if (rule.negated) {
			for (const ancestor of match.matchedAncestors) {
				ignoredAncestors.delete(ancestor);
			}
			if (match.matchedPath) {
				ignoredPath = false;
			}
		} else {
			if (match.matchedPath) {
				ignoredPath = true;
			}
			for (const ancestor of match.matchedAncestors) {
				ignoredAncestors.add(ancestor);
			}
		}
	}
	return { ignoredPath, ignoredAncestors };
}

async function isGitignoredPath(
	dir: string,
	relativePath: string,
	cache?: GitignoreRulesCache,
	base?: string,
): Promise<boolean> {
	const { ignoredPath, ignoredAncestors } = await getGitignoreState(dir, relativePath, undefined, cache, base);
	return ignoredPath || ignoredAncestors.size > 0;
}

async function isGitignoredDirectoryPath(
	dir: string,
	relativePath: string,
	cache?: GitignoreRulesCache,
	base?: string,
): Promise<boolean> {
	const { ignoredPath, ignoredAncestors } = await getGitignoreState(
		dir,
		relativePath,
		{ treatAsDirectory: true },
		cache,
		base,
	);
	return ignoredPath || ignoredAncestors.size > 0;
}

async function discoverLinkedFilesFromDir(
	dir: string,
	extensions: string[] | undefined,
	cache?: GitignoreRulesCache,
	base?: string,
): Promise<Array<{ path: string }>> {
	const matches: Array<{ path: string }> = [];
	async function collectLinkedDir(
		currentDir: string,
		relativeDir: string,
		activeRealDirs: ReadonlySet<string>,
	): Promise<void> {
		if (relativeDir && (await isGitignoredDirectoryPath(dir, relativeDir, cache, base))) return;
		const realDir = await fs.promises.realpath(currentDir).catch(() => currentDir);
		if (activeRealDirs.has(realDir)) return;
		const nextActiveRealDirs = new Set(activeRealDirs);
		nextActiveRealDirs.add(realDir);

		const entries = await readDirEntries(currentDir);
		await Promise.all(
			entries.map(async entry => {
				if (entry.name.startsWith(".") || entry.name === "node_modules") return;
				const entryPath = path.join(currentDir, entry.name);
				const relativePath = path.join(relativeDir, entry.name);
				if (await isDirectoryPath(entryPath)) {
					await collectLinkedDir(entryPath, relativePath, nextActiveRealDirs);
					return;
				}
				if (matchesExtension(entry.name, extensions)) {
					matches.push({ path: relativePath });
				}
			}),
		);
	}

	async function scanForLinkedDirs(currentDir: string, relativeDir: string): Promise<void> {
		const entries = await readDirEntries(currentDir);
		await Promise.all(
			entries.map(async entry => {
				if (entry.name.startsWith(".") || entry.name === "node_modules") return;
				const entryPath = path.join(currentDir, entry.name);
				const relativePath = path.join(relativeDir, entry.name);
				if (!(await isDirectoryPath(entryPath))) return;
				if (await isGitignoredDirectoryPath(dir, relativePath, cache, base)) return;
				if (entry.isSymbolicLink()) {
					await collectLinkedDir(entryPath, relativePath, new Set<string>());
					return;
				}
				await scanForLinkedDirs(entryPath, relativePath);
			}),
		);
	}

	await scanForLinkedDirs(dir, "");

	return matches;
}

// True when `dir` itself or any ancestor up to (but excluding) `base` is a symlink.
// The native glob canonicalizes a symlinked search root and applies the target's own
// ignores; that happens whether the link is the rules dir itself or a parent (e.g. a
// symlinked `.claude`), so both must trigger the unignored rescan + project-logical
// re-filter. `base` (cwd/home) bounds the walk so system links above the workspace
// (e.g. a symlinked /tmp) never count.
async function pathHasSymlinkedAncestor(dir: string, base: string): Promise<boolean> {
	const boundary = path.resolve(base);
	let current = path.resolve(dir);
	while (current !== boundary) {
		const stat = await fs.promises.lstat(current).catch(() => null);
		if (stat?.isSymbolicLink()) return true;
		const parent = path.dirname(current);
		if (parent === current) break; // reached filesystem root without hitting base
		current = parent;
	}
	return false;
}

/**
 * Load files from a directory matching extensions.
 * Uses native glob for fast filesystem scanning with gitignore support.
 */
export async function loadFilesFromDir<T>(
	ctx: LoadContext,
	dir: string,
	provider: string,
	level: "user" | "project",
	options: {
		/** File extensions to match (without dot) */
		extensions?: string[];
		/** Transform file to item (return null to skip) */
		transform: (name: string, content: string, path: string, source: SourceMeta) => T | null;
		/** Whether to recurse into subdirectories (default: false) */
		recursive?: boolean;
		/** Also traverse symlinked directories; native glob intentionally skips them. */
		followSymlinkDirectories?: boolean;
		/** Skip files whose absolute path matches a caller-defined exclusion. */
		excludePath?: (path: string) => boolean | Promise<boolean>;
	},
): Promise<LoadResult<T>> {
	const items: T[] = [];
	const warnings: string[] = [];
	// Build glob pattern based on extensions and recursion
	const { extensions, recursive = false, followSymlinkDirectories = false, excludePath } = options;

	let pattern: string;
	if (extensions && extensions.length > 0) {
		const extPattern = extensions.length === 1 ? extensions[0] : `{${extensions.join(",")}}`;
		pattern = recursive ? `**/*.${extPattern}` : `*.${extPattern}`;
	} else {
		pattern = recursive ? "**/*" : "*";
	}

	// Use native glob for fast scanning with gitignore support
	let matches: Array<{ path: string }>;
	try {
		const result = await glob({
			pattern,
			path: dir,
			gitignore: true,
			hidden: false,
			fileType: FileType.File,
		});
		matches = result.matches;
	} catch {
		// Directory doesn't exist or isn't readable
		return { items, warnings };
	}

	if (followSymlinkDirectories && recursive) {
		const ignoreCache: GitignoreRulesCache = new Map();
		// The native glob already honors ignore rules for a real directory. Only when the
		// rules directory — or any ancestor between it and the workspace base, e.g. a
		// symlinked `.claude` — is a symlink does the walker resolve into the target and
		// bypass project-local logical ignores, so re-filter native matches only in that
		// case, avoiding a per-file git subprocess fan-out for ordinary rule directories.
		const base = level === "user" ? ctx.home : ctx.cwd;
		if (await pathHasSymlinkedAncestor(dir, base)) {
			// The native scanner canonicalizes a symlinked search root and applies the
			// target checkout's own .gitignore, which git does not follow for a symlinked
			// rules directory. Re-scan without ignore handling so target-side ignores
			// cannot drop root-level rules, then apply only the project logical filter.
			try {
				const unfiltered = await glob({
					pattern,
					path: dir,
					gitignore: false,
					hidden: false,
					fileType: FileType.File,
				});
				matches = unfiltered.matches;
			} catch {
				// Keep the gitignore-filtered matches if the rescan fails.
			}
			const filteredNativeMatches = await Promise.all(
				matches.map(async match => ((await isGitignoredPath(dir, match.path, ignoreCache, base)) ? null : match)),
			);
			matches = filteredNativeMatches.filter((match): match is { path: string } => match !== null);
		}
		const linkedMatches = await Promise.all(
			(await discoverLinkedFilesFromDir(dir, extensions, ignoreCache, base)).map(async match =>
				(await isGitignoredPath(dir, match.path, ignoreCache, base)) ? null : match,
			),
		);
		const seen = new Set(matches.map(match => match.path));
		for (const match of linkedMatches) {
			if (!match || seen.has(match.path)) continue;
			seen.add(match.path);
			matches.push(match);
		}
	}

	if (excludePath) {
		const filteredMatches = await Promise.all(
			matches.map(async match => ((await excludePath(path.join(dir, match.path))) ? null : match)),
		);
		matches = filteredMatches.filter((match): match is { path: string } => match !== null);
	}

	// Read all matching files in parallel
	const fileResults = await Promise.all(
		matches.map(async match => {
			const filePath = path.join(dir, match.path);
			const content = await readFile(filePath);
			return { filePath, content };
		}),
	);

	for (const { filePath, content } of fileResults) {
		if (content === null) {
			warnings.push(`Failed to read file: ${filePath}`);
			continue;
		}

		const name = path.basename(filePath);
		const source = createSourceMeta(provider, filePath, level);

		try {
			const item = options.transform(name, content, filePath, source);
			if (item !== null) {
				items.push(item);
			}
		} catch (err) {
			warnings.push(`Failed to parse ${filePath}: ${err}`);
		}
	}
	return { items, warnings };
}

/**
 * Calculate depth of target directory relative to current working directory.
 * Depth is the number of directory levels from cwd to target.
 * - Positive depth: target is above cwd (parent/ancestor)
 * - Zero depth: target is cwd
 * - This uses path splitting to count directory levels
 */
export function calculateDepth(cwd: string, targetDir: string, separator: string): number {
	return cwd.split(separator).length - targetDir.split(separator).length;
}

interface ExtensionModuleManifest {
	extensions?: string[];
}

async function discoverLinkedExtensionModuleFiles(dir: string): Promise<{
	indexFiles: Array<{ path: string }>;
	packageJsonFiles: Array<{ path: string }>;
}> {
	const entries = await readDirEntries(dir);
	const indexFiles: Array<{ path: string }> = [];
	const packageJsonFiles: Array<{ path: string }> = [];

	await Promise.all(
		entries.map(async entry => {
			if (entry.name.startsWith(".") || entry.isDirectory()) return;

			const entryPath = path.join(dir, entry.name);
			const stat = await fs.promises.stat(entryPath).catch(() => null);
			if (!stat?.isDirectory()) return;

			const [packageJsonContent, indexTsContent, indexJsContent] = await Promise.all([
				readFile(path.join(entryPath, "package.json")),
				readFile(path.join(entryPath, "index.ts")),
				readFile(path.join(entryPath, "index.js")),
			]);

			if (packageJsonContent !== null) {
				packageJsonFiles.push({ path: `${entry.name}/package.json` });
			}
			if (indexTsContent !== null) {
				indexFiles.push({ path: `${entry.name}/index.ts` });
			} else if (indexJsContent !== null) {
				indexFiles.push({ path: `${entry.name}/index.js` });
			}
		}),
	);

	return { indexFiles, packageJsonFiles };
}

async function readExtensionModuleManifest(
	_ctx: LoadContext,
	packageJsonPath: string,
): Promise<ExtensionModuleManifest | null> {
	const content = await readFile(packageJsonPath);
	if (!content) return null;

	const pkg = tryParseJson<{ omp?: ExtensionModuleManifest; pi?: ExtensionModuleManifest }>(content);
	const manifest = pkg?.omp ?? pkg?.pi;
	if (manifest && typeof manifest === "object") {
		return manifest;
	}
	return null;
}

/**
 * Discover extension module entry points in a directory.
 *
 * Discovery rules:
 * 1. Direct files: `extensions/*.ts` or `*.js` → load
 * 2. Subdirectory with index: `extensions/<ext>/index.ts` or `index.js` → load
 * 3. Subdirectory with package.json: `extensions/<ext>/package.json` with "omp"/"pi" field → load declared paths
 *
 * No recursion beyond one level. Complex packages must use package.json manifest.
 * Uses native glob for fast filesystem scanning with gitignore support.
 */
export async function discoverExtensionModulePaths(_ctx: LoadContext, dir: string): Promise<string[]> {
	const discovered = new Set<string>();
	// Find all candidate files in parallel using glob
	const [directFiles, globIndexFiles, globPackageJsonFiles, linkedFiles] = await Promise.all([
		// 1. Direct *.ts or *.js files
		globIf(dir, "*.{ts,js}", FileType.File, false),
		// 2. Subdirectory index files
		globIf(dir, "*/index.{ts,js}", FileType.File, false),
		// 3. Subdirectory package.json files
		globIf(dir, "*/package.json", FileType.File, false),
		// Native glob does not follow linked extension directories.
		discoverLinkedExtensionModuleFiles(dir),
	]);
	const indexFiles = [...globIndexFiles, ...linkedFiles.indexFiles];
	const packageJsonFiles = [...globPackageJsonFiles, ...linkedFiles.packageJsonFiles];

	// The native glob walker runs with follow_links=false, so a symlinked extension
	// directory is yielded as a Symlink entry but never descended into: its inner
	// index.{ts,js}/package.json are invisible to the `*/...` patterns above.
	// Detect top-level symlinked directories and synthesize the equivalent subdir
	// matches so the resolution below treats them like real directories. Symlinked
	// *files* already match, because the native file-type filter resolves a
	// symlink's target type for File filters.
	const topLevelEntries = await readDirEntries(dir);
	for (const entry of topLevelEntries) {
		if (!entry.isSymbolicLink()) continue;
		// readDirEntries follows the symlink: a link to a file/dangling link yields [].
		const subEntries = await readDirEntries(path.join(dir, entry.name));
		const hasEntry = (name: string): boolean =>
			subEntries.some(e => e.name === name && (e.isFile() || e.isSymbolicLink()));
		if (hasEntry("package.json")) packageJsonFiles.push({ path: `${entry.name}/package.json` });
		if (hasEntry("index.ts")) indexFiles.push({ path: `${entry.name}/index.ts` });
		else if (hasEntry("index.js")) indexFiles.push({ path: `${entry.name}/index.js` });
	}

	// Process direct files
	for (const match of directFiles) {
		if (match.path.includes("/")) continue;
		discovered.add(path.join(dir, match.path));
	}
	// Track which subdirectories have package.json manifests with declared extensions
	const subdirsWithDeclaredExtensions = new Set<string>();
	for (const match of packageJsonFiles) {
		const subdir = path.dirname(match.path); // e.g., "my-extension"
		const packageJsonPath = path.join(dir, match.path);
		const manifest = await readExtensionModuleManifest(_ctx, packageJsonPath);
		const declaredExtensions =
			manifest?.extensions?.filter((extPath): extPath is string => typeof extPath === "string") ?? [];
		if (declaredExtensions.length === 0) continue;
		subdirsWithDeclaredExtensions.add(subdir);
		const subdirPath = path.join(dir, subdir);
		for (const extPath of declaredExtensions) {
			let resolvedExtPath = path.resolve(subdirPath, extPath);
			const entries = await readDirEntries(resolvedExtPath);
			if (entries.length !== 0) {
				const pluginFilePath = entries.find(
					e => e.isFile() && (e.name === "index.ts" || e.name === "index.js"),
				)?.name;
				resolvedExtPath = pluginFilePath ? path.join(resolvedExtPath, pluginFilePath) : resolvedExtPath;
			}
			const content = await readFile(resolvedExtPath);
			if (content !== null) {
				discovered.add(resolvedExtPath);
			}
		}
	}
	const preferredIndexBySubdir = new Map<string, string>();
	for (const match of indexFiles) {
		if (match.path.split("/").length !== 2) continue;
		const subdir = path.dirname(match.path);
		if (subdirsWithDeclaredExtensions.has(subdir)) continue;
		const existing = preferredIndexBySubdir.get(subdir);
		if (!existing || (existing.endsWith("index.js") && match.path.endsWith("index.ts"))) {
			preferredIndexBySubdir.set(subdir, match.path);
		}
	}
	for (const preferredPath of preferredIndexBySubdir.values()) {
		discovered.add(path.join(dir, preferredPath));
	}
	return [...discovered];
}

/**
 * Derive a stable extension name from a path.
 */
export function getExtensionNameFromPath(extensionPath: string): string {
	const base = extensionPath.replace(/\\/g, "/").split("/").pop() ?? extensionPath;

	if (base === "index.ts" || base === "index.js") {
		const parts = extensionPath.replace(/\\/g, "/").split("/");
		const parent = parts[parts.length - 2];
		return parent ?? base;
	}

	const dot = base.lastIndexOf(".");
	if (dot > 0) {
		return base.slice(0, dot);
	}

	return base;
}

/**
 * Build ExtensionModule items from discovered user/project paths.
 * Shared across providers that expose extension modules via user + project dirs.
 */
export function buildExtensionModuleItems(
	providerId: string,
	userPaths: string[],
	projectPaths: string[],
): ExtensionModule[] {
	return [
		...userPaths.map(extPath => ({
			name: getExtensionNameFromPath(extPath),
			path: extPath,
			level: "user" as const,
			_source: createSourceMeta(providerId, extPath, "user"),
		})),
		...projectPaths.map(extPath => ({
			name: getExtensionNameFromPath(extPath),
			path: extPath,
			level: "project" as const,
			_source: createSourceMeta(providerId, extPath, "project"),
		})),
	];
}

// =============================================================================
// Claude Code Plugin Cache Helpers
// =============================================================================

/**
 * Entry for an installed Claude Code plugin.
 */
export interface ClaudePluginEntry {
	scope: "user" | "project";
	installPath: string;
	version: string;
	installedAt: string;
	lastUpdated: string;
	gitCommitSha?: string;
	enabled?: boolean;
}

/**
 * Claude Code installed_plugins.json registry format.
 */
export interface ClaudePluginsRegistry {
	version: number;
	plugins: Record<string, ClaudePluginEntry[]>;
}

/**
 * Resolved plugin root for loading.
 */
export interface ClaudePluginRoot {
	/** Plugin ID (e.g., "simpleclaude-core@simpleclaude") */
	id: string;
	/** Marketplace name */
	marketplace: string;
	/** Plugin name */
	plugin: string;
	/** Version string */
	version: string;
	/** Absolute path to plugin root */
	path: string;
	/** Whether this is a user or project scope plugin */
	scope: "user" | "project";
}

/**
 * Parse Claude Code installed_plugins.json content.
 */
export function parseClaudePluginsRegistry(content: string): ClaudePluginsRegistry | null {
	const data = tryParseJson<ClaudePluginsRegistry>(content);
	if (!data || typeof data !== "object") return null;
	if (
		typeof data.version !== "number" ||
		!data.plugins ||
		typeof data.plugins !== "object" ||
		Array.isArray(data.plugins)
	)
		return null;
	return data;
}

/**
 * Resolve the active project registry path by walking up from `cwd`.
 *
 * Walk order:
 * 1. Walk up from `cwd` looking for the nearest directory containing `.omp/`.
 *    The first match returns `<dir>/.omp/plugins/installed_plugins.json`.
 * 2. If no `.omp/` is found, rescan from `cwd` upward looking for `.git`.
 *    The git root is used as an anchor: `<gitRoot>/.omp/plugins/installed_plugins.json`.
 * 3. If neither is found, return `null` — no project context is active.
 *
 * This is the single source of truth for "active project root" used by install,
 * uninstall, list, upgrade, discovery, and doctor. Deterministic for a given `cwd`.
 */
export async function resolveActiveProjectRegistryPath(cwd: string): Promise<string | null> {
	// Pass 1: walk up looking for an existing .omp/ directory (nearest wins).
	// Stop before os.homedir() — ~/.omp/ is the user-level config dir, not a project root.
	const homeDir = os.homedir();
	let dir = path.resolve(cwd);
	while (dir !== homeDir) {
		try {
			const stat = await fs.promises.stat(path.join(dir, getConfigDirName()));
			if (stat.isDirectory()) {
				return path.join(dir, getConfigDirName(), "plugins", "installed_plugins.json");
			}
		} catch {
			// not found at this level — continue up
		}
		const parent = path.dirname(dir);
		if (parent === dir) break; // filesystem root
		dir = parent;
	}

	// Pass 2: walk up looking for .git as a fallback anchor.
	dir = path.resolve(cwd);
	while (dir !== homeDir) {
		try {
			await fs.promises.stat(path.join(dir, ".git"));
			return path.join(dir, getConfigDirName(), "plugins", "installed_plugins.json");
		} catch {
			// not found at this level — continue up
		}
		const parent = path.dirname(dir);
		if (parent === dir) break; // filesystem root
		dir = parent;
	}

	return null; // not inside any project
}

/**
 * Like resolveActiveProjectRegistryPath, but falls back to `<cwd>/.omp/plugins/installed_plugins.json`
 * when no project anchor (.omp/ or .git/) is found.
 *
 * Use this when the caller accepts an explicit --scope project so that installing into a freshly
 * bootstrapped directory (no .omp/ or .git/ yet) works: writeInstalledPluginsRegistry auto-creates
 * the directory tree on first write.
 *
 * Returns undefined when cwd is os.homedir() — that path is already the user registry and must
 * never alias as the project registry.
 */
export async function resolveOrDefaultProjectRegistryPath(cwd: string): Promise<string | undefined> {
	const resolved = await resolveActiveProjectRegistryPath(cwd);
	if (resolved) return resolved;
	// Home directory must not be treated as a project root: the fallback path would alias
	// getInstalledPluginsRegistryPath(), causing MarketplaceManager to load the same file
	// as both user and project registry and producing duplicates / disambiguation errors.
	if (path.resolve(cwd) === os.homedir()) return undefined;
	return path.join(cwd, getConfigDirName(), "plugins", "installed_plugins.json");
}

const pluginRootsCache = new Map<string, { roots: ClaudePluginRoot[]; warnings: string[] }>();

/**
 * List all installed Claude Code plugin roots from the plugin cache.
 * Reads ~/.claude/plugins/installed_plugins.json and ~/.omp/plugins/installed_plugins.json,
 * and optionally the nearest project-scoped registry resolved from `cwd`.
 *
 * Results are cached per `home:resolvedProjectPath` key to avoid repeated parsing.
 */
export async function listClaudePluginRoots(
	home: string,
	cwd?: string,
): Promise<{ roots: ClaudePluginRoot[]; warnings: string[] }> {
	const resolvedProjectPath = cwd ? await resolveActiveProjectRegistryPath(cwd) : null;
	const cacheKey = `${home}:${resolvedProjectPath ?? ""}`;
	const cached = pluginRootsCache.get(cacheKey);
	if (cached) return cached;

	const roots: ClaudePluginRoot[] = [];
	const warnings: string[] = [];
	const projectRoots: ClaudePluginRoot[] = [];

	// ── Claude Code registry ──────────────────────────────────────────────────
	const registryPath = path.join(home, ".claude", "plugins", "installed_plugins.json");
	const content = await readFile(registryPath);

	if (content) {
		const registry = parseClaudePluginsRegistry(content);
		if (!registry) {
			warnings.push(`Failed to parse Claude Code plugin registry: ${registryPath}`);
		} else {
			for (const [pluginId, entries] of Object.entries(registry.plugins)) {
				if (!Array.isArray(entries) || entries.length === 0) continue;

				// Parse plugin ID format: "plugin-name@marketplace"
				const atIndex = pluginId.lastIndexOf("@");
				if (atIndex === -1) {
					warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
					continue;
				}

				const pluginName = pluginId.slice(0, atIndex);
				const marketplace = pluginId.slice(atIndex + 1);

				// Process all valid entries, not just the first one.
				// This handles plugins with multiple installs (different scopes/versions).
				for (const entry of entries) {
					if (!entry.installPath || typeof entry.installPath !== "string") {
						warnings.push(`Plugin ${pluginId} entry has no installPath`);
						continue;
					}
					if (entry.enabled === false) continue;

					roots.push({
						id: pluginId,
						marketplace,
						plugin: pluginName,
						version: entry.version || "unknown",
						path: entry.installPath,
						scope: entry.scope || "user",
					});
				}
			}
		}
	}

	// ── OMP installed plugins registry ───────────────────────────────────────
	// OMP registry is authoritative: its entries replace Claude's entries for the same plugin ID.
	// In production `home` is `os.homedir()`, so `getPluginsDir(home)` resolves to the
	// same XDG-aware path the marketplace writer uses (reads and writes always agree).
	// Tests pass a temp dir, which short-circuits the resolver for deterministic isolation.
	const ompRegistryPath = path.join(getPluginsDir(home), "installed_plugins.json");
	const ompContent = await readFile(ompRegistryPath);
	if (ompContent) {
		const ompRegistry = parseClaudePluginsRegistry(ompContent);
		if (ompRegistry) {
			for (const [pluginId, entries] of Object.entries(ompRegistry.plugins)) {
				if (!Array.isArray(entries) || entries.length === 0) continue;

				const atIndex = pluginId.lastIndexOf("@");
				if (atIndex === -1) {
					warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
					continue;
				}
				const pluginName = pluginId.slice(0, atIndex);
				const marketplace = pluginId.slice(atIndex + 1);

				// OMP is authoritative: drop all Claude-sourced entries for this plugin ID
				const filtered = roots.filter(r => r.id !== pluginId);
				roots.length = 0;
				roots.push(...filtered);

				for (const entry of entries) {
					if (!entry.installPath || typeof entry.installPath !== "string") {
						warnings.push(`Plugin ${pluginId} entry has no installPath`);
						continue;
					}
					if (entry.enabled === false) continue;
					// Deduplicate by installPath within same ID
					if (roots.some(r => r.id === pluginId && r.path === entry.installPath)) continue;

					roots.push({
						id: pluginId,
						marketplace,
						plugin: pluginName,
						version: entry.version || "unknown",
						path: entry.installPath,
						scope: entry.scope || "user",
					});
				}
			}
		} else {
			warnings.push(`Failed to parse OMP plugin registry: ${ompRegistryPath}`);
		}
	}

	// ── Project-scoped OMP registry ────────────────────────────────────────
	// Loaded from the nearest .omp/plugins/installed_plugins.json relative to cwd.
	// Project entries take precedence over user entries for the same plugin ID.
	if (resolvedProjectPath) {
		const projectContent = await readFile(resolvedProjectPath);
		if (projectContent) {
			const projectRegistry = parseClaudePluginsRegistry(projectContent);
			if (projectRegistry) {
				for (const [pluginId, entries] of Object.entries(projectRegistry.plugins)) {
					if (!Array.isArray(entries) || entries.length === 0) continue;
					const atIndex = pluginId.lastIndexOf("@");
					if (atIndex === -1) {
						warnings.push(`Invalid plugin ID format (missing @marketplace): ${pluginId}`);
						continue;
					}
					const pluginName = pluginId.slice(0, atIndex);
					const marketplace = pluginId.slice(atIndex + 1);
					for (const entry of entries) {
						if (!entry.installPath || typeof entry.installPath !== "string") {
							warnings.push(`Plugin ${pluginId} entry has no installPath`);
							continue;
						}
						if (entry.enabled === false) continue;
						projectRoots.push({
							id: pluginId,
							marketplace,
							plugin: pluginName,
							version: entry.version || "unknown",
							path: entry.installPath,
							scope: "project",
						});
					}
				}
			} else {
				warnings.push(`Failed to parse project plugin registry: ${resolvedProjectPath}`);
			}
		}
	}

	// Project entries shadow user entries for the same plugin ID.
	if (projectRoots.length > 0) {
		const projectIds = new Set(projectRoots.map(r => r.id));
		const deduped = roots.filter(r => !projectIds.has(r.id));
		roots.length = 0;
		roots.push(...projectRoots, ...deduped);
	}

	// Merge --plugin-dir roots (highest precedence) on every fresh load
	if (injectedPluginDirRoots.length > 0) {
		const injectedIds = new Set(injectedPluginDirRoots.map(r => r.id));
		const filtered = roots.filter(r => !injectedIds.has(r.id));
		roots.length = 0;
		roots.push(...injectedPluginDirRoots, ...filtered);
	}

	const result = { roots, warnings };
	pluginRootsCache.set(cacheKey, result);
	return result;
}

/**
 * Clear the plugin roots cache (useful for testing or when plugins change).
 */
export function clearClaudePluginRootsCache(): void {
	pluginRootsCache.clear();
	preloadedPluginRoots = [...injectedPluginDirRoots];
	// Re-warm preloaded roots asynchronously so sync LSP config reads stay valid
	if (lastPreloadHome) {
		void preloadPluginRoots(lastPreloadHome, getProjectDir());
	}
}

/**
 * Invalidate fs caches for installed-plugin registry files and reset the
 * in-memory plugin roots cache. Used by MarketplaceManager clients after
 * installing/uninstalling/enabling/disabling plugins.
 */
export function clearPluginRootsAndCaches(extraPaths?: readonly string[]): void {
	invalidateFsCache(path.join(os.homedir(), ".claude", "plugins", "installed_plugins.json"));
	invalidateFsCache(path.join(getPluginsDir(), "installed_plugins.json"));
	for (const p of extraPaths ?? []) invalidateFsCache(p);
	clearClaudePluginRootsCache();
}

// ── Preloaded plugin roots (for sync consumers like LSP config) ─────────────
// Populated at startup by preloadPluginRoots(). Read synchronously by
// getPreloadedPluginRoots(). Safe degradation: empty array if not warmed.

let preloadedPluginRoots: ClaudePluginRoot[] = [];
let injectedPluginDirRoots: ClaudePluginRoot[] = [];
let lastPreloadHome: string | undefined;

/**
 * Populate the module-level plugin roots cache for sync consumers.
 * Call during session initialization, after dir resolution completes
 * but before any LSP config is read.
 */
export async function preloadPluginRoots(home: string, cwd?: string): Promise<void> {
	lastPreloadHome = home;
	const { roots } = await listClaudePluginRoots(home, cwd);
	preloadedPluginRoots = roots;
}

/**
 * Get pre-loaded plugin roots synchronously.
 * Returns empty array if preloadPluginRoots() hasn't been called.
 */
export function getPreloadedPluginRoots(): readonly ClaudePluginRoot[] {
	return preloadedPluginRoots;
}

// ── --plugin-dir injection ──────────────────────────────────────────────────

/**
 * Inject synthetic plugin roots from --plugin-dir paths.
 * These are prepended to the cache with highest precedence (before OMP/Claude entries).
 * Must be called before any listClaudePluginRoots() access.
 */
export async function injectPluginDirRoots(home: string, dirs: string[], cwd?: string): Promise<void> {
	const injected: ClaudePluginRoot[] = [];
	for (const dir of dirs) {
		const resolved = path.resolve(dir);
		// Read plugin name from manifest
		let pluginName = path.basename(resolved);
		try {
			const manifestPath = path.join(resolved, ".claude-plugin", "plugin.json");
			const content = await Bun.file(manifestPath).text();
			const manifest = JSON.parse(content);
			if (typeof manifest.name === "string" && manifest.name) {
				pluginName = manifest.name;
			}
		} catch {
			// No manifest or invalid — use directory name
		}

		injected.push(buildPluginDirRoot(resolved, pluginName));
	}

	// Set injected roots BEFORE populating cache so listClaudePluginRoots merges them.
	injectedPluginDirRoots = injected;
	lastPreloadHome = home; // ensure cache-clear re-warm fires even when injectPluginDirRoots was the startup path
	// Clear any stale cache entries (populated before injected roots were set).
	pluginRootsCache.clear();
	// Rebuild — cache miss triggers fresh load that includes both user+project registries
	// and prepends injectedPluginDirRoots at highest precedence.
	const { roots } = await listClaudePluginRoots(home, cwd);
	preloadedPluginRoots = roots;
}
