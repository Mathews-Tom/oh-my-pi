export const BUILTIN_TOOL_NAMES = [
	"read",
	"bash",
	"edit",
	"ast_grep",
	"ast_edit",
	"ask",
	"debug",
	"eval",
	"github",
	"glob",
	"grep",
	"lsp",
	"inspect_image",
	"browser",
	"computer",
	"checkpoint",
	"rewind",
	"security_scan",
	"task",
	"hub",
	"todo",
	"web_search",
	"write",
	"memory_edit",
	"retain",
	"recall",
	"reflect",
	"learn",
	"manage_skill",
] as const;

export type BuiltinToolName = (typeof BUILTIN_TOOL_NAMES)[number];

export const HIDDEN_TOOL_NAMES = ["yield", "goal", "think"] as const;

export type HiddenToolName = (typeof HIDDEN_TOOL_NAMES)[number];

/**
 * Custom tools loaded dynamically outside the synchronous `BUILTIN_TOOLS`/
 * `HIDDEN_TOOLS` factory maps — `generate_image` needs an async
 * `ModelRegistry`/`Model` resolution (`getImageGenTools`), not just a
 * `ToolSession`, so it cannot satisfy those maps' exhaustive `ToolFactory`
 * signature. Still a real, permission-relevant tool name, so it belongs in
 * the resource-permission classification's exhaustiveness set
 * (`CLASSIFIED_TOOL_NAMES`, `tool-path-targets.ts`) without also being
 * required in either factory map.
 */
export const DYNAMIC_TOOL_NAMES = ["generate_image"] as const;

const LEGACY_BUILTIN_TOOL_NAME_ALIASES: ReadonlyMap<string, BuiltinToolName> = new Map([
	["search", "grep"],
	["find", "glob"],
]);

/** Return the canonical tool name for current and legacy built-in tool IDs. */
export function normalizeToolName(name: string): string {
	const normalized = name.toLowerCase();
	return LEGACY_BUILTIN_TOOL_NAME_ALIASES.get(normalized) ?? normalized;
}

/** Normalize and deduplicate tool names while preserving first-seen order. */
export function normalizeToolNames(names: Iterable<string>): string[] {
	const out: string[] = [];
	const seen = new Set<string>();
	for (const name of names) {
		const normalized = normalizeToolName(name);
		if (seen.has(normalized)) continue;
		seen.add(normalized);
		out.push(normalized);
	}
	return out;
}

/** MCP tool names carry the `mcp__<server>_<tool>` prefix minted by `createMCPToolName`. */
export function isMCPToolName(name: string): boolean {
	return name.startsWith("mcp__");
}
