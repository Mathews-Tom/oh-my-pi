/**
 * The `lsp` tool's action classification, as a dependency-free leaf.
 *
 * Split out of `./index.ts` so the resource permission layer
 * (`tools/permissions/tool-path-targets.ts`) can invert this set without
 * importing the LSP barrel — `lsp/index.ts` now depends on the permission gate
 * to validate server-supplied workspace edits, and pulling the barrel back in
 * from the permission side would close that into an import cycle.
 */

/**
 * LSP actions that do not mutate the workspace or language-server state.
 * Anything not in this set (rename, code_actions with apply, rename_file,
 * reload, raw request, etc.) is classified as write-tier.
 */
export const LSP_READONLY_ACTIONS: ReadonlySet<string> = new Set([
	"diagnostics",
	"definition",
	"type_definition",
	"implementation",
	"references",
	"hover",
	"symbols",
	"status",
	"capabilities",
]);
