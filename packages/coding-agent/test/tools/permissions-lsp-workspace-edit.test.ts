import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import type { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import {
	assertDiagnosticTargetsAllowed,
	assertLspCommandAllowed,
	assertWorkspaceDiagnosticsAllowed,
	assertWorkspaceEditAllowed,
	filterAuthorizedLocations,
	filterAuthorizedSymbols,
} from "@oh-my-pi/pi-coding-agent/lsp/permission-guard";
import type { Command, Location, SymbolInformation, WorkspaceEdit } from "@oh-my-pi/pi-coding-agent/lsp/types";
import type { ReadonlySessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import { PermissionDeniedError } from "@oh-my-pi/pi-coding-agent/tools/permissions";

let workspace: string;
let outside: string;

function fileUri(...segments: string[]): string {
	return `file://${path.join(workspace, ...segments)}`;
}

function settingsOf(overrides: Record<string, unknown>): Settings {
	return {
		get(key: string): unknown {
			return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
		},
	} as unknown as Settings;
}

function contextOf(overrides: Record<string, unknown>): AgentToolContext {
	const sessionManager = {
		getCwd: () => workspace,
		getAdditionalDirectories: () => [],
		getSessionId: () => "test-session",
	} as unknown as ReadonlySessionManager;
	return { sessionManager, settings: settingsOf(overrides) } as unknown as AgentToolContext;
}

const STRICT = { "permissions.profile": "strict" };
const WORKSPACE = { "permissions.profile": "workspace" };

beforeAll(() => {
	const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-lsp-perm-")));
	workspace = path.join(base, "ws");
	outside = path.join(base, "outside");
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.mkdirSync(outside, { recursive: true });
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export {};");
});

afterAll(() => {
	fs.rmSync(path.dirname(workspace), { recursive: true, force: true });
});

describe("assertWorkspaceEditAllowed", () => {
	it("denies a legacy changes-map edit that targets a denied secret", async () => {
		const edit: WorkspaceEdit = { changes: { [fileUri(".env")]: [] } };
		await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	it("denies a documentChanges text edit that targets a denied secret", async () => {
		const edit: WorkspaceEdit = {
			documentChanges: [{ textDocument: { uri: fileUri(".env"), version: 1 }, edits: [] }],
		};
		await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	// The rename-initiated-from-an-allowed-file scenario the finding names:
	// the *source* file is fine, but the server-returned edit also renames a
	// second file outside every workspace root.
	it("denies a rename op whose destination escapes the workspace", async () => {
		const edit: WorkspaceEdit = {
			documentChanges: [
				{ kind: "rename", oldUri: fileUri("src", "main.ts"), newUri: `file://${path.join(outside, "moved.ts")}` },
			],
		};
		await expect(assertWorkspaceEditAllowed(edit, contextOf(WORKSPACE), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	it("denies a create op that targets a denied secret", async () => {
		const edit: WorkspaceEdit = { documentChanges: [{ kind: "create", uri: fileUri(".env.local") }] };
		await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	it("denies a delete op that targets a denied secret", async () => {
		const edit: WorkspaceEdit = { documentChanges: [{ kind: "delete", uri: fileUri(".env") }] };
		await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	it("permits an ordinary in-workspace edit", async () => {
		const edit: WorkspaceEdit = { changes: { [fileUri("src", "main.ts")]: [] } };
		await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).resolves.toBeUndefined();
	});

	it("no-ops entirely under permissions.profile: off", async () => {
		const edit: WorkspaceEdit = { changes: { [fileUri(".env")]: [] } };
		await expect(
			assertWorkspaceEditAllowed(edit, contextOf({ "permissions.profile": "off" }), "lsp"),
		).resolves.toBeUndefined();
	});

	// The finding: a `delete` resource op names only the directory URI, so the
	// declared-target check above authorizes `config/` itself but never looks
	// inside it — yet `applyWorkspaceEdit` removes the whole subtree with
	// `fs.rm(dirPath, { recursive: true })`. A write-denied descendant must
	// block the delete even though the directory itself is allowed.
	describe("directory delete", () => {
		let deletableDir: string;

		beforeAll(() => {
			deletableDir = path.join(workspace, "deletable");
			fs.mkdirSync(path.join(deletableDir, "nested"), { recursive: true });
			fs.writeFileSync(path.join(deletableDir, "ok.ts"), "export {};");
			fs.writeFileSync(path.join(deletableDir, "nested", ".env"), "SECRET=1");
		});

		afterAll(() => {
			fs.rmSync(deletableDir, { recursive: true, force: true });
		});

		it("denies deleting an allowed directory that contains a write-denied descendant", async () => {
			const edit: WorkspaceEdit = { documentChanges: [{ kind: "delete", uri: `file://${deletableDir}` }] };
			await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
				PermissionDeniedError,
			);
		});

		it("permits deleting a directory whose every descendant is allowed", async () => {
			const cleanDir = path.join(workspace, "deletable-clean");
			fs.mkdirSync(path.join(cleanDir, "nested"), { recursive: true });
			fs.writeFileSync(path.join(cleanDir, "ok.ts"), "export {};");
			fs.writeFileSync(path.join(cleanDir, "nested", "also-ok.ts"), "export {};");
			try {
				const edit: WorkspaceEdit = { documentChanges: [{ kind: "delete", uri: `file://${cleanDir}` }] };
				await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).resolves.toBeUndefined();
			} finally {
				fs.rmSync(cleanDir, { recursive: true, force: true });
			}
		});

		// The finding: the descendant enumeration only ever pushed *files* as
		// write targets, `continue`-ing past every directory entry. A rule
		// matching a nested *directory itself* (e.g. `**/protected`, with
		// nothing individually denied inside it) never fired, so the allowed
		// parent's recursive delete could still remove a directory a
		// `deny.write` rule named explicitly.
		it("denies deleting a directory whose only denied descendant is itself a nested directory", async () => {
			const dirWithProtectedSubdir = path.join(workspace, "deletable-nested-dir");
			fs.mkdirSync(path.join(dirWithProtectedSubdir, "protected"), { recursive: true });
			fs.writeFileSync(path.join(dirWithProtectedSubdir, "ok.ts"), "export {};");
			try {
				const edit: WorkspaceEdit = {
					documentChanges: [{ kind: "delete", uri: `file://${dirWithProtectedSubdir}` }],
				};
				await expect(
					assertWorkspaceEditAllowed(
						edit,
						contextOf({ "permissions.profile": "workspace", "permissions.deny.write": ["**/protected"] }),
						"lsp",
					),
				).rejects.toBeInstanceOf(PermissionDeniedError);
			} finally {
				fs.rmSync(dirWithProtectedSubdir, { recursive: true, force: true });
			}
		});

		it("permits deleting a single denied-descendant-free file (no directory enumeration needed)", async () => {
			const edit: WorkspaceEdit = { documentChanges: [{ kind: "delete", uri: fileUri("src", "main.ts") }] };
			await expect(assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).resolves.toBeUndefined();
		});
	});

	// The finding: `applyWorkspaceEdit` creates every missing parent
	// directory of a `create`/`rename` target with `fs.mkdir(dir, {
	// recursive: true })`, but only the leaf file itself was ever checked. A
	// `deny.write` glob written for the directory (`**/blocked`) never
	// matches the leaf path (`blocked/file.ts`), so the denied directory got
	// silently created on the way to writing the (separately checked) file.
	describe("missing parent directories", () => {
		const DENY_BLOCKED = { ...WORKSPACE, "permissions.deny.write": ["**/blocked"] };

		it("denies a create op whose missing parent directory matches a deny rule", async () => {
			const edit: WorkspaceEdit = { documentChanges: [{ kind: "create", uri: fileUri("blocked", "file.ts") }] };
			await expect(assertWorkspaceEditAllowed(edit, contextOf(DENY_BLOCKED), "lsp")).rejects.toBeInstanceOf(
				PermissionDeniedError,
			);
			expect(fs.existsSync(path.join(workspace, "blocked"))).toBe(false);
		});

		it("denies a rename op whose destination's missing parent directory matches a deny rule", async () => {
			const edit: WorkspaceEdit = {
				documentChanges: [
					{ kind: "rename", oldUri: fileUri("src", "main.ts"), newUri: fileUri("blocked", "moved.ts") },
				],
			};
			await expect(assertWorkspaceEditAllowed(edit, contextOf(DENY_BLOCKED), "lsp")).rejects.toBeInstanceOf(
				PermissionDeniedError,
			);
			expect(fs.existsSync(path.join(workspace, "blocked"))).toBe(false);
		});

		it("permits a create op whose missing parent directory has no denial", async () => {
			try {
				const edit: WorkspaceEdit = {
					documentChanges: [{ kind: "create", uri: fileUri("fresh-nested", "dir", "file.ts") }],
				};
				await expect(assertWorkspaceEditAllowed(edit, contextOf(WORKSPACE), "lsp")).resolves.toBeUndefined();
			} finally {
				fs.rmSync(path.join(workspace, "fresh-nested"), { recursive: true, force: true });
			}
		});

		it("permits a create op whose parent directory already exists (no enumeration needed)", async () => {
			const edit: WorkspaceEdit = { documentChanges: [{ kind: "create", uri: fileUri("src", "new.ts") }] };
			await expect(assertWorkspaceEditAllowed(edit, contextOf(DENY_BLOCKED), "lsp")).resolves.toBeUndefined();
		});
	});

	// The finding: a directory `rename` resource op names only the two
	// directory URIs, so the declared-target check authorized `tree/` and
	// `moved-tree/` but never looked inside — yet `applyWorkspaceEdit` moves
	// the entire subtree with one `fs.rename`. A write-denied descendant must
	// block the rename even though the directory itself is allowed.
	describe("directory rename descendants", () => {
		let renamableDir: string;

		beforeAll(() => {
			renamableDir = path.join(workspace, "tree");
			fs.mkdirSync(renamableDir, { recursive: true });
			fs.writeFileSync(path.join(renamableDir, "ok.ts"), "export {};");
			fs.writeFileSync(path.join(renamableDir, "private.key"), "SECRET");
		});

		afterAll(() => {
			fs.rmSync(renamableDir, { recursive: true, force: true });
		});

		it("denies renaming an allowed directory that contains a write-denied descendant", async () => {
			const edit: WorkspaceEdit = {
				documentChanges: [{ kind: "rename", oldUri: `file://${renamableDir}`, newUri: fileUri("moved-tree") }],
			};
			await expect(
				assertWorkspaceEditAllowed(
					edit,
					contextOf({ ...WORKSPACE, "permissions.deny.write": ["**/*.key"] }),
					"lsp",
				),
			).rejects.toBeInstanceOf(PermissionDeniedError);
			expect(fs.existsSync(renamableDir)).toBe(true);
			expect(fs.existsSync(path.join(workspace, "moved-tree"))).toBe(false);
		});

		it("permits renaming a directory whose every descendant is allowed", async () => {
			const cleanDir = path.join(workspace, "tree-clean");
			fs.mkdirSync(cleanDir, { recursive: true });
			fs.writeFileSync(path.join(cleanDir, "ok.ts"), "export {};");
			try {
				const edit: WorkspaceEdit = {
					documentChanges: [{ kind: "rename", oldUri: `file://${cleanDir}`, newUri: fileUri("tree-clean-moved") }],
				};
				await expect(assertWorkspaceEditAllowed(edit, contextOf(WORKSPACE), "lsp")).resolves.toBeUndefined();
			} finally {
				fs.rmSync(cleanDir, { recursive: true, force: true });
				fs.rmSync(path.join(workspace, "tree-clean-moved"), { recursive: true, force: true });
			}
		});
	});
});

describe("assertLspCommandAllowed", () => {
	it("denies a workspace command whose arguments reference a denied secret", async () => {
		const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: [".env"] };
		await expect(assertLspCommandAllowed(command, contextOf(STRICT), "lsp")).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	it("permits a command with no denied references", async () => {
		const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: ["src/main.ts"] };
		await expect(assertLspCommandAllowed(command, contextOf(STRICT), "lsp")).resolves.toBeUndefined();
	});

	it("does not scan at all when opaqueToolScan is off", async () => {
		const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: [".env"] };
		const context = contextOf({ ...STRICT, "permissions.opaqueToolScan": "off" });
		await expect(assertLspCommandAllowed(command, context, "lsp")).resolves.toBeUndefined();
	});

	describe("opaqueToolScan: prompt", () => {
		const PROMPT = { ...STRICT, "permissions.opaqueToolScan": "prompt" };

		it("fails closed with no interactive UI available", async () => {
			const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: [".env"] };
			await expect(assertLspCommandAllowed(command, contextOf(PROMPT), "lsp")).rejects.toBeInstanceOf(
				PermissionDeniedError,
			);
		});

		it("confirms interactively and allows the command when the user approves", async () => {
			const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: [".env"] };
			const confirm = async () => true;
			const context = { ...contextOf(PROMPT), hasUI: true, ui: { confirm } } as unknown as AgentToolContext;
			await expect(assertLspCommandAllowed(command, context, "lsp")).resolves.toBeUndefined();
		});

		it("confirms interactively and denies the command when the user declines", async () => {
			const command: Command = { title: "Apply fix", command: "internal.applyFix", arguments: [".env"] };
			const confirm = async () => false;
			const context = { ...contextOf(PROMPT), hasUI: true, ui: { confirm } } as unknown as AgentToolContext;
			await expect(assertLspCommandAllowed(command, context, "lsp")).rejects.toBeInstanceOf(PermissionDeniedError);
		});
	});
});

describe("assertDiagnosticTargetsAllowed", () => {
	it("denies a glob-expanded target list that includes a denied secret", () => {
		const targets = [path.join(workspace, "src", "main.ts"), path.join(workspace, ".env")];
		expect(() => assertDiagnosticTargetsAllowed(targets, contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	it("permits an expanded target list with no denied entries", () => {
		const targets = [path.join(workspace, "src", "main.ts")];
		expect(() => assertDiagnosticTargetsAllowed(targets, contextOf(STRICT), "lsp")).not.toThrow();
	});

	it("no-ops entirely under permissions.profile: off", () => {
		const targets = [path.join(workspace, ".env")];
		expect(() =>
			assertDiagnosticTargetsAllowed(targets, contextOf({ "permissions.profile": "off" }), "lsp"),
		).not.toThrow();
	});
});

describe("assertWorkspaceDiagnosticsAllowed", () => {
	it("denies workspace-wide diagnostics under strict, whose secret-deny list is active by default", () => {
		expect(() => assertWorkspaceDiagnosticsAllowed(contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	it("permits workspace-wide diagnostics under workspace, which has no deny.read rules by default", () => {
		expect(() => assertWorkspaceDiagnosticsAllowed(contextOf(WORKSPACE), "lsp")).not.toThrow();
	});

	it("denies workspace-wide diagnostics under workspace once a custom deny.read rule is added", () => {
		const context = contextOf({ ...WORKSPACE, "permissions.deny.read": ["**/private.ts"] });
		expect(() => assertWorkspaceDiagnosticsAllowed(context, "lsp")).toThrow(PermissionDeniedError);
	});

	it("denies workspace-wide diagnostics under workspace with confineReads: true even without deny.read rules", () => {
		const context = contextOf({ ...WORKSPACE, "permissions.confineReads": true });
		expect(() => assertWorkspaceDiagnosticsAllowed(context, "lsp")).toThrow(PermissionDeniedError);
	});

	it("no-ops entirely under permissions.profile: off", () => {
		expect(() => assertWorkspaceDiagnosticsAllowed(contextOf({ "permissions.profile": "off" }), "lsp")).not.toThrow();
	});
});

describe("filterAuthorizedLocations", () => {
	function loc(...segments: string[]): Location {
		return { uri: fileUri(...segments), range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } } };
	}

	it("drops a server-returned location whose file matches a deny rule", () => {
		const locations = [loc("src", "main.ts"), loc(".env")];
		const filtered = filterAuthorizedLocations(locations, contextOf(STRICT), "lsp");
		expect(filtered.map(l => l.uri)).toEqual([fileUri("src", "main.ts")]);
	});

	it("keeps every location when none is denied", () => {
		const locations = [loc("src", "main.ts"), loc("src", "other.ts")];
		const filtered = filterAuthorizedLocations(locations, contextOf(STRICT), "lsp");
		expect(filtered).toHaveLength(2);
	});

	it("no-ops entirely under permissions.profile: off", () => {
		const locations = [loc(".env")];
		const filtered = filterAuthorizedLocations(locations, contextOf({ "permissions.profile": "off" }), "lsp");
		expect(filtered).toHaveLength(1);
	});
});

describe("filterAuthorizedSymbols", () => {
	function symbolAt(...segments: string[]): SymbolInformation {
		return {
			name: "example",
			kind: 12,
			location: {
				uri: fileUri(...segments),
				range: { start: { line: 0, character: 0 }, end: { line: 0, character: 0 } },
			},
		};
	}

	it("drops a workspace-symbol result whose file matches a deny rule", () => {
		const symbols = [symbolAt("src", "main.ts"), symbolAt("private.ts")];
		const context = contextOf({ ...WORKSPACE, "permissions.deny.read": ["**/private.ts"] });
		const filtered = filterAuthorizedSymbols(symbols, context, "lsp");
		expect(filtered.map(s => s.location.uri)).toEqual([fileUri("src", "main.ts")]);
	});

	it("keeps every symbol when none is denied", () => {
		const symbols = [symbolAt("src", "main.ts"), symbolAt("src", "other.ts")];
		const filtered = filterAuthorizedSymbols(symbols, contextOf(STRICT), "lsp");
		expect(filtered).toHaveLength(2);
	});

	it("no-ops entirely under permissions.profile: off", () => {
		const symbols = [symbolAt(".env")];
		const filtered = filterAuthorizedSymbols(symbols, contextOf({ "permissions.profile": "off" }), "lsp");
		expect(filtered).toHaveLength(1);
	});
});
