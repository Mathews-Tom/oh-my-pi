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
} from "@oh-my-pi/pi-coding-agent/lsp/permission-guard";
import type { Command, Location, WorkspaceEdit } from "@oh-my-pi/pi-coding-agent/lsp/types";
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
	it("denies a legacy changes-map edit that targets a denied secret", () => {
		const edit: WorkspaceEdit = { changes: { [fileUri(".env")]: [] } };
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	it("denies a documentChanges text edit that targets a denied secret", () => {
		const edit: WorkspaceEdit = {
			documentChanges: [{ textDocument: { uri: fileUri(".env"), version: 1 }, edits: [] }],
		};
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	// The rename-initiated-from-an-allowed-file scenario the finding names:
	// the *source* file is fine, but the server-returned edit also renames a
	// second file outside every workspace root.
	it("denies a rename op whose destination escapes the workspace", () => {
		const edit: WorkspaceEdit = {
			documentChanges: [
				{ kind: "rename", oldUri: fileUri("src", "main.ts"), newUri: `file://${path.join(outside, "moved.ts")}` },
			],
		};
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(WORKSPACE), "lsp")).toThrow(PermissionDeniedError);
	});

	it("denies a create op that targets a denied secret", () => {
		const edit: WorkspaceEdit = { documentChanges: [{ kind: "create", uri: fileUri(".env.local") }] };
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	it("denies a delete op that targets a denied secret", () => {
		const edit: WorkspaceEdit = { documentChanges: [{ kind: "delete", uri: fileUri(".env") }] };
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).toThrow(PermissionDeniedError);
	});

	it("permits an ordinary in-workspace edit", () => {
		const edit: WorkspaceEdit = { changes: { [fileUri("src", "main.ts")]: [] } };
		expect(() => assertWorkspaceEditAllowed(edit, contextOf(STRICT), "lsp")).not.toThrow();
	});

	it("no-ops entirely under permissions.profile: off", () => {
		const edit: WorkspaceEdit = { changes: { [fileUri(".env")]: [] } };
		expect(() => assertWorkspaceEditAllowed(edit, contextOf({ "permissions.profile": "off" }), "lsp")).not.toThrow();
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
