import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Settings } from "../../src/config/settings";
import type { ToolSession } from "../../src/tools";
import { GrepTool } from "../../src/tools/grep";

let workspace: string;

function settingsOf(overrides: Record<string, unknown>): Settings {
	return {
		get(key: string): unknown {
			return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
		},
	} as unknown as Settings;
}

function sessionOf(settingsOverrides: Record<string, unknown>): ToolSession {
	return {
		cwd: workspace,
		hasUI: false,
		settings: settingsOf(settingsOverrides),
		getSessionFile: () => null,
		getSessionSpawns: () => null,
	} as unknown as ToolSession;
}

function textOf(result: { content: Array<{ type: string; text?: string }> }): string {
	return result.content.map(part => part.text ?? "").join("\n");
}

beforeAll(() => {
	workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-grep-deny-")));
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.mkdirSync(path.join(workspace, "private"), { recursive: true });
	fs.writeFileSync(path.join(workspace, "private", "secret.txt"), "PRIVATE=glob-only-probe-c481\n");
	fs.writeFileSync(path.join(workspace, "src", "allowed.txt"), "PUBLIC=glob-visible-probe-c481\n");
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export const marker = 1;\n");
	// A marker that appears nowhere else, so a match on it can only have come
	// from opening this exact denied file.
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=env-only-marker-9f2c\n");
});

afterAll(() => {
	fs.rmSync(workspace, { recursive: true, force: true });
});

describe("GrepTool deny.read descendant exclusion", () => {
	// The finding: a broad recursive root (`path: "."`) passes the
	// pre-execution root check, and native grep's own `glob` filter has no
	// exclusion mechanism, so a `deny.read` descendant gets opened by the
	// recursive search regardless. Directly calling `GrepTool.execute` (as
	// this test does) bypasses the tool wrapper's own post-execution recheck
	// entirely, so a match surfacing here can only be explained by the tool
	// itself having searched a file it never should have opened.
	test("never opens the denied file during a broad recursive search under strict", async () => {
		const tool = new GrepTool(sessionOf({ "permissions.profile": "strict" }));
		const result = await tool.execute("grep-deny-1", { path: ".", pattern: "env-only-marker", gitignore: false });
		expect(textOf(result)).not.toContain("env-only-marker");
		expect(result.details?.files ?? []).not.toContain(".env");
	});

	test("still finds a match in an allowed file under the same strict search", async () => {
		const tool = new GrepTool(sessionOf({ "permissions.profile": "strict" }));
		const result = await tool.execute("grep-deny-2", { path: ".", pattern: "marker", gitignore: false });
		expect(textOf(result)).toContain("main.ts");
	});

	test("opens the denied file once permissions.profile is off", async () => {
		const tool = new GrepTool(sessionOf({ "permissions.profile": "off" }));
		const result = await tool.execute("grep-deny-3", { path: ".", pattern: "env-only-marker", gitignore: false });
		expect(textOf(result)).toContain("env-only-marker");
	});

	test("never opens a denied descendant during a globbed recursive search", async () => {
		const tool = new GrepTool(
			sessionOf({
				"permissions.profile": "workspace",
				"permissions.deny.read": ["**/secret.txt"],
			}),
		);
		const result = await tool.execute("grep-deny-glob", {
			path: "*.txt",
			pattern: "probe-c481",
			gitignore: false,
		});
		expect(textOf(result)).toContain("allowed.txt");
		expect(textOf(result)).not.toContain("secret.txt");
	});
});
