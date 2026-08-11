import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Settings } from "../../src/config/settings";
import { loadPermissionsConfig } from "../../src/tools/permissions/config";
import { excludeDenyReadDescendants } from "../../src/tools/permissions/tool-path-targets";
import type { PermissionPolicy, PermissionRoots } from "../../src/tools/permissions/types";

let workspace: string;

function settingsOf(overrides: Record<string, unknown>): Settings {
	return {
		get(key: string): unknown {
			return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
		},
	} as unknown as Settings;
}

function policyFor(overrides: Record<string, unknown>): PermissionPolicy {
	const policy = loadPermissionsConfig(settingsOf(overrides));
	if (!policy) throw new Error("expected a policy");
	return policy;
}

function rootsOf(): PermissionRoots {
	return { cwd: workspace, additionalDirectories: [] };
}

beforeAll(() => {
	workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-grep-descendants-")));
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.mkdirSync(path.join(workspace, "src", "nested"), { recursive: true });
	fs.mkdirSync(path.join(workspace, ".git"), { recursive: true });
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export {};");
	fs.writeFileSync(path.join(workspace, "src", "nested", "deep.ts"), "export {};");
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
	fs.writeFileSync(path.join(workspace, ".git", "config"), "[core]");
});

afterAll(() => {
	fs.rmSync(workspace, { recursive: true, force: true });
});

describe("excludeDenyReadDescendants", () => {
	test("returns null when the policy has no deny.read rules — the common, unaffected case", async () => {
		const files = await excludeDenyReadDescendants(
			workspace,
			policyFor({ "permissions.profile": "workspace" }),
			rootsOf(),
		);
		expect(files).toBeNull();
	});

	test("lists every allowed file and excludes a denied descendant and .git", async () => {
		const files = await excludeDenyReadDescendants(
			workspace,
			policyFor({ "permissions.profile": "strict" }),
			rootsOf(),
		);
		expect(files).not.toBeNull();
		const relative = (files ?? []).map(file => path.relative(workspace, file)).sort();
		expect(relative).toEqual([path.join("src", "main.ts"), path.join("src", "nested", "deep.ts")]);
	});

	test("excludes a custom deny.read rule the same way, including nested matches", async () => {
		const policy = policyFor({ "permissions.profile": "workspace", "permissions.deny.read": ["**/nested/**"] });
		const files = await excludeDenyReadDescendants(workspace, policy, rootsOf());
		expect(files).not.toBeNull();
		const relative = (files ?? []).map(file => path.relative(workspace, file)).sort();
		expect(relative).toEqual([".env", path.join("src", "main.ts")]);
	});
});
