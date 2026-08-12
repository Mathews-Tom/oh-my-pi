import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Settings } from "../../src/config/settings";
import { loadPermissionsConfig } from "../../src/tools/permissions/config";
import {
	excludeDenyReadDescendants,
	excludeDenyReadSearchTargets,
} from "../../src/tools/permissions/tool-path-targets";
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

	test("filters globbed directory targets while preserving direct file targets", async () => {
		const policy = policyFor({ "permissions.profile": "workspace", "permissions.deny.read": ["**/nested/**"] });
		const targets = await excludeDenyReadSearchTargets(
			[
				{ basePath: path.join(workspace, "src"), glob: "**/*.ts", pathIsFile: false },
				{ basePath: path.join(workspace, ".env"), pathIsFile: true },
			],
			policy,
			rootsOf(),
		);
		expect(targets).not.toBeNull();
		const relative = (targets ?? []).map(target => path.relative(workspace, target.basePath)).sort();
		expect(relative).toEqual([".env", path.join("src", "main.ts")]);
	});

	test("descends through a denied parent directory to reach an allowed descendant carve-out", async () => {
		// `private/**` denies the bare `private` directory spelling itself (no
		// trailing segment matches it), but `private/public/**` should still
		// admit `private/public/file.ts` below it — directory-level pruning on
		// `private`'s own decision must not make that carve-out unreachable.
		fs.mkdirSync(path.join(workspace, "private", "public"), { recursive: true });
		fs.writeFileSync(path.join(workspace, "private", "secret.ts"), "export {};");
		fs.writeFileSync(path.join(workspace, "private", "public", "file.ts"), "export {};");
		try {
			const policy = policyFor({
				"permissions.profile": "workspace",
				"permissions.deny.read": ["private/**"],
				"permissions.allow.read": ["private/public/**"],
			});
			const files = await excludeDenyReadDescendants(workspace, policy, rootsOf());
			expect(files).not.toBeNull();
			const relative = (files ?? []).map(file => path.relative(workspace, file)).sort();
			expect(relative).toEqual([
				".env",
				path.join("private", "public", "file.ts"),
				path.join("src", "main.ts"),
				path.join("src", "nested", "deep.ts"),
			]);
		} finally {
			fs.rmSync(path.join(workspace, "private"), { recursive: true, force: true });
		}
	});

	test("never follows a symlinked directory, matching the native walkers' no-follow semantics", async () => {
		const outside = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-grep-descendants-outside-")));
		fs.writeFileSync(path.join(outside, "leaked.ts"), "export {};");
		fs.symlinkSync(outside, path.join(workspace, "linked-dir"), "dir");
		fs.symlinkSync(path.join(workspace, "src", "main.ts"), path.join(workspace, "linked-file.ts"));
		try {
			const policy = policyFor({ "permissions.profile": "workspace", "permissions.deny.read": ["**/nested/**"] });
			const files = await excludeDenyReadDescendants(workspace, policy, rootsOf());
			expect(files).not.toBeNull();
			const relative = (files ?? []).map(file => path.relative(workspace, file)).sort();
			// The symlinked directory's contents (`leaked.ts`) never appear — it
			// is never followed — but the symlinked file is a single bounded
			// target and is still included, same as passing it explicitly.
			expect(relative).toEqual([".env", "linked-file.ts", path.join("src", "main.ts")]);
		} finally {
			fs.rmSync(path.join(workspace, "linked-dir"), { force: true });
			fs.rmSync(path.join(workspace, "linked-file.ts"), { force: true });
			fs.rmSync(outside, { recursive: true, force: true });
		}
	});
});
