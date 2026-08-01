import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	assertSecurityScanPlanFresh,
	createSecurityScanPlan,
	filterDiffByPermissionPolicy,
	prepareSecurityOutputDirectory,
	type SecurityGitAdapter,
	type SecurityTargetRequest,
	StaleSecurityScanPlanError,
} from "../../src/security";

let temporaryRoot = "";
let repositoryRoot = "";
let stateRoot = "";
let headSha = "a".repeat(40);
let statusText = "";
let refs = new Map<string, string>();

const adapter: SecurityGitAdapter = {
	root: async () => repositoryRoot,
	headSha: async () => headSha,
	resolveRef: async (_cwd, refName) => refs.get(refName) ?? null,
	diffTree: async (_cwd, base, head) => `diff:${base}:${head}`,
	status: async () => statusText,
	files: async () => ["src/a.ts", "src/b.ts"],
	untracked: async () => [],
};

beforeEach(async () => {
	temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-security-preflight-"));
	repositoryRoot = path.join(temporaryRoot, "repo");
	stateRoot = path.join(temporaryRoot, "output");
	await fs.mkdir(path.join(repositoryRoot, "src"), { recursive: true });
	await Bun.write(path.join(repositoryRoot, "src", "a.ts"), "export const a = 1;\n");
	await Bun.write(path.join(repositoryRoot, "src", "b.ts"), "export const b = 2;\n");
	headSha = "a".repeat(40);
	statusText = "";
	refs = new Map([
		["base", "b".repeat(40)],
		["head", "c".repeat(40)],
	]);
});

afterEach(async () => {
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

async function plan(target: SecurityTargetRequest = { kind: "repository" }) {
	return createSecurityScanPlan(
		{
			cwd: repositoryRoot,
			target,
			outputRoot: stateRoot,
			model: { provider: "openai-codex", modelId: "gpt-5.6-sol", thinkingLevel: "xhigh" },
			account: { provider: "openai-codex", credentialId: 17, accountId: "workspace_fixture" },
			config: { security: { enabled: true } },
			workflowFingerprint: "security-reviewer@fixture",
			createdAt: "2026-07-29T00:00:00.000Z",
		},
		adapter,
	);
}

describe("security preflight", () => {
	test("identical inputs produce stable fingerprints and record account/model", async () => {
		const first = await plan();
		const second = await plan();
		expect(first.fingerprint).toBe(second.fingerprint);
		expect(first.account.credentialId).toBe(17);
		expect(first.model).toEqual({ provider: "openai-codex", modelId: "gpt-5.6-sol", thinkingLevel: "xhigh" });
	});

	test("tree mutation makes a plan stale", async () => {
		const created = await plan();
		await Bun.write(path.join(repositoryRoot, "src", "a.ts"), "export const a = 99;\n");
		await expect(
			assertSecurityScanPlanFresh(
				created,
				{ config: { security: { enabled: true } }, workflowFingerprint: "security-reviewer@fixture" },
				adapter,
			),
		).rejects.toBeInstanceOf(StaleSecurityScanPlanError);
	});

	test("knowledge-base mutation makes a plan stale", async () => {
		const kb = path.join(temporaryRoot, "policy.md");
		await Bun.write(kb, "policy v1\n");
		const created = await createSecurityScanPlan(
			{
				cwd: repositoryRoot,
				target: { kind: "repository" },
				knowledgeBasePaths: [kb],
				outputRoot: stateRoot,
				model: { provider: "openai-codex", modelId: "gpt-5.6-sol" },
				account: { provider: "openai-codex", credentialId: 17 },
				config: {},
				workflowFingerprint: "fixture",
			},
			adapter,
		);
		await Bun.write(kb, "policy v2\n");
		await expect(
			assertSecurityScanPlanFresh(created, { config: {}, workflowFingerprint: "fixture" }, adapter),
		).rejects.toBeInstanceOf(StaleSecurityScanPlanError);
	});

	test("relative knowledge-base paths resolve from the repository", async () => {
		await Bun.write(path.join(repositoryRoot, "policy.md"), "policy v1\n");
		const created = await createSecurityScanPlan(
			{
				cwd: repositoryRoot,
				target: { kind: "repository" },
				knowledgeBasePaths: ["policy.md"],
				outputRoot: stateRoot,
				model: { provider: "openai-codex", modelId: "fixture" },
				account: { provider: "openai-codex", credentialId: 17 },
				config: {},
				workflowFingerprint: "fixture",
			},
			adapter,
		);
		expect(created.knowledgeBases[0]?.path).toBe(await fs.realpath(path.join(repositoryRoot, "policy.md")));
	});

	test("symlink target mutation makes a plan stale", async () => {
		if (process.platform === "win32") return;
		const linkedPath = path.join(repositoryRoot, "src", "a.ts");
		await fs.rm(linkedPath);
		await fs.symlink("first-target.ts", linkedPath);
		statusText = " M src/a.ts";
		const created = await plan();
		await fs.rm(linkedPath);
		await fs.symlink("second-target.ts", linkedPath);
		await expect(
			assertSecurityScanPlanFresh(
				created,
				{ config: { security: { enabled: true } }, workflowFingerprint: "security-reviewer@fixture" },
				adapter,
			),
		).rejects.toBeInstanceOf(StaleSecurityScanPlanError);
	});

	test("configuration mutation makes a plan stale", async () => {
		const created = await plan();
		await expect(
			assertSecurityScanPlanFresh(
				created,
				{ config: { changed: true }, workflowFingerprint: "security-reviewer@fixture" },
				adapter,
			),
		).rejects.toBeInstanceOf(StaleSecurityScanPlanError);
	});

	test("ref diff records resolved immutable revisions", async () => {
		const created = await plan({ kind: "ref_diff", baseRevision: "base", headRevision: "head" });
		expect(created.target.baseRevision).toBe("b".repeat(40));
		expect(created.target.headRevision).toBe("c".repeat(40));
	});

	test("output inside repository is rejected", async () => {
		await expect(
			createSecurityScanPlan(
				{
					cwd: repositoryRoot,
					target: { kind: "repository" },
					outputRoot: path.join(repositoryRoot, "security-output"),
					model: { provider: "openai-codex", modelId: "fixture" },
					account: { provider: "openai-codex", credentialId: 1 },
					config: {},
					workflowFingerprint: "fixture",
				},
				adapter,
			),
		).rejects.toThrow("outside");
	});

	test("non-empty output requires archiveExisting", async () => {
		await fs.mkdir(stateRoot);
		await Bun.write(path.join(stateRoot, "existing.txt"), "existing");
		await expect(plan()).rejects.toThrow("not empty");
	});

	test("archives a non-empty approved output directory before execution", async () => {
		await fs.mkdir(stateRoot);
		await Bun.write(path.join(stateRoot, "existing.txt"), "existing");
		const created = await createSecurityScanPlan(
			{
				cwd: repositoryRoot,
				target: { kind: "repository" },
				outputRoot: stateRoot,
				archiveExisting: true,
				model: { provider: "openai-codex", modelId: "fixture" },
				account: { provider: "openai-codex", credentialId: 1 },
				config: {},
				workflowFingerprint: "fixture",
			},
			adapter,
		);
		const prepared = await prepareSecurityOutputDirectory(created.output, "fixture");
		expect(prepared.archivedTo).toBe(`${created.output.root}.archive-fixture`);
		expect(await fs.readdir(created.output.root)).toEqual([]);
		expect(await Bun.file(path.join(`${created.output.root}.archive-fixture`, "existing.txt")).text()).toBe(
			"existing",
		);
	});

	test("symlink output is rejected", async () => {
		if (process.platform === "win32") return;
		const target = path.join(temporaryRoot, "real-output");
		await fs.mkdir(target);
		await fs.symlink(target, stateRoot);
		await expect(plan()).rejects.toThrow("symbolic link");
	});

	test("a root-dot scoped target includes repository descendants", async () => {
		const scoped = await plan({ kind: "scoped_path", includePaths: ["."] });
		const repository = await plan();
		expect(scoped.target.includePaths).toEqual(["."]);
		expect(scoped.target.treeDigest).toBe(repository.target.treeDigest);
	});

	test("an empty scoped target is rejected before planning", async () => {
		await expect(plan({ kind: "scoped_path", includePaths: [] })).rejects.toThrow(
			"scoped_path security scans require at least one include path",
		);
	});

	test("scope traversal is rejected", async () => {
		for (const candidate of ["../outside", "src/../outside", "C:\\outside", "src\\..\\outside"]) {
			await expect(plan({ kind: "scoped_path", includePaths: [candidate] })).rejects.toThrow("repository-relative");
		}
	});

	test("a deny-only policy excludes a matching file from the working-tree digest", async () => {
		await Bun.write(path.join(repositoryRoot, ".env"), "SECRET=1\n");
		const secretAwareAdapter: SecurityGitAdapter = {
			...adapter,
			files: async () => ["src/a.ts", "src/b.ts", ".env"],
		};
		const request = {
			cwd: repositoryRoot,
			target: { kind: "repository" as const },
			outputRoot: stateRoot,
			model: { provider: "openai-codex", modelId: "fixture" },
			account: { provider: "openai-codex", credentialId: 1 },
			config: {},
			workflowFingerprint: "fixture",
		};
		const denyOnly = { deny: ["**/.env"], allow: [] };
		const withoutPolicy = await createSecurityScanPlan(request, secretAwareAdapter);
		const withPolicy = await createSecurityScanPlan(request, secretAwareAdapter, denyOnly);
		expect(withPolicy.target.treeDigest).not.toBe(withoutPolicy.target.treeDigest);

		// Mutating .env changes the digest without the policy but not with it —
		// proof the excluded file never contributed to the digest at all, not
		// merely that its content happened to hash the same.
		await Bun.write(path.join(repositoryRoot, ".env"), "SECRET=2\n");
		const afterMutationWithPolicy = await createSecurityScanPlan(request, secretAwareAdapter, denyOnly);
		expect(afterMutationWithPolicy.target.treeDigest).toBe(withPolicy.target.treeDigest);

		const afterMutationWithoutPolicy = await createSecurityScanPlan(request, secretAwareAdapter);
		expect(afterMutationWithoutPolicy.target.treeDigest).not.toBe(withoutPolicy.target.treeDigest);
	});

	test("an allow carve-out keeps a file in the digest despite an overlapping deny rule", async () => {
		// Mirrors strict's own **/.env.example allow against its **/.env.* deny.
		await Bun.write(path.join(repositoryRoot, ".env.example"), "SECRET=\n");
		const secretAwareAdapter: SecurityGitAdapter = {
			...adapter,
			files: async () => ["src/a.ts", "src/b.ts", ".env.example"],
		};
		const request = {
			cwd: repositoryRoot,
			target: { kind: "repository" as const },
			outputRoot: stateRoot,
			model: { provider: "openai-codex", modelId: "fixture" },
			account: { provider: "openai-codex", credentialId: 1 },
			config: {},
			workflowFingerprint: "fixture",
		};
		const overlapping = { deny: ["**/.env.*"], allow: ["**/.env.example"] };
		const before = await createSecurityScanPlan(request, secretAwareAdapter, overlapping);
		await Bun.write(path.join(repositoryRoot, ".env.example"), "SECRET=changed\n");
		const after = await createSecurityScanPlan(request, secretAwareAdapter, overlapping);
		// The allowed file's content change must still move the digest — if it
		// were excluded (deny alone, ignoring the allow carve-out), the digest
		// would stay identical and a stale plan would pass `start`'s freshness
		// check even though the allowed file changed underneath it.
		expect(after.target.treeDigest).not.toBe(before.target.treeDigest);
	});

	test("filterDiffByPermissionPolicy strips a denied file's diff and preserves an allowed one", () => {
		const rawDiff = [
			"diff --git a/src/a.ts b/src/a.ts",
			"index 000..111 100644",
			"--- a/src/a.ts",
			"+++ b/src/a.ts",
			"@@ -1 +1 @@",
			"-old",
			"+new",
			"diff --git a/.env b/.env",
			"index 222..333 100644",
			"--- a/.env",
			"+++ b/.env",
			"@@ -1 +1 @@",
			"-SECRET=old",
			"+SECRET=new",
			"diff --git a/.env.example b/.env.example",
			"index 444..555 100644",
			"--- a/.env.example",
			"+++ b/.env.example",
			"@@ -1 +1 @@",
			"-SECRET=",
			"+SECRET=changed",
		].join("\n");
		const filtered = filterDiffByPermissionPolicy(rawDiff, { deny: ["**/.env*"], allow: ["**/.env.example"] });
		expect(filtered).toContain("src/a.ts");
		expect(filtered).toContain(".env.example");
		expect(filtered).not.toContain("SECRET=old");
		expect(filtered).not.toContain("SECRET=new\n");

		// An empty policy (no deny rules) never touches the diff.
		expect(filterDiffByPermissionPolicy(rawDiff, { deny: [], allow: [] })).toBe(rawDiff);
	});

	test("a ref_diff target's fingerprint reflects a filtered diff, not the raw one", async () => {
		const diffAdapter = (envContent: string): SecurityGitAdapter => ({
			...adapter,
			diffTree: async () =>
				[
					"diff --git a/src/a.ts b/src/a.ts",
					"index 000..111 100644",
					"--- a/src/a.ts",
					"+++ b/src/a.ts",
					"@@ -1 +1 @@",
					"-old",
					"+new",
					"diff --git a/.env b/.env",
					"index 222..333 100644",
					"--- a/.env",
					"+++ b/.env",
					"@@ -1 +1 @@",
					"-SECRET=old",
					`+SECRET=${envContent}`,
				].join("\n"),
		});
		const request = {
			cwd: repositoryRoot,
			target: { kind: "ref_diff" as const, baseRevision: "base", headRevision: "head" },
			outputRoot: stateRoot,
			model: { provider: "openai-codex", modelId: "fixture" },
			account: { provider: "openai-codex", credentialId: 1 },
			config: {},
			workflowFingerprint: "fixture",
		};
		const denyOnly = { deny: ["**/.env"], allow: [] };
		const first = await createSecurityScanPlan(request, diffAdapter("one"), denyOnly);
		// Changing only the denied file's diff content must not move the
		// fingerprint once it is filtered out before hashing.
		const second = await createSecurityScanPlan(request, diffAdapter("two"), denyOnly);
		expect(second.target.treeDigest).toBe(first.target.treeDigest);

		const unfiltered = await createSecurityScanPlan(request, diffAdapter("one"));
		expect(unfiltered.target.treeDigest).not.toBe(first.target.treeDigest);
	});
});
