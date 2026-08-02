import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
	assertSecurityScanPlanFresh,
	createSecurityScanPlan,
	prepareSecurityOutputDirectory,
	type SecurityGitAdapter,
	type SecurityTargetRequest,
	StaleSecurityScanPlanError,
	securityRefDiffPathspecs,
} from "../../src/security";

let temporaryRoot = "";
let repositoryRoot = "";
let stateRoot = "";
let headSha = "a".repeat(40);
let statusText = "";
let refs = new Map<string, string>();
let diffFiles: string[] = [];
let diffText = "";
const adapter: SecurityGitAdapter = {
	root: async () => repositoryRoot,
	headSha: async () => headSha,
	resolveRef: async (_cwd, refName) => refs.get(refName) ?? null,
	diffTreeFiles: async () => diffFiles,
	diffTree: async (_cwd, base, head) => diffText || `diff:${base}:${head}`,
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
	diffText = "";
	diffFiles = [];
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

	test("authorizes a repository-relative knowledge base at its canonical execution path", async () => {
		const relativePath = "policy.md";
		const canonical = path.join(repositoryRoot, relativePath);
		await Bun.write(canonical, "policy v1\n");
		const authorized: string[] = [];

		await createSecurityScanPlan(
			{
				cwd: repositoryRoot,
				target: { kind: "repository" },
				knowledgeBasePaths: [relativePath],
				outputRoot: stateRoot,
				model: { provider: "openai-codex", modelId: "fixture" },
				account: { provider: "openai-codex", credentialId: 17 },
				config: {},
				workflowFingerprint: "fixture",
				guard: { knowledgeBase: file => authorized.push(file) },
			},
			adapter,
		);

		expect(authorized).toEqual([await fs.realpath(canonical)]);
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

	test("authorizes changed ref-diff files before their patch is retained", async () => {
		const authorized: string[][] = [];
		diffFiles = [".env"];
		diffText = [
			"diff --git a/.env b/.env",
			"index 0000000..1111111 100644",
			"--- a/.env",
			"+++ b/.env",
			"@@ -0,0 +1 @@",
			"+SECRET=value",
		].join("\n");

		await createSecurityScanPlan(
			{
				cwd: repositoryRoot,
				target: { kind: "ref_diff", baseRevision: "base", headRevision: "head" },
				outputRoot: stateRoot,
				model: { provider: "openai-codex", modelId: "fixture" },
				account: { provider: "openai-codex", credentialId: 17 },
				config: {},
				workflowFingerprint: "fixture",
				guard: { scope: files => authorized.push([...files]) },
			},
			adapter,
		);

		expect(authorized).toEqual([[".env"]]);
	});

	test("refuses a changed ref-diff path before its patch is loaded", async () => {
		let patchLoads = 0;
		diffFiles = [".env"];
		diffText = "must not be loaded";
		const originalDiffTree = adapter.diffTree;
		adapter.diffTree = async () => {
			patchLoads += 1;
			return diffText;
		};

		let received: unknown;
		try {
			await createSecurityScanPlan(
				{
					cwd: repositoryRoot,
					target: { kind: "ref_diff", baseRevision: "base", headRevision: "head" },
					outputRoot: stateRoot,
					model: { provider: "openai-codex", modelId: "fixture" },
					account: { provider: "openai-codex", credentialId: 17 },
					config: {},
					workflowFingerprint: "fixture",
					guard: {
						scope: () => {
							throw new Error("resource permission denied");
						},
					},
				},
				adapter,
			);
		} catch (error) {
			received = error;
		}
		expect(received).toBeInstanceOf(Error);
		expect((received as Error).message).toBe("resource permission denied");
		expect(patchLoads).toBe(0);
		adapter.diffTree = originalDiffTree;
	});

	test("uses literal git pathspecs and ignores blank scope entries", async () => {
		expect(securityRefDiffPathspecs(["src"], ["docs"])).toEqual([":(literal)src", ":(exclude,literal)docs"]);

		const created = await plan({
			kind: "ref_diff",
			baseRevision: "base",
			headRevision: "head",
			includePaths: [""],
			excludePaths: [""],
		});
		expect(created.target.includePaths).toEqual([]);
		expect(created.target.excludePaths).toEqual([]);
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
});
