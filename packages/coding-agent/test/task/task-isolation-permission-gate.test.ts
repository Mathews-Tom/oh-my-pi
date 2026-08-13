import { afterEach, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { resetRegisteredArtifactDirsForTests } from "@oh-my-pi/pi-coding-agent/internal-urls/registry-helpers";
import * as discoveryModule from "@oh-my-pi/pi-coding-agent/task/discovery";
import * as executorModule from "@oh-my-pi/pi-coding-agent/task/executor";
import * as isolationRunner from "@oh-my-pi/pi-coding-agent/task/isolation-runner";
import {
	runStructuredSubagent,
	StructuredSubagentError,
	type StructuredSubagentRequest,
} from "@oh-my-pi/pi-coding-agent/task/structured-subagent";
import type { AgentDefinition, SingleResult } from "@oh-my-pi/pi-coding-agent/task/types";
import * as worktreeModule from "@oh-my-pi/pi-coding-agent/task/worktree";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import * as git from "@oh-my-pi/pi-coding-agent/utils/git";

let repoRoot = "";

const AGENT: AgentDefinition = {
	name: "worker",
	description: "Test worker",
	systemPrompt: "Do the assigned work.",
	source: "bundled",
	tools: ["read", "write"],
};

function session(settings: Record<string, unknown> = {}): ToolSession {
	return {
		cwd: repoRoot,
		hasUI: false,
		settings: Settings.isolated({
			"task.maxRecursionDepth": 2,
			"task.isolation.mode": "worktree",
			"task.enableLsp": true,
			...settings,
		}),
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
	} as unknown as ToolSession;
}

function request(overrides: Partial<StructuredSubagentRequest> = {}): StructuredSubagentRequest {
	return {
		session: session(),
		invocationKind: "task",
		assignment: "Inspect the target.",
		agent: "worker",
		...overrides,
	};
}

function result(): SingleResult {
	return {
		index: 0,
		id: "Worker",
		agent: "worker",
		agentSource: "bundled",
		task: "Inspect the target.",
		exitCode: 0,
		output: "{}",
		stderr: "",
		truncated: false,
		durationMs: 1,
		tokens: 0,
		requests: 1,
	};
}

function mockDiscovery(): void {
	vi.spyOn(discoveryModule, "discoverAgents").mockResolvedValue({ agents: [AGENT], projectAgentsDir: null });
}

/** Stub repo-root resolution without a real git checkout under `repoRoot`. */
function mockRepoRoot(): void {
	vi.spyOn(worktreeModule, "getRepoRoot").mockResolvedValue(repoRoot);
}

/** For success paths that must reach isolation setup: stub root + baseline capture, since `repoRoot` is a plain temp dir, not a real git checkout. */
function mockIsolationContext(): void {
	mockRepoRoot();
	vi.spyOn(worktreeModule, "captureBaseline").mockResolvedValue({} as never);
}

beforeEach(async () => {
	repoRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-isolation-permission-"));
	vi.spyOn(git.ls, "files").mockResolvedValue([]);
	// `repoRoot` is a plain temp dir, not a real git checkout — `discoverNestedRepos`
	// (now part of authorization, not just baseline capture) calls this for real
	// otherwise, which fails outside a git repository.
	vi.spyOn(git.ls, "submodules").mockResolvedValue([]);
});

afterEach(async () => {
	vi.restoreAllMocks();
	resetRegisteredArtifactDirsForTests();
	await fs.rm(repoRoot, { recursive: true, force: true });
});

describe("task isolation permission gate", () => {
	it("denies isolated execution whose isolation directory falls outside workspace roots under a confining profile", async () => {
		mockDiscovery();
		mockRepoRoot();
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess");

		const denied = runStructuredSubagent(
			request({
				session: session({ "permissions.profile": "workspace" }),
				isolation: { requested: true },
			}),
		);

		await expect(denied).rejects.toThrow(StructuredSubagentError);
		await expect(denied).rejects.toThrow(/permissions\.confineWrites/);
		expect(runIsolated).not.toHaveBeenCalled();
	});

	it("denies isolated execution when the source repo matches an explicit deny.read rule", async () => {
		mockDiscovery();
		mockRepoRoot();
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess");

		const denied = runStructuredSubagent(
			request({
				session: session({
					"permissions.profile": "workspace",
					"permissions.confineWrites": false,
					"permissions.deny.read": [repoRoot],
				}),
				isolation: { requested: true },
			}),
		);

		await expect(denied).rejects.toThrow(StructuredSubagentError);
		await expect(denied).rejects.toThrow(repoRoot);
		expect(runIsolated).not.toHaveBeenCalled();
	});

	it("denies isolated execution when a tracked source descendant matches permissions.deny.read", async () => {
		const deniedFile = path.join(repoRoot, ".env");
		await fs.writeFile(deniedFile, "SECRET=1");
		mockDiscovery();
		vi.spyOn(git.ls, "files").mockImplementation(async (_cwd, options) =>
			options?.cached && options.others && options.excludeStandard ? [".env"] : [],
		);
		mockRepoRoot();
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess");

		await expect(
			runStructuredSubagent(
				request({
					session: session({
						"permissions.profile": "workspace",
						"permissions.confineWrites": false,
						"permissions.deny.read": [deniedFile],
					}),
					isolation: { requested: true },
				}),
			),
		).rejects.toThrow(deniedFile);
		expect(runIsolated).not.toHaveBeenCalled();
	});

	it("never captures the repository baseline when a denied untracked source blocks isolation setup", async () => {
		// Baseline capture (`captureBaseline`) reads staged/unstaged diffs and
		// untracked file *content* straight off disk — it must never run before
		// the source-read permission gate has had a chance to deny. Previously
		// `prepareIsolationContext` (root resolution + baseline capture) ran as
		// one call before `authorizeIsolationTargets`, so a denied untracked
		// file's bytes were already read into the baseline patch by the time the
		// denial threw (finding under review).
		const deniedFile = path.join(repoRoot, ".env");
		await fs.writeFile(deniedFile, "SECRET=1");
		mockDiscovery();
		vi.spyOn(git.ls, "files").mockImplementation(async (_cwd, options) =>
			options?.cached && options.others && options.excludeStandard ? [".env"] : [],
		);
		mockRepoRoot();
		const captureBaseline = vi.spyOn(worktreeModule, "captureBaseline");
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess");

		await expect(
			runStructuredSubagent(
				request({
					session: session({
						"permissions.profile": "workspace",
						"permissions.confineWrites": false,
						"permissions.deny.read": [deniedFile],
					}),
					isolation: { requested: true },
				}),
			),
		).rejects.toThrow(deniedFile);

		expect(captureBaseline).not.toHaveBeenCalled();
		expect(runIsolated).not.toHaveBeenCalled();
	});

	it("denies isolated execution when a nested repo's untracked source matches permissions.deny.read", async () => {
		// `git ls-files` at `repoRoot` never sees into a nested repo (its own
		// untracked `.git` directory is invisible to it, like a submodule).
		// `captureBaseline` discovers and reads nested repos' working trees via
		// `discoverNestedRepos`, so the gate must enumerate the identical set of
		// nested repos as read targets or a denied source inside one is captured
		// before the gate ever sees it (finding under review).
		const nestedRel = "vendor";
		const nestedDir = path.join(repoRoot, nestedRel);
		await fs.mkdir(path.join(nestedDir, ".git"), { recursive: true });
		const deniedFile = path.join(nestedDir, ".env");
		await fs.writeFile(deniedFile, "SECRET=1");
		mockDiscovery();
		vi.spyOn(git.ls, "files").mockImplementation(async (cwd, options) => {
			if (!(options?.cached && options.others && options.excludeStandard)) return [];
			return cwd === nestedDir ? [".env"] : [];
		});
		mockRepoRoot();
		// Stubbed like `mockIsolationContext`'s `captureBaseline`, so that if
		// authorization fails to deny, the run proceeds all the way to
		// `runIsolated` instead of failing for an unrelated reason (real
		// baseline capture needs an actual git checkout, not this fixture).
		const captureBaseline = vi.spyOn(worktreeModule, "captureBaseline").mockResolvedValue({} as never);
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess").mockResolvedValue(result());

		await expect(
			runStructuredSubagent(
				request({
					session: session({
						"permissions.profile": "workspace",
						"permissions.confineWrites": false,
						"permissions.deny.read": [deniedFile],
					}),
					isolation: { requested: true },
				}),
			),
		).rejects.toThrow(deniedFile);

		expect(captureBaseline).not.toHaveBeenCalled();
		expect(runIsolated).not.toHaveBeenCalled();
	});

	it("does not deny a gitignored file that a git worktree isolation will not materialize", async () => {
		const ignoredFile = path.join(repoRoot, ".env");
		await fs.writeFile(ignoredFile, "SECRET=1");
		mockDiscovery();
		vi.spyOn(git.ls, "files").mockResolvedValue(["tracked.ts"]);
		mockIsolationContext();
		const runIsolated = vi.spyOn(isolationRunner, "runIsolatedSubprocess").mockResolvedValue(result());

		const settled = await runStructuredSubagent(
			request({
				session: session({
					"permissions.profile": "workspace",
					"permissions.confineWrites": false,
					"permissions.deny.read": [ignoredFile],
				}),
				isolation: { requested: true },
				retainArtifacts: true,
			}),
		);

		expect(settled.result.exitCode).toBe(0);
		expect(runIsolated).toHaveBeenCalled();
		await fs.rm(settled.artifactsDir, { recursive: true, force: true });
	});

	it("does not merely block every isolated task call — an explicit allow rule still lets it through", async () => {
		mockDiscovery();
		mockIsolationContext();
		vi.spyOn(isolationRunner, "runIsolatedSubprocess").mockResolvedValue(result());

		const settled = await runStructuredSubagent(
			request({
				session: session({ "permissions.profile": "workspace", "permissions.allow.write": ["**"] }),
				isolation: { requested: true },
				retainArtifacts: true,
			}),
		);

		expect(settled.result.exitCode).toBe(0);
		await fs.rm(settled.artifactsDir, { recursive: true, force: true });
	});

	it("leaves isolated execution unaffected when the permission profile is off (the default)", async () => {
		mockDiscovery();
		mockIsolationContext();
		vi.spyOn(isolationRunner, "runIsolatedSubprocess").mockResolvedValue(result());

		const settled = await runStructuredSubagent(
			request({ session: session(), isolation: { requested: true }, retainArtifacts: true }),
		);

		expect(settled.result.exitCode).toBe(0);
		await fs.rm(settled.artifactsDir, { recursive: true, force: true });
	});

	it("leaves non-isolated task execution unaffected under a confining profile", async () => {
		mockDiscovery();
		const getRepoRoot = vi.spyOn(worktreeModule, "getRepoRoot");
		vi.spyOn(executorModule, "runSubprocess").mockResolvedValue(result());

		const settled = await runStructuredSubagent(
			request({
				session: session({ "permissions.profile": "strict" }),
				retainArtifacts: true,
			}),
		);

		expect(settled.result.exitCode).toBe(0);
		expect(getRepoRoot).not.toHaveBeenCalled();
		await fs.rm(settled.artifactsDir, { recursive: true, force: true });
	});
});
