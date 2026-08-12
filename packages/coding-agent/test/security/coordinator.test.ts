import { afterEach, beforeEach, describe, expect, test, vi } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { unregisterCustomApis } from "@oh-my-pi/pi-ai/api-registry";
import { type AuthCredentialStore, AuthStorage, SqliteAuthCredentialStore } from "@oh-my-pi/pi-ai/auth-storage";
import { createMockModel, type MockResponseSource, registerMockApi } from "@oh-my-pi/pi-ai/providers/mock";
import { $ } from "bun";
import { ModelRegistry } from "../../src/config/model-registry";
import { Settings } from "../../src/config/settings";
import {
	createNativeSecurityProvenance,
	DEFAULT_SECURITY_GIT_ADAPTER,
	SecurityCoordinator,
	type SecurityGitAdapter,
	type SecurityScanBundle,
	SecurityStore,
} from "../../src/security";
import { SessionManager } from "../../src/session/session-manager";
import { PermissionDeniedError } from "../../src/tools/permissions/gate";

const MOCK_SOURCE_ID = "security-coordinator-test";
let temporaryRoot = "";
let repositoryRoot = "";
let stateRoot = "";
let credentialStore: AuthCredentialStore | null = null;
let authStorage: AuthStorage;
let settings: Settings;
let credentialId = 0;

const gitAdapter: SecurityGitAdapter = {
	root: async () => repositoryRoot,
	headSha: async () => "a".repeat(40),
	resolveRef: async (_cwd, refName) => (refName === "base" ? "b".repeat(40) : "c".repeat(40)),
	diffTree: async () => "fixture-diff",
	status: async () => "",
	files: async () => ["src/app.ts"],
	untracked: async () => [],
};

beforeEach(async () => {
	temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-security-coordinator-"));
	repositoryRoot = path.join(temporaryRoot, "repo");
	stateRoot = path.join(temporaryRoot, "state");
	await fs.mkdir(path.join(repositoryRoot, "src"), { recursive: true });
	await Bun.write(path.join(repositoryRoot, "src", "app.ts"), "export const app = true;\n");
	credentialStore = await SqliteAuthCredentialStore.open(path.join(temporaryRoot, "agent.db"));
	authStorage = new AuthStorage(credentialStore);
	await authStorage.set("openai-codex", {
		type: "oauth",
		access: "fixture-access-token",
		refresh: "fixture-refresh-token",
		expires: Date.now() + 60 * 60_000,
		accountId: "workspace-fixture",
		email: "security@example.invalid",
		orgId: "workspace-fixture",
		orgName: "pro",
	});
	const account = authStorage.listOAuthAccounts("openai-codex")[0];
	if (!account) throw new Error("expected fixture OAuth account");
	credentialId = account.credentialId;
	settings = Settings.isolated({ "security.enabled": true, "compaction.enabled": false });
	registerMockApi(MOCK_SOURCE_ID);
});

afterEach(async () => {
	vi.restoreAllMocks();
	unregisterCustomApis(MOCK_SOURCE_ID);
	settings.cancelPendingSaves();
	credentialStore?.close();
	credentialStore = null;
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function storeFactory(): Promise<SecurityStore> {
	return SecurityStore.open(repositoryRoot, { stateRoot });
}

// Mirrors storeFactory's { repositoryRoot, stateRoot } scoping exactly, but
// without SecurityStore.open's ensurePrivateDirectory/index-write side
// effects - preflight authorizes the derived work root before opening the
// store, so a mismatched derivation here would authorize a path the actually
// opened (test-scoped) store never lands at.
async function deriveOutputWorkRoot(): Promise<string> {
	const { projectDirectory } = await SecurityStore.deriveProjectDirectory(repositoryRoot, { stateRoot });
	return path.join(projectDirectory, "work");
}

function coordinatorWithMockSession(responses: MockResponseSource) {
	const mock = createMockModel({
		id: "security-mock",
		provider: "openai-codex",
		responses,
	});
	const modelRegistry = new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml"));
	const coordinator = new SecurityCoordinator(
		{
			cwd: repositoryRoot,
			settings,
			authStorage,
			modelRegistry,
			activeModel: mock.model,
			sessionId: "parent-session",
			agentId: "Main",
		},
		{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
	);
	return { coordinator, mock };
}

describe("native security coordinator", () => {
	test("scripted mock model publishes a canonical completed scan and restartable session", async () => {
		const { coordinator, mock } = coordinatorWithMockSession([
			{
				content: [
					{
						type: "toolCall",
						name: "security_publish",
						arguments: {
							findings: [
								{
									rule_id: "fixture.command-injection",
									title: "Untrusted command reaches a shell",
									summary: "A fixture value is interpolated into a shell command.",
									severity: "high",
									confidence: "high",
									category: "command-injection",
									locations: [{ path: "src/app.ts", start_line: 1, role: "sink" }],
									evidence: [{ label: "shell sink", explanation: "Fixture evidence" }],
									remediation: "Use an argument-vector API.",
									validation: "validated",
								},
							],
							coverage: { completeness: "complete" },
							report: "# Fixture security report\n\nOne validated finding.\n",
						},
					},
				],
			},
			{ content: ["Security publication completed."] },
		]);
		const createdPlan = await coordinator.preflight({ credentialId, model: mock.model });
		const started = await coordinator.start({ planId: createdPlan.id });
		const terminal = await coordinator.wait(started.operationId);
		expect(terminal.phase).toBe("completed");
		expect(terminal.findingCount).toBe(1);
		const bundle = await (await storeFactory()).getBundle(terminal.scanId);
		expect(bundle?.scan.status).toBe("completed");
		expect(bundle?.findings).toHaveLength(1);
		expect(terminal.sessionFile).toBeDefined();
		if (!terminal.sessionFile) throw new Error("expected persisted security session");
		const reopened = await SessionManager.open(terminal.sessionFile, undefined, undefined, {
			initialCwd: repositoryRoot,
		});
		expect(reopened.getSessionId()).toBeTruthy();
	});

	test("records a terminal failure when initial scan persistence fails", async () => {
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const store = await storeFactory();
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{
				openStore: async () => store,
				gitAdapter,
				deriveOutputWorkRoot,
				createSession: async () => {
					throw new Error("session must not launch when persistence fails");
				},
			},
		);
		const plan = await coordinator.preflight({ credentialId, model: mock.model });
		vi.spyOn(store, "putBundle").mockRejectedValue(new Error("security store unavailable"));
		const started = await coordinator.start({ planId: plan.id });
		await expect(coordinator.wait(started.operationId)).rejects.toThrow("security store unavailable");
		expect(await coordinator.status(started.operationId)).toMatchObject({
			phase: "failed",
			error: "security store unavailable",
		});
	});

	test("denies preflight when the defaulted output directory is outside every workspace root", async () => {
		const restrictiveSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		// No `outputRoot` supplied - the coordinator defaults it to a directory
		// beneath `SecurityStore.projectDirectory`, which lives outside every
		// workspace root the `workspace` profile confines writes to.
		await expect(coordinator.preflight({ credentialId, model: mock.model })).rejects.toThrow(PermissionDeniedError);
	});

	test("permits preflight's defaulted output directory when permissions are off", async () => {
		const openSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "off" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings: openSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		const plan = await coordinator.preflight({ credentialId, model: mock.model });
		expect(plan.output.root).toBeTruthy();
	});

	test("does not create the default output's work directory when preflight is denied", async () => {
		const restrictiveSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		const store = await storeFactory();
		const workRoot = path.join(store.projectDirectory, "work");
		await expect(coordinator.preflight({ credentialId, model: mock.model })).rejects.toThrow(PermissionDeniedError);
		// The denied call must not have created (or chmod'd) the default
		// output's parent directory as a side effect before the check ran.
		await expect(fs.stat(workRoot)).rejects.toThrow();
	});

	test("never opens the store (no index/state files) when the defaulted output is denied", async () => {
		const restrictiveSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		let openStoreCalls = 0;
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{
				openStore: async () => {
					openStoreCalls++;
					return storeFactory();
				},
				gitAdapter,
				deriveOutputWorkRoot,
			},
		);
		await expect(coordinator.preflight({ credentialId, model: mock.model })).rejects.toThrow(PermissionDeniedError);
		// `SecurityStore.open` (behind `openStore`) is what creates the
		// project directory and writes its index - a denied preflight must
		// never reach it at all, not just skip the later work-root mkdir.
		expect(openStoreCalls).toBe(0);
	});

	test("reauthorizes a stored plan's output root at start against live permissions", async () => {
		// `permissions.profile` starts unset (defaults to "off") - anything
		// passed to `Settings.isolated()`'s own overrides pins that key
		// permanently, so a later `.set()` below could never change it.
		const liveSettings = Settings.isolated({ "security.enabled": true });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings: liveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		// Created while permissions are off - the defaulted (outside-workspace)
		// output root is authorized without objection.
		const plan = await coordinator.preflight({ credentialId, model: mock.model });
		// Tightened between preflight and start - e.g. a mid-session `/set`.
		liveSettings.set("permissions.profile", "workspace");
		await expect(coordinator.start({ planId: plan.id })).rejects.toThrow(PermissionDeniedError);
	});

	test("authorizes an explicit output_root under an approved additional directory", async () => {
		const approvedOutputDir = path.join(temporaryRoot, "approved-reports");
		await fs.mkdir(approvedOutputDir, { recursive: true });
		const restrictiveSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				additionalDirectories: [approvedOutputDir],
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		// `normalizeOutput` requires the output to sit outside the scanned
		// repository - `additionalDirectories` is the only way for a
		// confining profile to have anywhere valid to put it.
		const outputRoot = path.join(approvedOutputDir, "scan-output");
		const plan = await coordinator.preflight({ credentialId, model: mock.model, outputRoot });
		expect(plan.output.root).toBe(path.join(await fs.realpath(approvedOutputDir), "scan-output"));
	});

	test("still denies an output_root outside cwd and every additional directory", async () => {
		const approvedOutputDir = path.join(temporaryRoot, "approved-reports-2");
		const outsideDir = path.join(temporaryRoot, "unapproved-reports");
		await fs.mkdir(approvedOutputDir, { recursive: true });
		await fs.mkdir(outsideDir, { recursive: true });
		const restrictiveSettings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				additionalDirectories: [approvedOutputDir],
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		const outputRoot = path.join(outsideDir, "scan-output");
		await expect(coordinator.preflight({ credentialId, model: mock.model, outputRoot })).rejects.toThrow(
			PermissionDeniedError,
		);
	});

	test("denies start() when a descendant deny rule matches a generated bundle file, even though output_root itself is approved", async () => {
		const approvedOutputDir = path.join(temporaryRoot, "approved-reports-3");
		await fs.mkdir(approvedOutputDir, { recursive: true });
		const restrictiveSettings = Settings.isolated({
			"security.enabled": true,
			"permissions.profile": "workspace",
			"permissions.deny.write": ["**/*.json"],
		});
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				additionalDirectories: [approvedOutputDir],
				settings: restrictiveSettings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		const outputRoot = path.join(approvedOutputDir, "scan-output");
		// `output_root` itself passes: it is not a `.json` file. The bundle
		// writer places `findings.json`/`provenance.json`/`scan.json` directly
		// under it, and those must still be checked against the same deny rule.
		const plan = await coordinator.preflight({ credentialId, model: mock.model, outputRoot });
		await expect(coordinator.start({ planId: plan.id })).rejects.toThrow(PermissionDeniedError);
	});

	test("cancellation before session launch has no inference side effects", async () => {
		let sessionCreations = 0;
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const modelRegistry = new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml"));
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings,
				authStorage,
				modelRegistry,
				activeModel: mock.model,
				sessionId: "parent-session",
			},
			{
				openStore: storeFactory,
				gitAdapter,
				deriveOutputWorkRoot,
				createSession: async () => {
					sessionCreations++;
					throw new Error("session must not launch after cancellation");
				},
			},
		);
		const createdPlan = await coordinator.preflight({ credentialId, model: mock.model });
		const started = await coordinator.start({ planId: createdPlan.id });
		expect(await coordinator.cancel(started.operationId)).toBeTrue();
		const terminal = await coordinator.wait(started.operationId);
		expect(terminal.phase).toBe("cancelled");
		expect(sessionCreations).toBe(0);
		expect(mock.calls).toHaveLength(0);
		const bundle = await (await storeFactory()).getBundle(terminal.scanId);
		expect(bundle?.scan.status).toBe("cancelled");
	});

	test("mid-review cancellation aborts the session and retains an honest partial record", async () => {
		const promptStarted = Promise.withResolvers<void>();
		const promptFinished = Promise.withResolvers<void>();
		let abortCalls = 0;
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		const modelRegistry = new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml"));
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings,
				authStorage,
				modelRegistry,
				activeModel: mock.model,
				sessionId: "parent-session",
			},
			{
				openStore: storeFactory,
				gitAdapter,
				deriveOutputWorkRoot,
				createSession: async () => ({
					prompt: async () => {
						promptStarted.resolve();
						await promptFinished.promise;
						throw new Error("review interrupted");
					},
					waitForIdle: async () => undefined,
					abort: async () => {
						abortCalls++;
						promptFinished.resolve();
					},
					dispose: async () => undefined,
				}),
			},
		);
		const createdPlan = await coordinator.preflight({ credentialId, model: mock.model });
		const started = await coordinator.start({ planId: createdPlan.id });
		await promptStarted.promise;
		expect(await coordinator.cancel(started.operationId)).toBeTrue();
		const terminal = await coordinator.wait(started.operationId);
		expect(terminal.phase).toBe("cancelled");
		expect(abortCalls).toBe(1);
		const bundle = await (await storeFactory()).getBundle(terminal.scanId);
		expect(bundle?.scan.status).toBe("cancelled");
		expect(bundle?.findings).toEqual([]);
	});
	test("ref-diff execution checks out the immutable head and supplies the exact diff", async () => {
		await $`git init --initial-branch=main`.cwd(repositoryRoot).quiet();
		await $`git config user.name Fixture`.cwd(repositoryRoot).quiet();
		await $`git config user.email fixture@example.invalid`.cwd(repositoryRoot).quiet();
		await $`git add src/app.ts`.cwd(repositoryRoot).quiet();
		await $`git commit -m base`.cwd(repositoryRoot).quiet();
		const baseRevision = (await $`git rev-parse HEAD`.cwd(repositoryRoot).text()).trim();
		await Bun.write(path.join(repositoryRoot, "src", "app.ts"), "export const app = 'head';\n");
		await $`git add src/app.ts`.cwd(repositoryRoot).quiet();
		await $`git commit -m head`.cwd(repositoryRoot).quiet();
		const headRevision = (await $`git rev-parse HEAD`.cwd(repositoryRoot).text()).trim();
		const mock = createMockModel({ id: "security-mock", provider: "openai-codex" });
		let executionRoot = "";
		let request = "";
		let reviewedContent = "";
		const coordinator = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{
				openStore: storeFactory,
				gitAdapter: DEFAULT_SECURITY_GIT_ADAPTER,
				deriveOutputWorkRoot,
				createSession: async input => {
					executionRoot = input.executionRoot;
					return {
						prompt: async text => {
							request = text;
							reviewedContent = await Bun.file(path.join(input.executionRoot, "src", "app.ts")).text();
							return true;
						},
						waitForIdle: async () => undefined,
						abort: async () => undefined,
						dispose: async () => undefined,
					};
				},
			},
		);
		const plan = await coordinator.preflight({
			credentialId,
			model: mock.model,
			target: { kind: "ref_diff", baseRevision, headRevision },
		});
		const started = await coordinator.start({ planId: plan.id });
		const terminal = await coordinator.wait(started.operationId);
		expect(terminal.phase).toBe("partial");
		expect(executionRoot).not.toBe(repositoryRoot);
		expect(reviewedContent).toBe("export const app = 'head';\n");
		expect(request).toContain("Requested base-to-head diff");
		expect(request).toContain("+export const app = 'head';");
		await expect(fs.stat(executionRoot)).rejects.toThrow();
	});

	test("restart recovery reconciles an interrupted persisted operation", async () => {
		const { coordinator, mock } = coordinatorWithMockSession([]);
		const plan = await coordinator.preflight({ credentialId, model: mock.model });
		const store = await storeFactory();
		const operationId = "secop_restart_fixture";
		const scanId = "secscan_restartfixture";
		const provenance = createNativeSecurityProvenance({
			createdAt: "2026-07-29T00:00:00.000Z",
			account: plan.account,
			planFingerprint: plan.fingerprint,
			workflowFingerprint: plan.workflowFingerprint,
			operationId,
		});
		const interrupted: SecurityScanBundle = {
			scan: {
				documentType: "omp-security.scan",
				schemaVersion: "1.0",
				id: scanId,
				projectKey: store.projectKey,
				status: "running",
				createdAt: plan.createdAt,
				startedAt: "2026-07-29T00:00:00.000Z",
				plan,
				target: plan.target,
				producer: provenance.producer,
				provenance,
				findingIds: [],
				coverage: {
					mode: "repository",
					completeness: "unknown",
					inventoryStrategy: "repository",
					includePaths: [],
					excludePaths: [],
					surfaces: [],
					explicitExclusions: [],
					deferred: [{ id: "scan-pending", reason: "Security review is still running" }],
				},
			},
			findings: [],
		};
		await store.putBundle(interrupted);
		const restarted = new SecurityCoordinator(
			{
				cwd: repositoryRoot,
				settings,
				authStorage,
				modelRegistry: new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml")),
				activeModel: mock.model,
			},
			{ openStore: storeFactory, gitAdapter, deriveOutputWorkRoot },
		);
		expect(await restarted.status(operationId)).toMatchObject({
			operationId,
			scanId,
			phase: "failed",
			error: "Security scan was interrupted by a process restart",
		});
		expect((await store.getBundle(scanId))?.scan).toMatchObject({
			status: "failed",
			error: "Security scan was interrupted by a process restart",
		});
		expect((await restarted.listOperations()).map(operation => operation.operationId)).toContain(operationId);
	});
});
