import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { unregisterCustomApis } from "@oh-my-pi/pi-ai/api-registry";
import { type AuthCredentialStore, AuthStorage, SqliteAuthCredentialStore } from "@oh-my-pi/pi-ai/auth-storage";
import { createMockModel, registerMockApi } from "@oh-my-pi/pi-ai/providers/mock";
import { ModelRegistry } from "../../src/config/model-registry";
import { Settings } from "../../src/config/settings";
import {
	getSecurityCoordinator,
	resetSecurityCoordinatorsForTests,
	type SecurityCoordinatorHost,
} from "../../src/security";
import { PermissionDeniedError } from "../../src/tools/permissions/gate";

const MOCK_SOURCE_ID = "security-coordinator-cache-test";
let temporaryRoot = "";
let repositoryRoot = "";
let credentialStore: AuthCredentialStore | null = null;
let authStorage: AuthStorage;
let settings: Settings;

beforeEach(async () => {
	resetSecurityCoordinatorsForTests();
	temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-security-coordinator-cache-"));
	repositoryRoot = path.join(temporaryRoot, "repo");
	await fs.mkdir(repositoryRoot, { recursive: true });
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
	// `workspace` confines writes to `cwd` plus `additionalDirectories` by
	// default — the exact confinement `assertSecurityWriteAllowed` checks an
	// `output_root` against.
	settings = Settings.isolated({
		"security.enabled": true,
		"compaction.enabled": false,
		"permissions.profile": "workspace",
	});
	registerMockApi(MOCK_SOURCE_ID);
});

afterEach(async () => {
	resetSecurityCoordinatorsForTests();
	unregisterCustomApis(MOCK_SOURCE_ID);
	settings.cancelPendingSaves();
	credentialStore?.close();
	credentialStore = null;
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function hostFor(additionalDirectories: string[]): SecurityCoordinatorHost {
	const mock = createMockModel({ id: "security-mock", provider: "openai-codex", responses: [] });
	const modelRegistry = new ModelRegistry(authStorage, path.join(temporaryRoot, "models.yml"));
	return {
		cwd: repositoryRoot,
		additionalDirectories,
		settings,
		authStorage,
		modelRegistry,
		activeModel: mock.model,
		sessionId: "cache-test-session",
	};
}

describe("getSecurityCoordinator cache", () => {
	// The finding: preflight a plan whose output is in an additional
	// directory, remove that directory with `/remove-dir`, then start the
	// plan — a cached coordinator kept authorizing against the directory list
	// captured when it was first constructed, so the removed directory stayed
	// approved forever.
	test("a removed additional directory is no longer authorized for output after a cache hit", async () => {
		const outsideDir = path.join(temporaryRoot, "outside");
		await fs.mkdir(outsideDir, { recursive: true });

		const first = getSecurityCoordinator(hostFor([outsideDir]));

		// Same cwd + sessionId as `hostFor` above -> a cache hit inside
		// `getSecurityCoordinator`, mirroring the session calling it again
		// after `/remove-dir` dropped `outsideDir` from the workspace. Before
		// the fix, this returned `first` unchanged, still carrying
		// `additionalDirectories: [outsideDir]` from construction, so the
		// call below would have been (wrongly) authorized.
		const second = getSecurityCoordinator(hostFor([]));
		expect(second).toBe(first);

		await expect(second.preflight({ outputRoot: path.join(outsideDir, "out") })).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);
	});

	test("an added additional directory is no longer denied for output after a cache hit", async () => {
		const addedDir = path.join(temporaryRoot, "added");
		await fs.mkdir(addedDir, { recursive: true });

		const first = getSecurityCoordinator(hostFor([]));
		await expect(first.preflight({ outputRoot: path.join(addedDir, "out") })).rejects.toBeInstanceOf(
			PermissionDeniedError,
		);

		const second = getSecurityCoordinator(hostFor([addedDir]));
		expect(second).toBe(first);
		// The resource-permission check must no longer reject this call. Any
		// failure past that point belongs to store I/O, not to this contract.
		await second.preflight({ outputRoot: path.join(addedDir, "out2") }).catch(err => {
			if (err instanceof PermissionDeniedError) throw err;
		});
	});
});
