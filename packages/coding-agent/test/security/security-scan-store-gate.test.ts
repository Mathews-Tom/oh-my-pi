import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "../../src/config/settings";
import { resolveSecurityProjectDirectoryForCwd } from "../../src/security/store";
import type { ToolSession } from "../../src/tools";
import { SecurityScanTool } from "../../src/tools/security-scan";

// `cloud_pull` and `validate` open the `SecurityStore` directly (there is no
// `SecurityCoordinator` action for either), so unlike `preflight`/`start` they
// never ran the caller's `stateDirectory` guard before mutating state on disk
// (finding under review). The store's project directory always lives outside
// every workspace root, so a `workspace`-confined session must refuse it —
// proving the guard runs, and runs before any store I/O, without needing a
// real `SecurityStore` (native file-lock bindings aren't required for a call
// that never reaches the store open).

let temporaryRoot = "";
let repositoryRoot = "";
let settings: Settings;

beforeEach(async () => {
	temporaryRoot = await fs.mkdtemp(path.join(os.tmpdir(), "omp-security-scan-store-gate-"));
	repositoryRoot = path.join(temporaryRoot, "repo");
	await fs.mkdir(repositoryRoot, { recursive: true });
	settings = Settings.isolated({ "security.enabled": true, "permissions.profile": "workspace" });
});

afterEach(async () => {
	settings.cancelPendingSaves();
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function toolSession(): ToolSession {
	return { cwd: repositoryRoot, settings } as ToolSession;
}

function workspaceContext(): AgentToolContext {
	return {
		sessionManager: {
			getCwd: () => repositoryRoot,
			getAdditionalDirectories: () => [],
			getSessionId: () => "test-session",
		},
		settings,
	} as unknown as AgentToolContext;
}

describe("security_scan store actions authorize the state directory before opening it", () => {
	test("cloud_pull refuses before the store is opened", async () => {
		const tool = new SecurityScanTool(toolSession());
		await expect(
			tool.execute(
				"call-1",
				{ action: "cloud_pull", cloud_configuration_id: "cfg-1" } as never,
				undefined,
				undefined,
				workspaceContext(),
			),
		).rejects.toThrow("permissions.confineWrites");
	});

	test("validate refuses before the store is opened", async () => {
		const tool = new SecurityScanTool(toolSession());
		await expect(
			tool.execute(
				"call-1",
				{
					action: "validate",
					scan_id: "secscan_fixture",
					finding_id: "secf_fixture",
					validation_status: "validated",
					validation_summary: "fixture",
				} as never,
				undefined,
				undefined,
				workspaceContext(),
			),
		).rejects.toThrow("permissions.confineWrites");
	});

	// The guard used to register the state directory as a write target only,
	// even though opening the store reads its index/plan/finding state from
	// disk first. A profile that explicitly permits writing there but denies
	// reading it — impossible to express as a mere `confineWrites` refusal —
	// used to sail straight past the guard and into the store (finding under
	// review). Granting write via an explicit allow rule (bypassing
	// `confineWrites`) while denying read isolates that gap.
	test("cloud_pull refuses a state directory that permits write but denies read, before the store is opened", async () => {
		const { projectDirectory } = await resolveSecurityProjectDirectoryForCwd(repositoryRoot);
		// The gated target is the state directory itself, not a path beneath it —
		// an allow/deny glob needs the exact directory, not `<dir>/**` (which only
		// matches descendants).
		const readDeniedSettings = Settings.isolated({
			"security.enabled": true,
			"permissions.profile": "workspace",
			"permissions.allow.write": [projectDirectory],
			"permissions.deny.read": [projectDirectory],
		});
		const tool = new SecurityScanTool({ cwd: repositoryRoot, settings: readDeniedSettings } as ToolSession);
		const context = {
			sessionManager: {
				getCwd: () => repositoryRoot,
				getAdditionalDirectories: () => [],
				getSessionId: () => "test-session",
			},
			settings: readDeniedSettings,
		} as unknown as AgentToolContext;

		await expect(
			tool.execute(
				"call-1",
				{ action: "cloud_pull", cloud_configuration_id: "cfg-1" } as never,
				undefined,
				undefined,
				context,
			),
		).rejects.toThrow("permissions.allow.read");

		// The refusal happened before the store touched disk: no project
		// directory was ever created.
		await expect(fs.stat(projectDirectory)).rejects.toThrow();
	});
});
