import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "../../src/config/settings";
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
});
