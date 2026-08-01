import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { stripVTControlCharacters } from "node:util";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { StatusLineComponent } from "@oh-my-pi/pi-coding-agent/modes/components/status-line";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";
import { removeSyncWithRetries, setProjectDir } from "@oh-my-pi/pi-utils";
import { beginSettingsTest, restoreSettingsTestState, type SettingsTestState } from "./helpers/settings-test-state";

let settingsState: SettingsTestState | undefined;
let projectDir = "";

beforeEach(async () => {
	settingsState = beginSettingsTest();
	projectDir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-status-line-permissions-"));
	setProjectDir(projectDir);
	await Settings.init({ inMemory: true, cwd: projectDir });
	await initTheme();
});

afterEach(() => {
	restoreSettingsTestState(settingsState);
	settingsState = undefined;
	if (projectDir) {
		removeSyncWithRetries(projectDir);
	}
	projectDir = "";
});

/**
 * `permissions.profile` is read off the session's settings at render time, so
 * the double only has to answer that one key the way the real store would.
 */
function makeSession(profile: string) {
	const model = { id: "test-model", name: "Test Model", contextWindow: 100_000 };
	return {
		state: { messages: [], model },
		messages: [],
		model,
		systemPrompt: [],
		agent: { state: { tools: [] } },
		skills: [],
		isStreaming: false,
		isAutoThinking: false,
		autoResolvedThinkingLevel: () => undefined,
		isFastModeActive: () => false,
		isAdvisorActive: () => false,
		getAdvisorStatusOverview: () => ({ configured: false, advisors: [] }),
		getAsyncJobSnapshot: () => ({ running: [] }),
		settings: { get: (key: string) => (key === "permissions.profile" ? profile : false) },
		sessionManager: {
			getSessionName: () => "Perm Session",
			getUsageStatistics: () => ({
				input: 0,
				output: 0,
				cacheRead: 0,
				cacheWrite: 0,
				totalTokens: 0,
				orchestrationInput: 0,
				orchestrationOutput: 0,
				orchestrationCacheRead: 0,
				premiumRequests: 0,
				cost: 0,
			}),
		},
		modelRegistry: { isUsingOAuth: () => false },
		getContextUsage: () => undefined,
	} as unknown as ConstructorParameters<typeof StatusLineComponent>[0];
}

function renderBar(profile: string): string {
	const component = new StatusLineComponent(makeSession(profile));
	component.updateSettings({
		preset: "custom",
		leftSegments: ["permissions"],
		rightSegments: [],
		sessionAccent: false,
	});
	return stripVTControlCharacters(component.getTopBorder(120).content);
}

describe("status line permissions segment", () => {
	it("renders nothing at the default off profile", () => {
		expect(renderBar("off")).not.toContain("perm:");
	});

	it("names the active profile once one is enabled", () => {
		expect(renderBar("workspace")).toContain("perm:workspace");
		expect(renderBar("strict")).toContain("perm:strict");
	});
});
