import { afterEach, describe, expect, it, spyOn } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { AuthStorage } from "@oh-my-pi/pi-ai";
import { ModelRegistry } from "@oh-my-pi/pi-coding-agent/config/model-registry";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { CustomToolContext } from "@oh-my-pi/pi-coding-agent/extensibility/custom-tools/types";
import { SessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import { ttsTool } from "@oh-my-pi/pi-coding-agent/tools/tts";
import { ttsClient } from "@oh-my-pi/pi-coding-agent/tts/tts-client";
import { removeWithRetries } from "@oh-my-pi/pi-utils";

// Regression for the finding: `tts` had no entry in `TOOL_PATH_CLASSES`, so
// `output_path` was never authorized against the resource permission policy,
// and the local backend's `.mp3` -> `.wav` substitution could still bypass a
// deny rule scoped to the substituted suffix even after adding one.
describe("tts permission gate", () => {
	const contexts: Array<{ authStorage: AuthStorage; tempDir: string }> = [];

	afterEach(async () => {
		for (const { authStorage, tempDir } of contexts.splice(0)) {
			authStorage.close();
			await removeWithRetries(tempDir);
		}
	});

	async function makeContext(settings: Settings, cwd: string): Promise<CustomToolContext> {
		const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "omp-tts-permission-"));
		const authStorage = await AuthStorage.create(path.join(tempDir, "auth.db"));
		contexts.push({ authStorage, tempDir });
		const modelRegistry = new ModelRegistry(authStorage, path.join(tempDir, "models.json"));
		const sessionManager = SessionManager.inMemory(cwd);
		return {
			sessionManager,
			modelRegistry,
			model: undefined,
			isIdle: () => true,
			hasQueuedMessages: () => false,
			abort: () => {},
			settings,
		};
	}

	it("denies writing a substituted .wav sibling path the policy denies, even though .mp3 is allowed", async () => {
		const cwd = await fs.mkdtemp(path.join(os.tmpdir(), "omp-tts-cwd-"));
		const settings = Settings.isolated({
			"providers.tts": "local",
			"permissions.profile": "strict",
			"permissions.deny.write": ["**/speech.wav"],
		});
		const ctx = await makeContext(settings, cwd);

		const synthesizeSpy = spyOn(ttsClient, "synthesize").mockResolvedValue({
			pcm: new Float32Array([0, 0.1, -0.1]),
			sampleRate: 24_000,
		});

		try {
			await expect(
				ttsTool.execute(
					"call-1",
					{ text: "hello", voice_id: "eve", language: "en", output_path: "speech.mp3" },
					undefined,
					ctx,
				),
			).rejects.toThrow("**/speech.wav");
			await expect(fs.access(path.join(cwd, "speech.wav"))).rejects.toThrow();
		} finally {
			synthesizeSpy.mockRestore();
			await removeWithRetries(cwd);
		}
	});

	it("allows writing the substituted .wav sibling path when the policy permits it", async () => {
		const cwd = await fs.mkdtemp(path.join(os.tmpdir(), "omp-tts-cwd-allow-"));
		const settings = Settings.isolated({ "providers.tts": "local" });
		const ctx = await makeContext(settings, cwd);

		const synthesizeSpy = spyOn(ttsClient, "synthesize").mockResolvedValue({
			pcm: new Float32Array([0, 0.1, -0.1]),
			sampleRate: 24_000,
		});

		try {
			const result = await ttsTool.execute(
				"call-2",
				{ text: "hello", voice_id: "eve", language: "en", output_path: "speech.mp3" },
				undefined,
				ctx,
			);
			expect(result.isError).toBeFalsy();
			await fs.access(path.join(cwd, "speech.wav"));
		} finally {
			synthesizeSpy.mockRestore();
			await removeWithRetries(cwd);
		}
	});
});
