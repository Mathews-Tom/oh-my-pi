/**
 * Issue #2600: Ctrl+C shutdown waits 30s on extension session_shutdown timeout.
 *
 * `ExtensionRunner.emit({ type: "session_shutdown" })` uses the generic
 * 30s extension handler timeout, so a single hung handler (in the wild:
 * `omp-discord-presence` waiting on a Discord IPC pipe that never replied)
 * holds Ctrl+C teardown hostage for the full window. `session_shutdown` is
 * fire-and-forget by contract — extensions can't observe the result — so it
 * MUST run on a tight, dedicated budget so dispose() returns quickly.
 *
 * Pins:
 *   1. Hung `session_shutdown` handlers settle within the short cap, not the
 *      generic timeout.
 *   2. The cap is independent of the generic handler timeout (raising one
 *      does not raise the other).
 *   3. The new public constant is the one `runner.emit()` consults.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs";
import * as path from "node:path";
import { ModelRegistry } from "@oh-my-pi/pi-coding-agent/config/model-registry";
import { discoverAndLoadExtensions } from "@oh-my-pi/pi-coding-agent/extensibility/extensions/loader";
import {
	EXTENSION_HANDLER_TIMEOUT_MS,
	ExtensionRunner,
	SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS,
	testSetExtensionHandlerTimeoutMs,
	testSetSessionShutdownHandlerTimeoutMs,
} from "@oh-my-pi/pi-coding-agent/extensibility/extensions/runner";
import { AuthStorage } from "@oh-my-pi/pi-coding-agent/session/auth-storage";
import { SessionManager } from "@oh-my-pi/pi-coding-agent/session/session-manager";
import { getProjectAgentDir, logger, TempDir } from "@oh-my-pi/pi-utils";

const HANG_EXTENSION_SRC = `
	export default function(pi) {
		pi.on("session_shutdown", async () => {
			await Promise.withResolvers().promise;
		});
	}
`;

describe("issue #2600 - session_shutdown handler timeout", () => {
	let sharedTempDir: TempDir;
	let modelRegistry: ModelRegistry;
	let authStorage: AuthStorage;

	beforeAll(async () => {
		sharedTempDir = TempDir.createSync("@pi-issue-2600-shared-");
		authStorage = await AuthStorage.create(path.join(sharedTempDir.path(), "auth.db"));
		modelRegistry = new ModelRegistry(authStorage);
	});

	afterAll(() => {
		authStorage.close();
		sharedTempDir.removeSync();
	});

	afterEach(() => {
		testSetExtensionHandlerTimeoutMs(EXTENSION_HANDLER_TIMEOUT_MS);
		testSetSessionShutdownHandlerTimeoutMs(SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS);
	});

	async function buildRunnerWithHangingShutdown(count = 1): Promise<{
		runner: ExtensionRunner;
		hangExtensionPath: string;
		hangExtensionPaths: string[];
		cleanup: () => void;
	}> {
		if (count < 1) throw new Error("count must be positive");
		const tempDir = TempDir.createSync("@pi-issue-2600-test-");
		const extensionsDir = path.join(getProjectAgentDir(tempDir.path()), "extensions");
		fs.mkdirSync(extensionsDir, { recursive: true });
		const hangExtensionPaths: string[] = [];
		for (let i = 0; i < count; i++) {
			const hangExtensionPath = path.join(tempDir.path(), `hang-session-shutdown-${i}.ts`);
			fs.writeFileSync(hangExtensionPath, HANG_EXTENSION_SRC);
			hangExtensionPaths.push(hangExtensionPath);
		}
		const hangExtensionPath = hangExtensionPaths[0];
		if (!hangExtensionPath) throw new Error("missing hanging extension");

		const sessionManager = SessionManager.inMemory();
		const result = await discoverAndLoadExtensions([extensionsDir, ...hangExtensionPaths], tempDir.path());
		const runner = new ExtensionRunner(
			result.extensions,
			result.runtime,
			tempDir.path(),
			sessionManager,
			modelRegistry,
		);
		return {
			runner,
			hangExtensionPath,
			hangExtensionPaths,
			cleanup: () => tempDir.removeSync(),
		};
	}

	it("runs multiple session_shutdown handlers within one cap", async () => {
		const { runner, hangExtensionPaths, cleanup } = await buildRunnerWithHangingShutdown(4);
		const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
		vi.useFakeTimers();
		try {
			testSetSessionShutdownHandlerTimeoutMs(100);
			let settled = false;
			const emitted = runner.emit({ type: "session_shutdown" }).then(() => {
				settled = true;
			});

			await Promise.resolve();
			vi.advanceTimersByTime(99);
			await Promise.resolve();
			expect(settled).toBe(false);

			vi.advanceTimersByTime(1);
			await Promise.resolve();
			vi.advanceTimersByTime(0);
			await emitted;
			expect(settled).toBe(true);
			for (const hangExtensionPath of hangExtensionPaths) {
				expect(warnSpy).toHaveBeenCalledWith("Extension handler timed out", {
					extensionPath: hangExtensionPath,
					event: "session_shutdown",
					timeoutMs: 100,
				});
			}
		} finally {
			vi.useRealTimers();
			warnSpy.mockRestore();
			cleanup();
		}
	});

	it("defaults the session_shutdown cap to ≤ 5s, never the generic 30s budget", () => {
		expect(SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS).toBeLessThanOrEqual(5_000);
		expect(SESSION_SHUTDOWN_HANDLER_TIMEOUT_MS).toBeLessThan(EXTENSION_HANDLER_TIMEOUT_MS);
	});

	it("session_shutdown cap is independent from the generic handler cap", async () => {
		const { runner, hangExtensionPath, cleanup } = await buildRunnerWithHangingShutdown();
		const warnSpy = vi.spyOn(logger, "warn").mockImplementation(() => {});
		vi.useFakeTimers();
		try {
			// If dispatch reads the generic knob, advancing the shutdown budget
			// cannot settle this handler.
			testSetExtensionHandlerTimeoutMs(10_000);
			testSetSessionShutdownHandlerTimeoutMs(50);
			let settled = false;
			const emitted = runner.emit({ type: "session_shutdown" }).then(() => {
				settled = true;
			});

			await Promise.resolve();
			vi.advanceTimersByTime(49);
			await Promise.resolve();
			expect(settled).toBe(false);

			vi.advanceTimersByTime(1);
			await Promise.resolve();
			vi.advanceTimersByTime(0);
			await emitted;
			expect(settled).toBe(true);
			expect(warnSpy).toHaveBeenCalledWith("Extension handler timed out", {
				extensionPath: hangExtensionPath,
				event: "session_shutdown",
				timeoutMs: 50,
			});
		} finally {
			vi.useRealTimers();
			warnSpy.mockRestore();
			cleanup();
		}
	});
});
