import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { InMemorySnapshotStore } from "@oh-my-pi/hashline";
import type { AgentTool } from "@oh-my-pi/pi-agent-core";
import type { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import { EDIT_MODE_STRATEGIES, type PerFileDiffPreview } from "@oh-my-pi/pi-coding-agent/edit";
import { ToolExecutionComponent } from "@oh-my-pi/pi-coding-agent/modes/components/tool-execution";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";
import { loadPermissionsConfig } from "@oh-my-pi/pi-coding-agent/tools/permissions";
import type { TUI } from "@oh-my-pi/pi-tui";
import { removeWithRetries } from "@oh-my-pi/pi-utils";

// The finding: a streamed hashline edit header naming a read-denied file
// (`.env` under `strict`) drives `computeDiffPreview`, which reads the target
// straight off disk, well before the tool wrapper's own resource-permission
// gate ever runs — a live preview of a denied file's content. `resolvePermissions`
// is the fix's hook: the component must check the streamed target against it
// and skip the preview entirely for a denied target, while an ordinary
// (allowed) target still previews normally.
describe("streaming edit preview resource-permission gate", () => {
	let tmpDir: string;
	let themed = false;
	let restore: (() => void) | undefined;
	let component: ToolExecutionComponent | undefined;

	beforeEach(async () => {
		if (!themed) {
			await initTheme();
			themed = true;
		}
		tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "preview-permissions-"));
		await fs.writeFile(path.join(tmpDir, ".env"), "SECRET=1\n");
		await fs.writeFile(path.join(tmpDir, "mod.ts"), "export const a = 1;\n");
	});

	afterEach(async () => {
		restore?.();
		restore = undefined;
		component?.stopAnimation();
		component = undefined;
		await removeWithRetries(tmpDir);
	});

	function settingsOf(overrides: Record<string, unknown>): Settings {
		return {
			get(key: string): unknown {
				return Object.hasOwn(overrides, key) ? overrides[key] : undefined;
			},
		} as unknown as Settings;
	}

	function strictResolvePermissions() {
		return () => {
			const policy = loadPermissionsConfig(settingsOf({ "permissions.profile": "strict" }));
			if (!policy) return null;
			return { policy, roots: { cwd: tmpDir, additionalDirectories: [] } };
		};
	}

	const ui = { requestRender() {} } as unknown as TUI;
	const tool = { mode: "hashline" } as unknown as AgentTool;

	test("never computes a preview for a streamed hashline header naming a denied file", async () => {
		const spy = spyOn(EDIT_MODE_STRATEGIES.hashline, "computeDiffPreview");
		restore = () => spy.mockRestore();

		component = new ToolExecutionComponent(
			"edit",
			{ input: "[.env#ab12]\n64:1\n|SECRET=2\n" },
			{ resolvePermissions: strictResolvePermissions(), snapshots: new InMemorySnapshotStore() },
			tool,
			ui,
			tmpDir,
		);
		await component.whenPreviewSettled();

		expect(spy).not.toHaveBeenCalled();
	});

	test("still computes a preview for a streamed hashline header naming an allowed file", async () => {
		const preview: PerFileDiffPreview[] = [{ path: "mod.ts", diff: "@@ -1 +1 @@\n-const a = 1;\n+const a = 2;" }];
		const spy = spyOn(EDIT_MODE_STRATEGIES.hashline, "computeDiffPreview").mockResolvedValue(preview);
		restore = () => spy.mockRestore();

		component = new ToolExecutionComponent(
			"edit",
			{ input: "[mod.ts#ab12]\n64:1\n|const a = 2;\n" },
			{ resolvePermissions: strictResolvePermissions(), snapshots: new InMemorySnapshotStore() },
			tool,
			ui,
			tmpDir,
		);
		await component.whenPreviewSettled();

		expect(spy).toHaveBeenCalledTimes(1);
	});

	test("computes a preview as before when the caller supplies no resolvePermissions", async () => {
		const preview: PerFileDiffPreview[] = [{ path: ".env", diff: "@@ -1 +1 @@\n-SECRET=1\n+SECRET=2" }];
		const spy = spyOn(EDIT_MODE_STRATEGIES.hashline, "computeDiffPreview").mockResolvedValue(preview);
		restore = () => spy.mockRestore();

		component = new ToolExecutionComponent(
			"edit",
			{ input: "[.env#ab12]\n64:1\n|SECRET=2\n" },
			{ snapshots: new InMemorySnapshotStore() },
			tool,
			ui,
			tmpDir,
		);
		await component.whenPreviewSettled();

		expect(spy).toHaveBeenCalledTimes(1);
	});
});
