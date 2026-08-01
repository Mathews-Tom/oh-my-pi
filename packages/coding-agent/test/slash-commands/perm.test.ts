import { describe, expect, it, vi } from "bun:test";
import { executeAcpBuiltinSlashCommand } from "@oh-my-pi/pi-coding-agent/slash-commands/acp-builtins";
import type { SlashCommandRuntime } from "@oh-my-pi/pi-coding-agent/slash-commands/types";

type Store = Record<string, unknown>;

function acpRuntime(initial?: Store) {
	const store: Store = { "permissions.profile": "off", ...initial };
	const get = vi.fn((path: string) => store[path]);
	const override = vi.fn((path: string, value: unknown) => {
		store[path] = value;
	});
	const set = vi.fn();
	const output = vi.fn();
	const runtime = {
		session: { settings: { get, override, set } },
		output,
	} as unknown as SlashCommandRuntime;
	return { get, override, set, output, runtime, store };
}

describe("/perm slash command", () => {
	it("reports the off profile and the tool classes it cannot guard", async () => {
		const h = acpRuntime();

		const result = await executeAcpBuiltinSlashCommand("/perm", h.runtime);

		expect(result).toEqual({ consumed: true });
		expect(h.override).not.toHaveBeenCalled();
		const text = String(h.output.mock.calls.at(-1)?.[0] ?? "");
		expect(text).toContain("Permission profile: off");
		// The honesty surface: Class B tools are named, and the report says the
		// scan is not a sandbox rather than implying the profile covers them.
		expect(text).toContain("never a sandbox");
		expect(text).toContain("bash, browser, computer, eval, hub");
		expect(text).toContain("MCP, extension, and any other tool absent from the table is treated as Class B.");
		expect(text).toContain("permissions.profile");
	});

	it("switches the profile for the session only, never persisting it", async () => {
		const h = acpRuntime();

		const result = await executeAcpBuiltinSlashCommand("/perm strict", h.runtime);

		expect(result).toEqual({ consumed: true });
		expect(h.override).toHaveBeenCalledWith("permissions.profile", "strict");
		expect(h.set).not.toHaveBeenCalled();
		const text = String(h.output.mock.calls.at(-1)?.[0] ?? "");
		expect(text).toContain("Permission profile: strict.");
		expect(text).toContain("Switched for this session only.");
	});

	it("resolves the strict profile's effective rules in the report", async () => {
		const h = acpRuntime({ "permissions.profile": "strict" });

		await executeAcpBuiltinSlashCommand("/perm", h.runtime);

		const text = String(h.output.mock.calls.at(-1)?.[0] ?? "");
		expect(text).toContain("Confine writes to workspace: yes");
		expect(text).toContain("Confine reads to workspace: no");
		expect(text).toContain("Deny read: **/.env");
		// `.env.example` is carved out of the secret globs; a report that omitted
		// the allow list would misdescribe what strict actually denies.
		expect(text).toContain("Allow read: **/.env.example, **/.env.sample");
	});

	it("says Class B is unchecked when the opaque scan is disabled", async () => {
		const h = acpRuntime({ "permissions.profile": "workspace", "permissions.opaqueToolScan": "off" });

		await executeAcpBuiltinSlashCommand("/perm", h.runtime);

		const text = String(h.output.mock.calls.at(-1)?.[0] ?? "");
		expect(text).toContain("not checked at all, permissions.opaqueToolScan is off");
		expect(text).not.toContain("never a sandbox");
	});

	it("rejects an unknown profile without touching settings", async () => {
		const h = acpRuntime();

		const result = await executeAcpBuiltinSlashCommand("/perm bogus", h.runtime);

		expect(result).toEqual({ consumed: true });
		expect(h.override).not.toHaveBeenCalled();
		expect(h.output).toHaveBeenCalledWith("Usage: /perm [off|workspace|strict]");
	});
});
