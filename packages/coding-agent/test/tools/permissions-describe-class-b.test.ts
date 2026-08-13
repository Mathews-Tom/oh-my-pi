import { describe, expect, it } from "bun:test";
import { buildPermissionPolicy, describePermissionState } from "@oh-my-pi/pi-coding-agent/tools/permissions";

describe("describePermissionState Class B coverage", () => {
	it("reports Class B as unchecked when the profile is off and policy is null", () => {
		const report = describePermissionState("off", null);
		const classBLine = report.split("\n").find(line => line.includes("Class B ("));
		expect(classBLine).toBeDefined();
		expect(classBLine).toContain("not checked");
		expect(classBLine).not.toContain("scan=deny");
	});

	it("reports Class B as scanned when a profile is active with the default scan mode", () => {
		const policy = buildPermissionPolicy("workspace");
		const report = describePermissionState("workspace", policy);
		const classBLine = report.split("\n").find(line => line.includes("Class B ("));
		expect(classBLine).toBeDefined();
		expect(classBLine).toContain(`scan=${policy.opaqueToolScan}`);
	});
});
