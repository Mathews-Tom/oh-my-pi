import { describe, expect, it } from "bun:test";
import type { Rule } from "@oh-my-pi/pi-coding-agent/capability/rule";
import { InternalUrlRouter } from "@oh-my-pi/pi-coding-agent/internal-urls";

function makeRule(name: string): Rule {
	return {
		name,
		path: `/rules/${name}.md`,
		content: `# ${name}`,
		_source: { provider: "test", providerName: "test", path: `/rules/${name}.md`, level: "project" },
	};
}

describe("RuleProtocolHandler", () => {
	it("resolves a percent-encoded rule name", async () => {
		const rules = [makeRule("C#")];
		const resource = await InternalUrlRouter.instance().resolve("rule://C%23", { rules });

		expect(resource.content).toBe("# C#");
	});

	it("does not double-decode a literal percent-sign name into an unrelated rule", async () => {
		const rules = [makeRule("C#")];

		await expect(InternalUrlRouter.instance().resolve("rule://C%2523", { rules })).rejects.toThrow(/Unknown rule/);
	});

	it("resolves a rule whose literal name is a percent-sign sequence", async () => {
		const rules = [makeRule("C%23")];
		const resource = await InternalUrlRouter.instance().resolve("rule://C%2523", { rules });

		expect(resource.content).toBe("# C%23");
	});
});
