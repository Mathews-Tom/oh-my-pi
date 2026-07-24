import { beforeAll, describe, expect, it } from "bun:test";
import { formatContextUsage } from "@oh-my-pi/pi-coding-agent/modes/components/status-line/context-thresholds";
import type { SegmentContext } from "@oh-my-pi/pi-coding-agent/modes/components/status-line/segments";
import { renderSegment } from "@oh-my-pi/pi-coding-agent/modes/components/status-line/segments";
import { initTheme } from "@oh-my-pi/pi-coding-agent/modes/theme/theme";

beforeAll(async () => {
	await initTheme();
});

function createContextContext(
	options: SegmentContext["options"],
	overrides: Partial<Pick<SegmentContext, "contextPercent" | "contextTokens" | "contextWindow">> = {},
): SegmentContext {
	return {
		session: {
			state: { model: { id: "test-model", name: "Test Model" } },
			isFastModeActive: () => false,
			isAutoThinking: false,
			autoResolvedThinkingLevel: () => undefined,
			isAdvisorActive: () => false,
			getAdvisorStatusOverview: () => ({ configured: false, advisors: [] }),
		} as unknown as SegmentContext["session"],
		width: 120,
		compactThinkingLevel: false,
		options,
		planMode: null,
		loopMode: null,
		prewalk: null,
		goalMode: null,
		vibeMode: null,
		collab: null,
		usageStats: {
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
			tokensPerSecond: null,
		},
		contextPercent: 25,
		contextTokens: 50_000,
		contextWindow: 200_000,
		autoCompactEnabled: false,
		subagentCount: 0,
		activeMs: 0,
		activeRepo: null,
		worktree: null,
		git: { branch: null, status: null, pr: null },
		usage: null,
		...overrides,
	};
}

describe("status line context_pct segment token display", () => {
	it("renders only the percentage over the window when no context_pct option is set", () => {
		const rendered = renderSegment("context_pct", createContextContext({}));
		expect(rendered.content).toContain("25.0%/200K");
		expect(rendered.content).not.toContain("50K/200K");
	});

	it("renders the absolute used/window token fraction after the percentage when showTokens is true", () => {
		const rendered = renderSegment("context_pct", createContextContext({ context_pct: { showTokens: true } }));
		expect(rendered.content).toContain("25.0% 50K/200K");
	});

	it("matches the default no-option format when showTokens is explicitly false", () => {
		const withFalse = renderSegment("context_pct", createContextContext({ context_pct: { showTokens: false } }));
		const withoutOption = renderSegment("context_pct", createContextContext({}));
		expect(withFalse.content).toBe(withoutOption.content);
	});

	it("leaves the unknown-window fallback unchanged when showTokens is true", () => {
		const rendered = renderSegment(
			"context_pct",
			createContextContext({ context_pct: { showTokens: true } }, { contextWindow: 0, contextPercent: 0 }),
		);
		expect(rendered.content).toContain("50K/?");
		expect(rendered.content).not.toContain("50K/50K");
	});
});

describe("formatContextUsage optional usedTokens contract", () => {
	it("falls back to the plain percent/window format when showTokens is true but usedTokens is unknown", () => {
		expect(formatContextUsage(12.3, 1_000_000, undefined, true)).toBe("12.3%/1M");
	});

	it("renders the used/window fraction when both showTokens and usedTokens are provided", () => {
		expect(formatContextUsage(12.3, 1_000_000, 123_000, true)).toBe("12.3% 123K/1M");
	});
});
