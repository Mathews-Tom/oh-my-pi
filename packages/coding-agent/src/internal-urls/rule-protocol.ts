/**
 * Protocol handler for rule:// URLs.
 *
 * URL forms:
 * - rule://<name> - Reads rule content
 */
import { getActiveRules } from "../capability/rule";
import type { InternalResource, InternalUrl, ProtocolHandler, UrlCompletion } from "./types";

function decodeRuleName(name: string): string {
	try {
		return decodeURIComponent(name);
	} catch {
		return name;
	}
}

export function encodeRuleUrlHost(name: string): string {
	return name
		.split(":")
		.map(segment => encodeURIComponent(segment))
		.join(":");
}

export class RuleProtocolHandler implements ProtocolHandler {
	readonly scheme = "rule";
	readonly immutable = true;

	async resolve(url: InternalUrl): Promise<InternalResource> {
		const rules = getActiveRules();

		const ruleName = url.rawHost || url.hostname;
		if (!ruleName) {
			throw new Error("rule:// URL requires a rule name: rule://<name>");
		}

		const exactNames = [url.rawHost, url.rawEncodedHost, url.hostname].filter(
			(name, index, names): name is string => Boolean(name) && names.indexOf(name) === index,
		);
		let rule = exactNames
			.map(name => rules.find(r => r.name === name))
			.find((candidate): candidate is (typeof rules)[number] => Boolean(candidate));
		if (!rule) {
			rule = exactNames
				.map(name => rules.find(r => decodeRuleName(r.name) === decodeRuleName(name)))
				.find((candidate): candidate is (typeof rules)[number] => Boolean(candidate));
		}
		if (!rule) {
			const available = rules.map(r => r.name);
			const availableStr = available.length > 0 ? available.join(", ") : "none";
			throw new Error(`Unknown rule: ${ruleName}\nAvailable: ${availableStr}`);
		}

		return {
			url: url.href,
			content: rule.content,
			contentType: "text/markdown",
			size: Buffer.byteLength(rule.content, "utf-8"),
			sourcePath: rule.path,
			notes: [],
		};
	}

	async complete(): Promise<UrlCompletion[]> {
		return getActiveRules().map(rule => {
			const value = encodeRuleUrlHost(rule.name);
			const label = rule._source.provider === "claude" ? decodeRuleName(rule.name) : rule.name;
			return {
				value,
				...(label !== value ? { label } : {}),
				...(rule.description ? { description: rule.description } : {}),
			};
		});
	}
}
