/**
 * Protocol handler for rule:// URLs.
 *
 * URL forms:
 * - rule://<name> - Reads rule content
 */
import { getActiveRules } from "../capability/rule";
import type { InternalResource, InternalUrl, ProtocolHandler, ResolveContext, UrlCompletion } from "./types";

export function encodeRuleUrlHost(name: string): string {
	return name
		.split(":")
		.map(segment => encodeURIComponent(segment))
		.join(":");
}

export class RuleProtocolHandler implements ProtocolHandler {
	readonly scheme = "rule";
	readonly immutable = true;

	async resolve(url: InternalUrl, context?: ResolveContext): Promise<InternalResource> {
		const rules = context?.rules ?? getActiveRules();

		const ruleName = url.rawHost || url.hostname;
		if (!ruleName) {
			throw new Error("rule:// URL requires a rule name: rule://<name>");
		}

		const exactNames = [url.rawHost, url.rawEncodedHost, ...(url.port ? [] : [url.hostname])].filter(
			(name, index, names): name is string => Boolean(name) && names.indexOf(name) === index,
		);
		const rule = exactNames
			.map(name => rules.find(r => r.name === name))
			.find((candidate): candidate is (typeof rules)[number] => Boolean(candidate));
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

	async complete(_query?: string, context?: ResolveContext): Promise<UrlCompletion[]> {
		return (context?.rules ?? getActiveRules()).map(rule => {
			const value = encodeRuleUrlHost(rule.name);
			return {
				value,
				...(rule.name !== value ? { label: rule.name } : {}),
				...(rule.description ? { description: rule.description } : {}),
			};
		});
	}
}
