import { describe, expect, it } from "bun:test";
import { validateGlobPattern } from "@oh-my-pi/pi-coding-agent/tools/permissions/matcher";

describe("validateGlobPattern", () => {
	it("rejects a balanced-but-empty character class that Bun.Glob silently compiles to no-match", () => {
		// `new Bun.Glob("**/secret[]")` never matches anything, including "**/secret[]"
		// itself — the leading "]" is a literal class member per POSIX glob dialect, so
		// there is no real closer and the class is dead. A deny rule using this pattern
		// would silently protect nothing.
		expect(validateGlobPattern("**/secret[]")).not.toBeNull();
	});

	it("rejects a negated-but-empty character class", () => {
		expect(validateGlobPattern("**/secret[!]")).not.toBeNull();
		expect(validateGlobPattern("**/secret[^]")).not.toBeNull();
	});

	it("rejects a dangling escape at the end of a pattern", () => {
		expect(validateGlobPattern("**/secret\\")).not.toBeNull();
	});

	it("accepts a non-empty character class", () => {
		expect(validateGlobPattern("**/secret[0-9]")).toBeNull();
		expect(validateGlobPattern("**/secret[!0-9]")).toBeNull();
	});

	it("accepts a character class whose first member is a literal ']'", () => {
		expect(validateGlobPattern("**/secret[]a]")).toBeNull();
	});

	it("accepts a mid-pattern escape", () => {
		expect(validateGlobPattern("**/secret\\*.env")).toBeNull();
	});

	it("still rejects an unterminated character class", () => {
		expect(validateGlobPattern("**/secret[a-")).not.toBeNull();
	});

	it("still rejects an unterminated brace expansion", () => {
		expect(validateGlobPattern("**/secret{a,b")).not.toBeNull();
	});

	it("accepts ordinary well-formed patterns", () => {
		expect(validateGlobPattern("**/*.env")).toBeNull();
		expect(validateGlobPattern("src/**")).toBeNull();
	});
});
