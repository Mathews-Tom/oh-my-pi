import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { resolveReadPath } from "@oh-my-pi/pi-coding-agent/tools/path-utils";
import {
	buildPermissionPolicy,
	confineToRoots,
	decideTarget,
	matchGlob,
	type PathAccess,
	type PathTarget,
	type PermissionRoots,
} from "@oh-my-pi/pi-coding-agent/tools/permissions";

let workspace: string;
let sibling: string;
let outside: string;
let roots: PermissionRoots;

function target(raw: string, access: PathAccess = "read"): PathTarget {
	return { raw, access, field: "path" };
}

beforeAll(() => {
	const base = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-perm-")));
	workspace = path.join(base, "ws");
	sibling = path.join(base, "extra");
	outside = path.join(base, "outside");
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.mkdirSync(sibling, { recursive: true });
	fs.mkdirSync(outside, { recursive: true });
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
	fs.writeFileSync(path.join(workspace, ".env.example"), "SECRET=");
	fs.writeFileSync(path.join(workspace, "src", "main.ts"), "export {};");
	fs.writeFileSync(path.join(outside, "loot.txt"), "loot");
	roots = { cwd: workspace, additionalDirectories: [sibling] };
});

afterAll(() => {
	fs.rmSync(path.dirname(workspace), { recursive: true, force: true });
});

describe("profile off", () => {
	it("permits every access, including outside every root", () => {
		const policy = buildPermissionPolicy("off");
		expect(decideTarget(target(".env"), policy, roots).kind).toBe("allow");
		expect(decideTarget(target("/etc/passwd", "write"), policy, roots).kind).toBe("allow");
		expect(decideTarget(target("../outside/loot.txt", "write"), policy, roots).kind).toBe("allow");
	});
});

describe("profile workspace", () => {
	const policy = buildPermissionPolicy("workspace");

	it("confines writes but not reads", () => {
		expect(decideTarget(target("/etc/hosts", "read"), policy, roots).kind).toBe("allow");
		const denied = decideTarget(target("/etc/hosts", "write"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("permissions.confineWrites");
	});

	it("permits writes under any workspace root", () => {
		expect(decideTarget(target("src/new.ts", "write"), policy, roots).kind).toBe("allow");
		expect(decideTarget(target(path.join(sibling, "note.md"), "write"), policy, roots).kind).toBe("allow");
	});

	it("denies a `..` traversal escape on a write", () => {
		const denied = decideTarget(target("../outside/loot.txt", "write"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") {
			expect(denied.rule).toBe("permissions.confineWrites");
			expect(denied.reason).toContain("outside every workspace root");
		}
	});

	it("does not deny secrets — that is strict's job", () => {
		expect(decideTarget(target(".env", "read"), policy, roots).kind).toBe("allow");
	});
});

describe("profile strict", () => {
	const policy = buildPermissionPolicy("strict");

	it("denies reading a secret and names the exact rule", () => {
		const denied = decideTarget(target(".env"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") {
			expect(denied.rule).toBe("**/.env");
			expect(denied.reason).toContain("permissions.allow.read");
		}
	});

	it("denies secrets at any depth, and only at a path boundary", () => {
		fs.mkdirSync(path.join(workspace, "svc"), { recursive: true });
		fs.writeFileSync(path.join(workspace, "svc", ".env"), "SECRET=1");
		expect(decideTarget(target("svc/.env"), policy, roots).kind).toBe("deny");
		expect(decideTarget(target("src/main.ts"), policy, roots).kind).toBe("allow");
	});

	it("ships a carve-out for .env.example so the common case needs no rule", () => {
		expect(decideTarget(target(".env.example"), policy, roots).kind).toBe("allow");
		expect(decideTarget(target(".env.local"), policy, roots).kind).toBe("deny");
	});

	it("honours an explicit user deny after the profile carve-out", () => {
		const tightened = buildPermissionPolicy("strict", { denyRead: ["**/.env.example"] });
		const denied = decideTarget(target(".env.example"), tightened, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("**/.env.example");
	});

	it("keeps the .env.example carve-out inside the workspace", () => {
		// The carve-out exists to relax `**/.env.*`, not `confineWrites`. When it
		// lived in the same list as a user's allow rules it won outright, so
		// `strict` — documented as "workspace + secret rules" — permitted writing
		// a matching name anywhere on the filesystem.
		const escaping = path.join(outside, ".env.example");
		const denied = decideTarget(target(escaping, "write"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("permissions.confineWrites");
		// Inside a root it still clears the secret deny globs.
		expect(decideTarget(target(".env.example", "write"), policy, roots).kind).toBe("allow");
	});

	it("does not let a carve-out matching the lexical spelling suppress a deny matching the resolved target", () => {
		// A workspace symlink literally named `.env.example` but pointing at the
		// real `.env` must not read as the shipped template: the deny fires on
		// the resolved spelling (`.env`), and the carve-out is only allowed to
		// suppress a deny that fired on the *same* spelling it matches.
		const linkDir = path.join(workspace, "link-carve-out");
		fs.mkdirSync(linkDir, { recursive: true });
		const link = path.join(linkDir, ".env.example");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(path.join(workspace, ".env"), link);
		const denied = decideTarget(target(path.join(linkDir, ".env.example")), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("**/.env");
	});

	it("still lets a user allow rule outrank confinement", () => {
		// The escape hatch every confinement denial message points at: a path the
		// user named explicitly is in bounds even outside every root.
		const relaxed = buildPermissionPolicy("strict", { allowWrite: [`${outside}/**`] });
		expect(decideTarget(target(path.join(outside, "loot.txt"), "write"), relaxed, roots).kind).toBe("allow");
	});

	it("honours a user allow carve-out over a deny rule", () => {
		const relaxed = buildPermissionPolicy("strict", { allowRead: ["**/.env.local"] });
		expect(decideTarget(target(".env.local"), relaxed, roots).kind).toBe("allow");
		expect(decideTarget(target(".env"), relaxed, roots).kind).toBe("deny");
	});

	it("merges user deny globs onto the profile floor", () => {
		const tightened = buildPermissionPolicy("strict", { denyRead: ["**/*.md"] });
		expect(decideTarget(target("README.md"), tightened, roots).kind).toBe("deny");
		expect(decideTarget(target(".env"), tightened, roots).kind).toBe("deny");
	});

	it("cannot be relaxed below its floor by an empty user deny list", () => {
		const policyWithEmptyOverride = buildPermissionPolicy("strict", { denyRead: [] });
		expect(decideTarget(target(".env"), policyWithEmptyOverride, roots).kind).toBe("deny");
	});
});

describe("symlink containment", () => {
	const policy = buildPermissionPolicy("workspace", { confineReads: true });

	it("denies a read through a symlink pointing out of the workspace", () => {
		const link = path.join(workspace, "escape");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(outside, link);
		const denied = decideTarget(target("escape/loot.txt"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("permissions.confineReads");
	});

	it("refuses a dangling symlink outright rather than guessing", () => {
		const dangling = path.join(workspace, "dangling");
		fs.rmSync(dangling, { force: true });
		fs.symlinkSync(path.join(outside, "nope", "gone"), dangling);
		const denied = decideTarget(target("dangling", "write"), buildPermissionPolicy("workspace"), roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.reason).toContain("unresolvable symlink");
	});

	it("permits a not-yet-created file whose deepest existing ancestor is inside", () => {
		expect(decideTarget(target("src/deeply/nested/new.ts", "write"), policy, roots).kind).toBe("allow");
	});

	it("treats a workspace root itself as contained", () => {
		expect(confineToRoots(workspace, [workspace]).contained).toBe(true);
	});

	it("reports no-roots rather than silently passing when nothing resolves", () => {
		const result = confineToRoots(path.join(workspace, "x"), [path.join(outside, "vanished")]);
		expect(result.contained).toBe(false);
		if (!result.contained) expect(result.reason).toBe("no-roots");
	});

	// The finding: with confinement off (`workspace`'s read default, or
	// `strict`'s), `relativeToRoots` only ever surfaces a symlink-resolved
	// spelling that lands *inside* a root, silently dropping the real target
	// once it fails every root's containment check. A symlink inside the
	// workspace pointing at a denied file outside every root was checked
	// only against its lexical spelling, so `**/.env` never matched.
	it("matches a deny rule against the real target of a symlink pointing outside every root, with confinement off", () => {
		const link = path.join(workspace, "innocent");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(path.join(outside, ".env"), link);
		fs.writeFileSync(path.join(outside, ".env"), "SECRET=1");
		const strictPolicy = buildPermissionPolicy("strict"); // confineReads: false by default
		const denied = decideTarget(target("innocent"), strictPolicy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("**/.env");
	});
});

describe("scheme exemptions", () => {
	const policy = buildPermissionPolicy("strict", { confineReads: true, denyRead: ["**/*"] });

	it("leaves internal URLs reachable under the strictest policy", () => {
		for (const url of ["local://plan.md", "memory://abc", "xd://browser", "artifact://7", "skill://github"]) {
			expect(decideTarget(target(url), policy, roots).kind).toBe("allow");
		}
	});

	it("leaves http(s) URLs alone — they are not filesystem targets", () => {
		expect(decideTarget(target("https://example.com/x"), policy, roots).kind).toBe("allow");
	});
});

describe("glob dialect", () => {
	it("matches nested paths only with the ** form, which is why *.env is wrong", () => {
		expect(matchGlob(["**/.env"], ["svc/.env"])).toBe("**/.env");
		expect(matchGlob(["*.env"], ["svc/.env"])).toBeNull();
	});

	// `Bun.Glob` accepts any string; a malformed pattern compiles and matches
	// nothing, so a typo'd rule silently protects nothing rather than throwing.
	it("treats a malformed pattern as matching nothing, without derailing the rest", () => {
		expect(matchGlob(["[a-", "**/.env"], ["svc/.env"])).toBe("**/.env");
	});

	// The finding: `path.relative`/`path.resolve`/`path.basename` all yield
	// `\`-separated candidates on Windows, while `Bun.Glob`'s documented
	// pattern rules use `/`. A directory-sensitive rule matched neither the
	// relative nor absolute Windows-style candidate before matching
	// normalized every candidate to forward slashes first.
	it("matches a Windows-style backslash-separated candidate against a forward-slash rule", () => {
		expect(matchGlob(["config/secrets.json"], ["config\\secrets.json"])).toBe("config/secrets.json");
		expect(matchGlob(["**/.aws/credentials"], ["C:\\Users\\dev\\.aws\\credentials"])).toBe("**/.aws/credentials");
		expect(matchGlob(["src/generated/**"], ["src\\generated\\out.ts"])).toBe("src/generated/**");
	});
});

describe("read-path normalization", () => {
	// `read({ path: "secret\\ file.txt" })` checks the literal-backslash spelling
	// here, but `resolveReadPath` strips the shell escape before the file is
	// actually opened, so the on-disk read lands on "secret file.txt" — a
	// different candidate than the one the deny glob was matched against.
	it("denies a shell-escaped spelling that resolves to a denied file at open time", () => {
		fs.writeFileSync(path.join(workspace, "secret file.txt"), "SECRET=1");
		const policy = buildPermissionPolicy("workspace", { denyRead: ["**/secret file.txt"] });
		const denied = decideTarget(target("secret\\ file.txt"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("**/secret file.txt");
	});

	it("still permits an ordinary escaped path with no denied on-disk variant", () => {
		fs.writeFileSync(path.join(workspace, "plain file.txt"), "hello");
		const policy = buildPermissionPolicy("workspace", { denyRead: ["**/secret file.txt"] });
		expect(decideTarget(target("plain\\ file.txt"), policy, roots).kind).toBe("allow");
	});
});

describe("resolveReadPath authorization ordering", () => {
	// The finding: `resolveReadPath` probed every filename-variant spelling
	// (shell-escape, AM/PM, NFD, curly-quote) with `fs.accessSync` before any
	// authorization ran, so a denied path was touched on disk merely to
	// discover whether some other spelling of it existed. `isPathAllowed`
	// must gate each candidate's existence probe, including the very first
	// one against the plain lexical path.

	it("stops at a denied candidate rather than continuing to probe a later, allowed spelling", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-read-path-"));
		try {
			// The literal (unescaped) candidate is denied but does not exist; the
			// shell-escaped variant is allowed and DOES exist. If a denial were
			// merely skipped, resolution would keep looking and return the
			// existing, allowed variant instead — exactly the "guess another
			// spelling past a denial" behavior this ordering must not permit.
			fs.writeFileSync(path.join(dir, "secret file.txt"), "SECRET=1");
			const literalPath = path.join(dir, "secret\\ file.txt");
			const escapedPath = path.join(dir, "secret file.txt");
			const denyLiteralOnly = (candidate: string): boolean => candidate !== literalPath;
			const resolved = resolveReadPath("secret\\ file.txt", dir, denyLiteralOnly);
			expect(resolved).toBe(literalPath);
			expect(resolved).not.toBe(escapedPath);
			// With no predicate at all, the same input resolves to the file that
			// actually exists — proving the deny above is what changed the outcome.
			expect(resolveReadPath("secret\\ file.txt", dir)).toBe(escapedPath);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	it("checks the plain lexical candidate before probing it for existence", () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-read-path-"));
		try {
			fs.writeFileSync(path.join(dir, "plain.txt"), "hello");
			const lexicalPath = path.join(dir, "plain.txt");
			const denyEverything = (): boolean => false;
			// Denying the lexical candidate itself must short-circuit before any
			// `fs.accessSync` probe — proven by falling back to the unconfirmed
			// lexical path even though the file exists and would otherwise win.
			expect(resolveReadPath("plain.txt", dir, denyEverything)).toBe(lexicalPath);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	// End-to-end through the permission layer: a denied variant spelling of an
	// existing secret must never surface as the resolved read target.
	it("keeps a denied shell-escaped spelling from resolving to the secret it names, via decideTarget", () => {
		const secretFile = path.join(workspace, "escaped secret.txt");
		fs.writeFileSync(secretFile, "SECRET=1");
		const policy = buildPermissionPolicy("workspace", { denyRead: ["**/escaped secret.txt"] });
		const denied = decideTarget(target("escaped\\ secret.txt"), policy, roots);
		expect(denied.kind).toBe("deny");
		if (denied.kind === "deny") expect(denied.rule).toBe("**/escaped secret.txt");
	});
});

describe("read selector suffixes", () => {
	const policy = buildPermissionPolicy("strict");

	// `read` and `grep` peel a trailing selector before opening the file, so a
	// guard that only checked the raw string would let `.env:raw` walk past
	// every deny glob.
	it("denies a secret named with a read selector", () => {
		for (const raw of [".env:raw", ".env:1-5", ".env:raw:1-50", ".env:conflicts"]) {
			const decision = decideTarget(target(raw), policy, roots);
			expect(decision.kind).toBe("deny");
			if (decision.kind === "deny") expect(decision.rule).toBe("**/.env");
		}
	});

	it("still permits an ordinary file read with a selector", () => {
		expect(decideTarget(target("src/main.ts:1-5"), policy, roots).kind).toBe("allow");
	});
});
