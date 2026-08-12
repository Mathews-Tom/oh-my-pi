import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { VaultProtocolHandler } from "@oh-my-pi/pi-coding-agent/internal-urls";
import * as vaultProtocol from "@oh-my-pi/pi-coding-agent/internal-urls/vault-protocol";
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

	it("honours a user allow carve-out over a deny rule", () => {
		const relaxed = buildPermissionPolicy("strict", { allowRead: ["**/.env.local"] });
		expect(decideTarget(target(".env.local"), relaxed, roots).kind).toBe("allow");
		expect(decideTarget(target(".env"), relaxed, roots).kind).toBe("deny");
	});

	it("lets an explicit user deny re-protect a path the profile's own carve-out allows", () => {
		// `.env.example` is allowed by strict's own built-in carve-out - a user
		// re-denying it must win, even though `decidePathTarget` checks the
		// merged allow list (which still contains that carve-out) before deny.
		const reprotected = buildPermissionPolicy("strict", { denyRead: ["**/.env.example"] });
		expect(decideTarget(target(".env.example"), reprotected, roots).kind).toBe("deny");
		// Unrelated carve-out (.env.sample) is untouched.
		expect(decideTarget(target(".env.sample"), reprotected, roots).kind).toBe("allow");
	});

	it("still lets an explicit user allow override that same user's own explicit deny", () => {
		// The one escape hatch: adding both an explicit deny and an explicit
		// allow for the same path is the user's own contradiction to resolve,
		// and allow wins - unchanged from today's user-vs-user behavior.
		const overridden = buildPermissionPolicy("strict", {
			denyRead: ["**/.env.example"],
			allowRead: ["**/.env.example"],
		});
		expect(decideTarget(target(".env.example"), overridden, roots).kind).toBe("allow");
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

describe("ssh:// is a filesystem target, not an exempt scheme", () => {
	const policy = buildPermissionPolicy("strict");

	it("denies a remote read matching a deny glob by its remote path", () => {
		const decision = decideTarget(target("ssh://host/home/user/.env"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("**/.env");
	});

	it("permits an ordinary remote path", () => {
		expect(decideTarget(target("ssh://host/etc/hosts"), policy, roots).kind).toBe("allow");
	});

	it("fails closed on an ssh:// URL with no path component", () => {
		expect(decideTarget(target("ssh://host"), policy, roots).kind).toBe("deny");
	});
});

describe("symlink alias deny matching", () => {
	// A symlink alias whose lexical spelling (`safe`) is itself inside the
	// workspace is contained under that spelling on the very first
	// root/target pair `relativeToRoots` checks — this used to return early
	// and never surface the resolved spelling (`.env`), so a `**/.env` deny
	// rule never saw the alias.
	it("denies reading a symlink alias whose resolved target matches a deny rule", () => {
		const link = path.join(workspace, "safe");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(path.join(workspace, ".env"), link);
		const policy = buildPermissionPolicy("strict");
		const decision = decideTarget(target("safe"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("**/.env");
	});

	it("does not weaken the separate outside-every-root containment check", () => {
		const link = path.join(workspace, "escape-alias");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(path.join(outside, "loot.txt"), link);
		const policy = buildPermissionPolicy("workspace", { confineReads: true });
		const decision = decideTarget(target("escape-alias"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("permissions.confineReads");
	});

	// `safe -> .ssh` is a symlinked *directory* (not a file), so a target
	// beneath it (`safe/new-config`) does not exist yet and cannot be
	// realpath-resolved outright. Without projecting through the deepest
	// existing ancestor's realpath, `relativeToRoots` only ever surfaced the
	// lexical spelling `safe/new-config`, so `**/.ssh/**` never matched.
	it("denies writing beneath a symlinked directory whose resolved ancestor matches a deny rule", () => {
		const link = path.join(workspace, "safe-dir");
		fs.rmSync(link, { force: true });
		fs.mkdirSync(path.join(workspace, ".ssh"), { recursive: true });
		fs.symlinkSync(path.join(workspace, ".ssh"), link);
		const policy = buildPermissionPolicy("strict");
		const decision = decideTarget(target("safe-dir/new-config", "write"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("**/.ssh/**");
	});

	// Simulates the Windows spelling of a directory-scoped deny rule's target
	// without needing an actual Windows runner: a POSIX filename may itself
	// contain a literal backslash, so `sub\widget.txt` here is exactly the
	// candidate `decidePathTarget` builds - a single path segment holding
	// the same bytes `path.relative` would emit on Windows for
	// `sub\widget.txt`. Before normalizing candidates to `/`, a
	// directory-scoped rule spelled with `/` never matched it.
	it("normalizes a backslash-separated candidate before glob matching", () => {
		fs.mkdirSync(path.join(workspace, "winlike"), { recursive: true });
		fs.writeFileSync(path.join(workspace, "winlike", "sub\\widget.txt"), "secret");
		const policy = buildPermissionPolicy("workspace", { denyRead: ["**/sub/widget.txt"] });
		const decision = decideTarget(target("winlike/sub\\widget.txt"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("**/sub/widget.txt");
	});
});

describe("vault:// targets", () => {
	let vaultRoot: string;

	beforeEach(() => {
		vaultRoot = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-vault-")));
		fs.writeFileSync(path.join(vaultRoot, ".env"), "SECRET=1");
		fs.mkdirSync(path.join(vaultRoot, "Notes"), { recursive: true });
		fs.writeFileSync(path.join(vaultRoot, "Notes", "note.md"), "hello");
		vi.spyOn(vaultProtocol, "isVaultEnabled").mockReturnValue(true);
		VaultProtocolHandler.setActiveVaultPathForTests(vaultRoot);
	});

	afterEach(() => {
		vi.restoreAllMocks();
		VaultProtocolHandler.resetForTests();
		fs.rmSync(vaultRoot, { recursive: true, force: true });
	});

	// The vault directory was previously exempted outright by
	// `isExemptPathArgument` (it is an internal-URL scheme), even though it
	// resolves to a real file on disk through the Obsidian integration.
	it("denies a vault:// target whose backing file matches a deny rule", () => {
		const policy = buildPermissionPolicy("strict");
		const decision = decideTarget(target("vault://_/.env"), policy, roots);
		expect(decision.kind).toBe("deny");
		if (decision.kind === "deny") expect(decision.rule).toBe("**/.env");
	});

	it("permits an ordinary vault:// target with no denied backing path", () => {
		const policy = buildPermissionPolicy("strict");
		const decision = decideTarget(target("vault://_/Notes/note.md"), policy, roots);
		expect(decision.kind).toBe("allow");
	});

	// The very first vault:// call in a session has nothing cached yet
	// (discovering the root is itself what a read does) - this must fail
	// closed rather than silently exempting the call the way it used to.
	it("fails closed when no vault root is cached yet", () => {
		VaultProtocolHandler.resetForTests();
		vi.spyOn(vaultProtocol, "isVaultEnabled").mockReturnValue(true);
		const policy = buildPermissionPolicy("strict");
		const decision = decideTarget(target("vault://_/note.md"), policy, roots);
		expect(decision.kind).toBe("deny");
	});

	it("permits any vault:// target under a policy with no active deny rules", () => {
		const policy = buildPermissionPolicy("off");
		expect(decideTarget(target("vault://_/.env"), policy, roots).kind).toBe("allow");
	});
});
