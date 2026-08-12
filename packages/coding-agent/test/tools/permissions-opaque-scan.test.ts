import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	buildPermissionPolicy,
	type PermissionRoots,
	scanOpaqueArguments,
} from "@oh-my-pi/pi-coding-agent/tools/permissions";

let workspace: string;
let roots: PermissionRoots;
const STRICT = buildPermissionPolicy("strict");

beforeAll(() => {
	workspace = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "omp-scan-")));
	fs.mkdirSync(path.join(workspace, "src"), { recursive: true });
	fs.writeFileSync(path.join(workspace, ".env"), "SECRET=1");
	roots = { cwd: workspace, additionalDirectories: [] };
});

afterAll(() => {
	fs.rmSync(workspace, { recursive: true, force: true });
});

describe("shell scan", () => {
	it("catches a literal secret in a plain command", () => {
		const hit = scanOpaqueArguments({ command: "cat .env" }, "shell", STRICT, roots);
		expect(hit?.rule).toBe("**/.env");
		expect(hit?.literal).toBe(".env");
	});

	it("catches it through quoting and past a pipe", () => {
		expect(scanOpaqueArguments({ command: "echo hi | cat './.env'" }, "shell", STRICT, roots)?.rule).toBe("**/.env");
	});

	it("catches an absolute reference to the same file", () => {
		const command = `cat ${path.join(workspace, ".env")}`;
		expect(scanOpaqueArguments({ command }, "shell", STRICT, roots)?.rule).toBe("**/.env");
	});
	it("catches a secret inside a command substitution", () => {
		expect(scanOpaqueArguments({ command: "$(cat .env)" }, "shell", STRICT, roots)?.rule).toBe("**/.env");
	});

	it("catches a secret passed as a flag value", () => {
		expect(scanOpaqueArguments({ command: "docker run --env-file=.env img" }, "shell", STRICT, roots)?.rule).toBe(
			"**/.env",
		);
	});

	it("falls back to a word split for a value the tokenizer yields nothing for", () => {
		// The first value tokenizes; the second does not. Before the fallback
		// was scoped per value, only the first could ever reach it.
		const args = { first: "ls src", second: "   " };
		expect(scanOpaqueArguments(args, "shell", STRICT, roots)).toBeNull();
		const withSecret = { first: "ls src", second: "\t.env\n" };
		expect(scanOpaqueArguments(withSecret, "shell", STRICT, roots)?.rule).toBe("**/.env");
	});

	it("leaves an ordinary command alone", () => {
		expect(scanOpaqueArguments({ command: "bun test src/main.ts" }, "shell", STRICT, roots)).toBeNull();
	});

	it("does not fire on a flag that merely looks path-shaped", () => {
		expect(scanOpaqueArguments({ command: "ls --color=auto src" }, "shell", STRICT, roots)).toBeNull();
	});

	// The documented limit, asserted so the claim in docs/permissions.md is
	// backed by a test rather than a promise.
	it("cannot see through indirection — this is not a sandbox", () => {
		expect(scanOpaqueArguments({ command: "cat $(echo Lmk|base64 -d)" }, "shell", STRICT, roots)).toBeNull();
	});
});

describe("string scan", () => {
	it("catches a secret named in nested arguments of an unknown tool", () => {
		const args = { operation: "read", target: { file: ".env" } };
		expect(scanOpaqueArguments(args, "strings", STRICT, roots)?.rule).toBe("**/.env");
	});

	it("catches a secret named inside evaluated code", () => {
		const code = 'const s = await Bun.file(".env").text();';
		expect(scanOpaqueArguments({ code }, "strings", STRICT, roots)?.rule).toBe("**/.env");
	});
});

describe("Windows path normalization", () => {
	// Simulates the Windows spelling of a directory-scoped deny rule's target
	// without needing an actual Windows runner: a POSIX filename may itself
	// contain a literal backslash, so `sub\.ssh\config` here is exactly the
	// same bytes the literal would carry on Windows (and what `path.relative`
	// would emit there too) - before normalizing every candidate to `/`, this
	// never matched `**/.ssh/**` because `Bun.Glob` never treated `\` as a
	// path separator.
	it("normalizes a backslash-separated literal before glob matching", () => {
		expect(scanOpaqueArguments({ code: "sub\\.ssh\\config" }, "strings", STRICT, roots)?.rule).toBe("**/.ssh/**");
	});
});

describe("policy interaction", () => {
	it("honours an allow carve-out", () => {
		const relaxed = buildPermissionPolicy("strict", { allowRead: ["**/.env"], allowWrite: ["**/.env"] });
		expect(scanOpaqueArguments({ command: "cat .env" }, "shell", relaxed, roots)).toBeNull();
	});

	it("does nothing when the profile carries no deny rules", () => {
		const workspaceOnly = buildPermissionPolicy("workspace");
		expect(scanOpaqueArguments({ command: "cat .env" }, "shell", workspaceOnly, roots)).toBeNull();
	});

	// Mirrors `decidePathTarget`'s own precedence test (`permissions-resolve.test.ts`):
	// the scan used to check `policy.allow` before `policy.deny` directly,
	// bypassing `matchAccessRule` and its explicit-deny-over-profile-carve-out
	// precedence entirely, so strict's own `.env.example` allow carve-out
	// silently outranked a user's own re-deny of that literal.
	it("lets an explicit user deny re-protect a literal the profile's own carve-out allows", () => {
		const reprotected = buildPermissionPolicy("strict", { denyRead: ["**/.env.example"] });
		expect(scanOpaqueArguments({ command: "cat .env.example" }, "shell", reprotected, roots)?.rule).toBe(
			"**/.env.example",
		);
		// Unrelated carve-out (.env.sample) is untouched.
		expect(scanOpaqueArguments({ command: "cat .env.sample" }, "shell", reprotected, roots)).toBeNull();
	});

	it("still lets an explicit user allow override that same user's own explicit deny on a literal", () => {
		const overridden = buildPermissionPolicy("strict", {
			denyRead: ["**/.env.example"],
			allowRead: ["**/.env.example"],
		});
		expect(scanOpaqueArguments({ command: "cat .env.example" }, "shell", overridden, roots)).toBeNull();
	});

	it("leaves internal URLs alone", () => {
		expect(scanOpaqueArguments({ command: "cat local://plan.md" }, "shell", STRICT, roots)).toBeNull();
	});

	it("does not apply confinement — naming a path is not writing to it", () => {
		const confined = buildPermissionPolicy("workspace", { confineWrites: true });
		expect(scanOpaqueArguments({ command: "ls /usr/bin" }, "shell", confined, roots)).toBeNull();
	});
});

describe("symlink alias identity separation", () => {
	// `STRICT_SECRET_ALLOW_GLOBS` carves out `**/.env.example` so the checked-in
	// template beside a real `.env` stays readable. If `.env.example` is
	// actually a symlink to `.env`, the alias's own lexical spelling still
	// matches that allow glob, but the command reads the canonical `.env`
	// content through it — the allow must not clear the deny on that
	// canonical spelling too.
	it("does not let an allowed symlink alias's lexical spelling clear a deny on its canonical target", () => {
		const aliasPath = path.join(workspace, ".env.example");
		fs.symlinkSync(path.join(workspace, ".env"), aliasPath);
		try {
			const hit = scanOpaqueArguments({ command: "cat .env.example" }, "shell", STRICT, roots);
			expect(hit?.rule).toBe("**/.env");
			expect(hit?.literal).toBe(".env.example");
		} finally {
			fs.rmSync(aliasPath, { force: true });
		}
	});

	it("still honours the allow carve-out for a real (non-symlinked) template file", () => {
		const templatePath = path.join(workspace, ".env.example");
		fs.writeFileSync(templatePath, "TEMPLATE=1");
		try {
			expect(scanOpaqueArguments({ command: "cat .env.example" }, "shell", STRICT, roots)).toBeNull();
		} finally {
			fs.rmSync(templatePath, { force: true });
		}
	});
});

describe("literal cap enforcement within a single string", () => {
	// The cap used to be checked only before expanding each *source* string,
	// so one sufficiently long value could grow the literal array without
	// bound and the eventual `push(...tokens)` spread could itself throw
	// once the array got large enough — defeating the resource bound before
	// any matching even began.
	it("does not throw on one oversized string", () => {
		const filler = Array.from({ length: 200_000 }, (_, i) => `word${i}`).join(" ");
		expect(() => scanOpaqueArguments({ command: filler }, "shell", STRICT, roots)).not.toThrow();
	});

	it("stops scanning at the cap within a single string, so a secret far past it is never reached", () => {
		const filler = Array.from({ length: 10_000 }, (_, i) => `word${i}`).join(" ");
		expect(scanOpaqueArguments({ command: `${filler} .env` }, "shell", STRICT, roots)).toBeNull();
	});

	it("still finds a secret comfortably within the cap", () => {
		const filler = Array.from({ length: 5 }, (_, i) => `word${i}`).join(" ");
		expect(scanOpaqueArguments({ command: `.env ${filler}` }, "shell", STRICT, roots)?.rule).toBe("**/.env");
	});
});
