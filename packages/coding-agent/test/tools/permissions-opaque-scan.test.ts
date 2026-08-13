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

describe("policy interaction", () => {
	it("honours an allow carve-out", () => {
		const relaxed = buildPermissionPolicy("strict", { allowRead: ["**/.env"], allowWrite: ["**/.env"] });
		expect(scanOpaqueArguments({ command: "cat .env" }, "shell", relaxed, roots)).toBeNull();
	});

	it("does nothing when the profile carries no deny rules", () => {
		const workspaceOnly = buildPermissionPolicy("workspace");
		expect(scanOpaqueArguments({ command: "cat .env" }, "shell", workspaceOnly, roots)).toBeNull();
	});

	it("leaves internal URLs alone", () => {
		expect(scanOpaqueArguments({ command: "cat local://plan.md" }, "shell", STRICT, roots)).toBeNull();
	});

	it("does not apply confinement — naming a path is not writing to it", () => {
		const confined = buildPermissionPolicy("workspace", { confineWrites: true });
		expect(scanOpaqueArguments({ command: "ls /usr/bin" }, "shell", confined, roots)).toBeNull();
	});

	it("does not let a carve-out matching the lexical spelling suppress a deny matching the resolved target", () => {
		// Mirrors the structured-path fix (`permissions-resolve.test.ts`): a
		// workspace symlink literally named `.env.example` but pointing at the
		// real `.env` must not read as the shipped template. The candidate set
		// for `cat .env.example` mixes the lexical spelling (which the carve-out
		// matches) with the symlink-resolved one (which the deny glob matches);
		// the carve-out may only suppress a deny that fired on the same
		// candidate it matches, never the whole set.
		const linkDir = path.join(workspace, "link-carve-out");
		fs.mkdirSync(linkDir, { recursive: true });
		const link = path.join(linkDir, ".env.example");
		fs.rmSync(link, { force: true });
		fs.symlinkSync(path.join(workspace, ".env"), link);
		const hit = scanOpaqueArguments({ command: `cat ${link}` }, "shell", STRICT, roots);
		expect(hit?.rule).toBe("**/.env");
	});
});
