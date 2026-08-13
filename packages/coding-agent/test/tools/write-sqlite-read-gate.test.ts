import { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import type { AgentToolContext } from "@oh-my-pi/pi-agent-core";
import { Settings } from "@oh-my-pi/pi-coding-agent/config/settings";
import type { ToolSession } from "@oh-my-pi/pi-coding-agent/tools";
import { WriteTool } from "@oh-my-pi/pi-coding-agent/tools/write";

// `write`'s sqlite dispatch (`#resolveSqliteWritePath`) used to `stat` and
// sniff a candidate's header (`isSqliteFile`) to decide whether it was the
// real sqlite target *before* the resource gate ever saw it — so a candidate
// this call has no read access to (`permissions.deny.read` /
// `permissions.confineReads`) still had its bytes opened and inspected, and
// the routing decision (and therefore the final outcome) depended on what
// those bytes actually were. Fixed to skip a read-denied candidate the same
// way the archive resolver already does: authorize before probing, not after
// (finding under review).

let temporaryRoot = "";
let workspace: string;
let outsideDir: string;
let dbPath: string;
let dbBytesBefore: Uint8Array<ArrayBuffer>;

function buildSqliteFixture(path_: string): void {
	const db = new Database(path_);
	try {
		db.run("CREATE TABLE items (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)");
		db.run("INSERT INTO items (name) VALUES ('seed')");
	} finally {
		db.close();
	}
}

beforeEach(async () => {
	temporaryRoot = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "omp-write-sqlite-gate-")));
	workspace = path.join(temporaryRoot, "ws");
	outsideDir = path.join(temporaryRoot, "outside");
	await fs.mkdir(workspace, { recursive: true });
	await fs.mkdir(outsideDir, { recursive: true });
	dbPath = path.join(outsideDir, "secret.db");
	buildSqliteFixture(dbPath);
	dbBytesBefore = await Bun.file(dbPath).bytes();
});

afterEach(async () => {
	await fs.rm(temporaryRoot, { recursive: true, force: true });
});

function session(): ToolSession {
	return {
		cwd: workspace,
		hasUI: false,
		getSessionFile: () => null,
		getSessionSpawns: () => "*",
		settings: Settings.isolated({}),
	} as ToolSession;
}

function contextOf(overrides: Record<string, unknown>): AgentToolContext {
	return {
		sessionManager: {
			getCwd: () => workspace,
			getAdditionalDirectories: () => [],
			getSessionId: () => "test-session",
		},
		settings: Settings.isolated(overrides),
	} as unknown as AgentToolContext;
}

describe("write refuses to probe a read-denied sqlite candidate before the gate runs", () => {
	test("treats a write-allowed, read-denied existing database as not found rather than opening its header", async () => {
		const tool = new WriteTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ path: `${dbPath}:items`, content: '{"name":"evil"}' } as never,
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.allow.write": [`${dbPath}*`],
					"permissions.deny.read": [dbPath],
				}),
			),
		).rejects.toThrow(/not found/i);

		// No row was inserted and the database is untouched, byte-for-byte: the
		// gate must have refused before the sqlite handle was ever opened for
		// writing.
		expect(await Bun.file(dbPath).bytes()).toEqual(dbBytesBefore);
	});

	test("does the same under permissions.confineReads instead of an explicit deny.read rule", async () => {
		const tool = new WriteTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ path: `${dbPath}:items`, content: '{"name":"evil"}' } as never,
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.allow.write": [`${dbPath}*`],
					"permissions.confineReads": true,
				}),
			),
		).rejects.toThrow(/not found/i);

		expect(await Bun.file(dbPath).bytes()).toEqual(dbBytesBefore);
	});

	test("refuses identically when the read-denied candidate is not actually a sqlite file", async () => {
		// Pre-fix, this case took a *different* path than a real sqlite database
		// at the same denied location: `isSqliteFile` would read the header,
		// find it didn't look like sqlite, and fall through to treating the
		// whole `path` argument (including the `:items` suffix) as a literal
		// filename to write — an outcome that depended on the denied file's
		// content instead of refusing it outright. This proves the two cases
		// are now indistinguishable from a read-denied caller's perspective.
		const garbagePath = path.join(outsideDir, "not-sqlite.db");
		await fs.writeFile(garbagePath, "not a sqlite file, just plain bytes\n".repeat(4));
		const garbageBytesBefore = await Bun.file(garbagePath).bytes();

		const tool = new WriteTool(session());
		await expect(
			tool.execute(
				"call-1",
				{ path: `${garbagePath}:items`, content: '{"name":"evil"}' } as never,
				undefined,
				undefined,
				contextOf({
					"permissions.profile": "workspace",
					"permissions.allow.write": [`${garbagePath}*`],
					"permissions.deny.read": [garbagePath],
				}),
			),
		).rejects.toThrow(/not found/i);

		expect(await Bun.file(garbagePath).bytes()).toEqual(garbageBytesBefore);
		// And no stray literal-named file was created next to it.
		await expect(fs.stat(`${garbagePath}:items`)).rejects.toThrow();
	});

	test("still writes the row once read access is authorized alongside write", async () => {
		const tool = new WriteTool(session());
		const result = await tool.execute(
			"call-1",
			{ path: `${dbPath}:items`, content: '{"name":"fresh"}' } as never,
			undefined,
			undefined,
			contextOf({ "permissions.profile": "workspace", "permissions.allow.write": [`${dbPath}*`] }),
		);
		expect(result.isError).toBeUndefined();

		const db = new Database(dbPath, { readonly: true });
		try {
			const rows = db.prepare<{ name: string }, []>("SELECT name FROM items ORDER BY id").all();
			expect(rows.map(row => row.name)).toEqual(["seed", "fresh"]);
		} finally {
			db.close();
		}
	});
});
