import { fork } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, rename, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it, vi } from "vitest";
import { createSessionCoordination } from "../src/core/coordination/identity.js";
import { Coordination } from "../src/core/coordination/service.js";

const directories: string[] = [];
afterEach(async () => {
	for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});
async function fixture() {
	const directory = await mkdtemp(join(tmpdir(), "zero-coordination-"));
	directories.push(directory);
	const workspace = join(directory, "workspace");
	await mkdir(workspace);
	const options = { workspace, storageDir: join(directory, ".zero"), familyId: "family", agentId: "parent" };
	const parent = new Coordination(options);
	const child = new Coordination({ ...options, agentId: "child", parentId: "parent" });
	await parent.register();
	await child.register();
	return { directory, workspace, options, parent, child };
}

it("shares durable state and authorizes only a direct parent to assign and reprioritize", async () => {
	const { parent, child, options } = await fixture();
	await parent.assign({
		id: "a",
		agentId: "child",
		title: "work",
		dependencies: [],
		writeFiles: ["a.txt"],
		priority: 3,
	});
	await expect(
		child.assign({ id: "a", agentId: "child", title: "spoof", dependencies: [], writeFiles: [], priority: 9 }),
	).rejects.toThrow("parent");
	await child.update("running");
	const restored = await new Coordination(options).snapshot();
	expect(restored.agents.child).toMatchObject({ task: "a", status: "running", priority: 3 });
	expect(restored.agents.parent.latestAction).toBe("registered");
});

it("rejects unknown dependencies, cycles, unfinished dependencies and overlapping assignments", async () => {
	const { parent, child, options } = await fixture();
	const sibling = new Coordination({ ...options, agentId: "sibling", parentId: "parent" });
	await sibling.register();
	const task = { id: "a", agentId: "child", title: "work", dependencies: [], writeFiles: ["a.txt"], priority: 0 };
	await expect(parent.assign({ ...task, dependencies: ["missing"] })).rejects.toThrow("dependency");
	await parent.assign(task);
	await parent.assign({ ...task, id: "b", agentId: "sibling", dependencies: ["a"], writeFiles: ["b.txt"] });
	await expect(parent.assign({ ...task, dependencies: ["b"] })).rejects.toThrow("cycle");
	await expect(sibling.update("running")).rejects.toThrow("dependency");
	await expect(parent.assign({ ...task, id: "c", agentId: "sibling" })).rejects.toThrow();
	await child.update("running");
	await child.update("done");
	await sibling.update("running");
});

it("records native file evidence without file contents and enforces assigned write scope", async () => {
	const { parent, child } = await fixture();
	await parent.assign({
		id: "a",
		agentId: "child",
		title: "work",
		dependencies: [],
		writeFiles: ["a.txt"],
		priority: 0,
	});
	await child.update("running");
	await child.write("a.txt", "SECRET FILE CONTENT");
	expect(await child.read("a.txt")).toBe("SECRET FILE CONTENT");
	await expect(child.write("b.txt", "no")).rejects.toThrow("scope");
	const snapshot = await parent.snapshot();
	expect(snapshot.agents.child.writeFiles).toEqual([await parent.canonicalPath("a.txt")]);
	expect(snapshot.links).toEqual(
		expect.arrayContaining([expect.objectContaining({ kind: "touched", grade: "native-write" })]),
	);
	expect(JSON.stringify(snapshot)).not.toContain("SECRET FILE CONTENT");
	await child.update("done");
	expect((await parent.snapshot()).links).toEqual(
		expect.arrayContaining([expect.objectContaining({ kind: "returned" })]),
	);
});

it("denies traversal, symlink escapes, private paths and Windows ambiguous paths", async () => {
	const { directory, parent, workspace } = await fixture();
	await writeFile(join(directory, "outside.txt"), "outside");
	await symlink(directory, join(workspace, "escape"), "junction");
	for (const path of ["../outside.txt", "escape/outside.txt", ".zero/state", "a.txt:stream", "NUL", "file. "]) {
		await expect(parent.read(path)).rejects.toThrow();
		await expect(parent.write(path, "bad")).rejects.toThrow();
	}
});

it("blocks readers and writers behind a writer, cancels waits, and releases after failures", async () => {
	const { parent, child } = await fixture();
	await parent.write("a.txt", "before");
	let release!: () => void;
	let entered!: () => void;
	const ready = new Promise<void>((resolve) => {
		entered = resolve;
	});
	const held = parent.withFile("a.txt", async () => {
		entered();
		await new Promise<void>((resolve) => {
			release = resolve;
		});
	});
	await ready;
	const abort = new AbortController();
	const waiting = child.read("a.txt", abort.signal);
	abort.abort();
	await expect(waiting).rejects.toThrow();
	let finished = false;
	const reader = child.read("a.txt").then(() => {
		finished = true;
	});
	await new Promise((resolve) => setTimeout(resolve, 60));
	expect(finished).toBe(false);
	release();
	await held;
	await reader;
	await expect(
		parent.withFile("a.txt", async () => {
			throw new Error("failure");
		}),
	).rejects.toThrow("failure");
	await child.write("a.txt", "after");
	expect(await child.read("a.txt")).toBe("after");
});

it("arbitrates file access across real worker processes, not just service instances", async () => {
	const { options, parent, workspace } = await fixture();
	await parent.write("a.txt", "before");
	const worker = fork(join(process.cwd(), "test/fixtures/coordination-worker.ts"), [JSON.stringify(options)], {
		execArgv: ["--import", "tsx"],
		stdio: ["ignore", "pipe", "pipe", "ipc"],
	});
	try {
		await new Promise<void>((resolve, reject) => {
			worker.once("message", () => resolve());
			worker.once("error", reject);
			worker.once("exit", (code) => reject(new Error(`worker exited ${code}`)));
		});
		const abort = new AbortController();
		const waiting = parent.read("a.txt", abort.signal);
		abort.abort();
		await expect(waiting).rejects.toThrow();
		let finished = false;
		const reader = parent.read("a.txt").then((text) => {
			finished = true;
			return text;
		});
		await vi.waitFor(async () => {
			const graph = await parent.graph();
			expect(graph.locks.some((lock) => lock.resource.startsWith("file:") && lock.waiters.length > 0)).toBe(true);
		});
		expect(finished).toBe(false);
		const exited = new Promise<void>((resolve) => worker.once("exit", () => resolve()));
		worker.send("release");
		expect(await reader).toBe("worker");
		await exited;
		expect(await readFile(join(workspace, "a.txt"), "utf8")).toBe("worker");
	} finally {
		worker.kill();
	}
});

it("never displaces an unfinished idle task with a second assignment", async () => {
	const { parent } = await fixture();
	const task = { id: "first", agentId: "child", title: "first", dependencies: [], writeFiles: ["a.txt"], priority: 0 };
	await parent.assign(task);
	await expect(parent.assign({ ...task, id: "second", writeFiles: ["b.txt"] })).rejects.toThrow("unfinished");
	expect((await parent.snapshot()).agents.child.task).toBe("first");
});

it("denies every other writer's reserved scope, including an unassigned parent, until cancellation", async () => {
	const { parent, child } = await fixture();
	await parent.assign({
		id: "reserved",
		agentId: "child",
		title: "work",
		dependencies: [],
		writeFiles: ["a.txt"],
		priority: 0,
	});
	await expect(parent.write("a.txt", "stolen")).rejects.toThrow("reserved");
	await child.update("running");
	await child.write("a.txt", "child");
	await expect(parent.write("a.txt", "stolen")).rejects.toThrow("reserved");
	await expect(child.cancel("reserved")).rejects.toThrow("parent");
	await parent.cancel("reserved");
	await expect(child.write("a.txt", "late")).rejects.toThrow("scope");
	await expect(child.update("running")).rejects.toThrow("terminal");
	await parent.write("a.txt", "released");
});

it("reclaims a crashed writer's lock only after its process has exited", async () => {
	const { options, parent } = await fixture();
	await parent.write("a.txt", "before");
	const worker = fork(join(process.cwd(), "test/fixtures/coordination-worker.ts"), [JSON.stringify(options)], {
		execArgv: ["--import", "tsx"],
		stdio: ["ignore", "pipe", "pipe", "ipc"],
	});
	try {
		await new Promise<void>((resolve, reject) => {
			worker.once("message", () => resolve());
			worker.once("error", reject);
			worker.once("exit", () => reject(new Error("worker exited before holding lock")));
		});
		const exited = new Promise<void>((resolve) => worker.once("exit", () => resolve()));
		worker.kill();
		await exited;
		const restored = new Coordination({ ...options, lockTimeoutMs: 100 });
		// The worker has exited, so its abandoned lock is reclaimed instead of blocking forever.
		expect(await restored.read("a.txt")).toBe("before");
		expect((await restored.graph()).locks).toEqual([]);
		expect(await readFile(join(options.workspace, "a.txt"), "utf8")).toBe("before");
	} finally {
		worker.kill();
	}
});

it("shares stable root family identity from persisted host ancestry in an independent worker", async () => {
	const { directory, workspace } = await fixture();
	const parentFile = join(directory, "root.jsonl");
	const rootHeader = {
		type: "session" as const,
		version: 3,
		id: "durable-root",
		cwd: workspace,
		timestamp: new Date().toISOString(),
		rlmDepth: 0,
	};
	await writeFile(parentFile, `${JSON.stringify(rootHeader)}\n`);
	const childHeader = { ...rootHeader, id: "durable-child", rlmDepth: 1, parentSession: parentFile };
	const input = {
		agentId: childHeader.id,
		workspace,
		header: childHeader,
		sessionFile: join(directory, "child.jsonl"),
	};
	const service = await createSessionCoordination({
		agentId: rootHeader.id,
		workspace,
		header: rootHeader,
		sessionFile: parentFile,
	});
	const worker = fork(
		join(process.cwd(), "test/fixtures/coordination-worker.ts"),
		[JSON.stringify(input), "identity"],
		{
			execArgv: ["--import", "tsx"],
			stdio: ["ignore", "pipe", "pipe", "ipc"],
		},
	);
	try {
		const exited = new Promise<void>((resolve, reject) => {
			worker.once("exit", (code) => (code === 0 ? resolve() : reject(new Error(`worker exited ${code}`))));
			worker.once("error", reject);
		});
		await new Promise<void>((resolve, reject) => {
			worker.once("message", () => resolve());
			worker.once("error", reject);
			worker.once("exit", (code) => reject(new Error(`worker exited ${code}`)));
		});
		await exited;
		const graph = await service.graph();
		expect(graph.agents[childHeader.id]).toMatchObject({ parentId: rootHeader.id, latestAction: "registered" });
		expect(graph.links).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ kind: "spawned", source: rootHeader.id, target: childHeader.id }),
			]),
		);
		await service.assign({
			id: "durable-task",
			agentId: childHeader.id,
			title: "work",
			dependencies: [],
			writeFiles: ["a.txt"],
			priority: 5,
		});
		const child = await createSessionCoordination(input);
		await child.update("running");
		await child.write("a.txt", "child");
		expect((await service.snapshot()).tasks["durable-task"].status).toBe("running");
	} finally {
		worker.kill();
	}
});

it("rejects internal symlink aliases and symlinked coordination storage", async () => {
	const { directory, workspace, parent, options } = await fixture();
	await mkdir(join(workspace, "real"));
	await writeFile(join(workspace, "real/a.txt"), "real");
	await symlink(join(workspace, "real"), join(workspace, "alias"), "junction");
	await expect(parent.write("alias/a.txt", "alias")).rejects.toThrow("Symlink");
	await symlink(options.storageDir, join(directory, "aliased-storage"), "junction");
	const unsafe = new Coordination({ ...options, storageDir: join(directory, "aliased-storage/nested") });
	await expect(unsafe.register()).rejects.toThrow("Unsafe");
});

it("rejects a directory swapped to a symlink while native operations wait", async () => {
	const { directory, workspace, parent, child } = await fixture();
	const safe = join(workspace, "safe");
	const displaced = join(workspace, "displaced");
	const outside = join(directory, "outside");
	await mkdir(safe);
	await mkdir(outside);
	await writeFile(join(safe, "a.txt"), "inside");
	await writeFile(join(outside, "a.txt"), "outside");
	let release!: () => void;
	let entered!: () => void;
	const ready = new Promise<void>((resolve) => {
		entered = resolve;
	});
	const held = parent.withFile("safe/a.txt", async () => {
		entered();
		await new Promise<void>((resolve) => {
			release = resolve;
		});
	});
	await ready;
	const read = child.read("safe/a.txt");
	const write = child.write("safe/a.txt", "escaped");
	const readRejected = read.then(
		() => false,
		() => true,
	);
	const writeRejected = write.then(
		() => false,
		() => true,
	);
	await vi.waitFor(async () => {
		const lock = (await parent.graph()).locks.find((candidate) => candidate.resource.startsWith("file:"));
		expect(lock?.waiters).toHaveLength(2);
	});
	await rename(safe, displaced);
	await symlink(outside, safe, "junction");
	release();
	await held;
	expect(await readRejected).toBe(true);
	expect(await writeRejected).toBe(true);
	expect(await readFile(join(outside, "a.txt"), "utf8")).toBe("outside");
});

it("refuses corrupted snapshots rather than silently dropping reserved scopes", async () => {
	const { options, parent } = await fixture();
	const directory = join(options.storageDir, "families");
	const [file] = await readdir(directory);
	await writeFile(join(directory, file), JSON.stringify({ version: 1, agents: {}, tasks: [], links: [] }));
	await expect(parent.write("a.txt", "unsafe")).rejects.toThrow("snapshot");
});

it("inspects reservations and ownership without reclaiming an unknown-owner lock", async () => {
	const { options, parent } = await fixture();
	await parent.assign({
		id: "reserved",
		agentId: "child",
		title: "work",
		dependencies: [],
		writeFiles: ["a.txt"],
		priority: 0,
	});
	const resource = `state:${options.familyId}`;
	const lock = join(options.storageDir, "locks", createHash("sha256").update(resource).digest("hex"));
	await mkdir(lock);
	await writeFile(
		join(lock, "owner.json"),
		JSON.stringify({
			resource,
			agentId: "child",
			familyId: options.familyId,
			pid: 0,
			token: "abandoned",
			since: "unknown",
		}),
	);
	const restored = new Coordination({ ...options, lockTimeoutMs: 100 });
	const graph = await restored.graph();
	expect(graph.tasks.reserved.status).toBe("idle");
	expect(graph.locks).toEqual(expect.arrayContaining([expect.objectContaining({ resource, token: "abandoned" })]));
	await expect(restored.write("a.txt", "unsafe")).rejects.toThrow("lock is held by a live owner");
});

it("keeps terminal task IDs immutable and repeated old cancellations do not cancel new work", async () => {
	const { parent, child } = await fixture();
	const task = { id: "first", agentId: "child", title: "work", dependencies: [], writeFiles: ["a.txt"], priority: 0 };
	await parent.assign(task);
	await parent.cancel(task.id);
	await parent.assign({ ...task, id: "second" });
	await parent.cancel(task.id);
	expect((await parent.snapshot()).agents.child).toMatchObject({ task: "second", status: "idle" });
	await child.update("running");
	await child.update("done");
	await expect(parent.assign({ ...task, id: "second" })).rejects.toThrow("Terminal task");
});

it("preserves a child's scoped reservation for follow-up runs", async () => {
	const { parent, child } = await fixture();
	await parent.assign({
		id: "initial",
		agentId: "child",
		title: "initial",
		dependencies: [],
		writeFiles: ["a.txt"],
		priority: 4,
	});
	const initial = await child.begin("initial");
	await child.finish(initial, false);
	const followUp = await child.begin("follow-up");
	const snapshot = await child.snapshot();
	expect(snapshot.tasks[followUp]).toMatchObject({
		writeFiles: [await child.canonicalPath("a.txt")],
		writePolicy: "scoped",
		priority: 4,
		status: "running",
	});
	await child.write("a.txt", "follow-up");
	await expect(child.write("b.txt", "outside")).rejects.toThrow("scope");
});

it("bounds terminal task history and per-agent file evidence", async () => {
	const { parent } = await fixture();
	for (let index = 0; index < 102; index++) {
		const task = await parent.begin(`run ${index}`);
		await parent.write(`file-${index}.txt`, String(index));
		await parent.read(`file-${index}.txt`);
		await parent.finish(task, false);
	}
	const snapshot = await parent.snapshot();
	expect(Object.keys(snapshot.tasks).length).toBeLessThanOrEqual(100);
	expect(snapshot.agents.parent.readFiles.length).toBeLessThanOrEqual(100);
	expect(snapshot.agents.parent.writeFiles.length).toBeLessThanOrEqual(100);
}, 120_000);

it("preserves destination mode when atomically replacing a file", async () => {
	if (process.platform === "win32") return;
	const { parent, workspace } = await fixture();
	const path = join(workspace, "mode.txt");
	await writeFile(path, "before", { mode: 0o640 });
	await chmod(path, 0o640);
	await parent.write("mode.txt", "after");
	expect((await stat(path)).mode & 0o777).toBe(0o640);
});

it("replays committed native-write receipts after a state commit failure", async () => {
	const { options, parent, workspace } = await fixture();
	const path = join(workspace, "recovered.txt");
	const content = "committed content";
	await writeFile(path, content);
	const operations = join(options.storageDir, "operations");
	await mkdir(operations, { mode: 0o700 });
	const receiptId = "committed-receipt";
	await writeFile(
		join(operations, `${receiptId}.json`),
		JSON.stringify({
			version: 1,
			kind: "native-write",
			ref: receiptId,
			familyId: options.familyId,
			agentId: "parent",
			path: await parent.canonicalPath("recovered.txt"),
			contentHash: createHash("sha256").update(content).digest("hex"),
			createdAt: new Date().toISOString(),
		}),
		{ mode: 0o600 },
	);

	const snapshot = await parent.graph();
	expect(snapshot.agents.parent.writeFiles).toContain(await parent.canonicalPath("recovered.txt"));
	expect(snapshot.links).toEqual(
		expect.arrayContaining([expect.objectContaining({ ref: receiptId, kind: "touched", grade: "native-write" })]),
	);
	expect(await readdir(operations)).toEqual([]);
});

it("rejects an existing coordination directory owned or writable by another user class", async () => {
	if (process.platform === "win32" || typeof process.getuid !== "function") return;
	const directory = await mkdtemp(join(tmpdir(), "zero-coordination-permissions-"));
	directories.push(directory);
	const workspace = join(directory, "workspace");
	const storageDir = join(directory, ".zero", "coordination");
	await mkdir(workspace);
	await mkdir(storageDir, { recursive: true, mode: 0o777 });
	await chmod(storageDir, 0o777);
	const service = new Coordination({ workspace, storageDir, familyId: "family", agentId: "parent" });
	await expect(service.register()).rejects.toThrow("permissions");
});
