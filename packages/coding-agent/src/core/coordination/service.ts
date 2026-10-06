import { createHash, randomUUID } from "node:crypto";
import { constants, lstatSync, readFileSync } from "node:fs";
import {
	access,
	chmod,
	chown,
	lstat,
	mkdir,
	open,
	readdir,
	readFile,
	realpath,
	rename,
	rm,
	rmdir,
	stat,
	unlink,
	writeFile,
} from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

// Original implementation; conceptual reference: Graphene (Alex Lopez, Apache-2.0),
// 4e1660cbc0a369d2ad7cc42f056a5f26ff6d51f9, graphene_map/{plan,graph,store}.py.
// Evidence is recorded, never inferred from imports. Native tools only, not an OS sandbox.
export interface CoordinationOptions {
	workspace: string;
	storageDir: string;
	familyId: string;
	agentId: string;
	parentId?: string;
	lockTimeoutMs?: number;
}
export type WorkStatus = "idle" | "running" | "done" | "cancelled";
export interface WorkState {
	workspace: string;
	parentId?: string;
	task?: string;
	status: WorkStatus;
	latestAction: string;
	readFiles: string[];
	writeFiles: string[];
	priority: number;
}
export interface WorkTask {
	id: string;
	agentId: string;
	title: string;
	dependencies: string[];
	writeFiles: string[];
	priority: number;
	status: WorkStatus;
	writePolicy: "scoped" | "unreserved";
}
export interface EvidenceLink {
	ref: string;
	kind: "spawned" | "returned" | "touched" | "assigned";
	source: string;
	target: string;
	grade: "record" | "native-read" | "native-write";
}
export interface WorkSnapshot {
	version: 1;
	agents: Record<string, WorkState>;
	tasks: Record<string, WorkTask>;
	links: EvidenceLink[];
}
export interface LockOwner {
	resource: string;
	agentId: string;
	familyId: string;
	pid: number;
	token: string;
	since: string;
}
export interface WorkGraph extends WorkSnapshot {
	locks: (LockOwner & { waiters: LockOwner[] })[];
	readyTasks: string[];
	coverage: "coordinated-native-operations-only";
}

interface NativeWriteReceipt {
	version: 1;
	kind: "native-write";
	ref: string;
	familyId: string;
	agentId: string;
	path: string;
	contentHash: string;
	createdAt: string;
}

const MAX_BYTES = 1024 * 1024;
const MAX_TASKS = 100;
const MAX_AGENT_FILES = 100;
function key(value: string): string {
	return createHash("sha256").update(value).digest("hex");
}
function identity(value: string): void {
	if (!/^[a-zA-Z0-9_.:-]{1,200}$/.test(value) || ["__proto__", "constructor", "prototype"].includes(value))
		throw new Error("Invalid coordination identity");
}
function inside(root: string, path: string): boolean {
	const part = relative(root, path);
	return part !== "" && part !== ".." && !part.startsWith(`..${sep}`) && !isAbsolute(part);
}
function normalized(path: string): string {
	return process.platform === "win32" ? path.toLowerCase() : path;
}
function record(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
function strings(value: unknown): value is string[] {
	return Array.isArray(value) && value.every((item) => typeof item === "string");
}
function nativeWriteReceipt(value: unknown): value is NativeWriteReceipt {
	return (
		record(value) &&
		value.version === 1 &&
		value.kind === "native-write" &&
		typeof value.ref === "string" &&
		typeof value.familyId === "string" &&
		typeof value.agentId === "string" &&
		typeof value.path === "string" &&
		/^[a-f0-9]{64}$/.test(String(value.contentHash)) &&
		typeof value.createdAt === "string"
	);
}
function validateSnapshot(value: unknown): asserts value is WorkSnapshot {
	if (
		!record(value) ||
		value.version !== 1 ||
		!record(value.agents) ||
		!record(value.tasks) ||
		!Array.isArray(value.links)
	)
		throw new Error("Invalid coordination snapshot");
	const statuses = ["idle", "running", "done", "cancelled"];
	for (const [id, agent] of Object.entries(value.agents)) {
		identity(id);
		if (
			!record(agent) ||
			typeof agent.workspace !== "string" ||
			!isAbsolute(agent.workspace) ||
			!statuses.includes(String(agent.status)) ||
			typeof agent.latestAction !== "string" ||
			!strings(agent.readFiles) ||
			!strings(agent.writeFiles) ||
			!Number.isInteger(agent.priority) ||
			(agent.parentId !== undefined &&
				(typeof agent.parentId !== "string" || !Object.hasOwn(value.agents, agent.parentId))) ||
			(agent.task !== undefined && (typeof agent.task !== "string" || !Object.hasOwn(value.tasks, agent.task)))
		)
			throw new Error("Invalid coordination snapshot agent");
	}
	for (const [id, task] of Object.entries(value.tasks)) {
		identity(id);
		if (
			!record(task) ||
			task.id !== id ||
			typeof task.agentId !== "string" ||
			!Object.hasOwn(value.agents, task.agentId) ||
			typeof task.title !== "string" ||
			!statuses.includes(String(task.status)) ||
			!Number.isInteger(task.priority) ||
			!strings(task.dependencies) ||
			!task.dependencies.every((dependency) => Object.hasOwn(value.tasks as object, dependency)) ||
			!strings(task.writeFiles) ||
			!task.writeFiles.every(isAbsolute) ||
			!["scoped", "unreserved"].includes(String(task.writePolicy))
		)
			throw new Error("Invalid coordination snapshot task");
	}
	if (
		!value.links.every(
			(link) =>
				record(link) &&
				typeof link.ref === "string" &&
				typeof link.source === "string" &&
				typeof link.target === "string" &&
				["spawned", "returned", "touched", "assigned"].includes(String(link.kind)) &&
				["record", "native-read", "native-write"].includes(String(link.grade)),
		)
	)
		throw new Error("Invalid coordination snapshot evidence");
}
async function privateDirectory(path: string): Promise<void> {
	for (let ancestor = resolve(path); ; ancestor = dirname(ancestor)) {
		try {
			const entry = await lstat(ancestor);
			if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error("Unsafe coordination directory");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
		}
		if (dirname(ancestor) === ancestor) break;
	}
	const parent = dirname(path);
	if (parent !== path) {
		try {
			const entry = await lstat(parent);
			if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error("Unsafe coordination directory");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			await privateDirectory(parent);
		}
	}
	await mkdir(path, { recursive: true, mode: 0o700 });
	const entry = await lstat(path);
	if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error("Unsafe coordination directory");
	await access(path, constants.R_OK | constants.W_OK | constants.X_OK);
	if (process.platform !== "win32" && typeof process.getuid === "function") {
		if (entry.uid !== process.getuid() || (entry.mode & 0o077) !== 0)
			throw new Error("Unsafe coordination directory ownership or permissions");
	}
}

function privateDirectoryExists(path: string): boolean {
	let target: ReturnType<typeof lstatSync> | undefined;
	for (let ancestor = resolve(path); ; ancestor = dirname(ancestor)) {
		try {
			const entry = lstatSync(ancestor);
			if (!entry.isDirectory() || entry.isSymbolicLink()) throw new Error("Unsafe coordination directory");
			if (ancestor === resolve(path)) target = entry;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
			throw error;
		}
		if (dirname(ancestor) === ancestor) break;
	}
	if (target && process.platform !== "win32" && typeof process.getuid === "function") {
		if (Number(target.uid) !== process.getuid() || (Number(target.mode) & 0o077) !== 0)
			throw new Error("Unsafe coordination directory ownership or permissions");
	}
	return true;
}

async function ensurePrivateDirectory(path: string): Promise<void> {
	if (!privateDirectoryExists(path)) await privateDirectory(path);
	await access(path, constants.R_OK | constants.W_OK | constants.X_OK);
}

async function atomicWrite(
	path: string,
	text: string,
	signal?: AbortSignal,
	options: { preserveMetadata?: boolean } = {},
): Promise<void> {
	const temporary = join(dirname(path), `.zero-write-${randomUUID()}`);
	try {
		const parentBefore = await lstat(dirname(path));
		if (!parentBefore.isDirectory() || parentBefore.isSymbolicLink()) throw new Error("Unsafe destination directory");
		const previous = options.preserveMetadata
			? await lstat(path).catch((error: NodeJS.ErrnoException) => {
					if (error.code !== "ENOENT") throw error;
					return undefined;
				})
			: undefined;
		if (previous && (!previous.isFile() || previous.isSymbolicLink() || previous.nlink !== 1))
			throw new Error("Unsafe destination file");
		const handle = await open(temporary, "wx", 0o600);
		try {
			signal?.throwIfAborted();
			await handle.writeFile(text, "utf8");
			await handle.sync();
		} finally {
			await handle.close();
		}
		if (previous) {
			await chmod(temporary, previous.mode & 0o7777);
			if (process.platform !== "win32") await chown(temporary, previous.uid, previous.gid);
		}
		signal?.throwIfAborted();
		const parentNow = await lstat(dirname(path));
		if (
			!parentNow.isDirectory() ||
			parentNow.isSymbolicLink() ||
			parentNow.dev !== parentBefore.dev ||
			parentNow.ino !== parentBefore.ino
		)
			throw new Error("Destination directory changed during write");
		if (previous) {
			const destination = await lstat(path);
			if (destination.isSymbolicLink() || destination.dev !== previous.dev || destination.ino !== previous.ino)
				throw new Error("Destination file changed during write");
		}
		for (let attempt = 0; ; attempt++) {
			try {
				await rename(temporary, path);
				break;
			} catch (error) {
				const code = (error as NodeJS.ErrnoException).code;
				if (process.platform !== "win32" || !["EACCES", "EPERM"].includes(code ?? "") || attempt >= 20) throw error;
				await delay(10);
			}
		}
	} finally {
		await unlink(temporary).catch((error: NodeJS.ErrnoException) => {
			if (error.code !== "ENOENT") throw error;
		});
	}
}

export async function readWorkspaceFile(workspace: string, raw: string, signal?: AbortSignal): Promise<string> {
	const service = new Coordination({
		workspace,
		storageDir: join(workspace, ".zero", "coordination"),
		familyId: "readonly",
		agentId: "readonly",
	});
	const path = await service.canonicalPath(raw);
	const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW);
	const handle = await open(path, flags);
	try {
		const entry = await handle.stat();
		if (!entry.isFile() || entry.nlink !== 1) throw new Error("Only regular unaliased files are supported");
		if (entry.size > MAX_BYTES) throw new Error("File exceeds native size limit");
		if ((await service.canonicalPath(raw)) !== path) throw new Error("File path changed before read");
		const current = await lstat(path);
		if (current.isSymbolicLink() || current.dev !== entry.dev || current.ino !== entry.ino)
			throw new Error("File changed before read");
		const text = await handle.readFile({ encoding: "utf8", signal });
		if (Buffer.byteLength(text) > MAX_BYTES) throw new Error("File exceeds native size limit");
		return text;
	} finally {
		await handle.close();
	}
}

function appendBounded(paths: string[], path: string): void {
	const existing = paths.indexOf(path);
	if (existing >= 0) paths.splice(existing, 1);
	paths.push(path);
	if (paths.length > MAX_AGENT_FILES) paths.splice(0, paths.length - MAX_AGENT_FILES);
}

function compactSnapshot(snapshot: WorkSnapshot): void {
	const protectedTasks = new Set<string>();
	for (const agent of Object.values(snapshot.agents)) if (agent.task) protectedTasks.add(agent.task);
	for (const task of Object.values(snapshot.tasks))
		for (const dependency of task.dependencies) protectedTasks.add(dependency);
	const removable = Object.values(snapshot.tasks).filter(
		(task) => ["done", "cancelled"].includes(task.status) && !protectedTasks.has(task.id),
	);
	while (Object.keys(snapshot.tasks).length > MAX_TASKS && removable.length > 0) {
		const task = removable.shift();
		if (task) delete snapshot.tasks[task.id];
	}
	if (Object.keys(snapshot.tasks).length > MAX_TASKS) throw new Error("Coordination task capacity exceeded");
}

function processAlive(pid: number): boolean {
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		return (error as NodeJS.ErrnoException).code === "EPERM";
	}
}

/** Reclaims a lock whose owner process on this machine is gone. Ambiguous or live owners are never reclaimed. */
async function reclaimAbandonedLock(lock: string): Promise<boolean> {
	let owner: LockOwner;
	try {
		owner = JSON.parse(await readFile(join(lock, "owner.json"), "utf8")) as LockOwner;
	} catch {
		return false;
	}
	if (!Number.isInteger(owner.pid) || owner.pid === process.pid || processAlive(owner.pid)) return false;
	const tombstone = `${lock}.reclaimed.${randomUUID()}`;
	try {
		await rename(lock, tombstone);
	} catch {
		return false;
	}
	let moved: LockOwner | undefined;
	try {
		moved = JSON.parse(await readFile(join(tombstone, "owner.json"), "utf8")) as LockOwner;
	} catch {
		moved = undefined;
	}
	if (moved?.token !== owner.token) {
		// Another reclaimer already replaced the lock; put the live lock back.
		await rename(tombstone, lock).catch(() => undefined);
		return false;
	}
	await rm(tombstone, { recursive: true, force: true });
	return true;
}

/** Exclusive mkdir arbitration also works across daemon processes/threads on a local filesystem.
 * A lock is reclaimed only when its owner process on this machine has exited; live or
 * unknown owners block until the timeout. Snapshots never confer ownership. Different
 * storageDir values are different authorities. */
export class Coordination {
	constructor(readonly options: CoordinationOptions) {
		identity(options.agentId);
		if (options.parentId) identity(options.parentId);
		if (!options.familyId) throw new Error("Family identity required");
		if (
			options.lockTimeoutMs !== undefined &&
			(!Number.isInteger(options.lockTimeoutMs) || options.lockTimeoutMs < 1 || options.lockTimeoutMs > 10000)
		)
			throw new Error("Invalid lock timeout");
	}

	private async locked<T>(name: string, operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
		const directory = join(this.options.storageDir, "locks");
		await ensurePrivateDirectory(directory);
		const lock = join(directory, key(name));
		const owner: LockOwner = {
			resource: name,
			agentId: this.options.agentId,
			familyId: this.options.familyId,
			pid: process.pid,
			token: randomUUID(),
			since: new Date().toISOString(),
		};
		const waiter = join(directory, `${key(name)}.${owner.token}.waiting`);
		const deadline = Date.now() + (this.options.lockTimeoutMs ?? 10000);
		let waiting = false;
		try {
			for (;;) {
				signal?.throwIfAborted();
				try {
					await mkdir(lock, { mode: 0o700 });
					break;
				} catch (error) {
					if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
					const entry = await lstat(lock).catch((error: NodeJS.ErrnoException) => {
						if (error.code !== "ENOENT") throw error;
						return undefined;
					});
					if (entry && (!entry.isDirectory() || entry.isSymbolicLink()))
						throw new Error("Unsafe coordination lock");
					if (entry && (await reclaimAbandonedLock(lock))) continue;
					if (!waiting) {
						await writeFile(waiter, JSON.stringify(owner), { flag: "wx", mode: 0o600 });
						waiting = true;
					}
					if (Date.now() >= deadline) throw new Error("Coordination busy; lock is held by a live owner");
					await delay(20, undefined, { signal });
				}
			}
		} finally {
			if (waiting) await unlink(waiter);
		}
		try {
			await writeFile(join(lock, "owner.json"), JSON.stringify(owner), { flag: "wx", mode: 0o600 });
			signal?.throwIfAborted();
			return await operation();
		} finally {
			await unlink(join(lock, "owner.json")).catch((error: NodeJS.ErrnoException) => {
				if (error.code !== "ENOENT") throw error;
			});
			await rmdir(lock);
		}
	}

	async canonicalPath(raw: string): Promise<string> {
		if (!raw || raw.length > 4096 || /[\x00-\x1f]/.test(raw)) throw new Error("Invalid file path");
		const root = await realpath(this.options.workspace);
		const lexical = resolve(root, raw);
		if (!inside(root, lexical)) throw new Error("File path outside workspace");
		const parts = relative(root, lexical).split(sep);
		let component = root;
		for (const part of parts) {
			component = join(component, part);
			try {
				if ((await lstat(component)).isSymbolicLink()) throw new Error("Symlink file paths denied");
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			}
		}
		if (
			parts.some(
				(part) =>
					/[:<>"|?*]/.test(part) ||
					/[. ]$/.test(part) ||
					/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(part),
			)
		)
			throw new Error("Ambiguous file path");
		if (parts.some((part) => [".zero", ".git"].includes(part.toLowerCase())))
			throw new Error("Private file path denied");
		let canonical: string;
		try {
			canonical = await realpath(lexical);
			const entry = await stat(canonical);
			if (!entry.isFile() || entry.nlink !== 1) throw new Error("Only regular unaliased files are supported");
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			// New files require an existing parent; no recursive directory creation.
			canonical = join(await realpath(dirname(lexical)), basename(lexical));
		}
		if (!inside(root, canonical)) throw new Error("File path outside workspace through symlink");
		const canonicalParts = relative(root, canonical).split(sep);
		if (canonicalParts.some((part) => [".zero", ".git"].includes(part.toLowerCase())))
			throw new Error("Private file path denied");
		const storage = resolve(this.options.storageDir);
		if (canonical === storage || inside(storage, canonical)) throw new Error("Private file path denied");
		return normalized(canonical);
	}

	async withFile<T>(raw: string, operation: (path: string) => Promise<T>, signal?: AbortSignal): Promise<T> {
		const path = await this.canonicalPath(raw);
		return this.locked(
			`file:${path}`,
			async () => {
				if ((await this.canonicalPath(raw)) !== path) throw new Error("File path changed while waiting");
				return operation(path);
			},
			signal,
		);
	}

	private snapshotPath(): string {
		return join(this.options.storageDir, "families", `${key(this.options.familyId)}.json`);
	}

	private async readSnapshot(signal?: AbortSignal): Promise<WorkSnapshot> {
		const path = this.snapshotPath();
		await ensurePrivateDirectory(this.options.storageDir);
		await ensurePrivateDirectory(dirname(path));
		try {
			const entry = await lstat(path);
			if (!entry.isFile() || entry.isSymbolicLink() || entry.size > MAX_BYTES * 8)
				throw new Error("Unsafe coordination snapshot");
			const parsed: unknown = JSON.parse(await readFile(path, { encoding: "utf8", signal }));
			validateSnapshot(parsed);
			return parsed;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			return { version: 1, agents: {}, tasks: {}, links: [] };
		}
	}

	private readSnapshotLocked(signal?: AbortSignal): WorkSnapshot {
		signal?.throwIfAborted();
		const path = this.snapshotPath();
		try {
			const entry = lstatSync(path);
			if (!entry.isFile() || entry.isSymbolicLink() || entry.size > MAX_BYTES * 8)
				throw new Error("Unsafe coordination snapshot");
			const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
			validateSnapshot(parsed);
			return parsed;
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
			return { version: 1, agents: {}, tasks: {}, links: [] };
		}
	}

	private async transaction<T>(
		operation: (snapshot: WorkSnapshot) => T | Promise<T>,
		signal?: AbortSignal,
		save = true,
	): Promise<T> {
		const family = join(this.options.storageDir, "families");
		await ensurePrivateDirectory(family);
		const path = this.snapshotPath();
		return this.locked(
			`state:${this.options.familyId}`,
			async () => {
				const snapshot = this.readSnapshotLocked(signal);
				const recoveredReceipts = await this.recoverNativeWrites(snapshot, signal);
				const value = await operation(snapshot);
				if (save || recoveredReceipts.length > 0) {
					compactSnapshot(snapshot);
					const text = JSON.stringify(snapshot);
					if (Buffer.byteLength(text) > MAX_BYTES * 8) throw new Error("Coordination snapshot capacity exceeded");
					// Commit completed operations' evidence even if cancellation arrived meanwhile.
					await atomicWrite(path, text);
					for (const receipt of recoveredReceipts) {
						await unlink(receipt).catch((error: NodeJS.ErrnoException) => {
							if (error.code !== "ENOENT") throw error;
						});
					}
				}
				return value;
			},
			signal,
		);
	}

	private async recoverNativeWrites(snapshot: WorkSnapshot, signal?: AbortSignal): Promise<string[]> {
		const directory = join(this.options.storageDir, "operations");
		let entries: string[];
		try {
			entries = await readdir(directory);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
			throw error;
		}
		const recovered: string[] = [];
		for (const name of entries.sort()) {
			signal?.throwIfAborted();
			if (!name.endsWith(".json")) continue;
			const receiptPath = join(directory, name);
			const entry = await lstat(receiptPath);
			if (!entry.isFile() || entry.isSymbolicLink() || entry.size > 16384)
				throw new Error("Unsafe native-write receipt");
			const parsed: unknown = JSON.parse(await readFile(receiptPath, "utf8"));
			if (!nativeWriteReceipt(parsed)) throw new Error("Invalid native-write receipt");
			if (parsed.familyId !== this.options.familyId) continue;
			identity(parsed.ref);
			identity(parsed.agentId);
			const agent = snapshot.agents[parsed.agentId];
			if (!agent) throw new Error("Native-write receipt references an unknown agent");
			const verifier = new Coordination({
				...this.options,
				workspace: agent.workspace,
				agentId: parsed.agentId,
				parentId: agent.parentId,
			});
			const path = await verifier.canonicalPath(parsed.path);
			if (path !== parsed.path) throw new Error("Native-write receipt path changed");
			const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW);
			const handle = await open(path, flags);
			let contentHash: string;
			try {
				const file = await handle.stat();
				if (!file.isFile() || file.nlink !== 1 || file.size > MAX_BYTES)
					throw new Error("Native-write receipt target is unsafe");
				contentHash = createHash("sha256")
					.update(await handle.readFile())
					.digest("hex");
			} finally {
				await handle.close();
			}
			if (contentHash === parsed.contentHash && !snapshot.links.some((link) => link.ref === parsed.ref)) {
				appendBounded(agent.writeFiles, path);
				agent.latestAction = "write_file";
				this.evidence(
					snapshot,
					{ kind: "touched", source: parsed.agentId, target: path, grade: "native-write" },
					parsed.ref,
				);
			}
			recovered.push(receiptPath);
		}
		return recovered;
	}

	private agent(snapshot: WorkSnapshot): WorkState {
		const agent = snapshot.agents[this.options.agentId];
		if (!agent || agent.parentId !== this.options.parentId) throw new Error("Agent not registered with this parent");
		return agent;
	}
	private evidence(snapshot: WorkSnapshot, link: Omit<EvidenceLink, "ref">, ref: string = randomUUID()): void {
		snapshot.links.push({ ...link, ref });
		if (snapshot.links.length > 2000) snapshot.links.shift();
	}

	async register(signal?: AbortSignal): Promise<void> {
		const workspace = await realpath(this.options.workspace);
		const existing = await this.readSnapshot(signal);
		if (Object.hasOwn(existing.agents, this.options.agentId)) {
			if (normalized(this.agent(existing).workspace) !== normalized(workspace))
				throw new Error("Agent workspace cannot change");
			return;
		}
		await this.transaction((snapshot) => {
			if (Object.hasOwn(snapshot.agents, this.options.agentId)) {
				if (normalized(this.agent(snapshot).workspace) !== normalized(workspace))
					throw new Error("Agent workspace cannot change");
				return;
			}
			if (this.options.parentId && !Object.hasOwn(snapshot.agents, this.options.parentId))
				throw new Error("Unknown parent");
			snapshot.agents[this.options.agentId] = {
				workspace,
				parentId: this.options.parentId,
				status: "idle",
				latestAction: "registered",
				readFiles: [],
				writeFiles: [],
				priority: 0,
			};
			if (this.options.parentId)
				this.evidence(snapshot, {
					kind: "spawned",
					source: this.options.parentId,
					target: this.options.agentId,
					grade: "record",
				});
		}, signal);
	}
	async snapshot(signal?: AbortSignal): Promise<WorkSnapshot> {
		return this.transaction((snapshot) => snapshot, signal, false);
	}

	async graph(signal?: AbortSignal): Promise<WorkGraph> {
		// Atomic snapshots are durable observations, not grants of lock ownership.
		let snapshot: WorkSnapshot;
		try {
			snapshot = await this.transaction((current) => current, signal, false);
		} catch (error) {
			if (!(error instanceof Error) || !error.message.includes("lock is held by a live owner")) throw error;
			snapshot = await this.readSnapshot(signal);
		}
		const directory = join(this.options.storageDir, "locks");
		const entries = await readdir(directory);
		const owners: LockOwner[] = [];
		const waiters: LockOwner[] = [];
		for (const entry of entries) {
			signal?.throwIfAborted();
			const waiting = entry.endsWith(".waiting");
			const path = waiting ? join(directory, entry) : join(directory, entry, "owner.json");
			try {
				if (!waiting) {
					const lock = await lstat(join(directory, entry));
					if (!lock.isDirectory() || lock.isSymbolicLink()) throw new Error("Unsafe coordination lock");
				}
				const info = await lstat(path);
				if (!info.isFile() || info.isSymbolicLink() || info.size > 16384) throw new Error("Unsafe lock metadata");
				const owner: LockOwner = JSON.parse(await readFile(path, "utf8"));
				(waiting ? waiters : owners).push(owner);
			} catch (error) {
				if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
				// Missing ownership never makes a lock stealable.
				if (!waiting)
					owners.push({
						resource: `unknown:${entry}`,
						agentId: "unknown",
						familyId: this.options.familyId,
						pid: 0,
						token: "unknown",
						since: "unknown",
					});
			}
		}
		return {
			...snapshot,
			locks: owners.map((owner) => ({
				...owner,
				waiters: waiters.filter((waiter) => waiter.resource === owner.resource),
			})),
			readyTasks: Object.values(snapshot.tasks)
				.filter(
					(task) =>
						task.status === "idle" && task.dependencies.every((id) => snapshot.tasks[id].status === "done"),
				)
				.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id))
				.map((task) => task.id),
			coverage: "coordinated-native-operations-only",
		};
	}

	async assign(input: Omit<WorkTask, "status" | "writePolicy">, signal?: AbortSignal): Promise<void> {
		identity(input.id);
		identity(input.agentId);
		if (
			!input.title.trim() ||
			input.title.length > 500 ||
			!Number.isInteger(input.priority) ||
			Math.abs(input.priority) > 100
		)
			throw new Error("Invalid task title or priority");
		if (input.writeFiles.length > 200 || input.dependencies.length > 200) throw new Error("Task capacity exceeded");
		const registered = await this.snapshot(signal);
		const assignedAgent = registered.agents[input.agentId];
		if (!assignedAgent || assignedAgent.parentId !== this.options.agentId)
			throw new Error("Only direct parent may assign or reprioritize");
		const targetPaths = new Coordination({ ...this.options, workspace: assignedAgent.workspace });
		const writeFiles = await Promise.all(input.writeFiles.map((path) => targetPaths.canonicalPath(path)));
		await this.transaction((snapshot) => {
			this.agent(snapshot);
			const target = snapshot.agents[input.agentId];
			if (!target || target.parentId !== this.options.agentId)
				throw new Error("Only direct parent may assign or reprioritize");
			const previous = snapshot.tasks[input.id];
			if (previous && previous.agentId !== input.agentId) throw new Error("Task owner cannot change");
			if (target.status === "running" || previous?.status === "running")
				throw new Error("Active work cannot be reassigned; release first");
			if (previous && ["done", "cancelled"].includes(previous.status))
				throw new Error("Terminal task IDs are immutable; assign a new task ID");
			if (
				target.task &&
				target.task !== input.id &&
				!["done", "cancelled"].includes(snapshot.tasks[target.task]?.status ?? "idle")
			)
				throw new Error("Agent already has an unfinished task; finish or cancel it first");
			const candidate: WorkTask = {
				...input,
				dependencies: [...new Set(input.dependencies)],
				writeFiles: [...new Set(writeFiles)],
				status: "idle",
				writePolicy: "scoped",
			};
			snapshot.tasks[input.id] = candidate;
			const visiting = new Set<string>();
			const visited = new Set<string>();
			const visit = (id: string) => {
				if (visiting.has(id)) throw new Error("Task dependency cycle");
				if (visited.has(id)) return;
				const task = Object.hasOwn(snapshot.tasks, id) ? snapshot.tasks[id] : undefined;
				if (!task) throw new Error("Unknown task dependency");
				visiting.add(id);
				for (const dependency of task.dependencies) visit(dependency);
				visiting.delete(id);
				visited.add(id);
			};
			for (const id of Object.keys(snapshot.tasks)) visit(id);
			for (const other of Object.values(snapshot.tasks)) {
				if (
					other.id !== input.id &&
					other.status !== "done" &&
					other.status !== "cancelled" &&
					other.writeFiles.some((path) => writeFiles.includes(path))
				)
					throw new Error(`Write scope conflict with task ${other.id}; parent must narrow or cancel it first`);
			}
			target.task = input.id;
			target.priority = input.priority;
			target.status = "idle";
			target.latestAction = "assigned";
			this.evidence(snapshot, { kind: "assigned", source: this.options.agentId, target: input.id, grade: "record" });
		}, signal);
	}

	async reprioritize(agentId: string, priority: number, signal?: AbortSignal): Promise<void> {
		if (!Number.isInteger(priority) || Math.abs(priority) > 100) throw new Error("Invalid priority");
		await this.transaction((snapshot) => {
			this.agent(snapshot);
			const target = snapshot.agents[agentId];
			if (!target || target.parentId !== this.options.agentId)
				throw new Error("Only direct parent may reprioritize");
			target.priority = priority;
			target.latestAction = "reprioritized";
			if (target.task) snapshot.tasks[target.task].priority = priority;
		}, signal);
	}

	async update(status: WorkStatus, signal?: AbortSignal): Promise<void> {
		if (!["idle", "running", "done", "cancelled"].includes(status)) throw new Error("Invalid status");
		await this.transaction((snapshot) => {
			const agent = this.agent(snapshot);
			const task = agent.task ? snapshot.tasks[agent.task] : undefined;
			if (task && ["done", "cancelled"].includes(task.status) && status !== task.status)
				throw new Error("Task is terminal; parent must assign new work");
			if (
				task &&
				(status === "running" || status === "done") &&
				task.dependencies.some((id) => snapshot.tasks[id].status !== "done")
			)
				throw new Error("Unfinished task dependency");
			agent.status = status;
			agent.latestAction = status;
			if (task) task.status = status;
			if ((status === "done" || status === "cancelled") && agent.parentId)
				this.evidence(snapshot, {
					kind: "returned",
					source: this.options.agentId,
					target: agent.parentId,
					grade: "record",
				});
		}, signal);
	}

	async cancel(taskId: string, signal?: AbortSignal): Promise<void> {
		identity(taskId);
		await this.transaction((snapshot) => {
			this.agent(snapshot);
			const task = snapshot.tasks[taskId];
			if (!task || snapshot.agents[task.agentId]?.parentId !== this.options.agentId)
				throw new Error("Only direct parent may cancel");
			if (task.status === "done") throw new Error("Task is terminal");
			task.status = "cancelled";
			const agent = snapshot.agents[task.agentId];
			if (agent.task === taskId) {
				agent.status = "cancelled";
				agent.latestAction = "cancelled";
			}
			this.evidence(snapshot, {
				kind: "returned",
				source: task.agentId,
				target: this.options.agentId,
				grade: "record",
			});
		}, signal);
	}

	async activity(action: string, status?: "idle" | "running", signal?: AbortSignal): Promise<void> {
		await this.transaction((snapshot) => {
			const agent = this.agent(snapshot);
			if (!agent.task && status) agent.status = status;
			agent.latestAction = action;
		}, signal);
	}

	async begin(title: string, signal?: AbortSignal): Promise<string> {
		return this.transaction((snapshot) => {
			const agent = this.agent(snapshot);
			let task = agent.task ? snapshot.tasks[agent.task] : undefined;
			if (!task || ["done", "cancelled"].includes(task.status)) {
				const previous = task;
				const id = `run:${randomUUID()}`;
				task = {
					id,
					agentId: this.options.agentId,
					title: title.slice(0, 500),
					dependencies: [],
					writeFiles: previous?.writePolicy === "scoped" ? [...previous.writeFiles] : [],
					priority: agent.priority,
					status: "idle",
					writePolicy: previous?.writePolicy === "scoped" ? "scoped" : "unreserved",
				};
				snapshot.tasks[id] = task;
				agent.task = id;
			}
			if (task.dependencies.some((id) => snapshot.tasks[id].status !== "done"))
				throw new Error("Unfinished task dependency");
			agent.status = "running";
			agent.latestAction = "task_started";
			task.status = "running";
			return task.id;
		}, signal);
	}

	async finish(taskId: string, cancelled: boolean): Promise<void> {
		await this.transaction((snapshot) => {
			const agent = this.agent(snapshot);
			const task = snapshot.tasks[taskId];
			if (!task || agent.task !== taskId || ["done", "cancelled"].includes(task.status)) return;
			task.status = cancelled ? "cancelled" : "done";
			agent.status = task.status;
			agent.latestAction = task.status;
			if (agent.parentId)
				this.evidence(snapshot, {
					kind: "returned",
					source: this.options.agentId,
					target: agent.parentId,
					grade: "record",
				});
		});
	}

	async close(): Promise<void> {
		await this.transaction((snapshot) => {
			const agent = this.agent(snapshot);
			const task = agent.task ? snapshot.tasks[agent.task] : undefined;
			if (task && !["done", "cancelled"].includes(task.status)) {
				task.status = "cancelled";
				agent.status = "cancelled";
				if (agent.parentId)
					this.evidence(snapshot, {
						kind: "returned",
						source: this.options.agentId,
						target: agent.parentId,
						grade: "record",
					});
			}
			agent.latestAction = "disposed";
		});
	}

	private async file(raw: string, content: string | undefined, signal?: AbortSignal): Promise<string> {
		if (content !== undefined && Buffer.byteLength(content) > MAX_BYTES)
			throw new Error("File exceeds native size limit");
		let committedReceipt: string | undefined;
		const result = await this.withFile(
			raw,
			(path) =>
				this.transaction(async (snapshot) => {
					const agent = this.agent(snapshot);
					const task = agent.task ? snapshot.tasks[agent.task] : undefined;
					if (content !== undefined) {
						const reserved = Object.values(snapshot.tasks).find(
							(other) =>
								other.agentId !== this.options.agentId &&
								!["done", "cancelled"].includes(other.status) &&
								other.writeFiles.includes(path),
						);
						if (reserved)
							throw new Error(
								`Write scope reserved by task ${reserved.id}; parent must narrow or cancel it first`,
							);
					}
					if (
						content !== undefined &&
						task &&
						(task.status !== "running" || (task.writePolicy !== "unreserved" && !task.writeFiles.includes(path)))
					)
						throw new Error("Write outside running task scope");
					let text: string;
					if (content === undefined) {
						const flags = constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW);
						const handle = await open(path, flags);
						try {
							const entry = await handle.stat();
							if (!entry.isFile() || entry.nlink !== 1)
								throw new Error("Only regular unaliased files are supported");
							if (entry.size > MAX_BYTES) throw new Error("File exceeds native size limit");
							if ((await this.canonicalPath(raw)) !== path) throw new Error("File path changed before read");
							const current = await lstat(path);
							if (current.isSymbolicLink() || current.dev !== entry.dev || current.ino !== entry.ino)
								throw new Error("File changed before read");
							text = await handle.readFile({ encoding: "utf8", signal });
						} finally {
							await handle.close();
						}
						if (Buffer.byteLength(text) > MAX_BYTES) throw new Error("File exceeds native size limit");
					} else {
						const operations = join(this.options.storageDir, "operations");
						await ensurePrivateDirectory(operations);
						const ref = randomUUID();
						const receipt = join(operations, `${ref}.json`);
						await atomicWrite(
							receipt,
							JSON.stringify({
								version: 1,
								kind: "native-write",
								ref,
								familyId: this.options.familyId,
								agentId: this.options.agentId,
								path,
								contentHash: createHash("sha256").update(content).digest("hex"),
								createdAt: new Date().toISOString(),
							}),
							signal,
						);
						try {
							if ((await this.canonicalPath(raw)) !== path) throw new Error("File path changed before write");
							await atomicWrite(path, content, signal, { preserveMetadata: true });
						} catch (error) {
							await unlink(receipt).catch(() => undefined);
							throw error;
						}
						text = "written";
						committedReceipt = receipt;
					}
					const paths = content === undefined ? agent.readFiles : agent.writeFiles;
					appendBounded(paths, path);
					agent.latestAction = content === undefined ? "read_file" : "write_file";
					this.evidence(
						snapshot,
						{
							kind: "touched",
							source: this.options.agentId,
							target: path,
							grade: content === undefined ? "native-read" : "native-write",
						},
						committedReceipt ? basename(committedReceipt, ".json") : undefined,
					);
					return text;
				}, signal),
			signal,
		);
		if (committedReceipt) await unlink(committedReceipt).catch(() => undefined);
		return result;
	}
	read(path: string, signal?: AbortSignal): Promise<string> {
		return this.file(path, undefined, signal);
	}
	write(path: string, content: string, signal?: AbortSignal): Promise<string> {
		return this.file(path, content, signal);
	}
}
