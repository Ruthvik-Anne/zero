import { chmodSync, existsSync, lstatSync, mkdirSync, unlinkSync, writeFileSync } from "node:fs";
import { createConnection } from "node:net";
import { tmpdir, userInfo } from "node:os";
import { dirname, join } from "node:path";
import lockfile from "proper-lockfile";

const DAEMON_SOCKET_MODE = 0o600;
const DAEMON_SOCKET_DIR_MODE = 0o700;
const DAEMON_SOCKET_RELEASE_GRACE_MS = 1000;
const DAEMON_SOCKET_RELEASE_POLL_MS = 25;
const DAEMON_SOCKET_LOCK_STALE_MS = 5000;
const DAEMON_SOCKET_LOCK_UPDATE_MS = 1000;

export class DaemonSocketPathLease {
	private released = false;

	constructor(
		readonly socketPath: string,
		private readonly releaseLock: () => Promise<void>,
	) {}

	async release(): Promise<void> {
		if (this.released) {
			return;
		}
		this.released = true;
		await this.releaseLock();
	}
}

export interface DaemonSocketIdentity {
	dev: number;
	ino: number;
}

// (B7) Was a hardcoded machine-global pipe name while the POSIX path is
// uid-scoped (defaultDaemonSocketDir() below) — two different users on the
// same machine, or a stale daemon from an old session, collided with a bare
// EADDRINUSE. Scope it the same way.
function windowsPipeUserSuffix(): string {
	try {
		return userInfo().username.replace(/[^A-Za-z0-9_.-]/g, "_") || "user";
	} catch {
		return "user";
	}
}

export function defaultDaemonSocketPath(): string {
	if (process.platform === "win32") {
		return `\\\\.\\pipe\\zero-daemon-${windowsPipeUserSuffix()}`;
	}
	return join(defaultDaemonSocketDir(), "daemon.sock");
}

/**
 * (B7) Windows named pipes have no filesystem path proper-lockfile can lock —
 * `\\.\pipe\...` isn't a real file. Lock a real auxiliary file instead (same
 * directory convention as the POSIX socket dir) purely for mutual exclusion;
 * the pipe itself is still created by whoever wins this lock.
 */
function windowsDaemonLockPath(socketPath: string): string {
	const suffix = socketPath.replace(/[^A-Za-z0-9_.-]/g, "_");
	return join(tmpdir(), `zero-daemon-lock-${suffix}`);
}

export async function acquireDaemonSocketPathLease(socketPath: string): Promise<DaemonSocketPathLease | undefined> {
	ensureDefaultDaemonSocketDir(socketPath);
	if (process.platform === "win32") {
		const lockPath = windowsDaemonLockPath(socketPath);
		if (!existsSync(lockPath)) {
			writeFileSync(lockPath, "", { flag: "wx" });
		}
		const releaseLock = await lockfile.lock(lockPath, {
			realpath: false,
			stale: DAEMON_SOCKET_LOCK_STALE_MS,
			update: DAEMON_SOCKET_LOCK_UPDATE_MS,
			retries: {
				retries: 600,
				factor: 1,
				minTimeout: DAEMON_SOCKET_RELEASE_POLL_MS,
				maxTimeout: DAEMON_SOCKET_RELEASE_POLL_MS,
			},
		});
		return new DaemonSocketPathLease(socketPath, releaseLock);
	}
	const releaseLock = await lockfile.lock(socketPath, {
		realpath: false,
		stale: DAEMON_SOCKET_LOCK_STALE_MS,
		update: DAEMON_SOCKET_LOCK_UPDATE_MS,
		retries: {
			retries: 600,
			factor: 1,
			minTimeout: DAEMON_SOCKET_RELEASE_POLL_MS,
			maxTimeout: DAEMON_SOCKET_RELEASE_POLL_MS,
		},
	});
	return new DaemonSocketPathLease(socketPath, releaseLock);
}

export async function prepareDaemonSocketPath(socketPath: string, lease?: DaemonSocketPathLease): Promise<void> {
	ensureDefaultDaemonSocketDir(socketPath);

	if (process.platform === "win32") {
		if (lease) {
			assertSocketLease(socketPath, lease);
		}
		// (B7) A Windows named pipe has no persistent filesystem entry to stat —
		// `existsSync`/`lstatSync` don't apply to `\\.\pipe\...` the way they do
		// to a Unix socket inode, so there is nothing to "detect as stale" the
		// same way. But `canConnectToUnixSocket` below is not actually
		// POSIX-specific despite its name — `net.createConnection(path)`
		// connects to a Windows named pipe identically to a Unix socket — so the
		// one check that actually matters (is something listening right now)
		// still works unchanged.
		if (await canConnectToUnixSocket(socketPath)) {
			throw new Error(`Daemon socket already in use: ${socketPath}`);
		}
		return;
	}
	if (lease) {
		assertSocketLease(socketPath, lease);
		await prepareUnixDaemonSocketPath(socketPath);
		return;
	}
	if (!existsSync(socketPath)) {
		return;
	}
	if (await canConnectToUnixSocket(socketPath)) {
		throw new Error(`Daemon socket already in use: ${socketPath}`);
	}
	const ownedLease = await acquireDaemonSocketPathLease(socketPath);
	try {
		await prepareUnixDaemonSocketPath(socketPath);
	} finally {
		await ownedLease?.release();
	}
}

async function prepareUnixDaemonSocketPath(socketPath: string): Promise<void> {
	if (!existsSync(socketPath)) {
		return;
	}

	let stat: ReturnType<typeof lstatSync>;
	try {
		stat = lstatSync(socketPath);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			return;
		}
		throw error;
	}
	if (!stat.isSocket()) {
		throw new Error(`Daemon socket path exists and is not a socket: ${socketPath}`);
	}

	const staleIdentity: DaemonSocketIdentity = { dev: stat.dev, ino: stat.ino };
	if (await canConnectToUnixSocket(socketPath)) {
		throw new Error(`Daemon socket already in use: ${socketPath}`);
	}
	const deadline = Date.now() + DAEMON_SOCKET_RELEASE_GRACE_MS;
	while (Date.now() < deadline) {
		await delay(DAEMON_SOCKET_RELEASE_POLL_MS);
		if (!existsSync(socketPath)) {
			return;
		}
		let currentIdentity: DaemonSocketIdentity | undefined;
		try {
			currentIdentity = getDaemonSocketIdentity(socketPath);
		} catch (error) {
			if ((error as NodeJS.ErrnoException).code === "ENOENT") {
				return;
			}
			throw error;
		}
		if (!currentIdentity || currentIdentity.dev !== staleIdentity.dev || currentIdentity.ino !== staleIdentity.ino) {
			throw new Error(`Daemon socket changed ownership while waiting for cleanup: ${socketPath}`);
		}
		if (await canConnectToUnixSocket(socketPath)) {
			throw new Error(`Daemon socket already in use: ${socketPath}`);
		}
	}

	unlinkSync(socketPath);
}

/**
 * (B7) Documented platform gap, not silently faked: a Windows named pipe's
 * permissions are set by the security descriptor passed at *creation* time
 * (which Node's `net.Server.listen()` does not expose a way to customize),
 * not by a POSIX-style chmod applied afterward — there is no equivalent call
 * to retrofit here. In practice this matters less than the POSIX case: a
 * pipe's default ACL already restricts it to the creating user + built-in
 * Administrators, unlike a fresh Unix socket file's default mode.
 */
export function restrictDaemonSocketPath(socketPath: string): void {
	if (process.platform === "win32") {
		return;
	}
	chmodSync(socketPath, DAEMON_SOCKET_MODE);
}

/**
 * (B7) Documented platform gap: `lstatSync` doesn't apply to `\\.\pipe\...`
 * paths — Windows named pipes aren't part of the regular filesystem
 * namespace, so there is no dev/ino (or equivalent) to retrofit an identity
 * check onto. Callers already treat `undefined` as "no identity available"
 * (see `cleanupUnixDaemonSocketPath`'s `expectedIdentity` check), so this is
 * a safe, honest "unavailable" rather than a faked value.
 */
export function getDaemonSocketIdentity(socketPath: string): DaemonSocketIdentity | undefined {
	if (process.platform === "win32") {
		return undefined;
	}
	const stat = lstatSync(socketPath);
	return { dev: stat.dev, ino: stat.ino };
}

export function cleanupDaemonSocketPath(
	socketPath: string,
	expectedIdentity?: DaemonSocketIdentity,
	lease?: DaemonSocketPathLease,
): void {
	if (process.platform === "win32") {
		// (B7) Not a gap: unlike a Unix socket, a Windows named pipe leaves no
		// persistent filesystem entry once its last handle closes — there is
		// nothing to unlink. Releasing the mutex lease (acquireDaemonSocketPathLease's
		// auxiliary lock file) is the only real cleanup, and callers already do
		// that themselves via `lease.release()`.
		return;
	}
	if (lease) {
		assertSocketLease(socketPath, lease);
		try {
			cleanupUnixDaemonSocketPath(socketPath, expectedIdentity);
		} catch {
			// Best effort cleanup; shutdown should not be blocked by socket unlink failures.
		}
		return;
	}
	let releaseLock: (() => void) | undefined;
	try {
		releaseLock = lockfile.lockSync(socketPath, {
			realpath: false,
			stale: DAEMON_SOCKET_LOCK_STALE_MS,
			update: DAEMON_SOCKET_LOCK_UPDATE_MS,
			retries: 0,
		});
	} catch {
		return;
	}
	try {
		cleanupUnixDaemonSocketPath(socketPath, expectedIdentity);
	} catch {
		// Best effort cleanup; shutdown should not be blocked by socket unlink failures.
	} finally {
		try {
			releaseLock();
		} catch {
			// Best effort cleanup; a failed release is recoverable as a stale lock.
		}
	}
}

function cleanupUnixDaemonSocketPath(socketPath: string, expectedIdentity?: DaemonSocketIdentity): void {
	if (!existsSync(socketPath)) {
		return;
	}
	if (expectedIdentity) {
		const currentIdentity = getDaemonSocketIdentity(socketPath);
		if (
			!currentIdentity ||
			currentIdentity.dev !== expectedIdentity.dev ||
			currentIdentity.ino !== expectedIdentity.ino
		) {
			return;
		}
	}
	unlinkSync(socketPath);
}

function assertSocketLease(socketPath: string, lease: DaemonSocketPathLease): void {
	if (lease.socketPath !== socketPath) {
		throw new Error(`Daemon socket lease does not match ${socketPath}`);
	}
}

export function defaultDaemonSocketDir(): string {
	const suffix = typeof process.getuid === "function" ? String(process.getuid()) : "user";
	return join(tmpdir(), `prime-agent-${suffix}`);
}

function ensureDefaultDaemonSocketDir(socketPath: string): void {
	if (process.platform === "win32" || dirname(socketPath) !== defaultDaemonSocketDir()) {
		return;
	}

	if (!existsSync(defaultDaemonSocketDir())) {
		mkdirSync(defaultDaemonSocketDir(), { recursive: true, mode: DAEMON_SOCKET_DIR_MODE });
	}

	const stat = lstatSync(defaultDaemonSocketDir());
	if (!stat.isDirectory()) {
		throw new Error(`Daemon socket directory exists and is not a directory: ${defaultDaemonSocketDir()}`);
	}

	if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
		throw new Error(`Daemon socket directory is not owned by the current user: ${defaultDaemonSocketDir()}`);
	}

	chmodSync(defaultDaemonSocketDir(), DAEMON_SOCKET_DIR_MODE);
}

function canConnectToUnixSocket(socketPath: string): Promise<boolean> {
	return new Promise((resolveConnect) => {
		const socket = createConnection(socketPath);
		let settled = false;
		let timeoutId: ReturnType<typeof setTimeout> | undefined;

		const finish = (canConnect: boolean) => {
			if (settled) {
				return;
			}
			settled = true;
			if (timeoutId) {
				clearTimeout(timeoutId);
			}
			socket.removeAllListeners();
			socket.destroy();
			resolveConnect(canConnect);
		};

		timeoutId = setTimeout(() => finish(false), 250);
		socket.once("connect", () => finish(true));
		socket.once("error", () => finish(false));
	});
}

function delay(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
