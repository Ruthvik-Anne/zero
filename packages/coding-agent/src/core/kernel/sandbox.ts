import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { getAgentDir } from "../../config.js";
import { SANDBOX_LAUNCHER, SANDBOX_LAUNCHER_DARWIN, SANDBOX_RELAY } from "./sandbox-runtime.js";

const MAX_RELAY_BYTES = 32 * 1024 * 1024;

export function sandboxPath(value: string, platform: NodeJS.Platform = process.platform): string {
	if (platform !== "win32") return resolve(value);
	if (!/^[a-z]:[\\/]/i.test(value))
		throw new Error("Sandbox requires an absolute Windows drive path (UNC unsupported)");
	return value;
}

export class RelayChannel implements AsyncIterable<Buffer[]> {
	private queue: Buffer[][] = [];
	private bytes = 0;
	private waiter?: { resolve: (frames: Buffer[]) => void; reject: (error: Error) => void };
	private closed = false;
	constructor(private readonly write: (frames: Buffer[]) => Promise<void>) {}
	push(frames: Buffer[]): void {
		if (this.closed) return;
		if (this.waiter) {
			this.waiter.resolve(frames);
			this.waiter = undefined;
		} else {
			this.bytes += frames.reduce((size, frame) => size + frame.length, 0);
			if (this.bytes > MAX_RELAY_BYTES) throw new Error("Sandbox relay queue exceeded limit");
			this.queue.push(frames);
		}
	}
	send(frames: Buffer[]): Promise<void> {
		if (this.closed) return Promise.reject(new Error("Sandbox relay closed"));
		return this.write(frames);
	}
	receive(): Promise<Buffer[]> {
		const frames = this.queue.shift();
		if (frames) {
			this.bytes -= frames.reduce((size, frame) => size + frame.length, 0);
			return Promise.resolve(frames);
		}
		if (this.closed) return Promise.reject(new Error("Sandbox relay closed"));
		if (this.waiter) return Promise.reject(new Error("Concurrent relay receive"));
		return new Promise((resolve, reject) => {
			this.waiter = { resolve, reject };
		});
	}
	close(): void {
		this.closed = true;
		this.queue = [];
		this.bytes = 0;
		this.waiter?.reject(new Error("Sandbox relay closed"));
		this.waiter = undefined;
	}
	async *[Symbol.asyncIterator](): AsyncIterator<Buffer[]> {
		while (!this.closed) yield await this.receive();
	}
}

export class KernelSandbox {
	readonly process: ChildProcessWithoutNullStreams;
	readonly shell: RelayChannel;
	readonly control: RelayChannel;
	readonly iopub: RelayChannel;
	readonly ready: Promise<unknown>;
	private readonly exited: Promise<void>;
	private diagnostics = "";
	private closing = false;

	constructor(options: {
		cwd: string;
		python?: string;
		connection: unknown;
		env?: Record<string, string>;
		trustedPaths?: readonly string[];
	}) {
		if (process.platform !== "win32" && process.platform !== "linux" && process.platform !== "darwin") {
			throw new Error(
				"Kernel sandbox requires Linux bubblewrap, Windows WSL2, or macOS Seatbelt; no unsandboxed fallback",
			);
		}
		const darwin = process.platform === "darwin";
		const scratch = darwin ? mkdtempSync(join(tmpdir(), "zero-sandbox-")) : undefined;
		const workspace = sandboxPath(options.cwd);
		const protectedPath = sandboxPath(getAgentDir());
		const python = options.python ?? process.env.ZERO_KERNEL_SANDBOX_PYTHON ?? process.env.ZERO_KERNEL_PYTHON;
		const trustedPaths = [...new Set((options.trustedPaths ?? []).map((value) => sandboxPath(value)))];
		const writableEnvPaths = Object.entries(options.env ?? {})
			.filter(([key, value]) => /^RLM_(?:GLOBAL_)?(?:HARNESS_STATE|SESSION)_DIR$/.test(key) && existsSync(value))
			.map(([, value]) => sandboxPath(value));
		const env: NodeJS.ProcessEnv =
			process.platform === "win32"
				? {
						SystemRoot: process.env.SystemRoot,
						WINDIR: process.env.WINDIR,
						PATH: `${process.env.SystemRoot}\\System32`,
					}
				: { PATH: "/usr/bin:/bin" };
		this.process = darwin
			? spawn("/usr/bin/python3", ["-I", "-u", "-c", SANDBOX_LAUNCHER_DARWIN], {
					env: { PATH: "/usr/bin:/bin" },
					stdio: "pipe",
					detached: true,
				})
			: process.platform === "win32"
				? spawn(
						"wsl.exe",
						[
							"-d",
							process.env.ZERO_KERNEL_WSL_DISTRO ?? "Ubuntu",
							"--exec",
							"/usr/bin/python3",
							"-I",
							"-u",
							"-c",
							SANDBOX_LAUNCHER,
						],
						{ env, stdio: "pipe", windowsHide: true },
					)
				: spawn("/usr/bin/python3", ["-I", "-u", "-c", SANDBOX_LAUNCHER], {
						env,
						stdio: "pipe",
						detached: true,
					});
		this.exited = new Promise((resolve) => {
			this.process.once("close", () => resolve());
		});
		if (scratch) {
			this.exited.then(() => rmSync(scratch, { recursive: true, force: true }));
		}
		const write = (channel: string, frames: Buffer[]) =>
			new Promise<void>((resolve, reject) => {
				const line = JSON.stringify({ channel, frames: frames.map((frame) => frame.toString("base64")) });
				if (Buffer.byteLength(line) > MAX_RELAY_BYTES) {
					reject(new Error("Sandbox relay message exceeded limit"));
					return;
				}
				this.process.stdin.write(`${line}\n`, (error) => (error ? reject(error) : resolve()));
			});
		this.shell = new RelayChannel((frames) => write("shell", frames));
		this.control = new RelayChannel((frames) => write("control", frames));
		this.iopub = new RelayChannel((frames) => write("iopub", frames));
		this.ready = new Promise((resolve, reject) => {
			let ready = false;
			const timer = setTimeout(() => fail(new Error("Sandbox startup timed out")), 30000);
			const fail = (error: Error) => {
				clearTimeout(timer);
				reject(new Error(`${error.message}\n${this.diagnostics}`));
				this.close();
			};
			let pending = Buffer.alloc(0);
			this.process.stderr.on("data", (data: Buffer) => {
				this.diagnostics = `${this.diagnostics}${data.toString()}`.slice(-4096);
			});
			this.process.on("error", fail);
			this.process.stdin.on("error", fail);
			this.process.on("exit", () => fail(new Error("Sandbox process exited")));
			this.process.stdout.on("data", (data: Buffer) => {
				try {
					pending = Buffer.concat([pending, data]);
					if (pending.length > MAX_RELAY_BYTES) throw new Error("Sandbox relay output exceeded limit");
					while (pending.includes(10)) {
						const end = pending.indexOf(10);
						const message: { ready?: unknown; channel?: string; frames?: unknown } = JSON.parse(
							pending.subarray(0, end).toString(),
						);
						pending = pending.subarray(end + 1);
						if (!ready && message.ready) {
							ready = true;
							clearTimeout(timer);
							resolve(message.ready);
							continue;
						}
						if (
							!ready ||
							!Array.isArray(message.frames) ||
							!message.frames.every((frame) => typeof frame === "string")
						)
							throw new Error("Malformed sandbox relay frame");
						const channel =
							message.channel === "shell"
								? this.shell
								: message.channel === "control"
									? this.control
									: message.channel === "iopub"
										? this.iopub
										: undefined;
						if (!channel) throw new Error("Unknown sandbox relay channel");
						channel.push(message.frames.map((frame: string) => Buffer.from(frame, "base64")));
					}
				} catch (error) {
					fail(error instanceof Error ? error : new Error(String(error)));
				}
			});
			this.process.stdin.write(
				`${JSON.stringify({ workspace, protectedPath, python, connection: options.connection, relay: SANDBOX_RELAY, env: options.env, trustedPaths, writableEnvPaths, windowsPaths: process.platform === "win32", scratch })}\n`,
			);
		});
	}

	async waitForExit(): Promise<void> {
		let timer: ReturnType<typeof setTimeout> | undefined;
		let forced = false;
		try {
			await Promise.race([
				this.exited,
				new Promise<void>((resolve) => {
					timer = setTimeout(() => {
						forced = true;
						this.terminateProcessTree();
						resolve();
					}, 5000);
				}),
			]);
		} finally {
			clearTimeout(timer);
		}
		if (forced) {
			await Promise.race([
				this.exited,
				new Promise<never>((_, reject) => {
					timer = setTimeout(
						() => reject(new Error("Sandbox process tree did not exit after forced termination")),
						5000,
					);
				}),
			]).finally(() => clearTimeout(timer));
		}
	}

	close(): void {
		if (this.closing) return;
		this.closing = true;
		this.shell.close();
		this.control.close();
		this.iopub.close();
		// EOF makes the Linux supervisor terminate bwrap and its PID namespace.
		this.process.stdin.end();
	}

	private terminateProcessTree(): void {
		if (!this.process.pid) return;
		try {
			if (process.platform === "win32") {
				const killer = spawn("taskkill.exe", ["/pid", String(this.process.pid), "/t", "/f"], {
					stdio: "ignore",
					windowsHide: true,
				});
				killer.unref();
			} else {
				process.kill(-this.process.pid, "SIGKILL");
			}
		} catch {
			this.process.kill("SIGKILL");
		}
	}
}
