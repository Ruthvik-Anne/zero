import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { KernelManager } from "../src/core/kernel/index.js";

let tempDir = "";

function writeExecutable(filePath: string, content: string): void {
	writeFileSync(filePath, content);
	chmodSync(filePath, 0o755);
}

describe.skipIf(process.platform === "win32" && !process.env.ZERO_KERNEL_SANDBOX_PYTHON)(
	"KernelManager startup",
	() => {
		beforeEach(() => {
			tempDir = mkdtempSync(join(tmpdir(), "prime-agent-kernel-startup-"));
		});

		afterEach(() => {
			if (tempDir) {
				rmSync(tempDir, { recursive: true, force: true });
				tempDir = "";
			}
		});

		it("surfaces kernels that exit before resolving ports", async () => {
			const venv = join(tempDir, "venv");
			const python = join(venv, "bin", "python");
			mkdirSync(join(venv, "bin"), { recursive: true });
			writeFileSync(join(venv, "pyvenv.cfg"), "home = /usr/bin\n");
			writeExecutable(python, ["#!/bin/sh", 'echo "fake kernel died before binding" >&2', "exit 42", ""].join("\n"));
			const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
			const manager = new KernelManager({ python, cwd: tempDir });

			try {
				await expect(manager.execute("print(1)")).rejects.toThrow(/fake kernel died before binding/);
			} finally {
				errorSpy.mockRestore();
				await manager.dispose();
			}
		});

		it("preserves the original startup failure when cleanup also fails", async () => {
			const manager = new KernelManager({ python: "/nonexistent/zero-sandbox-python", cwd: tempDir });
			const waitForExit = vi
				.spyOn(manager as unknown as { shutdown: () => Promise<void> }, "shutdown")
				.mockRejectedValue(new Error("cleanup failed"));

			await expect(manager.start()).rejects.toThrow("Sandbox prerequisite missing: Linux Python");
			waitForExit.mockRestore();
		}, 40_000);
	},
);
