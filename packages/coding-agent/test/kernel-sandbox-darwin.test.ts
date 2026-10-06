import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { SANDBOX_LAUNCHER_DARWIN, SANDBOX_RELAY } from "../src/core/kernel/sandbox-runtime.js";

const hasPython3 = spawnSync("python3", ["--version"]).status === 0;

describe("kernel sandbox launchers", () => {
	it.skipIf(!hasPython3)("parses the macOS launcher and the relay as Python", () => {
		for (const source of [SANDBOX_LAUNCHER_DARWIN, SANDBOX_RELAY]) {
			const result = spawnSync("python3", ["-c", "import ast, sys; ast.parse(sys.stdin.read())"], {
				input: source,
				encoding: "utf8",
			});
			expect(result.stderr).toBe("");
			expect(result.status).toBe(0);
		}
	});

	it("gates the Linux namespace and seccomp checks behind the host handshake", () => {
		expect(SANDBOX_RELAY).toContain("if 'host_net' in config:");
	});

	it("builds a deny-by-default Seatbelt profile with a confinement probe", () => {
		expect(SANDBOX_LAUNCHER_DARWIN).toContain("'(deny default)'");
		expect(SANDBOX_LAUNCHER_DARWIN).toContain("'(allow network-outbound (remote ip \"localhost:*\"))'");
		expect(SANDBOX_LAUNCHER_DARWIN).toContain("sys.exit(5)");
	});
});
