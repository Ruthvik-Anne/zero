import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	buildRestoreCode,
	buildSnapshotCode,
	DEFAULT_SNAPSHOT_MAX_BYTES,
	manifestPathIn,
	parseRestoreResult,
	parseSnapshotResult,
	snapshotPathIn,
} from "../src/core/kernel/state-snapshot.js";

// Kept in sync with the marker the Python helpers print.
const MARKER = "__ZERO_KERNEL_STATE__";

describe("kernel state snapshot paths", () => {
	it("places snapshot + manifest inside the session artifact directory", () => {
		const artifactDir = "/home/u/.prime/agent/session-artifacts/abc-123";
		expect(snapshotPathIn(artifactDir)).toBe(join(artifactDir, "kernel-state.dill"));
		expect(manifestPathIn(artifactDir)).toBe(join(artifactDir, "kernel-state.json"));
	});
});

describe("parseSnapshotResult", () => {
	it("parses a valid marker line", () => {
		const stdout = `${MARKER}${JSON.stringify({
			saved: ["x", "y"],
			skipped: [{ name: "sock", reason: "TypeError: cannot pickle" }],
			bytes: 1234,
		})}\n`;
		const result = parseSnapshotResult(stdout, "/tmp/s.dill");
		expect(result).toEqual({
			saved: ["x", "y"],
			skipped: [{ name: "sock", reason: "TypeError: cannot pickle" }],
			bytes: 1234,
			path: "/tmp/s.dill",
		});
	});

	it("ignores stdout printed before the marker line", () => {
		const stdout = `some earlier print output\n${MARKER}${JSON.stringify({ saved: ["a"], skipped: [], bytes: 7 })}`;
		expect(parseSnapshotResult(stdout, "/tmp/s.dill")?.saved).toEqual(["a"]);
	});

	it("returns null when the marker is absent", () => {
		expect(parseSnapshotResult("no marker here", "/tmp/s.dill")).toBeNull();
	});

	it("returns null when the payload reports an error", () => {
		const stdout = `${MARKER}${JSON.stringify({ error: "dill unavailable" })}`;
		expect(parseSnapshotResult(stdout, "/tmp/s.dill")).toBeNull();
	});

	it("returns null on malformed JSON", () => {
		expect(parseSnapshotResult(`${MARKER}{not json`, "/tmp/s.dill")).toBeNull();
	});

	it("tolerates missing fields", () => {
		const result = parseSnapshotResult(`${MARKER}{}`, "/tmp/s.dill");
		expect(result).toEqual({ saved: [], skipped: [], bytes: 0, path: "/tmp/s.dill" });
	});
});

describe("parseRestoreResult", () => {
	it("parses restored and failed names", () => {
		const stdout = `${MARKER}${JSON.stringify({
			restored: ["df", "model"],
			failed: [{ name: "conn", reason: "TypeError" }],
		})}`;
		expect(parseRestoreResult(stdout, "/tmp/s.dill")).toEqual({
			restored: ["df", "model"],
			failed: [{ name: "conn", reason: "TypeError" }],
			path: "/tmp/s.dill",
		});
	});

	it("returns null when the marker is absent", () => {
		expect(parseRestoreResult("", "/tmp/s.dill")).toBeNull();
	});

	it("returns null when the payload reports an error", () => {
		expect(parseRestoreResult(`${MARKER}${JSON.stringify({ error: "load failed" })}`, "/tmp/s.dill")).toBeNull();
	});
});

describe("buildSnapshotCode", () => {
	const code = buildSnapshotCode("/state/sess.dill", "/state/sess.json", DEFAULT_SNAPSHOT_MAX_BYTES);

	it("embeds the output, manifest paths, and the byte cap", () => {
		expect(code).toContain('"/state/sess.dill"');
		expect(code).toContain('"/state/sess.json"');
		expect(code).toContain(String(DEFAULT_SNAPSHOT_MAX_BYTES));
	});

	it("uses dill, an atomic write, and skips internal handles", () => {
		expect(code).toContain("import dill");
		expect(code).toContain("os.replace");
		// rlm and the IPython display names must never be serialized.
		expect(code).toContain('"rlm"');
		expect(code).toContain(`print(${JSON.stringify(MARKER)}`);
	});

	it("sets restrictive (0o600) permissions on the payload file before the atomic rename", () => {
		expect(code).toContain("os.chmod(tmp, 0o600)");
		// Defense-in-depth on top of the exclusion check, not instead of it —
		// the chmod must precede the rename into the real path.
		const chmodIndex = code.indexOf("os.chmod(tmp, 0o600)");
		const replaceIndex = code.indexOf("os.replace(tmp,");
		expect(chmodIndex).toBeGreaterThan(-1);
		expect(chmodIndex).toBeLessThan(replaceIndex);
	});

	// Finding #1: without an exclusion list, no secret material to guard
	// against — the generated source must still be well-formed (an empty
	// Python list), and per the "no-op cost for the common case" requirement,
	// the per-variable str(value) check must be gated behind it.
	describe("with no excluded secrets (default)", () => {
		it("embeds an empty Python list and gates the per-variable check on it", () => {
			expect(code).toContain("_excluded_secrets = []");
			expect(code).toContain("if _excluded_secrets:");
		});
	});

	describe("with excluded secrets", () => {
		const secretCode = buildSnapshotCode("/state/sess.dill", "/state/sess.json", DEFAULT_SNAPSHOT_MAX_BYTES, [
			"sk-live-abc123",
			'has"quote',
		]);

		it("embeds each excluded secret as a properly-escaped Python string literal", () => {
			expect(secretCode).toContain(JSON.stringify("sk-live-abc123"));
			expect(secretCode).toContain(JSON.stringify('has"quote'));
			expect(secretCode).toContain(
				`_excluded_secrets = [${JSON.stringify("sk-live-abc123")}, ${JSON.stringify('has"quote')}]`,
			);
		});

		it("checks str(value) against the excluded secrets before dill.dumps, and skips defensively on error", () => {
			const strIndex = secretCode.indexOf("_value_str = _b.str(value)");
			const dumpsIndex = secretCode.indexOf("dill.dumps(value)");
			expect(strIndex).toBeGreaterThan(-1);
			expect(strIndex).toBeLessThan(dumpsIndex);
			expect(secretCode).toContain("_contains_secret = True");
			expect(secretCode).toContain('"reason": "excluded: contains vault credential material"');
		});

		it("deduplicates and drops empty-string secrets, which would otherwise match every variable", () => {
			const withDupesAndEmpty = buildSnapshotCode(
				"/state/sess.dill",
				"/state/sess.json",
				DEFAULT_SNAPSHOT_MAX_BYTES,
				["dup", "dup", ""],
			);
			expect(withDupesAndEmpty).toContain(`_excluded_secrets = [${JSON.stringify("dup")}]`);
		});
	});
});

describe("buildRestoreCode", () => {
	const code = buildRestoreCode("/state/sess.dill");

	it("embeds the input path and no-ops when the file is missing", () => {
		expect(code).toContain('"/state/sess.dill"');
		expect(code).toContain("os.path.exists");
		expect(code).toContain("dill.loads");
	});
});
