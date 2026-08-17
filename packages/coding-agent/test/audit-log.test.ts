import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { appendAuditLog, auditEntry } from "../src/core/audit/audit-log.js";

describe("audit log (module H)", () => {
	let dir: string;

	beforeEach(async () => {
		dir = await mkdtemp(join(tmpdir(), "zero-audit-test-"));
	});

	afterEach(async () => {
		await rm(dir, { recursive: true, force: true });
	});

	it("creates the audit directory on first write", async () => {
		const auditLogPath = join(dir, "nested", "audit", "audit.jsonl");
		expect(existsSync(auditLogPath)).toBe(false);

		await appendAuditLog(auditLogPath, auditEntry("tool_call", { toolName: "ipython", outcome: "ok" }));

		expect(existsSync(auditLogPath)).toBe(true);
	});

	it("appends one JSON line per entry, preserving order", async () => {
		const auditLogPath = join(dir, "audit.jsonl");

		await appendAuditLog(auditLogPath, auditEntry("harm_verdict", { action: "soft_block", toolName: "bash" }));
		await appendAuditLog(auditLogPath, auditEntry("tool_call", { toolName: "bash", outcome: "ok" }));
		await appendAuditLog(auditLogPath, auditEntry("mode_switch", { from: "auto", to: "manual" }));

		const lines = (await readFile(auditLogPath, "utf8"))
			.trim()
			.split("\n")
			.map((line) => JSON.parse(line));

		expect(lines).toHaveLength(3);
		expect(lines[0].type).toBe("harm_verdict");
		expect(lines[0].detail.action).toBe("soft_block");
		expect(lines[1].type).toBe("tool_call");
		expect(lines[2].type).toBe("mode_switch");
		expect(lines.every((l: { timestamp: number }) => typeof l.timestamp === "number")).toBe(true);
	});
});
