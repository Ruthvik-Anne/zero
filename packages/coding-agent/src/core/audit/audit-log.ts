import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

/**
 * Native audit log (module H) — append-only, one line per event, persisted
 * as a sibling of `harness_state.json`/`kernel-state.json`/`scheduled-jobs.json`
 * under a session's `session-artifacts/<id>/` directory (the existing
 * artifact-directory convention), so it inherits that directory's lifecycle
 * rather than inventing a new storage location.
 *
 * Plain durable log for v1 — no hash-chaining/tamper-evidence yet.
 */

export type AuditEventType = "tool_call" | "harm_verdict" | "mode_switch" | "ask_user" | "provider_fallback";

export interface AuditEntry {
	timestamp: number;
	type: AuditEventType;
	detail: Record<string, unknown>;
}

export async function appendAuditLog(auditLogPath: string, entry: AuditEntry): Promise<void> {
	await mkdir(dirname(auditLogPath), { recursive: true });
	await appendFile(auditLogPath, `${JSON.stringify(entry)}\n`, "utf8");
}

export function auditEntry(type: AuditEventType, detail: Record<string, unknown>): AuditEntry {
	return { timestamp: Date.now(), type, detail };
}
