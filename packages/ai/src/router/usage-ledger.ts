import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import type { Provider, Usage } from "../types.js";

/**
 * One provider-router attempt, persisted so /usage can report historical,
 * cross-session totals (module G) instead of only the live in-memory number.
 */
export interface UsageLedgerEntry {
	timestamp: number;
	provider: Provider;
	model: string;
	outcome: "success" | "error";
	failureKind?: string;
	usage?: Usage;
}

export async function appendUsageLedger(ledgerPath: string, entry: UsageLedgerEntry): Promise<void> {
	await mkdir(dirname(ledgerPath), { recursive: true });
	await appendFile(ledgerPath, `${JSON.stringify(entry)}\n`, "utf8");
}
