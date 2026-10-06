import { open } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import type { SessionHeader } from "../session-manager.js";
import { Coordination } from "./service.js";

async function headerAt(path: string): Promise<SessionHeader> {
	const handle = await open(path, "r");
	try {
		const buffer = Buffer.alloc(16384);
		const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
		const text = buffer.subarray(0, bytesRead).toString("utf8");
		const end = text.indexOf("\n");
		if (end < 0) throw new Error("Missing bounded session header for coordination");
		const header: SessionHeader = JSON.parse(text.slice(0, end));
		if (header.type !== "session" || typeof header.id !== "string" || typeof header.cwd !== "string")
			throw new Error("Invalid session ancestry for coordination");
		return header;
	} finally {
		await handle.close();
	}
}

/** Session headers are host-owned lineage, shared by resumed daemon workers. */
export async function createSessionCoordination(input: {
	agentId: string;
	workspace: string;
	header?: SessionHeader | null;
	sessionFile?: string;
	parent?: Coordination;
}): Promise<Coordination> {
	if (input.parent) {
		const service = new Coordination({
			...input.parent.options,
			workspace: input.workspace,
			agentId: input.agentId,
			parentId: input.parent.options.agentId,
		});
		await service.register();
		return service;
	}
	const ancestors: SessionHeader[] = [];
	let header = input.header;
	let file = input.sessionFile;
	const seen = new Set<string>([input.agentId]);
	while (header?.rlmDepth && header.parentSession) {
		if (!file || ancestors.length >= 64) throw new Error("Unresolved session ancestry for coordination");
		file = isAbsolute(header.parentSession) ? header.parentSession : resolve(dirname(file), header.parentSession);
		header = await headerAt(file);
		if (seen.has(header.id)) throw new Error("Cyclic session ancestry for coordination");
		seen.add(header.id);
		ancestors.push(header);
	}
	const root = ancestors.at(-1) ?? input.header;
	const familyId = root?.id ?? input.agentId;
	const storageDir = join(
		ancestors.at(-1)?.cwd ?? (input.sessionFile ? input.header?.cwd : undefined) ?? input.workspace,
		".zero",
		"coordination",
	);
	for (let index = ancestors.length - 1; index >= 0; index--) {
		await new Coordination({
			workspace: ancestors[index].cwd,
			storageDir,
			familyId,
			agentId: ancestors[index].id,
			parentId: ancestors[index + 1]?.id,
		}).register();
	}
	const service = new Coordination({
		workspace: input.workspace,
		storageDir,
		familyId,
		agentId: input.agentId,
		parentId: ancestors[0]?.id,
	});
	await service.register();
	return service;
}
