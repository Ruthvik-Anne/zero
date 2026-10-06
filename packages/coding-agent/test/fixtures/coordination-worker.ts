import { writeFile } from "node:fs/promises";
import { createSessionCoordination } from "../../src/core/coordination/identity.js";
import { Coordination } from "../../src/core/coordination/service.js";

if (process.argv[3] === "identity") {
	const service = await createSessionCoordination(JSON.parse(process.argv[2]));
	process.send?.({ familyId: service.options.familyId, agentId: service.options.agentId });
} else {
	const coordination = new Coordination(JSON.parse(process.argv[2]));
	await coordination.withFile("a.txt", async (path) => {
		process.send?.("held");
		await new Promise<void>((resolve) => process.once("message", () => resolve()));
		await writeFile(path, "worker");
	});
}
process.disconnect();
