import { ensureKernelPython } from "./bootstrap.js";
import { KernelManager } from "./index.js";

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

try {
	const python = await ensureKernelPython();
	const manager = new KernelManager({ python, cwd: process.cwd() });
	try {
		await manager.start();
		const result = await manager.execute("import ipykernel, zmq, dill, rlm");
		if (result.status !== "ok") throw new Error(result.error?.evalue ?? result.stderr);
	} finally {
		await manager.dispose();
	}
	console.log(`kernel python: ${python}`);
} catch (error) {
	console.error(errorMessage(error));
	process.exit(1);
}
