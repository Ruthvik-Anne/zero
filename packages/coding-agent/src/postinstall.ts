import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ensureKernelPython } from "./core/kernel/bootstrap.js";
import { ensureTool } from "./utils/tools-manager.js";

const bootstrapKernel = process.env.ZERO_BOOTSTRAP_KERNEL_ON_INSTALL === "1";
const bootstrapTools = process.env.ZERO_BOOTSTRAP_TOOLS_ON_INSTALL === "1";
// (D13) chromium.launch() throws "Executable doesn't exist" on every fresh
// install otherwise — playwright is a direct dependency, but nothing ever ran
// `playwright install`. Opt-in, matching bootstrapKernel/bootstrapTools's own
// pattern: browser binaries are a large download (chromium alone is ~300MB),
// so this must not become an unconditional default-install cost.
const bootstrapBrowser = process.env.ZERO_BOOTSTRAP_BROWSER_ON_INSTALL === "1";

if (!bootstrapKernel && !bootstrapTools && !bootstrapBrowser) {
	process.exit(0);
}

if (bootstrapKernel && process.env.ZERO_INSTALL_UV === undefined) {
	process.env.ZERO_INSTALL_UV = "1";
}

function errorMessage(error: unknown): string {
	return error instanceof Error ? error.message : String(error);
}

function oneLine(message: string): string {
	return message.replace(/\s+/g, " ").trim();
}

/** Only chromium is ever launched (browser-session.ts's `chromium.launch()`) — no point installing firefox/webkit too. */
function installPlaywrightChromium(): void {
	const cliPath = fileURLToPath(import.meta.resolve("playwright/cli.js"));
	execFileSync(process.execPath, [cliPath, "install", "chromium"], { stdio: "inherit", windowsHide: true });
}

try {
	if (bootstrapTools) {
		await Promise.all([ensureTool("fd", true), ensureTool("rg", true)]);
	}
	if (bootstrapKernel) {
		await ensureKernelPython();
	}
	if (bootstrapBrowser) {
		installPlaywrightChromium();
	}
} catch (error) {
	console.error(`prime-agent: postinstall setup skipped: ${oneLine(errorMessage(error))}`);
}
