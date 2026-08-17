import { type Browser, chromium, type Page } from "playwright";

/**
 * Native browser automation (module J) — Playwright as a direct npm
 * dependency (resolved at `npm install` time, same lifecycle as every other
 * core dependency), with a hand-written action surface exposed as host
 * requests, rather than a Python skill lazily installing `browser-use` into
 * the uv-managed kernel venv at runtime. The model is the perception/action
 * loop (it reads each action's result and decides the next one via ordinary
 * IPython calls); this module only owns the browser lifecycle and the
 * primitive actions themselves — navigate, click, type, extract, screenshot.
 */

export interface BrowserNavigateResult {
	url: string;
	title: string;
}

export interface BrowserExtractResult {
	text: string;
}

export interface BrowserScreenshotResult {
	/** base64-encoded PNG. */
	data: string;
	mimeType: "image/png";
}

const DEFAULT_TIMEOUT_MS = 30_000;

// (D11) browser.navigate had zero validation — any scheme, any host. Two real
// bypasses this closes: file:///.../.aws/credentials read into the transcript
// via a subsequent extract_text (credential-exfiltration entirely outside
// harm-check's own detection, which only inspects ipython/bash source text,
// never a browser URL), and cloud-metadata SSRF via the well-known
// 169.254.169.254 link-local address.
const BLOCKED_HOSTNAMES = new Set(["169.254.169.254", "metadata.google.internal"]);

function isLinkLocalOrMetadataHost(hostname: string): boolean {
	const lower = hostname.toLowerCase();
	if (BLOCKED_HOSTNAMES.has(lower)) return true;
	// IPv4 link-local, 169.254.0.0/16 — covers the AWS/Azure/GCP metadata address
	// and the whole range it lives in, not just the one well-known IP.
	if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
	// IPv6 link-local (fe80::/10).
	if (lower.startsWith("fe80:") || lower.startsWith("[fe80:")) return true;
	return false;
}

/**
 * Throws on: any non-http(s) scheme (file:, data:, javascript:, ...) and any
 * link-local/cloud-metadata host. Does NOT restrict localhost/private-network
 * hosts — a coding agent legitimately browse-testing the user's own local dev
 * server is a real use case, and the "attacker" surface here is a malicious
 * page's content steering the model, not a remote multi-tenant caller.
 *
 * Known limitation (v1, not closed here): this only validates the URL passed
 * to navigate() — a server-side redirect chain during that navigation could
 * still hop to a blocked target after the initial check passes. Closing that
 * needs response/frame-navigation interception, out of scope for this pass.
 */
export function validateBrowserUrl(rawUrl: string): void {
	let parsed: URL;
	try {
		parsed = new URL(rawUrl);
	} catch {
		throw new Error(`browser.navigate: invalid URL "${rawUrl}"`);
	}
	// data: is self-contained (the caller supplies the content inline) — it can't
	// read local files or reach a network host, so it carries none of the risk
	// file:/javascript:/etc. do. Allowed alongside http(s) for that reason.
	if (parsed.protocol !== "http:" && parsed.protocol !== "https:" && parsed.protocol !== "data:") {
		throw new Error(
			`browser.navigate: refused scheme "${parsed.protocol}" on "${rawUrl}" — this can read local files or run scripts instead of browsing the web.`,
		);
	}
	if (isLinkLocalOrMetadataHost(parsed.hostname)) {
		throw new Error(
			`browser.navigate: refused link-local/metadata address "${parsed.hostname}" (cloud instance metadata / SSRF target).`,
		);
	}
}

export class BrowserSession {
	private browser: Browser | undefined;
	private page: Page | undefined;
	private launching: Promise<Page> | undefined;

	private async ensurePage(): Promise<Page> {
		if (this.page && !this.page.isClosed()) {
			return this.page;
		}
		if (!this.launching) {
			this.launching = this.launch();
		}
		try {
			return await this.launching;
		} finally {
			this.launching = undefined;
		}
	}

	private async launch(): Promise<Page> {
		let browser: Browser;
		try {
			browser = await chromium.launch({ headless: true });
		} catch (error) {
			// (D13) Playwright's own "Executable doesn't exist" error gives no hint
			// this is a one-time setup step, not a real bug — nothing runs
			// `playwright install` by default (see postinstall.ts's opt-in
			// ZERO_BOOTSTRAP_BROWSER_ON_INSTALL, deliberately not automatic: chromium
			// alone is a ~300MB download).
			const message = error instanceof Error ? error.message : String(error);
			if (/executable doesn.?t exist/i.test(message)) {
				throw new Error(
					`Chromium is not installed for the browser tool. Run "npx playwright install chromium" once, or set ZERO_BOOTSTRAP_BROWSER_ON_INSTALL=1 before reinstalling. (${message})`,
				);
			}
			throw error;
		}
		try {
			const page = await browser.newPage();
			page.setDefaultTimeout(DEFAULT_TIMEOUT_MS);
			// (D13) Only assigned on full success — if newPage() throws below, this
			// browser process must not become reachable through `this.browser` at
			// all, since a later navigate() would overwrite the field with a fresh
			// launch and orphan this one for the rest of the process's lifetime.
			this.browser = browser;
			this.page = page;
			return page;
		} catch (error) {
			await browser.close().catch(() => {});
			throw error;
		}
	}

	async navigate(url: string): Promise<BrowserNavigateResult> {
		validateBrowserUrl(url);
		const page = await this.ensurePage();
		await page.goto(url, { waitUntil: "domcontentloaded" });
		return { url: page.url(), title: await page.title() };
	}

	async click(selector: string): Promise<void> {
		const page = await this.ensurePage();
		await page.click(selector);
	}

	async type(selector: string, text: string): Promise<void> {
		const page = await this.ensurePage();
		await page.fill(selector, text);
	}

	/** Current value of an input/textarea/select — verifies a prior `type()` landed. */
	async getInputValue(selector: string): Promise<{ value: string }> {
		const page = await this.ensurePage();
		return { value: await page.locator(selector).first().inputValue() };
	}

	/** Visible text of the page, or of one element when `selector` is given. */
	async extractText(selector?: string): Promise<BrowserExtractResult> {
		const page = await this.ensurePage();
		if (selector) {
			const text = await page.locator(selector).first().innerText();
			return { text };
		}
		const text = await page.locator("body").innerText();
		return { text };
	}

	async screenshot(): Promise<BrowserScreenshotResult> {
		const page = await this.ensurePage();
		const buffer = await page.screenshot({ type: "png" });
		return { data: buffer.toString("base64"), mimeType: "image/png" };
	}

	async close(): Promise<void> {
		// (D13) Wait out any in-flight launch first. Without this, a close() that
		// races a pending launch() would tear down this.browser/this.page while
		// they're still undefined (launch() only assigns them on success), and
		// whatever launch() eventually produces — or fails to produce, now
		// self-cleaned above — would never be reachable through this session again.
		if (this.launching) {
			await this.launching.catch(() => undefined);
		}
		const page = this.page;
		const browser = this.browser;
		this.page = undefined;
		this.browser = undefined;
		try {
			await page?.close();
		} catch {
			// Already closed / crashed — nothing more to do.
		}
		try {
			await browser?.close();
		} catch {
			// Already closed / crashed — nothing more to do.
		}
	}

	get isOpen(): boolean {
		return Boolean(this.page && !this.page.isClosed());
	}
}
