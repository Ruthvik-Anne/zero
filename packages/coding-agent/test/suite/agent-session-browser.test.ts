import { afterEach, describe, expect, it } from "vitest";
import { createHarness, type Harness } from "./harness.js";

/**
 * module J: browser.* host requests, driven end to end through AgentSession
 * against a real headless Chromium instance (no network — every page here is
 * a self-contained data: URL).
 */
describe("AgentSession browser automation", () => {
	const harnesses: Harness[] = [];

	afterEach(async () => {
		while (harnesses.length > 0) {
			const harness = harnesses.pop();
			await harness?.session.handleBrowserHostRequest("browser.close").catch(() => undefined);
			harness?.cleanup();
		}
	});

	async function createBrowserHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		return harness;
	}

	const testPage = `data:text/html,${encodeURIComponent(`
		<html><head><title>Zero Test</title></head>
		<body>
			<h1 id="heading">initial</h1>
			<input id="box" type="text" />
			<button id="go" onclick="document.getElementById('heading').innerText = 'done'">Go</button>
		</body></html>
	`)}`;

	it("navigates, extracts text, types, clicks, and screenshots via host requests", async () => {
		const harness = await createBrowserHarness();

		const nav = await harness.session.handleBrowserHostRequest("browser.navigate", { url: testPage });
		expect(nav.title).toBe("Zero Test");

		const before = await harness.session.handleBrowserHostRequest("browser.extract_text", { selector: "#heading" });
		expect(before.text).toBe("initial");

		await harness.session.handleBrowserHostRequest("browser.type", { selector: "#box", text: "hello" });
		const value = await harness.session.handleBrowserHostRequest("browser.get_value", { selector: "#box" });
		expect(value.value).toBe("hello");

		await harness.session.handleBrowserHostRequest("browser.click", { selector: "#go" });
		const after = await harness.session.handleBrowserHostRequest("browser.extract_text", { selector: "#heading" });
		expect(after.text).toBe("done");

		const shot = await harness.session.handleBrowserHostRequest("browser.screenshot");
		expect(shot.mimeType).toBe("image/png");
		expect(typeof shot.data).toBe("string");
	}, 30_000);

	it("rejects a missing url/selector before touching the browser", async () => {
		const harness = await createBrowserHarness();

		await expect(harness.session.handleBrowserHostRequest("browser.navigate", {})).rejects.toThrow(
			"browser.navigate requires a non-empty url",
		);
		await expect(harness.session.handleBrowserHostRequest("browser.click", {})).rejects.toThrow(
			"browser.click requires a non-empty selector",
		);
	});

	it("rejects an unknown browser request type", async () => {
		const harness = await createBrowserHarness();

		await expect(harness.session.handleBrowserHostRequest("browser.teleport", {})).rejects.toThrow(
			'unknown browser request type "browser.teleport"',
		);
	});

	it("reuses the same lazily-launched browser across multiple host requests", async () => {
		const harness = await createBrowserHarness();

		await harness.session.handleBrowserHostRequest("browser.navigate", { url: testPage });
		await harness.session.handleBrowserHostRequest("browser.navigate", { url: testPage });
		const result = await harness.session.handleBrowserHostRequest("browser.extract_text", { selector: "#heading" });

		expect(result.text).toBe("initial");
	}, 30_000);
});
