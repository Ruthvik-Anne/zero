import { afterEach, describe, expect, it } from "vitest";
import { BrowserSession, validateBrowserUrl } from "../src/core/browser/browser-session.js";

/**
 * module J: native browser automation, exercised against a real headless
 * Chromium instance (Playwright, launched locally — no network dependency,
 * every page here is a self-contained data: URL).
 */
describe("BrowserSession (module J)", () => {
	const sessions: BrowserSession[] = [];

	function createSession(): BrowserSession {
		const session = new BrowserSession();
		sessions.push(session);
		return session;
	}

	afterEach(async () => {
		while (sessions.length > 0) {
			await sessions.pop()?.close();
		}
	});

	const testPage = `data:text/html,${encodeURIComponent(`
		<html>
			<head><title>Test Page</title></head>
			<body>
				<h1 id="heading">Hello from the test page</h1>
				<input id="name-input" type="text" />
				<button id="submit-button" onclick="document.getElementById('heading').innerText = 'Clicked!'">Submit</button>
			</body>
		</html>
	`)}`;

	it("navigates to a page and reports its url and title", async () => {
		const session = createSession();

		const result = await session.navigate(testPage);

		expect(result.title).toBe("Test Page");
		expect(result.url).toContain("data:text/html");
		expect(session.isOpen).toBe(true);
	}, 30_000);

	it("extracts visible text from the whole page or one element", async () => {
		const session = createSession();
		await session.navigate(testPage);

		const whole = await session.extractText();
		expect(whole.text).toContain("Hello from the test page");

		const heading = await session.extractText("#heading");
		expect(heading.text).toBe("Hello from the test page");
	}, 30_000);

	it("types into an input field", async () => {
		const session = createSession();
		await session.navigate(testPage);

		await session.type("#name-input", "Zero");

		expect((await session.getInputValue("#name-input")).value).toBe("Zero");
	}, 30_000);

	it("clicks an element and observes the resulting DOM change", async () => {
		const session = createSession();
		await session.navigate(testPage);
		expect((await session.extractText("#heading")).text).toBe("Hello from the test page");

		await session.click("#submit-button");

		expect((await session.extractText("#heading")).text).toBe("Clicked!");
	}, 30_000);

	it("takes a PNG screenshot", async () => {
		const session = createSession();
		await session.navigate(testPage);

		const shot = await session.screenshot();

		expect(shot.mimeType).toBe("image/png");
		expect(shot.data.length).toBeGreaterThan(100);
		// PNG magic bytes, base64-decoded: 89 50 4E 47 -> base64 starts "iVBOR".
		expect(shot.data.startsWith("iVBOR")).toBe(true);
	}, 30_000);

	it("reuses the same page across calls until close()", async () => {
		const session = createSession();
		await session.navigate(testPage);
		await session.click("#submit-button");

		// A second navigate() reuses the already-launched browser/page.
		await session.navigate(testPage);
		expect((await session.extractText("#heading")).text).toBe("Hello from the test page");
	}, 30_000);

	it("close() is safe to call twice and leaves isOpen false", async () => {
		const session = createSession();
		await session.navigate(testPage);

		await session.close();
		await session.close();

		expect(session.isOpen).toBe(false);
	}, 30_000);

	// D11: browser.navigate had no validation at all — any scheme, any host.
	describe("validateBrowserUrl (D11)", () => {
		it("allows http/https/data URLs", () => {
			expect(() => validateBrowserUrl("https://example.com")).not.toThrow();
			expect(() => validateBrowserUrl("http://example.com")).not.toThrow();
			expect(() => validateBrowserUrl("data:text/html,<h1>hi</h1>")).not.toThrow();
		});

		it("refuses file: — the credential-exfiltration repro from the finding", () => {
			expect(() => validateBrowserUrl("file:///C:/Users/x/.aws/credentials")).toThrow(/refused scheme/);
		});

		it("refuses javascript: and other non-navigational schemes", () => {
			expect(() => validateBrowserUrl("javascript:alert(1)")).toThrow(/refused scheme/);
		});

		it("refuses the cloud instance metadata address", () => {
			expect(() => validateBrowserUrl("http://169.254.169.254/latest/meta-data/")).toThrow(/link-local|metadata/);
		});

		it("refuses the wider link-local range, not just the one well-known IP", () => {
			expect(() => validateBrowserUrl("http://169.254.1.1/")).toThrow(/link-local|metadata/);
		});

		it("refuses an IPv6 link-local host", () => {
			expect(() => validateBrowserUrl("http://[fe80::1]/")).toThrow(/link-local|metadata/);
		});

		it("does not refuse ordinary private/loopback hosts", () => {
			// Deliberately permissive: a coding agent browse-testing the user's own
			// local dev server is a real, legitimate use case (see the comment on
			// validateBrowserUrl for the reasoning).
			expect(() => validateBrowserUrl("http://localhost:3000")).not.toThrow();
			expect(() => validateBrowserUrl("http://192.168.1.1")).not.toThrow();
		});

		it("propagates from navigate() itself, before any page is launched", async () => {
			const session = createSession();
			await expect(session.navigate("file:///etc/passwd")).rejects.toThrow(/refused scheme/);
			expect(session.isOpen).toBe(false);
		});
	});
});
