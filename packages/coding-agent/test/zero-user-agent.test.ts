import { describe, expect, it } from "vitest";
import { getZeroUserAgent } from "../src/utils/zero-user-agent.js";

describe("getZeroUserAgent", () => {
	it("formats the Zero user agent", () => {
		const runtime = process.versions.bun ? `bun/${process.versions.bun}` : `node/${process.version}`;
		const userAgent = getZeroUserAgent("1.2.3");

		expect(userAgent).toBe(`zero/1.2.3 (${process.platform}; ${runtime}; ${process.arch})`);
		expect(userAgent).toMatch(/^zero\/[^\s()]+ \([^;()]+;\s*[^;()]+;\s*[^()]+\)$/);
	});
});
