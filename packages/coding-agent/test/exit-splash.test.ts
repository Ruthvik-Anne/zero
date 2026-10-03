import { describe, expect, test } from "vitest";
import { APP_NAME, VERSION } from "../src/config.js";
import { EXIT_SPLASH_CAPTION, formatExitSplash } from "../src/modes/interactive/exit-splash.js";
import { ZERO_LOGO } from "../src/themes/zero-logo.js";

const stripAnsi = (text: string) => text.replace(/\x1b\[[0-9;]*m/g, "");

describe("formatExitSplash", () => {
	test("renders the logo with name, version and author caption", () => {
		const output = stripAnsi(formatExitSplash(undefined));
		for (const logoLine of ZERO_LOGO.split("\n")) {
			expect(output).toContain(logoLine.trimEnd());
		}
		expect(output).toContain(APP_NAME);
		expect(output).toContain(`v${VERSION}`);
		expect(output).toContain(EXIT_SPLASH_CAPTION);
		expect(EXIT_SPLASH_CAPTION).toBe("by Ruthvik Anne");
	});

	test("appends the resume hint below the splash", () => {
		const hint = "Resume this session with: zero --resume abc";
		const output = stripAnsi(formatExitSplash(hint));
		expect(output.trimEnd().endsWith(hint)).toBe(true);
	});

	test("omits the resume hint when there is none", () => {
		const output = stripAnsi(formatExitSplash(undefined));
		expect(output).not.toContain("Resume this session");
	});
});
