import chalk from "chalk";
import { APP_NAME, VERSION } from "../../config.js";
import { ZERO_LOGO } from "../../themes/zero-logo.js";

export const EXIT_SPLASH_CAPTION = "by Ruthvik Anne";

const LOGO_GUTTER = 4;

/**
 * Splash printed to stdout after the interactive TUI exits: the Zero mark with
 * the app name, version and author caption beside it, followed by an optional
 * resume hint.
 */
export function formatExitSplash(resumeHint: string | undefined): string {
	const logoLines = ZERO_LOGO.split("\n");
	const logoWidth = Math.max(...logoLines.map((line) => line.length));
	const meta = [chalk.bold(APP_NAME), chalk.dim(`v${VERSION}`), chalk.dim(EXIT_SPLASH_CAPTION)];
	const metaStart = Math.floor((logoLines.length - meta.length) / 2);

	const lines = logoLines.map((line, index) => {
		const metaIndex = index - metaStart;
		if (metaIndex < 0 || metaIndex >= meta.length) return line;
		return `${line.padEnd(logoWidth + LOGO_GUTTER)}${meta[metaIndex]}`;
	});
	if (resumeHint) lines.push("", resumeHint);

	return ["", ...lines, ""].join("\n");
}
