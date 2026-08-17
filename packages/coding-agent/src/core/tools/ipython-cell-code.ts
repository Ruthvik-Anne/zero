const BASH_CELL_MAGIC_PATTERN = /^((?:[ \t]*\r?\n)*)([ \t]*)%%bash\b([^\r\n]*)(\r?\n|$)/;

export interface ParsedIpythonBashCell {
	leadingWhitespace: string;
	indent: string;
	magicArguments: string;
	lineBreak: string;
	body: string;
}

export function parseIpythonBashCell(code: string): ParsedIpythonBashCell | undefined {
	const match = BASH_CELL_MAGIC_PATTERN.exec(code);
	if (!match) {
		return undefined;
	}
	return {
		leadingWhitespace: match[1] ?? "",
		indent: match[2] ?? "",
		magicArguments: match[3] ?? "",
		lineBreak: match[4] ?? "",
		body: code.slice(match[0].length),
	};
}

// IPython's `ScriptMagics` extension auto-registers a cell magic per entry in its
// default `script_magics` list — not just the generic `%%script <interpreter>` form,
// but a dedicated magic per common interpreter (`%%sh`, `%%perl`, `%%ruby`,
// `%%python`/`%%python2`/`%%python3`, `%%pypy`/`%%pypy3`). Each hands its body
// straight to that interpreter, exactly like `%%script <name>` does — longest names
// first so e.g. `%%python3` doesn't get cut short by a `%%python` alternative match.
const SCRIPT_MAGIC_NAMES = "python3|python2|pypy3|pypy|python|sh|perl|ruby|script";

const SCRIPT_CELL_MAGIC_PATTERN = new RegExp(
	`^((?:[ \\t]*\\r?\\n)*)([ \\t]*)%%(${SCRIPT_MAGIC_NAMES})\\b([^\\r\\n]*)(\\r?\\n|$)`,
);

export interface ParsedIpythonScriptCell {
	leadingWhitespace: string;
	indent: string;
	/** The matched magic name, e.g. `"script"`, `"sh"`, `"python3"`. */
	magicName: string;
	magicArguments: string;
	lineBreak: string;
	body: string;
	/** The interpreter `body` is handed to: the magic name itself for `%%sh`/`%%perl`/`%%ruby`/`%%python[23]`/`%%pypy[3]`, or the first `%%script <interpreter>` argument for the generic form. */
	interpreter: string;
}

/** Strips a single layer of matching quotes IPython's `arg_split` would have consumed around the first `%%script` argument. */
function firstScriptArgument(magicArguments: string): string {
	const trimmed = magicArguments.trim();
	const quoted = /^"([^"]*)"|^'([^']*)'/.exec(trimmed);
	if (quoted) return quoted[1] ?? quoted[2] ?? "";
	return trimmed.split(/\s+/)[0] ?? "";
}

/** Same shape as `parseIpythonBashCell`, for every `ScriptMagics`-registered cell magic (`%%script <interpreter>`, `%%sh`, `%%perl`, `%%ruby`, `%%python[23]`, `%%pypy[3]`) — each hands its body to a real (non-Python-scanned-by-default) process. */
export function parseIpythonScriptCell(code: string): ParsedIpythonScriptCell | undefined {
	const match = SCRIPT_CELL_MAGIC_PATTERN.exec(code);
	if (!match) {
		return undefined;
	}
	const magicName = match[3] ?? "";
	const magicArguments = match[4] ?? "";
	return {
		leadingWhitespace: match[1] ?? "",
		indent: match[2] ?? "",
		magicName,
		magicArguments,
		lineBreak: match[5] ?? "",
		body: code.slice(match[0].length),
		interpreter: magicName === "script" ? firstScriptArgument(magicArguments) : magicName,
	};
}

const NESTED_SHELL_CELL_MAGIC_PATTERN = new RegExp(
	`^[ \\t]*%%(bash|${SCRIPT_MAGIC_NAMES})\\b([^\\r\\n]*)(?:\\r?\\n|$)`,
	"m",
);

export interface NestedShellMagicCell {
	kind: "bash" | "script";
	/** The matched magic name, e.g. `"bash"`, `"sh"`, `"python3"`. */
	magicName: string;
	interpreter: string;
	body: string;
}

/**
 * Finds a `%%bash`/`%%script`/`%%sh`/`%%perl`/`%%ruby`/`%%python[23]`/`%%pypy[3]` cell
 * magic anywhere in `code`, not just as the very first line — e.g. a `%%capture` line
 * wrapping a nested `%%bash` block, which `parseIpythonBashCell`'s start-anchored match
 * misses entirely. A cell magic consumes the rest of the cell, so `body` is everything
 * after the matched line.
 */
export function findNestedShellMagicCell(code: string): NestedShellMagicCell | undefined {
	const match = NESTED_SHELL_CELL_MAGIC_PATTERN.exec(code);
	if (!match) {
		return undefined;
	}
	const magicName = match[1] ?? "";
	const magicArguments = match[2] ?? "";
	const kind = magicName === "bash" ? "bash" : "script";
	return {
		kind,
		magicName,
		interpreter: magicName === "script" ? firstScriptArgument(magicArguments) : magicName,
		body: code.slice((match.index ?? 0) + match[0].length),
	};
}

const SHELL_ESCAPE_LINE_PATTERN = /^[ \t]*!(.*)$/;
const SYSTEM_LINE_MAGIC_PATTERN = /^[ \t]*%(?:system|sx)\b(.*)$/i;

/**
 * Extracts the shell command from every `!<command>` escape line and `%system`/`%sx`
 * line magic in `code` (IPython's documented aliases for `!`). Anchored to the start
 * of the line (after optional indentation) so `x != y` — invalid at line-start anyway
 * for a bare `!` — never false-positives.
 */
export function extractShellEscapeCommands(code: string): string[] {
	const commands: string[] = [];
	for (const line of code.split(/\r?\n/)) {
		const bang = SHELL_ESCAPE_LINE_PATTERN.exec(line);
		if (bang) {
			const command = (bang[1] ?? "").trim();
			if (command) commands.push(command);
			continue;
		}
		const systemMagic = SYSTEM_LINE_MAGIC_PATTERN.exec(line);
		if (systemMagic) {
			const command = (systemMagic[1] ?? "").trim();
			if (command) commands.push(command);
		}
	}
	return commands;
}
