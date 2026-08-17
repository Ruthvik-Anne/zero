import { homedir } from "node:os";
import { isAbsolute, relative, resolve } from "node:path";
import {
	extractShellEscapeCommands,
	findNestedShellMagicCell,
	parseIpythonBashCell,
	parseIpythonScriptCell,
} from "../tools/ipython-cell-code.js";

/**
 * Native two-layer harm-check gate (module F).
 *
 * Layer 1 is a deterministic, always-run scan of the raw source about to execute
 * (an ipython cell — plain Python or a `%%bash` cell — or a `bash` tool command).
 * It never decides an outcome; it only produces candidate flags.
 *
 * Layer 2 turns those flags plus execution context (workspace containment, mode,
 * checkpoint availability) into one verdict. Hard-block is reserved for actions
 * that would harm the OS or the user outside the agent's legitimate workspace
 * scope; everything else flagged is a soft-block (ask the user), never a silent
 * refusal for in-scope, legitimate-but-risky work.
 */

export type HarmAction = "allow" | "soft_block" | "hard_block";
export type HarmScope = "workspace" | "outside_workspace" | "os_level";

export interface HarmVerdict {
	action: HarmAction;
	reason: string;
	/** Plain-language: what happens if this is allowed to proceed. */
	consequence: string;
	/** Whether a checkpoint is expected to cover undoing this (module H wires the real answer in). */
	reversible: boolean;
	scope: HarmScope;
	matchedPatterns: string[];
}

export type HarmCheckKind = "ipython" | "bash";

export interface HarmCheckContext {
	/** Workspace root; targets resolving outside this are never `allow`. */
	cwd: string;
	/** Module I mode. Hard-block ignores this; soft-block behavior downstream (confirm UI) can vary by mode. */
	mode?: "plan" | "auto" | "manual";
	/** Module H hook: does a checkpoint already cover this target? Defaults to "no" (false) until module H exists. */
	hasCheckpoint?: (targetPath: string | undefined) => boolean;
}

type FlagCategory =
	| "process-exec"
	| "filesystem-delete"
	| "filesystem-write"
	| "permissions"
	| "os-level"
	| "credential-exfiltration"
	| "network-pipe-to-shell";

interface Layer1Flag {
	category: FlagCategory;
	label: string;
	matchedText: string;
	/** Best-effort path literal extracted near the match, if any. */
	targetPath?: string;
}

interface PatternSpec {
	re: RegExp;
	category: FlagCategory;
	label: string;
}

// Verbs that make a `sudo`/`Administrator`-elevated command inherently OS-affecting
// regardless of any extractable path — elevation applies system-wide, not to a file.
// Requires an actual "sudo" elevation token somewhere before the dangerous verb; a
// bare `rm -rf <workspace path>` (no sudo) is NOT elevated and is scoped by its
// target path instead (see classifyScope). Deliberately NOT anchored to line start:
// `os.system("sudo shutdown -h now")` embeds the same threat inside a Python string
// argument rather than as a raw shell line, and must be caught the same way.
const OS_LEVEL_ELEVATED_VERBS =
	/\bsudo\b.*\b(dd\s+if=|mkfs|shutdown|reboot|init\s+0|passwd|useradd|userdel|iptables|ufw\s+(disable|--force)|systemctl\s+(disable|stop)\s+(firewalld|ufw)|visudo|bcdedit|takeown)\b/is;

// sudo/elevated invocations of these verbs are routine dev workflow, not OS-harmful.
const SUDO_SAFE_VERBS =
	/^\s*sudo\s+(apt(-get)?|yum|dnf|brew|snap|pip3?|npm|systemctl\s+(status|enable|start|restart)|service\s+\w+\s+(status|start|restart))\b/i;

const PY_PATTERNS: PatternSpec[] = [
	{ re: /\bos\.system\s*\(/, category: "process-exec", label: "os.system(...)" },
	{
		re: /\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(/,
		category: "process-exec",
		label: "subprocess.*(...)",
	},
	{ re: /\bos\.popen\s*\(/, category: "process-exec", label: "os.popen(...)" },
	{ re: /\bshutil\.rmtree\s*\(/, category: "filesystem-delete", label: "shutil.rmtree(...)" },
	{ re: /\bos\.(remove|unlink|rmdir)\s*\(/, category: "filesystem-delete", label: "os.remove/unlink/rmdir(...)" },
	{ re: /\.unlink\s*\(/, category: "filesystem-delete", label: "Path.unlink(...)" },
	{ re: /\bopen\s*\([^)]*,\s*["'](w|wb|a|ab|x)["']/, category: "filesystem-write", label: "open(..., 'w'/'a'/...)" },
	{ re: /\bos\.chmod\s*\([^)]*0o?7{2,3}/, category: "permissions", label: "os.chmod(..., 0o777)" },
	{ re: /\bos\.chown\s*\(/, category: "permissions", label: "os.chown(...)" },
	{ re: /\bwinreg\.(SetValue|DeleteKey|DeleteValue)/, category: "os-level", label: "winreg mutation" },
	// (D5) Forward-slash-only originally — a Windows path like r"C:\Users\x\.ssh\id_rsa"
	// never matches ".ssh/id_rsa", so the hard block for credential reads is
	// effectively absent on Windows. [/\\] accepts either separator.
	{
		re: /\bopen\s*\([^)]*\.(ssh[/\\]id_rsa|aws[/\\]credentials|env\b|netrc)[^)]*\)/,
		category: "credential-exfiltration",
		label: "read of known secret file",
	},
];

const BASH_PATTERNS: PatternSpec[] = [
	{ re: /\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b/i, category: "filesystem-delete", label: "rm -rf" },
	{ re: /^\s*sudo\b/im, category: "os-level", label: "sudo" },
	{ re: /\bchmod\s+(-R\s+)?0?7{2,3}\b/, category: "permissions", label: "chmod 777" },
	{ re: /\bchown\s+(-R\s+)?/, category: "permissions", label: "chown" },
	{ re: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, category: "os-level", label: "fork bomb" },
	{ re: /\b(shutdown|reboot|halt)\b/i, category: "os-level", label: "shutdown/reboot" },
	{ re: />\s*\/dev\/sd[a-z]\d*\b/, category: "filesystem-delete", label: "raw device write" },
	{ re: /\bmkfs(\.\w+)?\b/, category: "os-level", label: "mkfs" },
	{ re: /\bdd\s+if=/, category: "os-level", label: "dd if=..." },
	{
		re: /\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b/i,
		category: "network-pipe-to-shell",
		label: "curl|sh pipe",
	},
	{ re: /\bdel\s+\/[fsq]{1,3}\b/i, category: "filesystem-delete", label: "del /f /s /q" },
	{
		re: /Remove-Item\s+.*-Recurse.*-Force|Remove-Item\s+.*-Force.*-Recurse/i,
		category: "filesystem-delete",
		label: "Remove-Item -Recurse -Force",
	},
	{ re: /\bformat\s+[a-zA-Z]:/i, category: "os-level", label: "format <drive>:" },
	{ re: /\bdiskpart\b/i, category: "os-level", label: "diskpart" },
	{ re: /\breg\s+(add|delete)\b/i, category: "os-level", label: "reg add/delete" },
	{ re: /\bnetsh\s+advfirewall\b.*\bdisable\b/i, category: "os-level", label: "disable firewall" },
	{ re: /\btaskkill\s+\/F\b/i, category: "os-level", label: "taskkill /F" },
	{ re: /\bnet\s+user\b.*\/(add|delete)\b/i, category: "os-level", label: "net user /add or /delete" },
	{ re: /\bicacls\b.*\/(grant|deny)\b.*\bEveryone\b/i, category: "permissions", label: "icacls grant Everyone" },
];

const QUOTED_PATH_RE = /["']((?:[A-Za-z]:)?[/\\][^"']{1,300})["']/;
// (D3) A model actually emits unquoted paths (`rm -rf /etc`, `rm -rf ~/Documents`,
// `rm -rf ../../other-project`) far more often than quoted ones — the original
// quoted-only regex meant classifyScope could never see a targetPath for any of
// them, so the outside-workspace hard block was unreachable in practice. Requires
// at least 2 characters after the leading marker so a bare 1-letter Windows flag
// (`/f`, `/s`, `/q`) is never mistaken for a path target.
const UNQUOTED_PATH_RE = /(?:^|\s)((?:~[/\\]|\.\.?[/\\]|(?:[A-Za-z]:)?[/\\])[^\s"'|&;<>]{2,300})/;

function extractPathNear(source: string, matchIndex: number): string | undefined {
	// (D3) Search forward from the match first — a shell command's target follows
	// its verb, and forward-only avoids grabbing an unrelated earlier quoted string
	// that happened to fall inside the old bidirectional window.
	const forward = source.slice(matchIndex, Math.min(source.length, matchIndex + 300));
	const quotedForward = QUOTED_PATH_RE.exec(forward);
	const unquotedForward = UNQUOTED_PATH_RE.exec(forward);
	if (quotedForward && (!unquotedForward || quotedForward.index <= unquotedForward.index)) {
		return quotedForward[1];
	}
	if (unquotedForward) return unquotedForward[1];
	// Fall back to a preceding window for a path literal written just before the verb.
	const backward = source.slice(Math.max(0, matchIndex - 200), matchIndex);
	return QUOTED_PATH_RE.exec(backward)?.[1];
}

/** (D3) `~`/`~/...` never resolves to anything meaningful without expansion —
 * `resolve(cwd, "~/Documents")` would treat "~" as a literal subdirectory name
 * inside the workspace instead of the user's home directory. */
function expandHome(targetPath: string): string {
	if (targetPath === "~") return homedir();
	if (targetPath.startsWith("~/") || targetPath.startsWith("~\\")) {
		return resolve(homedir(), targetPath.slice(2));
	}
	return targetPath;
}

interface ScanUnit {
	source: string;
	isBash: boolean;
}

const PYTHON_LIKE_SCRIPT_INTERPRETERS = new Set(["python", "python3", "python2", "pypy", "pypy3"]);

/**
 * (finding #1) `%%script <interpreter>` hands `body` to whatever process `interpreter`
 * names, same as `%%bash` does for a real shell — only a clearly-Python interpreter is
 * scanned with PY_PATTERNS; every shell-like or unrecognized/ambiguous interpreter
 * (bash, sh, zsh, ruby, node, a bare path, ...) is scanned with the broader BASH_PATTERNS
 * denylist, erring conservative rather than risking a silent bypass via an interpreter
 * name we don't recognize.
 */
function isPythonLikeScriptInterpreter(rawInterpreter: string): boolean {
	const trimmed = rawInterpreter.trim().replace(/^["']|["']$/g, "");
	const base = (trimmed.split(/[\\/]/).pop() ?? trimmed).replace(/\.exe$/i, "").toLowerCase();
	return PYTHON_LIKE_SCRIPT_INTERPRETERS.has(base);
}

/**
 * (D1, finding #1) An ipython `%%bash`/`%%script` cell hands its entire body to a real
 * shell/process, not Python — scanning it with PY_PATTERNS means none of the
 * bash-specific denylist entries (rm -rf, sudo, chmod 777, curl|sh, ...) ever run
 * against it. Reuses the exact parser production already uses to recognize/rewrite
 * `%%bash` cells (ipython.ts's applyShellSettingsToBashMagicCell), so detection can't
 * drift out of sync with it.
 *
 * A leading `%%bash`/`%%script` cell magic consumes the WHOLE cell, so only its body
 * is returned as the single scan unit (matching prior behavior for `%%bash`). Anything
 * else — plain Python, possibly containing shell-escape lines (`!cmd`, `%system`/`%sx`)
 * or a nested `%%bash`/`%%script` wrapped in e.g. `%%capture` — is returned as the full
 * source (scanned as Python) PLUS one additional bash-scanned unit per shell-escaped
 * fragment found anywhere in it, so neither the surrounding Python nor the shelled-out
 * command goes unscanned.
 */
function resolveScanUnits(source: string, kind: HarmCheckKind): ScanUnit[] {
	if (kind === "bash") return [{ source, isBash: true }];

	const bashCell = parseIpythonBashCell(source);
	if (bashCell) return [{ source: bashCell.body, isBash: true }];

	const scriptCell = parseIpythonScriptCell(source);
	if (scriptCell) return [{ source: scriptCell.body, isBash: !isPythonLikeScriptInterpreter(scriptCell.interpreter) }];

	const units: ScanUnit[] = [{ source, isBash: false }];
	for (const command of extractShellEscapeCommands(source)) {
		units.push({ source: command, isBash: true });
	}
	const nested = findNestedShellMagicCell(source);
	if (nested) {
		const nestedIsBash = nested.kind === "bash" || !isPythonLikeScriptInterpreter(nested.interpreter);
		units.push({ source: nested.body, isBash: nestedIsBash });
	}
	return units;
}

/**
 * (D2) `SUDO_SAFE_VERBS` is anchored to the start of a single command, but must be
 * checked per sudo invocation — testing it against the whole (possibly multi-line,
 * possibly `&&`/`;`/`|`-chained) source lets one leading safe `sudo apt-get update`
 * disarm detection for every other, unrelated `sudo` invocation in the same cell,
 * including ones chained onto the very same line.
 */
function hasUnsafeSudoLine(source: string): boolean {
	const segments = source.split(/\r?\n|&&|\|\||[;|]/).map((segment) => segment.trim());
	const sudoSegments = segments.filter((segment) => /^sudo\b/i.test(segment));
	return sudoSegments.some((segment) => !SUDO_SAFE_VERBS.test(segment));
}

/**
 * (finding #2) A pattern can match more than once in one command/cell — e.g.
 * `rm -rf ./build && rm -rf /etc` — and `RegExp.exec` without a global flag only ever
 * returns the first. Runs the pattern globally instead so every occurrence gets its
 * own flag (and its own `extractPathNear` computed relative to THAT occurrence),
 * rather than a decoy earlier match silently absorbing the only flag raised.
 */
function allMatches(re: RegExp, source: string): RegExpExecArray[] {
	const globalRe = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
	const matches: RegExpExecArray[] = [];
	for (let match = globalRe.exec(source); match !== null; match = globalRe.exec(source)) {
		matches.push(match);
		if (match[0].length === 0) {
			globalRe.lastIndex += 1;
		}
	}
	return matches;
}

export function scanLayer1(source: string, kind: HarmCheckKind): Layer1Flag[] {
	const flags: Layer1Flag[] = [];
	for (const { source: scanSource, isBash } of resolveScanUnits(source, kind)) {
		const patterns = isBash ? BASH_PATTERNS : PY_PATTERNS;
		const unsafeSudo = isBash && hasUnsafeSudoLine(scanSource);
		for (const spec of patterns) {
			if (spec.label === "sudo" && !unsafeSudo) {
				// Routine package-manager/service invocations under sudo are not OS-harmful by default.
				continue;
			}
			for (const match of allMatches(spec.re, scanSource)) {
				flags.push({
					category: spec.category,
					label: spec.label,
					matchedText: match[0],
					targetPath: extractPathNear(scanSource, match.index ?? 0),
				});
			}
		}
	}
	return flags;
}

function resolvesOutsideWorkspace(targetPath: string, cwd: string): boolean {
	const expanded = expandHome(targetPath);
	const abs = isAbsolute(expanded) ? expanded : resolve(cwd, expanded);
	const rel = relative(cwd, abs);
	return rel.startsWith("..") || isAbsolute(rel);
}

function classifyScope(flags: Layer1Flag[], source: string, ctx: HarmCheckContext): HarmScope {
	if (flags.some((f) => f.category === "os-level" || f.category === "credential-exfiltration")) {
		return "os_level";
	}
	if (OS_LEVEL_ELEVATED_VERBS.test(source)) {
		return "os_level";
	}
	const outsideTargets = flags.filter((f) => f.targetPath && resolvesOutsideWorkspace(f.targetPath, ctx.cwd));
	if (outsideTargets.length > 0) {
		return "outside_workspace";
	}
	return "workspace";
}

function describeConsequence(flags: Layer1Flag[], scope: HarmScope): string {
	const labels = [...new Set(flags.map((f) => f.label))].join(", ");
	if (scope === "os_level") {
		return `This action (${labels}) affects the operating system or user environment outside the workspace and cannot be safely undone.`;
	}
	if (scope === "outside_workspace") {
		return `This action (${labels}) targets a path outside the current workspace root.`;
	}
	return `This action (${labels}) will modify or delete files inside the current workspace.`;
}

export function adjudicateLayer2(flags: Layer1Flag[], source: string, ctx: HarmCheckContext): HarmVerdict {
	if (flags.length === 0) {
		return {
			action: "allow",
			reason: "no risk patterns matched",
			consequence: "",
			reversible: true,
			scope: "workspace",
			matchedPatterns: [],
		};
	}
	const scope = classifyScope(flags, source, ctx);
	// (finding #2) Dedupe — a single pattern can now raise multiple flags (one per
	// occurrence), and a duplicated label here leaks into both the user-facing `reason`
	// and the guardrail-precedent record built from `matchedPatterns`.
	const matchedPatterns = [...new Set(flags.map((f) => f.label))];
	const consequence = describeConsequence(flags, scope);
	// (finding #2) "Reversible" must hold for EVERY flagged target, not just the first
	// one found — a soft-block covering two in-workspace targets where only one is
	// checkpoint-covered is not honestly reversible.
	const flagsWithTargets = flags.filter((f) => f.targetPath);
	const reversible =
		flagsWithTargets.length > 0 ? flagsWithTargets.every((f) => ctx.hasCheckpoint?.(f.targetPath) ?? false) : false;

	// Hard-block: OS/user-affecting scope, or a destructive/write op whose target
	// resolves outside the workspace root. Non-negotiable, applies in every mode.
	const destructiveOutsideWorkspace =
		scope === "outside_workspace" &&
		flags.some(
			(f) =>
				f.category === "filesystem-delete" || f.category === "filesystem-write" || f.category === "process-exec",
		);
	if (scope === "os_level" || destructiveOutsideWorkspace) {
		return {
			action: "hard_block",
			reason: `Refused: ${matchedPatterns.join(", ")} affects the OS or user outside the agent's legitimate scope.`,
			consequence,
			reversible: false,
			scope,
			matchedPatterns,
		};
	}

	// Everything else flagged is workspace-contained or otherwise legitimate-but-risky:
	// ask the user rather than refuse.
	return {
		action: "soft_block",
		reason: `Confirmation required: ${matchedPatterns.join(", ")}.`,
		consequence,
		reversible,
		scope,
		matchedPatterns,
	};
}

/** Run both layers. Layer 2 currently rule-based; module G wiring for model-assisted
 * adjudication on ambiguous cases lands when the provider router (module G) exists. */
export function checkHarm(source: string, kind: HarmCheckKind, ctx: HarmCheckContext): HarmVerdict {
	const flags = scanLayer1(source, kind);
	return adjudicateLayer2(flags, source, ctx);
}
