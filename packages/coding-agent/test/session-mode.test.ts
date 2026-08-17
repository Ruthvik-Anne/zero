import { describe, expect, it } from "vitest";
import {
	DEFAULT_SESSION_MODE,
	isPersistedSessionMode,
	isPlanModeSafe,
	isSessionMode,
	parseModeSlashCommand,
} from "../src/core/mode/session-mode.js";

describe("session-mode (module I)", () => {
	describe("isSessionMode / isPersistedSessionMode", () => {
		it("accepts the three valid modes", () => {
			expect(isSessionMode("plan")).toBe(true);
			expect(isSessionMode("auto")).toBe(true);
			expect(isSessionMode("manual")).toBe(true);
		});

		it("rejects anything else", () => {
			expect(isSessionMode("yolo")).toBe(false);
			expect(isSessionMode(undefined)).toBe(false);
		});

		it("validates a persisted custom entry shape", () => {
			expect(isPersistedSessionMode({ mode: "plan" })).toBe(true);
			expect(isPersistedSessionMode({ mode: "nope" })).toBe(false);
			expect(isPersistedSessionMode(null)).toBe(false);
		});

		it("defaults to auto", () => {
			expect(DEFAULT_SESSION_MODE).toBe("auto");
		});
	});

	describe("isPlanModeSafe", () => {
		it("allows read-only exploration", () => {
			expect(isPlanModeSafe("git status", "bash")).toBe(true);
			expect(isPlanModeSafe("git diff", "bash")).toBe(true);
			expect(isPlanModeSafe("ls -la", "bash")).toBe(true);
			expect(isPlanModeSafe("print(open('a.txt').read())", "ipython")).toBe(true);
		});

		it("blocks anything module F's Layer 1 would flag", () => {
			expect(isPlanModeSafe("os.system('ls')", "ipython")).toBe(false);
			expect(isPlanModeSafe("rm -rf /tmp/foo", "bash")).toBe(false);
		});

		// D1: isPlanModeSafe calls scanLayer1 directly, so a %%bash cell must be
		// recognized as bash content here too, not just inside checkHarm.
		it("blocks a destructive command hidden inside an ipython %%bash cell", () => {
			expect(isPlanModeSafe("%%bash\nrm -rf ~/Documents", "ipython")).toBe(false);
		});

		it("blocks benign-but-mutating operations Layer 1 doesn't bother flagging", () => {
			expect(isPlanModeSafe("git commit -am 'wip'", "bash")).toBe(false);
			expect(isPlanModeSafe("git push", "bash")).toBe(false);
			expect(isPlanModeSafe("npm install left-pad", "bash")).toBe(false);
			expect(isPlanModeSafe("mkdir new-dir", "bash")).toBe(false);
			expect(isPlanModeSafe("touch new-file.txt", "bash")).toBe(false);
		});

		// D13: a bare `>` inside a quoted string is not a real shell redirection —
		// blocking it made ordinary read-only work like `grep "a > b"` unusable in
		// plan mode, while genuinely missing verbs (rm, sed -i, python -c, node -e,
		// git worktree add) passed through unblocked.
		it("does not mistake a quoted > for a shell redirection", () => {
			expect(isPlanModeSafe('grep "a > b" file.txt', "bash")).toBe(true);
			expect(isPlanModeSafe("echo 'x > y'", "bash")).toBe(true);
		});

		it("still blocks a real unquoted redirection", () => {
			expect(isPlanModeSafe("echo hi > out.txt", "bash")).toBe(false);
			expect(isPlanModeSafe("echo hi >> out.txt", "bash")).toBe(false);
		});

		it("blocks the verbs the denylist was previously missing", () => {
			expect(isPlanModeSafe("rm notes.txt", "bash")).toBe(false);
			expect(isPlanModeSafe("sed -i 's/a/b/' file.txt", "bash")).toBe(false);
			expect(isPlanModeSafe("python -c \"import os; os.remove('x')\"", "bash")).toBe(false);
			expect(isPlanModeSafe("node -e \"require('fs').unlinkSync('x')\"", "bash")).toBe(false);
			expect(isPlanModeSafe("git worktree add ../scratch", "bash")).toBe(false);
		});
	});

	describe("parseModeSlashCommand", () => {
		it("parses an empty command as 'show'", () => {
			expect(parseModeSlashCommand("")).toEqual({ kind: "show" });
			expect(parseModeSlashCommand("   ")).toEqual({ kind: "show" });
		});

		it("parses a valid mode name as 'set'", () => {
			expect(parseModeSlashCommand("plan")).toEqual({ kind: "set", mode: "plan" });
			expect(parseModeSlashCommand(" Manual ")).toEqual({ kind: "set", mode: "manual" });
		});

		it("returns undefined for an invalid mode name", () => {
			expect(parseModeSlashCommand("yolo")).toBeUndefined();
		});
	});
});
