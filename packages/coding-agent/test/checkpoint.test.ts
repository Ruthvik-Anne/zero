import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	createCheckpoint,
	hasAnyCheckpoint,
	isGitRepo,
	listCheckpoints,
	rollbackCheckpoint,
} from "../src/core/checkpoint/checkpoint.js";

function git(args: string[], cwd: string, env?: Record<string, string>): string {
	const result = spawnSync("git", args, {
		cwd,
		encoding: "utf-8",
		env: env ? { ...process.env, ...env } : undefined,
		windowsHide: true,
	});
	if (result.status !== 0) {
		throw new Error(`Command failed: git ${args.join(" ")}\n${result.stderr}`);
	}
	return result.stdout.trim();
}

function initGitRepo(repoDir: string): void {
	git(["init", "--initial-branch=main"], repoDir);
	git(["config", "--local", "user.email", "test@test.com"], repoDir);
	git(["config", "--local", "user.name", "Test"], repoDir);
	// Disable line-ending translation so file content round-trips byte-for-byte
	// through checkpoint/rollback regardless of the host platform's git config.
	git(["config", "--local", "core.autocrlf", "false"], repoDir);
}

describe("checkpoint (module H)", () => {
	let repoDir: string;

	beforeEach(() => {
		repoDir = join(tmpdir(), `zero-checkpoint-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(repoDir, { recursive: true });
		initGitRepo(repoDir);
		writeFileSync(join(repoDir, "tracked.txt"), "original content\n");
		git(["add", "tracked.txt"], repoDir);
		git(["commit", "-m", "initial commit"], repoDir);
	});

	afterEach(() => {
		if (existsSync(repoDir)) rmSync(repoDir, { recursive: true, force: true });
	});

	it("reports no checkpoint coverage for a non-git directory", () => {
		const nonGitDir = join(tmpdir(), `zero-checkpoint-nongit-${Date.now()}`);
		mkdirSync(nonGitDir, { recursive: true });
		try {
			expect(isGitRepo(nonGitDir)).toBe(false);
			expect(hasAnyCheckpoint(nonGitDir)).toBe(false);
			const result = createCheckpoint(nonGitDir);
			expect(result.method).toBe("unavailable");
		} finally {
			rmSync(nonGitDir, { recursive: true, force: true });
		}
	});

	it("reports no checkpoints before any are created", () => {
		expect(hasAnyCheckpoint(repoDir)).toBe(false);
		expect(listCheckpoints(repoDir)).toEqual([]);
	});

	it("creates a checkpoint that captures an uncommitted modification", () => {
		writeFileSync(join(repoDir, "tracked.txt"), "modified content\n");

		const result = createCheckpoint(repoDir);

		expect(result.method).toBe("git-stash");
		expect(hasAnyCheckpoint(repoDir)).toBe(true);
		expect(listCheckpoints(repoDir)).toHaveLength(1);
		// git stash create does not touch the working tree — the modification is still there.
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("modified content\n");
	});

	it("rolls back a destructive change to the checkpointed content", () => {
		writeFileSync(join(repoDir, "tracked.txt"), "content before destructive edit\n");
		createCheckpoint(repoDir);

		// Simulate a destructive action after the checkpoint.
		writeFileSync(join(repoDir, "tracked.txt"), "DESTROYED\n");
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("DESTROYED\n");

		const rollback = rollbackCheckpoint(repoDir);

		expect(rollback.ok).toBe(true);
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("content before destructive edit\n");
	});

	it("rolls back to a specific checkpoint by id when multiple exist", () => {
		writeFileSync(join(repoDir, "tracked.txt"), "state A\n");
		createCheckpoint(repoDir, "checkpoint-a");

		writeFileSync(join(repoDir, "tracked.txt"), "state B\n");
		createCheckpoint(repoDir, "checkpoint-b");

		writeFileSync(join(repoDir, "tracked.txt"), "state C (destroyed)\n");

		const rollback = rollbackCheckpoint(repoDir, "checkpoint-a");

		expect(rollback.ok).toBe(true);
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("state A\n");
	});

	it("fails gracefully when rolling back an unknown checkpoint id", () => {
		const rollback = rollbackCheckpoint(repoDir, "does-not-exist");
		expect(rollback.ok).toBe(false);
		expect(rollback.error).toContain("does-not-exist");
	});

	// D9: a checkpoint's ordering must reflect when it was actually created, not
	// the git commit date of whatever it happens to point at — the clean-tree
	// branch points a checkpoint ref straight at HEAD, whose commit date can be
	// arbitrarily old.
	it("orders a clean-tree checkpoint by real creation time, not HEAD's old commit date", () => {
		// Rewrite the initial commit's own date to something clearly in the past —
		// old enough that git's second-resolution creatordate can never confuse it
		// with "just now", however fast this test happens to run.
		git(["commit", "--amend", "--no-edit", "--date=2000-01-01T00:00:00"], repoDir, {
			GIT_COMMITTER_DATE: "2000-01-01T00:00:00",
		});

		// Checkpoint 1: a real dirty-tree stash-create, authored "now" — its git
		// commit date is recent.
		writeFileSync(join(repoDir, "tracked.txt"), "modified content\n");
		createCheckpoint(repoDir, "cp-recent-dirty");

		// Clean the tree, then checkpoint again: this hits the clean-tree branch and
		// points straight at HEAD — whose commit date is the artificially old one
		// above — even though this checkpoint was, in real wall-clock terms, created
		// *after* cp-recent-dirty.
		writeFileSync(join(repoDir, "tracked.txt"), "original content\n");
		createCheckpoint(repoDir, "cp-recent-clean");

		const checkpoints = listCheckpoints(repoDir);
		expect(checkpoints.map((c) => c.id)).toEqual(["cp-recent-clean", "cp-recent-dirty"]);

		// A no-id rollback must restore the actually-most-recent checkpoint
		// (cp-recent-clean, which snapshots HEAD == "original content"), not
		// cp-recent-dirty just because its underlying commit date looks newer.
		writeFileSync(join(repoDir, "tracked.txt"), "DESTROYED\n");
		const rollback = rollbackCheckpoint(repoDir);
		expect(rollback.ok).toBe(true);
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("original content\n");
	});

	it("handles a clean tree (nothing to checkpoint) as a harmless no-op checkpoint", () => {
		const result = createCheckpoint(repoDir);
		expect(result.method).toBe("git-stash");
		expect(hasAnyCheckpoint(repoDir)).toBe(true);

		writeFileSync(join(repoDir, "tracked.txt"), "changed after clean checkpoint\n");
		const rollback = rollbackCheckpoint(repoDir);
		expect(rollback.ok).toBe(true);
		expect(readFileSync(join(repoDir, "tracked.txt"), "utf-8")).toBe("original content\n");
	});
});
