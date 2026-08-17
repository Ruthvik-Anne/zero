import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createWorktree, listWorktrees, removeWorktree } from "../src/core/workspace/git-worktree.js";

function git(args: string[], cwd: string): string {
	const result = spawnSync("git", args, { cwd, encoding: "utf-8", windowsHide: true });
	if (result.status !== 0) {
		throw new Error(`Command failed: git ${args.join(" ")}\n${result.stderr}`);
	}
	return result.stdout.trim();
}

function initGitRepo(repoDir: string): void {
	git(["init", "--initial-branch=main"], repoDir);
	git(["config", "--local", "user.email", "test@test.com"], repoDir);
	git(["config", "--local", "user.name", "Test"], repoDir);
}

describe("git-worktree.ts (module B/K)", () => {
	let repoDir: string;

	beforeEach(() => {
		repoDir = join(tmpdir(), `zero-worktree-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(repoDir, { recursive: true });
		initGitRepo(repoDir);
		writeFileSync(join(repoDir, "tracked.txt"), "shared content\n");
		git(["add", "tracked.txt"], repoDir);
		git(["commit", "-m", "initial commit"], repoDir);
	});

	afterEach(() => {
		if (existsSync(repoDir)) rmSync(repoDir, { recursive: true, force: true });
	});

	it("fails closed (not throw) in a non-git directory", () => {
		const nonGitDir = join(tmpdir(), `zero-worktree-nongit-${Date.now()}`);
		mkdirSync(nonGitDir, { recursive: true });
		try {
			const result = createWorktree(nonGitDir, "child-1");
			expect(result.ok).toBe(false);
		} finally {
			rmSync(nonGitDir, { recursive: true, force: true });
		}
	});

	it("creates an isolated worktree that shares history but not the working tree", () => {
		const result = createWorktree(repoDir, "child-1");

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(existsSync(join(result.path, "tracked.txt"))).toBe(true);
		expect(result.branch).toBe("zero/worktree/child-1");

		// A change in the worktree does not appear in the base repo's working tree.
		writeFileSync(join(result.path, "tracked.txt"), "changed in worktree\n");
		expect(git(["show", "HEAD:tracked.txt"], repoDir)).toBe("shared content");
	});

	it("lists created worktrees under the .zero/worktrees convention", () => {
		const created = createWorktree(repoDir, "child-2");
		expect(created.ok).toBe(true);

		const worktrees = listWorktrees(repoDir);

		expect(worktrees.some((w) => w.id === "child-2")).toBe(true);
	});

	it("removes a worktree and its branch cleanly", () => {
		const created = createWorktree(repoDir, "child-3");
		expect(created.ok).toBe(true);
		if (!created.ok) return;

		const removed = removeWorktree(created);

		expect(removed.ok).toBe(true);
		expect(existsSync(created.path)).toBe(false);
		expect(listWorktrees(repoDir).some((w) => w.id === "child-3")).toBe(false);
	});

	it("supports two concurrent worktrees without conflict", () => {
		const a = createWorktree(repoDir, "concurrent-a");
		const b = createWorktree(repoDir, "concurrent-b");
		expect(a.ok).toBe(true);
		expect(b.ok).toBe(true);
		if (!a.ok || !b.ok) return;

		writeFileSync(join(a.path, "tracked.txt"), "from A\n");
		writeFileSync(join(b.path, "tracked.txt"), "from B\n");

		expect(git(["show", "HEAD:tracked.txt"], a.path)).toBe("shared content");
		expect(git(["show", "HEAD:tracked.txt"], b.path)).toBe("shared content");
	});

	// D6: teardown must never silently discard real work a worktree child produced.
	describe("teardown data-loss prevention (D6)", () => {
		it("still deletes the branch outright when nothing was ever committed (no regression)", () => {
			const created = createWorktree(repoDir, "child-nocommits");
			expect(created.ok).toBe(true);
			if (!created.ok) return;

			const removed = removeWorktree(created);

			expect(removed.ok).toBe(true);
			expect(removed.preservedBranchRef).toBeUndefined();
			expect(git(["branch", "--list", created.branch], repoDir)).toBe("");
		});

		it("archives (does not force-delete) a branch with commits beyond its base", () => {
			const created = createWorktree(repoDir, "child-withcommits");
			expect(created.ok).toBe(true);
			if (!created.ok) return;

			writeFileSync(join(created.path, "child-work.txt"), "important work\n");
			git(["add", "child-work.txt"], created.path);
			git(["-c", "commit.gpgsign=false", "commit", "--no-gpg-sign", "-m", "child commit"], created.path);
			const childCommitHash = git(["rev-parse", "HEAD"], created.path);

			const removed = removeWorktree(created);

			expect(removed.ok).toBe(true);
			expect(removed.preservedBranchRef).toBe(`refs/zero/worktree-archive/${created.id}`);
			// The branch pointer itself is gone, but the commit is still reachable
			// (and therefore not gc-able) through the archive ref.
			expect(git(["branch", "--list", created.branch], repoDir)).toBe("");
			expect(git(["log", "-1", "--format=%H", removed.preservedBranchRef!], repoDir)).toBe(childCommitHash);
			expect(git(["cat-file", "-t", childCommitHash], repoDir)).toBe("commit");
		});

		it("checkpoints uncommitted changes before removing a dirty worktree", () => {
			const created = createWorktree(repoDir, "child-dirty");
			expect(created.ok).toBe(true);
			if (!created.ok) return;

			writeFileSync(join(created.path, "tracked.txt"), "uncommitted change\n");

			const removed = removeWorktree(created);

			expect(removed.ok).toBe(true);
			expect(removed.preservedUncommittedCheckpointId).toBe(`worktree-teardown-${created.id}`);
			const ref = `refs/zero/checkpoints/${removed.preservedUncommittedCheckpointId}`;
			expect(git(["rev-parse", "--verify", ref], repoDir).length).toBeGreaterThan(0);
			// The checkpointed blob content is recoverable from the stash commit.
			const stashHash = git(["rev-parse", ref], repoDir);
			expect(git(["show", `${stashHash}:tracked.txt`], repoDir)).toBe("uncommitted change");
		});

		it("does not archive or checkpoint a clean worktree with no commits (both preserved-fields stay unset)", () => {
			const created = createWorktree(repoDir, "child-clean");
			expect(created.ok).toBe(true);
			if (!created.ok) return;

			const removed = removeWorktree(created);

			expect(removed.preservedBranchRef).toBeUndefined();
			expect(removed.preservedUncommittedCheckpointId).toBeUndefined();
		});
	});
});
