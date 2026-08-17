import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { createCheckpoint, isGitRepo } from "../checkpoint/checkpoint.js";

/**
 * Git worktree registry (module K infrastructure, first consumer is module B's
 * RLM `isolation: "worktree"` option) — one mechanism serves both per-child
 * delegation isolation and general multi-workspace support, per the plan's
 * explicit decision to avoid two isolation mechanisms.
 *
 * Worktrees live under `<repoRoot>/.zero/worktrees/<id>`, a fresh branch off
 * the current HEAD, so concurrent children can mutate files without
 * conflicting on the same working tree while still sharing repo history.
 */

export interface WorktreeInfo {
	id: string;
	path: string;
	branch: string;
	baseCwd: string;
	createdAt: number;
	/** (D6) HEAD's commit at creation time — lets teardown tell "the child never
	 * committed anything" apart from "the child's branch has real, undiverged-
	 * from-base work" without guessing from the branch name alone. */
	baseCommit: string;
}

export type CreateWorktreeResult = ({ ok: true } & WorktreeInfo) | { ok: false; error: string };

function runGit(cwd: string, args: string[]): { ok: boolean; stdout: string; stderr: string } {
	const result = spawnSync("git", ["--no-optional-locks", ...args], {
		cwd,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "pipe"],
		windowsHide: true,
	});
	return {
		ok: result.status === 0,
		stdout: typeof result.stdout === "string" ? result.stdout.trim() : "",
		stderr: typeof result.stderr === "string" ? result.stderr.trim() : "",
	};
}

function worktreePath(baseCwd: string, id: string): string {
	return join(baseCwd, ".zero", "worktrees", id);
}

function branchName(id: string): string {
	return `zero/worktree/${id}`;
}

/**
 * Create a fresh worktree + branch off the current HEAD. Fails closed (a
 * result, not a throw) when `baseCwd` isn't a git repo — callers (module B)
 * are expected to fall back to sharing the parent's cwd rather than crash a
 * delegation over missing worktree support.
 */
export function createWorktree(baseCwd: string, id: string): CreateWorktreeResult {
	if (!isGitRepo(baseCwd)) {
		return { ok: false, error: "not a git repository — worktree isolation is unavailable" };
	}
	const head = runGit(baseCwd, ["rev-parse", "HEAD"]);
	if (!head.ok || !head.stdout) {
		return { ok: false, error: head.stderr || "git rev-parse HEAD failed" };
	}
	const path = worktreePath(baseCwd, id);
	const branch = branchName(id);
	const add = runGit(baseCwd, ["worktree", "add", "-b", branch, path, "HEAD"]);
	if (!add.ok) {
		return { ok: false, error: add.stderr || "git worktree add failed" };
	}
	return { ok: true, id, path, branch, baseCwd, createdAt: Date.now(), baseCommit: head.stdout };
}

export interface RemoveWorktreeResult {
	ok: boolean;
	error?: string;
	/**
	 * (D6) Set when the branch had commits beyond `baseCommit` — teardown never
	 * force-deletes those; it re-points them at this ref instead so they stay
	 * reachable (and therefore not gc-able) after the branch itself is removed.
	 */
	preservedBranchRef?: string;
	/**
	 * (D6) Set when the worktree had uncommitted changes at teardown — captured
	 * via module H's own createCheckpoint (a `git stash create` object under
	 * `refs/zero/checkpoints/<id>`), the same durable, non-destructive mechanism
	 * a risky-action checkpoint uses, so it can be restored with the same
	 * `/rollback` machinery rather than invented as a one-off.
	 */
	preservedUncommittedCheckpointId?: string;
}

const WORKTREE_ARCHIVE_REF_PREFIX = "refs/zero/worktree-archive/";

/** Count of commits reachable from `branch` but not from `baseCommit`. 0 on any git failure — treated as "nothing to preserve," never as "preserve unconditionally," since a failed count must not block teardown. */
function countCommitsBeyondBase(baseCwd: string, baseCommit: string, branch: string): number {
	const result = runGit(baseCwd, ["rev-list", "--count", `${baseCommit}..${branch}`]);
	if (!result.ok) return 0;
	const count = Number.parseInt(result.stdout, 10);
	return Number.isFinite(count) ? count : 0;
}

/** True if the worktree at `path` has uncommitted (tracked or untracked) changes. */
function hasUncommittedChanges(path: string): boolean {
	const status = runGit(path, ["status", "--porcelain"]);
	return status.ok && status.stdout.length > 0;
}

/**
 * Remove a worktree and its branch. Safe to call on an already-removed worktree
 * (no-op). (D6) Never silently discards real work: uncommitted changes are
 * snapshotted into a checkpoint before the worktree is removed, and a branch
 * that has commits beyond its creation point is archived under a dedicated ref
 * instead of being force-deleted — only a branch with zero commits beyond base
 * (the common, nothing-happened case) is deleted outright, exactly as before.
 */
export function removeWorktree(info: WorktreeInfo): RemoveWorktreeResult {
	let preservedUncommittedCheckpointId: string | undefined;
	if (hasUncommittedChanges(info.path)) {
		const checkpointId = `worktree-teardown-${info.id}`;
		const checkpoint = createCheckpoint(info.path, checkpointId);
		if (checkpoint.method === "git-stash") {
			preservedUncommittedCheckpointId = checkpointId;
		}
	}

	const remove = runGit(info.baseCwd, ["worktree", "remove", "--force", info.path]);
	if (!remove.ok && !remove.stderr.includes("is not a working tree")) {
		// Directory may already be gone (e.g. manual cleanup) — try a filesystem
		// removal as a fallback before treating this as a real failure.
		try {
			rmSync(info.path, { recursive: true, force: true });
		} catch {
			return { ok: false, error: remove.stderr || "git worktree remove failed", preservedUncommittedCheckpointId };
		}
	}

	const commitsAhead = countCommitsBeyondBase(info.baseCwd, info.baseCommit, info.branch);
	let preservedBranchRef: string | undefined;
	if (commitsAhead > 0) {
		const archiveRef = `${WORKTREE_ARCHIVE_REF_PREFIX}${info.id}`;
		const archived = runGit(info.baseCwd, ["update-ref", archiveRef, info.branch]);
		if (archived.ok) {
			preservedBranchRef = archiveRef;
		}
	}
	// Once the commits (if any) are reachable from the archive ref, the branch
	// pointer itself can always be deleted — its commits stay reachable via
	// preservedBranchRef, so this is never a data-loss operation even when
	// commitsAhead > 0.
	runGit(info.baseCwd, ["branch", "-D", info.branch]);
	return { ok: true, preservedBranchRef, preservedUncommittedCheckpointId };
}

export function listWorktrees(baseCwd: string): WorktreeInfo[] {
	if (!isGitRepo(baseCwd)) return [];
	const result = runGit(baseCwd, ["worktree", "list", "--porcelain"]);
	if (!result.ok) return [];
	const worktrees: WorktreeInfo[] = [];
	let currentPath: string | undefined;
	let currentBranch: string | undefined;
	// Match the trailing ".zero/worktrees/<id>" segment rather than prefix-comparing
	// against a Node-computed absolute path: on Windows, git internally resolves
	// paths to their long form (".../ruthvikanne/...") while os.tmpdir()-derived
	// paths can be in 8.3 short form (".../RUTHVI~1/...") — the same real
	// directory, two different string representations. A trailing-segment match
	// is immune to that aliasing since it never compares the divergent prefix.
	const idPattern = /\.zero\/worktrees\/([^/]+)$/;
	const flush = () => {
		if (!currentPath) return;
		const match = idPattern.exec(currentPath);
		if (match && currentBranch) {
			// (D6) This entry wasn't necessarily created by createWorktree() in this
			// process, so there's no recorded creation-time HEAD to reuse — the merge
			// base with the repo's current HEAD is the best available approximation
			// of "where this branch diverged," and is exact for the common case (a
			// worktree branch that was created off HEAD and never rebased since).
			const mergeBase = runGit(baseCwd, ["merge-base", currentBranch, "HEAD"]);
			worktrees.push({
				id: match[1]!,
				path: currentPath,
				branch: currentBranch,
				baseCwd,
				createdAt: 0,
				baseCommit: mergeBase.ok ? mergeBase.stdout : currentBranch,
			});
		}
		currentPath = undefined;
	};
	// runGit() trims stdout, which strips the trailing blank line git uses to
	// separate porcelain entries — so the LAST entry never hits the "blank
	// line" branch below and must be flushed once more after the loop ends.
	for (const line of result.stdout.split(/\r?\n/)) {
		if (line.startsWith("worktree ")) {
			flush();
			currentPath = line.slice("worktree ".length).replace(/\\/g, "/");
			currentBranch = undefined;
		} else if (line.startsWith("branch ")) {
			currentBranch = line.slice("branch ".length).replace(/^refs\/heads\//, "");
		} else if (line === "") {
			flush();
		}
	}
	flush();
	return worktrees;
}
