import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { findGitPaths } from "../../utils/git.js";

/**
 * Native checkpoint/rollback (module H), git-based.
 *
 * A checkpoint is a `git stash create` commit object (captures the full
 * worktree + index state relative to HEAD, without touching either) recorded
 * under `refs/zero/checkpoints/<id>` — durable, doesn't clutter `git stash
 * list`, and doesn't disturb any stash the user has of their own.
 *
 * Rollback uses `git read-tree --reset -u <hash>`, NOT `git stash apply`:
 * `stash apply` does a 3-way merge and refuses ("would be overwritten by
 * merge") whenever the working tree has uncommitted changes at a path the
 * stash also touches — exactly the situation a rollback is called in (undo
 * the risky action that was just taken). `read-tree --reset -u` unconditionally
 * resets the index and working tree to the checkpoint's tree, which is the
 * destructive-on-purpose semantics rollback needs.
 *
 * v1 scope/limitations, both worth knowing before relying on this:
 * - Git repositories only. A non-git workspace has no checkpoint coverage —
 *   `createCheckpoint` returns `{ method: "unavailable" }` and
 *   `hasAnyCheckpoint` reports false, so module F's harm-check correctly shows
 *   "cannot be undone" rather than a false promise of reversibility.
 * - `read-tree --reset -u` restores tracked-file content but does not delete
 *   files newly created after the checkpoint (they aren't part of any tree it
 *   resets to) — a rollback undoes edits/deletes to already-tracked content,
 *   not files the risky action created from scratch.
 */

export interface CheckpointInfo {
	id: string;
	createdAt: number;
	/** The `git stash create` commit hash this checkpoint points at. */
	hash: string;
}

export type CreateCheckpointResult = ({ method: "git-stash" } & CheckpointInfo) | { method: "unavailable" };

const REF_PREFIX = "refs/zero/checkpoints/";

function runGit(cwd: string, args: string[]): { ok: boolean; stdout: string } {
	const result = spawnSync("git", ["--no-optional-locks", ...args], {
		cwd,
		encoding: "utf8",
		stdio: ["ignore", "pipe", "ignore"],
		windowsHide: true,
	});
	return { ok: result.status === 0, stdout: typeof result.stdout === "string" ? result.stdout.trim() : "" };
}

export function isGitRepo(cwd: string): boolean {
	return findGitPaths(cwd) !== null;
}

function refName(id: string): string {
	return `${REF_PREFIX}${id}`;
}

/**
 * (D9) `listCheckpoints` used to derive `createdAt` from the checkpoint's git
 * **commit** date, but `createCheckpoint`'s own clean-tree branch points the ref
 * at HEAD itself rather than a fresh commit — HEAD's commit date can be months
 * old, while the checkpoint was genuinely just created "now". That gave two
 * different clocks for one field, and could make `rollbackCheckpoint(cwd)` (no
 * explicit id, defaults to `checkpoints[0]`) pick the wrong snapshot whenever a
 * later checkpoint happened to hit the clean-tree branch. A tiny sidecar file
 * recording the real wall-clock creation time (written once, at the moment of
 * creation, by the one function that actually knows it) replaces the derived
 * git-commit-date guess. Stored in the shared (not per-worktree) git dir so it's
 * visible consistently regardless of which worktree a caller queries from — refs
 * under refs/zero/checkpoints/ are themselves shared across worktrees the same way.
 */
function checkpointTimesPath(cwd: string): string | undefined {
	const result = runGit(cwd, ["rev-parse", "--git-common-dir"]);
	if (!result.ok || !result.stdout) return undefined;
	const gitDir = isAbsolute(result.stdout) ? result.stdout : join(cwd, result.stdout);
	return join(gitDir, "zero-checkpoint-times.json");
}

function readCheckpointTimes(cwd: string): Record<string, number> {
	const path = checkpointTimesPath(cwd);
	if (!path || !existsSync(path)) return {};
	try {
		const parsed = JSON.parse(readFileSync(path, "utf8"));
		return typeof parsed === "object" && parsed !== null ? parsed : {};
	} catch {
		return {};
	}
}

/** Best-effort: if this fails, listCheckpoints falls back to the (buggy but
 * previously-only) git-commit-date guess for this one entry — never throws. */
function writeCheckpointTime(cwd: string, id: string, createdAt: number): void {
	const path = checkpointTimesPath(cwd);
	if (!path) return;
	try {
		const times = readCheckpointTimes(cwd);
		times[id] = createdAt;
		writeFileSync(path, JSON.stringify(times));
	} catch {
		// Non-fatal — see comment above.
	}
}

/**
 * Snapshot the current worktree + index. No-op (returns a checkpoint with an
 * empty-tree hash) when there is nothing to checkpoint (clean tree) — rollback
 * of a clean-tree checkpoint is a harmless no-op, not an error.
 */
// (D13) String(Date.now()) collided when two soft-block approvals landed in
// the same millisecond, silently overwriting the earlier checkpoint's ref.
// randomUUID is collision-resistant regardless of timing; also no delete/prune
// API exists yet, so every approval still permanently pins a full-tree stash
// commit `git gc` cannot collect — a real prune/list-with-delete command is a
// separate, larger follow-up, not fixed here.
export function createCheckpoint(cwd: string, id: string = randomUUID()): CreateCheckpointResult {
	if (!isGitRepo(cwd)) {
		return { method: "unavailable" };
	}
	// (D9) Captured once and reused for both the returned result and the sidecar
	// record below, so there is exactly one clock for this checkpoint's creation
	// time — not "whatever git reports as the commit's authored date".
	const createdAt = Date.now();
	// `git stash create` builds the stash commit object without touching the
	// working tree, the index, or the real stash list (`git stash push` would).
	const created = runGit(cwd, ["stash", "create", `zero-checkpoint-${id}`]);
	const hash = created.stdout;
	if (!created.ok || !hash) {
		// Clean tree: git stash create prints nothing and exits 0. Point the ref
		// at HEAD itself so rollback is a well-defined (harmless) no-op.
		const head = runGit(cwd, ["rev-parse", "HEAD"]);
		if (!head.ok || !head.stdout) {
			return { method: "unavailable" };
		}
		runGit(cwd, ["update-ref", refName(id), head.stdout]);
		writeCheckpointTime(cwd, id, createdAt);
		return { method: "git-stash", id, createdAt, hash: head.stdout };
	}
	runGit(cwd, ["update-ref", refName(id), hash]);
	writeCheckpointTime(cwd, id, createdAt);
	return { method: "git-stash", id, createdAt, hash };
}

/** True if at least one checkpoint has been recorded for this workspace. */
export function hasAnyCheckpoint(cwd: string): boolean {
	if (!isGitRepo(cwd)) return false;
	const result = runGit(cwd, ["for-each-ref", REF_PREFIX]);
	return result.ok && result.stdout.length > 0;
}

/**
 * (D8) Whether a checkpoint created *for this specific target* would actually
 * cover it — the honest, action-specific question module F's `reversible` field
 * needs, in place of "does any checkpoint exist anywhere" (which stays true
 * forever after the first approval, regardless of relevance to a later action).
 * `git stash create` only captures tracked content, so a target that isn't
 * tracked (e.g. a file that was never committed) can never be restored by this
 * mechanism no matter when the checkpoint is taken — deleting it is unrecoverable.
 */
export function isPathTrackedByGit(cwd: string, targetPath: string): boolean {
	if (!isGitRepo(cwd)) return false;
	return runGit(cwd, ["ls-files", "--error-unmatch", "--", targetPath]).ok;
}

export function listCheckpoints(cwd: string): CheckpointInfo[] {
	if (!isGitRepo(cwd)) return [];
	const result = runGit(cwd, ["for-each-ref", "--format=%(refname) %(objectname) %(creatordate:unix)", REF_PREFIX]);
	if (!result.ok || !result.stdout) return [];
	// (D9) Prefer the recorded wall-clock creation time; the commit-date column
	// above is only a fallback for checkpoints created before this fix existed.
	const recordedTimes = readCheckpointTimes(cwd);
	return result.stdout
		.split("\n")
		.filter(Boolean)
		.map((line) => {
			const [ref, hash, createdAtRaw] = line.split(" ");
			const id = (ref ?? "").slice(REF_PREFIX.length);
			const fallbackCreatedAt = createdAtRaw ? Number(createdAtRaw) * 1000 : 0;
			return {
				id,
				hash: hash ?? "",
				createdAt: recordedTimes[id] ?? fallbackCreatedAt,
			};
		})
		.filter((entry) => entry.id && entry.hash)
		.sort((a, b) => b.createdAt - a.createdAt);
}

export interface RollbackResult {
	ok: boolean;
	error?: string;
}

/** Restore the worktree + index to a checkpoint. Defaults to the most recent one. */
export function rollbackCheckpoint(cwd: string, id?: string): RollbackResult {
	if (!isGitRepo(cwd)) {
		return { ok: false, error: "Not a git repository — no checkpoint coverage available." };
	}
	const checkpoints = listCheckpoints(cwd);
	const target = id ? checkpoints.find((c) => c.id === id) : checkpoints[0];
	if (!target) {
		return { ok: false, error: id ? `No checkpoint found with id "${id}".` : "No checkpoints recorded." };
	}
	const reset = runGit(cwd, ["read-tree", "--reset", "-u", target.hash]);
	if (!reset.ok) {
		return { ok: false, error: `git read-tree --reset failed for checkpoint "${target.id}" (${target.hash}).` };
	}
	return { ok: true };
}
