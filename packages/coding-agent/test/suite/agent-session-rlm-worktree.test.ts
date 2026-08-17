import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { listWorktrees } from "../../src/core/workspace/git-worktree.js";
import { createHarness, type Harness } from "./harness.js";

function git(args: string[], cwd: string): string {
	const result = spawnSync("git", args, { cwd, encoding: "utf-8", windowsHide: true });
	if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
	return result.stdout.trim();
}

function initGitRepo(repoDir: string): void {
	git(["init", "--initial-branch=main"], repoDir);
	git(["config", "--local", "user.email", "test@test.com"], repoDir);
	git(["config", "--local", "user.name", "Test"], repoDir);
	git(["config", "--local", "core.autocrlf", "false"], repoDir);
	writeFileSync(join(repoDir, "tracked.txt"), "shared\n");
	git(["add", "tracked.txt"], repoDir);
	git(["commit", "-m", "init"], repoDir);
}

/**
 * module B: rlm.run(..., isolation="worktree") — the worktree is created
 * synchronously within admission (before the detached child-startup task
 * runs), so these tests can assert on it right after runRlmChild() resolves
 * without needing the child to actually complete a turn.
 */
describe("AgentSession RLM worktree isolation", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createGitBackedHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		initGitRepo(harness.tempDir);
		return harness;
	}

	it("creates a fresh git worktree for the child when isolation=worktree is requested", async () => {
		const harness = await createGitBackedHarness();

		const handle = await harness.session.runRlmChild("do a parallel task", { isolation: "worktree" });

		const expectedPath = join(harness.tempDir, ".zero", "worktrees", handle.rlm_child_id);
		expect(existsSync(expectedPath)).toBe(true);
		expect(existsSync(join(expectedPath, "tracked.txt"))).toBe(true);
		expect(listWorktrees(harness.tempDir).some((w) => w.id === handle.rlm_child_id)).toBe(true);
	});

	it("does not create a worktree when isolation is omitted (backward compatible)", async () => {
		const harness = await createGitBackedHarness();

		await harness.session.runRlmChild("do a task");

		expect(listWorktrees(harness.tempDir)).toHaveLength(0);
	});

	it("rejects an unrecognized isolation value", async () => {
		const harness = await createGitBackedHarness();

		await expect(harness.session.runRlmChild("do a task", { isolation: "container" })).rejects.toThrow(
			'rlm.run isolation must be "worktree" when provided',
		);
	});

	it("fails closed with a clear error when the cwd is not a git repository", async () => {
		// Deliberately not git-initialized.
		const harness = await createHarness();
		harnesses.push(harness);

		await expect(harness.session.runRlmChild("do a task", { isolation: "worktree" })).rejects.toThrow(
			/isolation="worktree" failed/,
		);
	});

	it("allows two concurrent worktree-isolated children without path collision", async () => {
		const harness = await createGitBackedHarness();

		const [a, b] = await Promise.all([
			harness.session.runRlmChild("task a", { isolation: "worktree" }),
			harness.session.runRlmChild("task b", { isolation: "worktree" }),
		]);

		expect(a.rlm_child_id).not.toBe(b.rlm_child_id);
		const worktrees = listWorktrees(harness.tempDir);
		expect(worktrees.some((w) => w.id === a.rlm_child_id)).toBe(true);
		expect(worktrees.some((w) => w.id === b.rlm_child_id)).toBe(true);
	});
});
