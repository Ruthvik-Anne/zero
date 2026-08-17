import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fauxAssistantMessage } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { createCheckpoint } from "../../src/core/checkpoint/checkpoint.js";
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
}

/**
 * module H integration check: "workspace-contained destructive edit, /rollback
 * restores." rollbackCheckpoint() itself was already implemented and tested
 * (checkpoint.test.ts, tool-definition-wrapper-guardrails.test.ts), but it was
 * never wired to an actual user-facing command — `/rollback` genuinely did not
 * exist until this verification pass. Adds it as a session-level command (like
 * /mode, /goal, /autonomous) so it works uniformly in interactive/print/RPC/
 * daemon modes, not just the interactive TUI.
 */
describe("/rollback command (module H)", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createGitBackedHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		initGitRepo(harness.tempDir);
		writeFileSync(join(harness.tempDir, "tracked.txt"), "original\n");
		git(["add", "tracked.txt"], harness.tempDir);
		git(["commit", "-m", "init"], harness.tempDir);
		return harness;
	}

	it("restores a workspace-contained destructive edit to the most recent checkpoint", async () => {
		const harness = await createGitBackedHarness();
		const filePath = join(harness.tempDir, "tracked.txt");
		createCheckpoint(harness.tempDir, "before-edit");
		writeFileSync(filePath, "mutated by the risky action\n");
		expect(readFileSync(filePath, "utf8")).toBe("mutated by the risky action\n");

		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/rollback");

		expect(readFileSync(filePath, "utf8")).toBe("original\n");
	});

	it("restores to a specific checkpoint id when given one", async () => {
		const harness = await createGitBackedHarness();
		const filePath = join(harness.tempDir, "tracked.txt");
		createCheckpoint(harness.tempDir, "checkpoint-a");
		writeFileSync(filePath, "state after checkpoint-a\n");
		createCheckpoint(harness.tempDir, "checkpoint-b");
		writeFileSync(filePath, "state after checkpoint-b\n");

		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/rollback checkpoint-a");

		expect(readFileSync(filePath, "utf8")).toBe("original\n");
	});

	it("reports a clear message when there are no checkpoints yet", async () => {
		const harness = await createGitBackedHarness();

		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/rollback");

		const lastMessage = harness.session.messages.at(-1);
		expect(JSON.stringify(lastMessage)).toContain("No checkpoints recorded");
	});

	it("reports a clear message for a non-git workspace", async () => {
		const harness = await createHarness();
		harnesses.push(harness);

		harness.setResponses([fauxAssistantMessage("ack")]);
		await harness.session.prompt("/rollback");

		const lastMessage = harness.session.messages.at(-1);
		expect(JSON.stringify(lastMessage)).toContain("not a git repository");
	});
});
