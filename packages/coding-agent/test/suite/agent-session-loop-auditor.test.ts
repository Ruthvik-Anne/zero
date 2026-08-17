import { fauxAssistantMessage } from "@zero-agent/ai";
import { afterEach, describe, expect, it } from "vitest";
import { LOOP_AUDIT_CONTEXT_CUSTOM_TYPE } from "../../src/core/advisor/loop-auditor.js";
import { createHarness, getAssistantTexts, type Harness } from "./harness.js";

/**
 * module E: the loop auditor is module D's turn-interval trigger paired with
 * module E's advisor — this test drives it through AgentSession end to end
 * (not just the pure loop-auditor.ts functions), proving it actually fires on
 * schedule and injects its findings into the live conversation.
 */
describe("AgentSession loop auditor", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createAuditedHarness(turnInterval: number): Promise<Harness> {
		const harness = await createHarness({ loopAuditor: { enabled: true, turnInterval } });
		harnesses.push(harness);
		return harness;
	}

	it("never fires when disabled (default, unconfigured behavior unchanged)", async () => {
		const harness = await createHarness();
		harnesses.push(harness);
		for (let i = 0; i < 5; i++) {
			harness.setResponses([fauxAssistantMessage(`turn ${i}`)]);
			await harness.session.prompt(`message ${i}`);
		}

		const auditEntries = harness.session.messages.filter(
			(message) => message.role === "custom" && message.customType === LOOP_AUDIT_CONTEXT_CUSTOM_TYPE,
		);
		expect(auditEntries).toHaveLength(0);
	});

	it("fires after the configured turn interval and injects findings, then resumes normal turns", async () => {
		const harness = await createAuditedHarness(2);

		harness.setResponses([fauxAssistantMessage("turn 1 done")]);
		await harness.session.prompt("first message");

		harness.setResponses([
			fauxAssistantMessage("turn 2 done"),
			fauxAssistantMessage("Work is on track; no drift found."),
			fauxAssistantMessage("Acknowledged, continuing as planned."),
		]);
		await harness.session.prompt("second message");

		const auditEntries = harness.session.messages.filter(
			(message) => message.role === "custom" && message.customType === LOOP_AUDIT_CONTEXT_CUSTOM_TYPE,
		);
		expect(auditEntries).toHaveLength(1);
		expect((auditEntries[0] as { content: string }).content).toContain("Work is on track; no drift found.");
		expect(getAssistantTexts(harness)).toEqual([
			"turn 1 done",
			"turn 2 done",
			"Acknowledged, continuing as planned.",
		]);
	});

	it("does not mutate the main transcript that the advisor reviewed", async () => {
		const harness = await createAuditedHarness(1);
		harness.setResponses([
			fauxAssistantMessage("only turn"),
			fauxAssistantMessage("Looks fine."),
			fauxAssistantMessage("Ok, continuing."),
		]);

		await harness.session.prompt("go");

		// The advisor's own side-conversation framing text must never leak into
		// the main assistant transcript the user sees.
		expect(getAssistantTexts(harness)).not.toContain(expect.stringContaining("skeptical reviewer"));
	});
});
