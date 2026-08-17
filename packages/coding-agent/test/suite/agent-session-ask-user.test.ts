import { afterEach, describe, expect, it, vi } from "vitest";
import type { ExtensionUIContext } from "../../src/core/extensions/types.js";
import { createHarness, type Harness } from "./harness.js";

function fakeUI(overrides: Partial<ExtensionUIContext> = {}): ExtensionUIContext {
	return {
		select: vi.fn(async () => undefined),
		confirm: vi.fn(async () => true),
		input: vi.fn(async () => undefined),
		notify: vi.fn(),
		onTerminalInput: vi.fn(() => () => {}),
		setStatus: vi.fn(),
		setWorkingMessage: vi.fn(),
		setWorkingVisible: vi.fn(),
		setWorkingIndicator: vi.fn(),
		setHiddenThinkingLabel: vi.fn(),
		setWidget: vi.fn(),
		...overrides,
	} as unknown as ExtensionUIContext;
}

/** module E: ask_user.ask host request, driven end to end through AgentSession. */
describe("AgentSession ask_user", () => {
	const harnesses: Harness[] = [];

	afterEach(() => {
		while (harnesses.length > 0) harnesses.pop()?.cleanup();
	});

	async function createAskUserHarness(): Promise<Harness> {
		const harness = await createHarness();
		harnesses.push(harness);
		return harness;
	}

	it("routes a confirm spec through the bound UI context", async () => {
		const harness = await createAskUserHarness();
		const confirm = vi.fn(async () => true);
		await harness.session.bindExtensions({ uiContext: fakeUI({ confirm }) });

		const result = await harness.session.handleAskUserHostRequest({
			type: "confirm",
			question: "Delete the build cache?",
			consequence: "This is reversible via checkpoint.",
		});

		expect(result).toEqual({ type: "confirm", answer: "yes" });
		expect(confirm).toHaveBeenCalledWith(
			"Delete the build cache?",
			"Delete the build cache?\nThis is reversible via checkpoint.",
			expect.anything(),
		);
	});

	it("routes a single_select spec and returns the plain label", async () => {
		const harness = await createAskUserHarness();
		await harness.session.bindExtensions({
			uiContext: fakeUI({ select: vi.fn(async () => "worktree — isolate in a fresh git worktree") }),
		});

		const result = await harness.session.handleAskUserHostRequest({
			type: "single_select",
			question: "How should this subagent be isolated?",
			options: [
				{ label: "inline", description: "share the current worktree" },
				{ label: "worktree", description: "isolate in a fresh git worktree" },
			],
		});

		expect(result).toEqual({ type: "single_select", answer: "worktree" });
	});

	it("rejects a malformed spec before touching the UI", async () => {
		const harness = await createAskUserHarness();
		const select = vi.fn();
		await harness.session.bindExtensions({ uiContext: fakeUI({ select }) });

		await expect(harness.session.handleAskUserHostRequest({ type: "single_select", question: "x" })).rejects.toThrow(
			"ask_user options must be a non-empty array",
		);
		expect(select).not.toHaveBeenCalled();
	});

	it("fails with actionable guidance when no UI is attached (headless session)", async () => {
		const harness = await createAskUserHarness();

		await expect(harness.session.handleAskUserHostRequest({ type: "confirm", question: "Proceed?" })).rejects.toThrow(
			/no interactive UI is attached.*reasonable assumption/s,
		);
	});
});
