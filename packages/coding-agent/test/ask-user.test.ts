import { describe, expect, it, vi } from "vitest";
import { askUser, validateAskUserSpec } from "../src/core/ask-user/ask-user.js";
import type { ExtensionUIContext } from "../src/core/extensions/types.js";

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

describe("ask-user.ts (module E)", () => {
	describe("validateAskUserSpec", () => {
		it("parses a free_text spec", () => {
			expect(validateAskUserSpec({ type: "free_text", question: "What port?", placeholder: "8080" })).toEqual({
				type: "free_text",
				question: "What port?",
				placeholder: "8080",
			});
		});

		it("parses a confirm spec with an optional consequence", () => {
			expect(validateAskUserSpec({ type: "confirm", question: "Proceed?", consequence: "Deletes files." })).toEqual({
				type: "confirm",
				question: "Proceed?",
				consequence: "Deletes files.",
			});
		});

		it("normalizes single_select/multi_select string options into {label} objects", () => {
			const spec = validateAskUserSpec({ type: "single_select", question: "Which?", options: ["a", "b"] });
			expect(spec).toEqual({ type: "single_select", question: "Which?", options: [{ label: "a" }, { label: "b" }] });
		});

		it("preserves object-form options with a description", () => {
			const spec = validateAskUserSpec({
				type: "multi_select",
				question: "Which?",
				options: [{ label: "a", description: "first" }],
			});
			expect(spec).toEqual({
				type: "multi_select",
				question: "Which?",
				options: [{ label: "a", description: "first" }],
			});
		});

		it("rejects a missing/empty question", () => {
			expect(() => validateAskUserSpec({ type: "confirm", question: "" })).toThrow(
				"ask_user question must be a non-empty string",
			);
		});

		it("rejects an unknown type", () => {
			expect(() => validateAskUserSpec({ type: "yes_no", question: "x" })).toThrow("ask_user type must be one of");
		});

		it("rejects select types with empty options", () => {
			expect(() => validateAskUserSpec({ type: "single_select", question: "x", options: [] })).toThrow(
				"ask_user options must be a non-empty array",
			);
		});
	});

	describe("askUser", () => {
		it("free_text returns the typed answer", async () => {
			const ui = fakeUI({ input: vi.fn(async () => "my-answer") });
			const result = await askUser(ui, { type: "free_text", question: "What?" });
			expect(result).toEqual({ type: "free_text", answer: "my-answer" });
		});

		it("free_text returns null when cancelled", async () => {
			const ui = fakeUI({ input: vi.fn(async () => undefined) });
			const result = await askUser(ui, { type: "free_text", question: "What?" });
			expect(result.answer).toBeNull();
		});

		it("confirm maps true/false to yes/no", async () => {
			const uiYes = fakeUI({ confirm: vi.fn(async () => true) });
			expect(await askUser(uiYes, { type: "confirm", question: "Proceed?" })).toEqual({
				type: "confirm",
				answer: "yes",
			});
			const uiNo = fakeUI({ confirm: vi.fn(async () => false) });
			expect(await askUser(uiNo, { type: "confirm", question: "Proceed?" })).toEqual({
				type: "confirm",
				answer: "no",
			});
		});

		it("single_select returns the chosen option's plain label, not the formatted display string", async () => {
			const ui = fakeUI({ select: vi.fn(async () => "b — second option") });
			const result = await askUser(ui, {
				type: "single_select",
				question: "Which?",
				options: [
					{ label: "a", description: "first option" },
					{ label: "b", description: "second option" },
				],
			});
			expect(result).toEqual({ type: "single_select", answer: "b" });
		});

		it("single_select returns null when cancelled", async () => {
			const ui = fakeUI({ select: vi.fn(async () => undefined) });
			const result = await askUser(ui, { type: "single_select", question: "Which?", options: [{ label: "a" }] });
			expect(result.answer).toBeNull();
		});

		it("multi_select accumulates choices across repeated select() calls until Done", async () => {
			const responses = ["a", "c", "Done (2 selected)"];
			let call = 0;
			const ui = fakeUI({ select: vi.fn(async () => responses[call++]) });
			const result = await askUser(ui, {
				type: "multi_select",
				question: "Which?",
				options: [{ label: "a" }, { label: "b" }, { label: "c" }],
			});
			expect(result.type).toBe("multi_select");
			expect(result.selected).toEqual(["a", "c"]);
			expect(result.answer).toBe("a, c");
		});

		it("multi_select returns an empty/null result when Done is chosen immediately", async () => {
			const ui = fakeUI({ select: vi.fn(async () => "Done") });
			const result = await askUser(ui, {
				type: "multi_select",
				question: "Which?",
				options: [{ label: "a" }],
			});
			expect(result.selected).toEqual([]);
			expect(result.answer).toBeNull();
		});

		it("multi_select stops when cancelled mid-selection", async () => {
			const responses = ["a", undefined];
			let call = 0;
			const ui = fakeUI({ select: vi.fn(async () => responses[call++]) });
			const result = await askUser(ui, {
				type: "multi_select",
				question: "Which?",
				options: [{ label: "a" }, { label: "b" }],
			});
			expect(result.selected).toEqual(["a"]);
		});
	});
});
