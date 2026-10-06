import { setKeybindings, type TUI } from "@zero-agent/tui";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.js";
import { CustomEditor } from "../src/modes/interactive/components/custom-editor.js";
import { InteractiveMode } from "../src/modes/interactive/interactive-mode.js";
import { getEditorTheme, initTheme } from "../src/modes/interactive/theme/theme.js";

function context() {
	const mode = Object.create(InteractiveMode.prototype) as InteractiveMode;
	const connection = { promptAndWait: vi.fn(async () => {}) };
	Object.assign(mode, {
		agentConnection: connection,
		connectionState: { sessionId: "one" },
		sessionEventGeneration: 0,
		modeCycleQueue: Promise.resolve(),
		showError: vi.fn(),
	});
	return { mode, connection };
}

const cycle = Reflect.get(InteractiveMode.prototype, "handleModeCycle") as (this: InteractiveMode) => void;
const settle = (mode: InteractiveMode) => Reflect.get(mode, "modeCycleQueue") as Promise<void>;

describe("native prompt mode cycling", () => {
	beforeAll(() => initTheme("dark"));

	it("defaults to Shift+Tab and can be remapped or disabled independently of menu tabs", () => {
		const defaults = new KeybindingsManager();
		expect(defaults.getKeys("app.mode.cycle")).toEqual(["shift+tab"]);
		const remapped = new KeybindingsManager({ "app.mode.cycle": "alt+m" });
		expect(remapped.getKeys("app.mode.cycle")).toEqual(["alt+m"]);
		expect(remapped.getKeys("app.configuration.previousTab")).toEqual(["shift+tab"]);
		expect(new KeybindingsManager({ "app.mode.cycle": [] }).getKeys("app.mode.cycle")).toEqual([]);
	});

	it("dispatches the configurable editor action without submitting or changing the draft", () => {
		const kb = new KeybindingsManager({ "app.mode.cycle": "alt+m" });
		setKeybindings(kb);
		const editor = new CustomEditor({ requestRender: vi.fn() } as unknown as TUI, getEditorTheme(), kb);
		const handler = vi.fn();
		editor.onAction("app.mode.cycle", handler);
		editor.onSubmit = vi.fn();
		editor.setText("draft /mode manual");
		editor.handleInput("\x1b[Z");
		expect(handler).not.toHaveBeenCalled();
		editor.handleInput("\x1bm");
		expect(handler).toHaveBeenCalledOnce();
		expect(editor.getText()).toBe("draft /mode manual");
		expect(editor.onSubmit).not.toHaveBeenCalled();
	});

	it("registers Shift+Tab on the prompt editor only", async () => {
		const { mode, connection } = context();
		const kb = new KeybindingsManager();
		setKeybindings(kb);
		const ui = { requestRender: vi.fn() };
		const editor = new CustomEditor(ui as unknown as TUI, getEditorTheme(), kb);
		editor.setText("keep draft");
		Object.assign(mode, { defaultEditor: editor, editor, ui });
		const setup = Reflect.get(InteractiveMode.prototype, "setupKeyHandlers") as (this: InteractiveMode) => void;
		setup.call(mode);
		editor.handleInput("\x1b[Z");
		await settle(mode);
		expect(connection.promptAndWait).toHaveBeenCalledWith("/mode cycle", { queueIfBusy: true });
		expect(editor.getText()).toBe("keep draft");
	});

	it("serializes native commands without guessing or patching client mode", async () => {
		const { mode, connection } = context();
		cycle.call(mode);
		cycle.call(mode);
		await settle(mode);
		expect(connection.promptAndWait.mock.calls).toEqual([
			["/mode cycle", { queueIfBusy: true }],
			["/mode cycle", { queueIfBusy: true }],
		]);
	});

	it("drops queued cycling after a session transition", async () => {
		const { mode, connection } = context();
		cycle.call(mode);
		Reflect.set(mode, "sessionEventGeneration", 1);
		await settle(mode);
		expect(connection.promptAndWait).not.toHaveBeenCalled();
	});

	it("ignores cycling in side conversations or during shutdown", async () => {
		const { mode, connection } = context();
		Reflect.set(mode, "sideQuestionComponent", {});
		cycle.call(mode);
		Reflect.set(mode, "sideQuestionComponent", undefined);
		Reflect.set(mode, "isShuttingDown", true);
		cycle.call(mode);
		await settle(mode);
		expect(connection.promptAndWait).not.toHaveBeenCalled();
	});

	it("does not surface stale failures in a replacement session", async () => {
		const { mode, connection } = context();
		let reject!: (error: Error) => void;
		connection.promptAndWait.mockImplementationOnce(
			() =>
				new Promise<void>((_, fail) => {
					reject = fail;
				}),
		);
		cycle.call(mode);
		await Promise.resolve();
		Reflect.set(mode, "sessionEventGeneration", 1);
		reject(new Error("old session"));
		await settle(mode);
		expect(Reflect.get(mode, "showError")).not.toHaveBeenCalled();
	});

	it("reports connection failures and allows the next cycle", async () => {
		const { mode, connection } = context();
		connection.promptAndWait.mockRejectedValueOnce(new Error("offline"));
		cycle.call(mode);
		await settle(mode);
		expect(Reflect.get(mode, "showError")).toHaveBeenCalledWith("offline");
		cycle.call(mode);
		await settle(mode);
		expect(connection.promptAndWait).toHaveBeenCalledTimes(2);
	});

	it("does not forward cycling from the child tray into the prompt", () => {
		const { mode } = context();
		const editor = { handleInput: vi.fn() };
		Object.assign(mode, { keybindings: new KeybindingsManager(), editor, focusEditor: vi.fn() });
		const handle = Reflect.get(InteractiveMode.prototype, "handleSubagentSummaryChatAction") as (
			this: InteractiveMode,
			data: string,
		) => void;
		handle.call(mode, "\x1b[Z");
		expect(editor.handleInput).not.toHaveBeenCalled();
	});
});
