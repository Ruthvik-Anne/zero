import type { Theme } from "../../modes/interactive/theme/theme.js";
import { theme } from "../../modes/interactive/theme/theme.js";
import type {
	ExtensionUIContext,
	ExtensionUIDialogOptions,
	ExtensionWidgetOptions,
	WorkingIndicatorOptions,
} from "../extensions/types.js";
import type { McpTaskRegistry } from "./task-registry.js";

/**
 * Headless `ExtensionUIContext` for an MCP-driven task session — the same
 * role `rpc-extension-ui-context.ts` plays for RPC clients, but instead of
 * round-tripping over a socket it round-trips through the task registry:
 * `ask_user.ask` (module E) and the harm-check soft-block confirm (module F)
 * both call `ctx.ui.select/confirm/input`, which here become a pending
 * question surfaced via `get_status` and resolved by the external MCP
 * caller's `answer(task_id, question_id, response)`.
 */
export function createMcpTaskUiContext(registry: McpTaskRegistry, taskId: string): ExtensionUIContext {
	const ask = async <T>(
		method: "select" | "confirm" | "input",
		title: string,
		extra: { message?: string; options?: string[]; placeholder?: string },
		opts: ExtensionUIDialogOptions | undefined,
		fallback: T,
		parse: (response: { cancelled: true } | { cancelled: false; value?: string; confirmed?: boolean }) => T,
	): Promise<T> => {
		if (opts?.signal?.aborted) return fallback;
		const response = await registry.askQuestion(taskId, { method, title, ...extra }, opts?.signal);
		return parse(response);
	};

	const uiContext: ExtensionUIContext = {
		select: (title, options, opts) =>
			ask("select", title, { options }, opts, undefined, (response) =>
				response.cancelled ? undefined : response.value,
			),
		confirm: (title, message, opts) =>
			ask("confirm", title, { message }, opts, false, (response) =>
				response.cancelled ? false : Boolean(response.confirmed),
			),
		input: (title, placeholder, opts) =>
			ask("input", title, { placeholder }, opts, undefined, (response) =>
				response.cancelled ? undefined : response.value,
			),
		notify: (message, notifyType) => registry.notify(taskId, message, notifyType ?? "info"),
		onTerminalInput: () => () => {},
		setStatus: () => {},
		setWorkingMessage: () => {},
		setWorkingVisible: () => {},
		setWorkingIndicator: (_options?: WorkingIndicatorOptions) => {},
		setHiddenThinkingLabel: () => {},
		setWidget: (_widgetKey: string, _content: unknown, _options?: ExtensionWidgetOptions) => {},
		setFooter: () => {},
		setHeader: () => {},
		setTitle: () => {},
		custom: async () => undefined as never,
		pasteToEditor: () => {},
		setEditorText: () => {},
		getEditorText: () => "",
		editor: async (_title, prefill) => prefill,
		addAutocompleteProvider: () => {},
		setEditorComponent: () => {},
		getEditorComponent: () => undefined,
		get theme() {
			return theme;
		},
		getAllThemes: () => [],
		getTheme: (_name: string) => undefined,
		setTheme: (_theme: string | Theme) => ({ success: false, error: "Theme switching not supported in MCP mode" }),
		getToolsExpanded: () => false,
		setToolsExpanded: () => {},
	};
	return uiContext;
}
