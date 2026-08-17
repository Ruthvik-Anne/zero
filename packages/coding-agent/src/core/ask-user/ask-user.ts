import type { ExtensionUIContext } from "../extensions/types.js";
import { CREDENTIAL_NAME_PATTERN } from "../vault/vault.js";

/**
 * Native ask-user primitive (module E) — a discriminated question-format union
 * so the model asks in the shape that matches the situation (a dilemma between
 * named approaches is `single_select`; "I need a value I don't have" is
 * `free_text`) rather than forcing everything through a bare confirm/deny.
 * Each variant maps onto an existing TUI primitive; `multi_select` is the one
 * exception — there is no native checkbox-list primitive, so it's built by
 * composing repeated `select()` calls with a "done" sentinel rather than
 * adding a new TUI widget.
 */

export interface AskUserOption {
	label: string;
	description?: string;
}

export type AskUserSpec =
	| { type: "free_text"; question: string; placeholder?: string }
	| { type: "confirm"; question: string; consequence?: string }
	| { type: "single_select"; question: string; options: AskUserOption[] }
	| { type: "multi_select"; question: string; options: AskUserOption[] }
	/**
	 * (task #78) Passwordless local vault input. `name` is a short identifier
	 * the model chooses to refer to this credential across turns and via
	 * `vault.list` — validated against CREDENTIAL_NAME_PATTERN since it becomes
	 * part of a filename-adjacent identifier and of the opaque placeholder
	 * token. The UI renders this masked (module E → TUI `Input.masked`); the
	 * model never receives the typed value, only a `zero-cred://` placeholder
	 * — see agent-session.ts's handleAskUserHostRequest.
	 */
	| { type: "credential"; question: string; name: string };

export interface AskUserResult {
	type: AskUserSpec["type"];
	/**
	 * free_text: the typed text, or null if cancelled.
	 * confirm: "yes" or "no".
	 * single_select: the chosen option's label, or null if cancelled.
	 * multi_select: the chosen labels joined with ", ", or null if none chosen.
	 * credential: the typed secret, or null if cancelled — ONLY inside this
	 * module, between the TUI and handleAskUserHostRequest. The host request
	 * handler replaces this with an opaque placeholder token before any of it
	 * is returned to the model; askUser() itself has no reason to know that.
	 */
	answer: string | null;
	/** multi_select only: the individual chosen labels. */
	selected?: string[];
}

const MULTI_SELECT_DONE_PREFIX = "Done";

function formatOption(option: AskUserOption): string {
	return option.description ? `${option.label} — ${option.description}` : option.label;
}

async function askMultiSelect(
	ui: ExtensionUIContext,
	question: string,
	options: AskUserOption[],
	signal: AbortSignal | undefined,
): Promise<AskUserResult> {
	const selected = new Set<string>();
	while (true) {
		const remaining = options.filter((option) => !selected.has(option.label));
		const doneLabel =
			selected.size > 0 ? `${MULTI_SELECT_DONE_PREFIX} (${selected.size} selected)` : MULTI_SELECT_DONE_PREFIX;
		const choices = [...remaining.map(formatOption), doneLabel];
		const prompt = selected.size > 0 ? `${question}\n(selected so far: ${[...selected].join(", ")})` : question;
		const chosen = await ui.select(prompt, choices, { signal });
		if (chosen === undefined || chosen === doneLabel || remaining.length === 0) {
			break;
		}
		const match = remaining.find((option) => formatOption(option) === chosen);
		if (match) {
			selected.add(match.label);
		} else {
			break;
		}
	}
	const selectedList = [...selected];
	return {
		type: "multi_select",
		answer: selectedList.length > 0 ? selectedList.join(", ") : null,
		selected: selectedList,
	};
}

export async function askUser(ui: ExtensionUIContext, spec: AskUserSpec, signal?: AbortSignal): Promise<AskUserResult> {
	switch (spec.type) {
		case "free_text": {
			const answer = await ui.input(spec.question, spec.placeholder, { signal });
			return { type: "free_text", answer: answer ?? null };
		}
		case "confirm": {
			const message = spec.consequence ? `${spec.question}\n${spec.consequence}` : spec.question;
			const approved = await ui.confirm(spec.question, message, { signal });
			return { type: "confirm", answer: approved ? "yes" : "no" };
		}
		case "single_select": {
			const labels = spec.options.map(formatOption);
			const chosen = await ui.select(spec.question, labels, { signal });
			const index = chosen === undefined ? -1 : labels.indexOf(chosen);
			return { type: "single_select", answer: index >= 0 ? spec.options[index]!.label : null };
		}
		case "multi_select":
			return askMultiSelect(ui, spec.question, spec.options, signal);
		case "credential": {
			// masked: true — password-style input, never a plain free_text prompt.
			const answer = await ui.input(spec.question, undefined, { signal, masked: true });
			return { type: "credential", answer: answer ?? null };
		}
		default: {
			const exhaustive: never = spec;
			throw new Error(`unknown ask_user spec type: ${JSON.stringify(exhaustive)}`);
		}
	}
}

function validateAskUserOptions(value: unknown): AskUserOption[] {
	if (!Array.isArray(value) || value.length === 0) {
		throw new Error("ask_user options must be a non-empty array");
	}
	return value.map((item) => {
		if (typeof item === "string") {
			return { label: item };
		}
		if (typeof item === "object" && item !== null && typeof (item as { label?: unknown }).label === "string") {
			const record = item as { label: string; description?: unknown };
			return {
				label: record.label,
				description: typeof record.description === "string" ? record.description : undefined,
			};
		}
		throw new Error("ask_user options entries must be a string or {label, description?} object");
	});
}

export function validateAskUserSpec(payload: Record<string, unknown>): AskUserSpec {
	const question = payload.question;
	if (typeof question !== "string" || !question.trim()) {
		throw new Error("ask_user question must be a non-empty string");
	}
	const type = payload.type;
	switch (type) {
		case "free_text":
			return {
				type,
				question,
				placeholder: typeof payload.placeholder === "string" ? payload.placeholder : undefined,
			};
		case "confirm":
			return {
				type,
				question,
				consequence: typeof payload.consequence === "string" ? payload.consequence : undefined,
			};
		case "single_select":
		case "multi_select":
			return { type, question, options: validateAskUserOptions(payload.options) };
		case "credential": {
			const name = payload.name;
			if (typeof name !== "string" || !CREDENTIAL_NAME_PATTERN.test(name)) {
				throw new Error(
					`ask_user credential name must match ${CREDENTIAL_NAME_PATTERN} (got ${JSON.stringify(name)})`,
				);
			}
			return { type, question, name };
		}
		default:
			throw new Error(
				`ask_user type must be one of free_text, confirm, single_select, multi_select, credential (got ${JSON.stringify(type)})`,
			);
	}
}
