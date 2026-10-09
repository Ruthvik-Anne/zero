import { type Static, type TSchema, Type } from "typebox";
import type { ExtensionContext, ToolDefinition } from "../extensions/types.js";
import { defineTool } from "../extensions/types.js";
import type { HostRequestHandlers } from "../kernel/index.js";

export type RuntimePermission = (
	ctx: ExtensionContext,
	name: string,
	mutates: boolean,
	signal?: AbortSignal,
) => Promise<
	| { content: { type: "text"; text: string }[]; details: { harmBlocked: boolean; action: string }; isError: boolean }
	| undefined
>;

const string = () => Type.String({ minLength: 1 });
const object = <T extends Record<string, TSchema>>(fields: T) => Type.Object(fields, { additionalProperties: false });
const action = <T extends string>(...names: T[]) => Type.Unsafe<T>(Type.Union(names.map((name) => Type.Literal(name))));
const criterion = Type.Union([
	string(),
	object({ id: Type.Optional(string()), text: string(), met: Type.Optional(Type.Boolean()) }),
]);
const subGoal = Type.Union([
	string(),
	object({ id: Type.Optional(string()), text: string(), done: Type.Optional(Type.Boolean()) }),
]);

/** Provider adapters such as Anthropic expose only root properties/required. */
export function runtimeToolSchema<S extends TSchema>(schema: S): S {
	const branches = (schema as TSchema & { anyOf?: unknown }).anyOf as
		| { properties?: Record<string, TSchema>; required?: string[] }[]
		| undefined;
	if (!branches || branches.some((branch) => !branch.properties)) return schema;
	const fields = new Map<string, TSchema[]>();
	for (const branch of branches) {
		for (const [key, value] of Object.entries(branch.properties!)) {
			const variants = fields.get(key) ?? [];
			if (!variants.some((existing) => JSON.stringify(existing) === JSON.stringify(value))) variants.push(value);
			fields.set(key, variants);
		}
	}
	const properties = Object.fromEntries(
		[...fields].map(([key, variants]) => [
			key,
			variants.every((variant) => typeof (variant as TSchema & { const?: unknown }).const === "string")
				? Type.Unsafe({
						type: "string",
						enum: [...new Set(variants.map((variant) => (variant as TSchema & { const?: unknown }).const))],
					})
				: variants.length === 1
					? variants[0]
					: Type.Union(variants),
		]),
	);
	const required = (branches[0].required ?? []).filter((key) =>
		branches.every((branch) => branch.required?.includes(key)),
	);
	// Keep branch constraints for local validation while exposing provider-visible arguments.
	return { ...schema, type: "object", properties, required } as S;
}

export const RUNTIME_SKILL_TO_TOOL: Readonly<Record<string, string>> = {
	"agent-message": "agent_message",
	"agent-observe": "agent_observe",
	"ask-user": "ask_user",
	"attach-image": "attach_image",
	advisor: "advisor",
	browser: "browser",
	compact: "compact",
	edit: "edit",
	goal: "goal",
	linear: "linear",
	notion: "notion",
	refine: "refine",
	"rlm-heartbeat": "rlm_heartbeat",
	vault: "vault",
	websearch: "websearch",
};

export function createHostRuntimeTools(
	getHandlers: (signal?: AbortSignal) => HostRequestHandlers,
	permission: RuntimePermission,
	wait: <T>(operation: Promise<T>, signal?: AbortSignal) => Promise<T>,
	operationSignal: (signal?: AbortSignal) => AbortSignal | undefined = (signal) => signal,
): ToolDefinition[] {
	const tools: ToolDefinition[] = [];
	function register<S extends TSchema>(
		name: string,
		description: string,
		parameters: S,
		request: (params: Static<S>) => string,
		mutates: (params: Static<S>) => boolean,
		availableRequest: string,
	): void {
		if (!getHandlers()[availableRequest]) return;
		tools.push(
			defineTool({
				name,
				label: name.replace(/_/g, " "),
				description,
				parameters: runtimeToolSchema(parameters),
				executionMode: "sequential",
				promptGuidelines: [
					"Use direct runtime tools for their documented operations; IPython is for programmable computation and shell cells.",
				],
				execute: async (_id, params, signal, _update, ctx) => {
					signal = operationSignal(signal);
					signal?.throwIfAborted();
					const blocked = await permission(ctx, name, mutates(params), signal);
					if (blocked) return blocked;
					signal?.throwIfAborted();
					const type = request(params);
					const handler = getHandlers(signal)[type];
					if (!handler) throw new Error(`${name} is unavailable in this session`);
					const { action: _action, ...payload } = params as Record<string, unknown>;
					const details = await wait(handler(payload), signal);
					if (
						name === "browser" &&
						(params as Record<string, unknown>).action === "screenshot" &&
						typeof details.data === "string"
					) {
						return {
							content: [{ type: "image", data: details.data, mimeType: "image/png" }],
							details: { captured: true },
						};
					}
					return { content: [{ type: "text", text: JSON.stringify(details, null, 2) }], details };
				},
			}),
		);
	}
	register(
		"goal",
		"Get, create, update or complete the persistent goal. Create only when explicitly requested. Complete only when required work is finished; report the completion budget report.",
		Type.Union([
			object({ action: action("get", "complete") }),
			object({
				action: Type.Literal("create"),
				objective: string(),
				token_budget: Type.Optional(Type.Integer({ minimum: 1 })),
				sub_goals: Type.Optional(Type.Array(subGoal, { maxItems: 50 })),
				acceptance_criteria: Type.Optional(Type.Array(criterion, { maxItems: 20 })),
			}),
			object({
				action: Type.Literal("update"),
				sub_goals: Type.Optional(Type.Array(subGoal, { maxItems: 50 })),
				acceptance_criteria: Type.Optional(Type.Array(criterion, { maxItems: 20 })),
			}),
		]),
		(p) => `goal.${p.action}`,
		(p) => p.action !== "get",
		"goal.get",
	);
	for (const name of ["compact", "refine"] as const) {
		register(
			name,
			name === "compact"
				? "Inspect context usage or schedule compaction at the turn boundary. Continue working after scheduling."
				: "Inspect or schedule evidence-backed harness refinement at the turn boundary. Continue working after scheduling.",
			Type.Union([
				object({ action: Type.Literal("status") }),
				object({
					action: Type.Literal("run"),
					instructions: Type.Optional(Type.String()),
					...(name === "refine" ? { global: Type.Optional(Type.Boolean()) } : {}),
				}),
			]),
			(p) => `${name}.${p.action}`,
			(p) => p.action === "run",
			`${name}.status`,
		);
	}
	register(
		"ask_user",
		"Ask an attached human for text, confirmation, choices or a masked credential. Credentials return opaque placeholders, never plaintext. Unavailable headless sessions fail promptly.",
		Type.Union([
			object({ type: Type.Literal("free_text"), question: string(), placeholder: Type.Optional(Type.String()) }),
			object({ type: Type.Literal("confirm"), question: string(), consequence: Type.Optional(Type.String()) }),
			object({
				type: action("single_select", "multi_select"),
				question: string(),
				options: Type.Array(
					Type.Union([string(), object({ label: string(), description: Type.Optional(Type.String()) })]),
					{ minItems: 1, maxItems: 30 },
				),
			}),
			object({ type: Type.Literal("credential"), question: string(), name: string() }),
		]),
		() => "ask_user.ask",
		(p) => p.type === "credential",
		"ask_user.ask",
	);
	register(
		"vault",
		"List stored credential names only. No secret values or placeholder tokens are returned.",
		object({ action: Type.Literal("list") }),
		() => "vault.list",
		() => false,
		"vault.list",
	);
	register(
		"browser",
		"Control the session's browser using CSS selectors. Inspect visible text before selecting elements. Screenshot returns an image. Close when finished.",
		Type.Union([
			object({ action: Type.Literal("navigate"), url: string() }),
			object({ action: action("click", "get_value"), selector: string() }),
			object({ action: Type.Literal("type"), selector: string(), text: Type.String() }),
			object({ action: Type.Literal("extract_text"), selector: Type.Optional(string()) }),
			object({ action: action("screenshot", "close") }),
		]),
		(p) => `browser.${p.action}`,
		(p) => !["extract_text", "get_value", "screenshot"].includes(p.action),
		"browser.navigate",
	);
	register(
		"agent_observe",
		"Read-only family status and bounded transcript previews. Cannot mutate or observe agents outside the nuclear family.",
		Type.Union([
			object({ action: Type.Literal("list_agents") }),
			object({ action: Type.Literal("get_agent"), target: string() }),
			object({
				action: Type.Literal("recent_messages"),
				target: string(),
				limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 50 })),
				max_chars: Type.Optional(Type.Integer({ minimum: 80, maximum: 2000 })),
			}),
		]),
		(p) => `agent_observe.${p.action === "list_agents" ? "list" : p.action === "get_agent" ? "get" : "recent"}`,
		() => false,
		"agent_observe.list",
	);
	register(
		"rlm_heartbeat",
		"Manage this agent's internal recurring prompts. This does not change the user's /heartbeat. Schedule only when requested.",
		Type.Union([
			object({ action: Type.Literal("list"), include_inactive: Type.Optional(Type.Boolean()) }),
			object({
				action: Type.Literal("create"),
				instruction: string(),
				interval: Type.Optional(string()),
				label: Type.Optional(string()),
				delivery_mode: Type.Optional(action("steer", "follow_up")),
			}),
			object({
				action: Type.Literal("update"),
				id: string(),
				instruction: Type.Optional(string()),
				interval: Type.Optional(string()),
				label: Type.Optional(string()),
				status: Type.Optional(action("pause", "resume")),
				delivery_mode: Type.Optional(action("steer", "follow_up")),
			}),
			object({ action: Type.Literal("delete"), id: string() }),
		]),
		(p) => `rlm_heartbeat.${p.action}`,
		(p) => p.action !== "list",
		"rlm_heartbeat.list",
	);
	register(
		"find_models",
		"Search the authenticated model catalog without loading the entire catalog into context.",
		object({ query: Type.String(), limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 20 })) }),
		() => "rlm.find_models",
		() => false,
		"rlm.find_models",
	);
	return tools;
}
