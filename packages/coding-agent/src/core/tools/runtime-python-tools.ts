import { type Static, type TSchema, Type } from "typebox";
import type { AgentSession } from "../agent-session.js";
import { defineTool, type ToolDefinition } from "../extensions/types.js";
import type { Skill } from "../skills.js";
import { type RuntimePermission, runtimeToolSchema } from "./runtime-operations.js";
import { wrapToolDefinition } from "./tool-definition-wrapper.js";

export const KERNEL_RUNTIME_TOOL_NAMES = new Set(["edit", "attach_image", "websearch", "linear", "notion"]);

/** Only fixed, documented expressions are executable; arguments are JSON data. */
export function runtimePythonCode(expression: string, params: Record<string, unknown>): string {
	return `import json as _zero_tool_json\n_zero_tool_args = _zero_tool_json.loads(${JSON.stringify(JSON.stringify(params))})\n${expression}`;
}

export function createKernelRuntimeTools(
	session: AgentSession,
	getSkills: () => Skill[],
	permission: RuntimePermission,
): ToolDefinition[] {
	const tools: ToolDefinition[] = [];
	function register<S extends TSchema>(
		name: string,
		skill: string,
		description: string,
		parameters: S,
		expression: (params: Static<S>) => string,
		mutates: boolean,
	): void {
		if (
			!getSkills().some((entry) => entry.name === skill && entry.kind === "python" && !entry.disableModelInvocation)
		)
			return;
		tools.push(
			defineTool({
				name,
				label: name.replace(/_/g, " "),
				description,
				parameters: runtimeToolSchema(parameters),
				executionMode: "sequential",
				renderShell: "self",
				execute: async (id, params, signal, update, ctx) => {
					signal?.throwIfAborted();
					const blocked = ctx.mode === "manual" ? undefined : await permission(ctx, name, mutates, signal);
					if (blocked) return blocked;
					if (
						!getSkills().some(
							(entry) => entry.name === skill && entry.kind === "python" && !entry.disableModelInvocation,
						)
					)
						throw new Error(`${name} is disabled`);
					const kernel = session.getToolDefinition("ipython");
					if (!kernel) throw new Error(`${name} requires the IPython runtime`);
					return wrapToolDefinition(kernel, () => ctx).execute(
						id,
						{ code: runtimePythonCode(expression(params), params as Record<string, unknown>) },
						signal,
						update,
					);
				},
			}),
		);
	}
	const object = <T extends Record<string, TSchema>>(fields: T) =>
		Type.Object(fields, { additionalProperties: false });
	const string = () => Type.String({ minLength: 1 });
	register(
		"edit",
		"edit",
		"Replace one exact, unique string in a file. Missing or ambiguous matches fail without writing. Returns the applied file diff.",
		object({ path: string(), old_str: string(), new_str: Type.String() }),
		() => "await edit(**_zero_tool_args)",
		true,
	);
	register(
		"attach_image",
		"attach-image",
		"Load local PNG, JPEG, GIF or WebP images into model context with size validation and compression. Requires a vision-capable model.",
		object({ paths: Type.Array(string(), { minItems: 1, maxItems: 10 }) }),
		() => "await attach_image(*_zero_tool_args['paths'])",
		false,
	);
	register(
		"websearch",
		"websearch",
		"Search the web through configured Serper access. Several queries run concurrently. Configure missing access through /login → MCP Connections → Serper.",
		object({ queries: Type.Array(string(), { minItems: 1, maxItems: 10 }) }),
		() => "await websearch.research(_zero_tool_args['queries'])",
		false,
	);
	for (const name of ["linear", "notion"] as const) {
		register(
			name,
			name,
			`Discover ${name} MCP tools and their exact input schemas, then call a discovered tool. Authentication uses the existing /login connection.`,
			Type.Union([
				object({ action: Type.Literal("list_tools") }),
				object({
					action: Type.Literal("call_tool"),
					tool: string(),
					arguments: Type.Record(Type.String(), Type.Unknown()),
				}),
			]),
			(p) =>
				p.action === "list_tools"
					? `await ${name}.list_tools()`
					: `await ${name}.call_tool(_zero_tool_args['tool'], _zero_tool_args['arguments'])`,
			true,
		);
	}
	return tools;
}
