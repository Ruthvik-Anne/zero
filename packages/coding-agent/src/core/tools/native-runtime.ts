import { readFile } from "node:fs/promises";
import { Type } from "typebox";
import { stripFrontmatter } from "../../utils/frontmatter.js";
import type { AgentSession } from "../agent-session.js";
import { buildCodeMap, canonicalMapPath, dependenciesOf, dependentsOf } from "../code-map/code-map.js";
import { readWorkspaceFile } from "../coordination/service.js";
import { defineTool, type ExtensionContext, type ToolDefinition } from "../extensions/types.js";
import type { HostRequestHandlers } from "../kernel/index.js";
import type { Skill } from "../skills.js";

async function nativePermission(ctx: ExtensionContext, name: string, mutates: boolean, signal?: AbortSignal) {
	signal?.throwIfAborted();
	let reason: string | undefined;
	if (ctx.mode === "plan" && mutates) reason = `Blocked in plan mode: ${name} mutates runtime state.`;
	else if (ctx.mode === "manual") {
		if (!ctx.hasUI || ctx.allowRiskyActions === false) reason = "Manual mode requires human confirmation.";
		else if (!(await awaitNativeOperation(ctx.ui.confirm("Confirm action (manual mode)", `Run ${name}?`), signal)))
			reason = `Declined in manual mode: ${name}.`;
	}
	signal?.throwIfAborted();
	if (ctx.mode === "plan" && mutates) reason = `Blocked in plan mode: ${name} mutates runtime state.`;
	return reason
		? {
				content: [{ type: "text" as const, text: reason }],
				details: { harmBlocked: true, action: "hard_block" },
				isError: true,
			}
		: undefined;
}

export async function awaitNativeOperation<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
	if (!signal) return operation;
	return new Promise<T>((resolve, reject) => {
		const aborted = () => {
			cleanup();
			reject(new Error("Native tool operation cancelled"));
		};
		const cleanup = () => signal.removeEventListener("abort", aborted);
		signal.addEventListener("abort", aborted, { once: true });
		operation.then(
			(value) => {
				cleanup();
				resolve(value);
			},
			(error) => {
				cleanup();
				reject(error);
			},
		);
		if (signal.aborted) aborted();
	});
}

function result(details: unknown) {
	return { content: [{ type: "text" as const, text: JSON.stringify(details) }], details };
}

function canDegradeRead(error: unknown): boolean {
	const code = (error as NodeJS.ErrnoException | undefined)?.code;
	return code === "EACCES" || code === "EPERM" || code === "EROFS";
}

export function createNativeRuntimeToolDefinitions(
	session: AgentSession,
	getHandlers: (signal?: AbortSignal) => HostRequestHandlers,
	getSkills: () => Skill[],
): ToolDefinition[] {
	const subagent = defineTool({
		name: "subagent",
		label: "Subagent",
		description:
			"Spawn independent work, list direct children, or delete a direct child. Spawn returns an admission handle, not an answer. Children inherit tools, permissions, model and depth limits. Use IPython for searching and model discovery.",
		promptGuidelines: [
			"Use subagent to delegate independent work. End your turn after admission; collect replies via agent_message or files.",
		],
		parameters: Type.Object(
			{
				action: Type.Union([Type.Literal("spawn"), Type.Literal("list"), Type.Literal("delete")]),
				prompt: Type.Optional(Type.String({ minLength: 1, description: "Required for spawn." })),
				name: Type.Optional(Type.String()),
				model: Type.Optional(Type.String()),
				modelClass: Type.Optional(Type.Union([Type.Literal("same"), Type.Literal("smaller")])),
				isolation: Type.Optional(Type.Literal("worktree")),
				target: Type.Optional(Type.String({ minLength: 1, description: "Required for delete." })),
				writeFiles: Type.Optional(
					Type.Array(Type.String(), {
						maxItems: 200,
						description:
							"Reserve exact child-workspace files before the child's initial task starts. Empty means read-only.",
					}),
				),
				priority: Type.Optional(Type.Integer({ minimum: -100, maximum: 100 })),
				dependencies: Type.Optional(Type.Array(Type.String(), { maxItems: 200 })),
			},
			{ additionalProperties: false },
		),
		execute: async (_id, params, signal, _update, ctx) => {
			signal?.throwIfAborted();
			if (params.action !== "list") {
				const blocked = await nativePermission(ctx, `subagent.${params.action}`, true, signal);
				if (blocked) return blocked;
			} else {
				const blocked = await nativePermission(ctx, "subagent.list", false, signal);
				if (blocked) return blocked;
			}
			if (params.action === "spawn") {
				const { action: _action, prompt, target, ...kwargs } = params;
				if (!prompt?.trim()) throw new Error("subagent spawn requires a non-empty prompt");
				if (target !== undefined) throw new Error("subagent spawn does not accept target");
				const operation = session.runRlmChild(prompt, kwargs, undefined, signal);
				// Admission may settle after cancellation; never leave that late child running.
				void operation.then(
					(handle) => {
						if (signal?.aborted) session.cancelRlmChildRun(handle.rlm_child_id, "Native spawn cancelled");
					},
					() => undefined,
				);
				return result(await awaitNativeOperation(operation, signal));
			}
			if (
				params.prompt !== undefined ||
				params.name !== undefined ||
				params.model !== undefined ||
				params.modelClass !== undefined ||
				params.isolation !== undefined ||
				params.writeFiles !== undefined ||
				params.priority !== undefined ||
				params.dependencies !== undefined
			)
				throw new Error("subagent spawn options require action=spawn");
			if (params.action === "list") {
				if (params.target !== undefined) throw new Error("subagent list does not accept target");
				return result(await awaitNativeOperation(session.listRlmSubagents(), signal));
			}
			if (!params.target?.trim()) throw new Error("subagent delete requires target");
			return result(await awaitNativeOperation(session.deleteRlmSubagent(params.target), signal));
		},
	});
	const advisor = defineTool({
		name: "advisor",
		label: "Advisor",
		description:
			"Consult the existing skeptical advisor about your recent approach. Returns advice only; does not execute actions.",
		parameters: Type.Object({ question: Type.Optional(Type.String()) }, { additionalProperties: false }),
		execute: async (_id, params, signal, _update, ctx) => {
			signal?.throwIfAborted();
			const blocked = await nativePermission(ctx, "advisor", false, signal);
			if (blocked) return blocked;
			return result(await awaitNativeOperation(session.handleAdvisorHostRequest(params, signal), signal));
		},
	});
	const loadSkill = defineTool({
		name: "load_skill",
		label: "Load Skill",
		description:
			"Load instructions for an exact visible skill name. Returns SKILL.md and reference directory; never executes a skill or guesses a callable. Execute only documented APIs using IPython.",
		promptGuidelines: [
			"Use load_skill with an exact available skill name before using its documented interface. Searching remains in IPython.",
		],
		parameters: Type.Object({ name: Type.String({ minLength: 1 }) }, { additionalProperties: false }),
		execute: async (_id, params, signal, _update, ctx) => {
			signal?.throwIfAborted();
			const blocked = await nativePermission(ctx, "load_skill", false, signal);
			if (blocked) return blocked;
			const skill = getSkills().find((skill) => skill.name === params.name && !skill.disableModelInvocation);
			if (!skill) throw new Error(`Skill ${JSON.stringify(params.name)} is not visible in this session`);
			const content = await readFile(skill.filePath, { encoding: "utf8", signal });
			return {
				content: [
					{
						type: "text",
						text: `Skill: ${skill.name}\nLocation: ${skill.filePath}\nReferences are relative to ${skill.baseDir}.\n\n${stripFrontmatter(content).trim()}`,
					},
				],
				details: { name: skill.name, filePath: skill.filePath, baseDir: skill.baseDir },
			};
		},
	});
	const coordination = defineTool({
		name: "coordination",
		label: "Coordination",
		description:
			"Inspect durable family agents, tasks, typed evidence, current lock owners/waiters and ready tasks; assign exact file scopes to direct children, reprioritize, cancel, or update your task status. Authority comes from the host session identity. Cancel or narrow conflicting scopes before assigning; priorities never preempt active writers.",
		promptGuidelines: [
			"Use coordination inspect to recover task IDs and stable session agent IDs. Parent assignments reserve exact files; finish or cancel unfinished tasks before replacing them.",
			"Use native read_file/write_file for coordinated access. Searching stays in IPython. Arbitrary IPython open calls are not arbitrated or tracked; these tools are not an OS sandbox.",
		],
		parameters: Type.Union([
			Type.Object({ action: Type.Literal("inspect") }, { additionalProperties: false }),
			Type.Object(
				{
					action: Type.Literal("assign"),
					id: Type.String({ minLength: 1 }),
					agentId: Type.String({ minLength: 1 }),
					title: Type.String({ minLength: 1, maxLength: 500 }),
					dependencies: Type.Array(Type.String(), { maxItems: 200 }),
					writeFiles: Type.Array(Type.String(), { maxItems: 200 }),
					priority: Type.Integer({ minimum: -100, maximum: 100 }),
				},
				{ additionalProperties: false },
			),
			Type.Object(
				{
					action: Type.Literal("reprioritize"),
					agentId: Type.String({ minLength: 1 }),
					priority: Type.Integer({ minimum: -100, maximum: 100 }),
				},
				{ additionalProperties: false },
			),
			Type.Object(
				{ action: Type.Literal("cancel"), taskId: Type.String({ minLength: 1 }) },
				{ additionalProperties: false },
			),
			Type.Object(
				{
					action: Type.Literal("status"),
					status: Type.Union([
						Type.Literal("idle"),
						Type.Literal("running"),
						Type.Literal("done"),
						Type.Literal("cancelled"),
					]),
				},
				{ additionalProperties: false },
			),
		]),
		execute: async (_id, params, signal, _update, ctx) => {
			const operationSignal = session.nativeOperationSignal(signal);
			operationSignal.throwIfAborted();
			if (params.action !== "inspect") {
				const blocked = await nativePermission(ctx, `coordination.${params.action}`, true, operationSignal);
				if (blocked) return blocked;
			} else {
				const blocked = await nativePermission(ctx, "coordination.inspect", false, operationSignal);
				if (blocked) return blocked;
			}
			const service = await session.getCoordination();
			operationSignal.throwIfAborted();
			switch (params.action) {
				case "inspect":
					return result(await service.graph(operationSignal));
				case "assign": {
					const { action: _action, ...task } = params;
					await service.assign(task, operationSignal);
					break;
				}
				case "reprioritize":
					await service.reprioritize(params.agentId, params.priority, operationSignal);
					break;
				case "cancel":
					await session.cancelCoordinationTask(params.taskId, operationSignal);
					break;
				case "status":
					if ((params.status === "done" || params.status === "cancelled") && session.isStreaming)
						throw new Error("Terminal coordination status is unavailable while execution continues");
					await service.update(params.status, operationSignal);
					break;
			}
			return result({ action: params.action, updated: true });
		},
	});
	const read = defineTool({
		name: "read_file",
		label: "Read File",
		description:
			"Read a bounded UTF-8 workspace file through cross-process coordination. Waits for the current writer to release; records native-read evidence. Symlinks, private state, traversal, hardlinks and ambiguous paths are denied.",
		parameters: Type.Object({ path: Type.String({ minLength: 1 }) }, { additionalProperties: false }),
		execute: async (_id, params, signal, _update, ctx) => {
			const operationSignal = session.nativeOperationSignal(signal);
			operationSignal.throwIfAborted();
			const blocked = await nativePermission(ctx, "read_file", false, operationSignal);
			if (blocked) return blocked;
			let text: string;
			let evidence = "native-read";
			try {
				text = await (await session.getCoordination()).read(params.path, operationSignal);
			} catch (error) {
				if (!canDegradeRead(error)) throw error;
				text = await readWorkspaceFile(session.getWorkspaceDir(), params.path, operationSignal);
				evidence = "uncoordinated-read";
			}
			return { content: [{ type: "text", text }], details: { path: params.path, evidence } };
		},
	});
	const write = defineTool({
		name: "write_file",
		label: "Write File",
		description:
			"Atomically replace a bounded UTF-8 workspace file using native cross-process arbitration. Respects all other reserved scopes, even for unassigned parents; assigned tasks must be running and within scope. Existing parent directory required. Records native-write evidence.",
		parameters: Type.Object(
			{ path: Type.String({ minLength: 1 }), content: Type.String() },
			{ additionalProperties: false },
		),
		execute: async (_id, params, signal, _update, ctx) => {
			const operationSignal = session.nativeOperationSignal(signal);
			const blocked = await nativePermission(ctx, "write_file", true, operationSignal);
			if (blocked) return blocked;
			await (await session.getCoordination()).write(params.path, params.content, operationSignal);
			return result({ path: params.path, written: true, evidence: "native-write" });
		},
	});
	const codeMap = defineTool({
		name: "code_map",
		label: "Code Map",
		description:
			"Read-only workspace file/dependency map. TypeScript/JavaScript edges are compiler-parsed and compiler-resolved; Python edges are syntactic. Unresolved specifiers are reported, never invented. Task dependencies live in coordination, never inferred from imports. Searching stays in IPython.",
		promptGuidelines: [
			"Use code_map dependencies/dependents to scope changes before editing. An import edge is not a task prerequisite.",
		],
		parameters: Type.Union([
			Type.Object({ action: Type.Literal("map") }, { additionalProperties: false }),
			Type.Object(
				{
					action: Type.Union([Type.Literal("dependencies"), Type.Literal("dependents")]),
					path: Type.String({ minLength: 1 }),
					maxDepth: Type.Optional(Type.Integer({ minimum: 1, maximum: 25 })),
				},
				{ additionalProperties: false },
			),
		]),
		execute: async (_id, params, signal, _update, ctx) => {
			const operationSignal = session.nativeOperationSignal(signal);
			operationSignal.throwIfAborted();
			const blocked = await nativePermission(ctx, "code_map", false, operationSignal);
			if (blocked) return blocked;
			const workspace = session.getWorkspaceDir();
			const map = await buildCodeMap({ workspace }, operationSignal);
			if (params.action === "map") {
				const edges = map.edges.slice(0, 1000);
				return result({
					files: map.files.length > 500 ? { count: map.files.length } : map.files,
					edgeCount: map.edges.length,
					edges,
					edgesTruncated: map.edges.length > edges.length,
					skipped: map.skipped.slice(0, 100),
					truncated: map.truncated,
				});
			}
			const path = await canonicalMapPath(workspace, params.path);
			if (!map.files.includes(path)) throw new Error(`File is not indexed by the code map: ${path}`);
			const neighbors =
				params.action === "dependencies"
					? dependenciesOf(map, path, params.maxDepth ?? 5)
					: dependentsOf(map, path, params.maxDepth ?? 5);
			return result({ path, action: params.action, neighbors });
		},
	});
	const definitions: ToolDefinition[] = [subagent, advisor, loadSkill, coordination, read, write, codeMap];
	if (getHandlers()["agent_message.send"])
		definitions.push(
			defineTool({
				name: "agent_message",
				label: "Agent Message",
				description:
					"List your family or send a message to parent, sibling or direct child using the existing authenticated messaging service. Use target=all for the existing family broadcast. No delivery controls or arbitrary identities.",
				promptGuidelines: [
					'Reply to a parent task with agent_message action="send", receiver_role="parent" when an answer is needed.',
				],
				parameters: Type.Object(
					{
						action: Type.Union([Type.Literal("list"), Type.Literal("send")]),
						message: Type.Optional(Type.String({ minLength: 1 })),
						receiver_role: Type.Optional(
							Type.Union([Type.Literal("parent"), Type.Literal("sibling"), Type.Literal("child")]),
						),
						receiver_name: Type.Optional(Type.String()),
						target: Type.Optional(Type.Literal("all")),
					},
					{ additionalProperties: false },
				),
				execute: async (_id, params, signal, _update, ctx) => {
					signal?.throwIfAborted();
					if (params.action === "send") {
						const blocked = await nativePermission(ctx, "agent_message.send", true, signal);
						if (blocked) return blocked;
					} else {
						const blocked = await nativePermission(ctx, "agent_message.list", false, signal);
						if (blocked) return blocked;
					}
					const { action, ...payload } = params;
					if (action === "list" && Object.values(payload).some((value) => value !== undefined))
						throw new Error("agent_message list does not accept send options");
					const handler =
						getHandlers(signal)[action === "list" ? "agent_message.list_agents" : "agent_message.send"];
					if (!handler) throw new Error("Agent messaging is not available in this session");
					return result(await awaitNativeOperation(handler(payload), signal));
				},
			}),
		);
	return definitions;
}
