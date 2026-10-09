import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fauxAssistantMessage, fauxToolCall } from "@zero-agent/ai";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentSessionMessageController } from "../../src/core/agent-messages.js";
import { AgentSession } from "../../src/core/agent-session.js";
import { createAgentSession } from "../../src/core/sdk.js";
import type { Skill } from "../../src/core/skills.js";
import { createSyntheticSourceInfo } from "../../src/core/source-info.js";
import { awaitNativeOperation } from "../../src/core/tools/native-runtime.js";
import { createTestResourceLoader } from "../utilities.js";
import { createHarness, type Harness } from "./harness.js";

describe("native runtime tools", () => {
	const harnesses: Harness[] = [];
	afterEach(async () => {
		for (const harness of harnesses.splice(0)) {
			await harness.session.disposeAsync();
			harness.cleanup();
		}
	});

	it("activates native adapters alongside IPython without a search tool", async () => {
		const h = await createHarness();
		harnesses.push(h);
		expect(h.session.getActiveToolNames()).toEqual(
			expect.arrayContaining([
				"ipython",
				"subagent",
				"advisor",
				"load_skill",
				"coordination",
				"read_file",
				"write_file",
				"code_map",
			]),
		);
		expect(h.session.getActiveToolNames()).not.toContain("search");
	});

	it("reads goals through a schema-validated native call without executing Python", async () => {
		const h = await createHarness({ initialGoal: { objective: "ship native tools" } });
		harnesses.push(h);
		const python = vi.spyOn(h.session.getToolDefinition("ipython")!, "execute");
		h.setResponses([
			fauxAssistantMessage([fauxToolCall("goal", { action: "get" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("read"),
		]);
		await h.session.prompt("read the current goal");
		const result = h.session.messages.find((message) => message.role === "toolResult" && message.toolName === "goal");
		expect(result).toMatchObject({ isError: false, details: { goal: { objective: "ship native tools" } } });
		expect(python).not.toHaveBeenCalled();
	});

	it("session cancellation settles a direct host wait even without a caller signal", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const browser = vi.spyOn(h.session, "handleBrowserHostRequest").mockImplementation(() => new Promise(() => {}));
		const operation = h.session.state.tools
			.find((tool) => tool.name === "browser")!
			.execute("wait", { action: "navigate", url: "https://example.com" });
		const rejection = expect(operation).rejects.toThrow("cancelled");
		await vi.waitFor(() => expect(browser).toHaveBeenCalled());
		h.session.requestAbort();
		await rejection;
	});

	it("produces durable native file evidence and lifecycle state through a real faux-provider turn", async () => {
		const h = await createHarness();
		harnesses.push(h);
		h.setResponses([
			fauxAssistantMessage([fauxToolCall("write_file", { path: "native.txt", content: "native content" })], {
				stopReason: "toolUse",
			}),
			fauxAssistantMessage([fauxToolCall("read_file", { path: "native.txt" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("finished"),
		]);
		await h.session.prompt("write and read");
		expect(await readFile(join(h.tempDir, "native.txt"), "utf8")).toBe("native content");
		const inspect = h.session.state.tools.find((tool) => tool.name === "coordination")!;
		const graph = (await inspect.execute("inspect", { action: "inspect" })).details as {
			agents: Record<string, unknown>;
			links: unknown[];
		};
		const path = await (await h.session.getCoordination()).canonicalPath("native.txt");
		expect(graph.agents[h.session.sessionId]).toMatchObject({
			status: "done",
			readFiles: [path],
			writeFiles: [path],
		});
		expect(graph.links).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ grade: "native-write" }),
				expect.objectContaining({ grade: "native-read" }),
			]),
		);
		const files = await readdir(join(h.tempDir, ".zero/coordination/families"));
		expect(files.some((file) => file.endsWith(".json"))).toBe(true);
		for (const mode of ["plan", "manual"] as const) {
			h.session.setSessionMode(mode);
			expect(
				(
					await h.session.state.tools
						.find((tool) => tool.name === "write_file")!
						.execute("blocked", { path: "native.txt", content: "bad" })
				).details,
			).toMatchObject({ harmBlocked: true });
			expect((await inspect.execute("blocked", { action: "status", status: "running" })).details).toMatchObject({
				harmBlocked: true,
			});
		}
	});

	it("delegates through the existing runtime and blocks mutations in plan/manual", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const spawn = vi
			.spyOn(h.session, "runRlmChild")
			.mockResolvedValue({ rlm_child_id: "child", name: "worker", session_dir: "dir", model: "faux/test" });
		const tool = h.session.state.tools.find((t) => t.name === "subagent")!;
		const result = await tool.execute("spawn", { action: "spawn", prompt: "review", name: "worker" });
		expect(result.details).toMatchObject({ rlm_child_id: "child" });
		expect(spawn).toHaveBeenCalledWith("review", { name: "worker" }, undefined, undefined);
		for (const mode of ["plan", "manual"] as const) {
			h.session.setSessionMode(mode);
			expect((await tool.execute("blocked", { action: "spawn", prompt: "edit" })).details).toMatchObject({
				harmBlocked: true,
			});
		}
		expect(spawn).toHaveBeenCalledTimes(1);
	});

	it("rejects hidden and unknown skills instead of executing guessed functions", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const tool = h.session.state.tools.find((t) => t.name === "load_skill")!;
		await expect(tool.execute("skill", { name: "unknown" })).rejects.toThrow("not visible");
	});

	it("does not start an already cancelled operation", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const spawn = vi.spyOn(h.session, "runRlmChild");
		const abort = new AbortController();
		abort.abort();
		await expect(
			h.session.state.tools
				.find((t) => t.name === "subagent")!
				.execute("cancel", { action: "spawn", prompt: "review" }, abort.signal),
		).rejects.toThrow();
		expect(spawn).not.toHaveBeenCalled();
	});

	it("exposes native tools to the faux provider", async () => {
		const h = await createHarness();
		harnesses.push(h);
		h.setResponses([
			fauxAssistantMessage([fauxToolCall("subagent", { action: "list" })], { stopReason: "toolUse" }),
			fauxAssistantMessage("ready"),
		]);
		await h.session.prompt("ready");
		expect(h.session.getLastAssistantText()).toBe("ready");
		expect(
			h.session.messages.find((message) => message.role === "toolResult" && message.toolName === "subagent"),
		).toMatchObject({ isError: false, details: { subagents: [] } });
	});

	it("SDK defaults activate adapters while explicit allowlists stay authoritative", async () => {
		const h = await createHarness();
		harnesses.push(h);
		for (const tools of [undefined, ["load_skill"], []]) {
			const { session } = await createAgentSession({
				cwd: h.tempDir,
				model: h.getModel(),
				modelRegistry: h.session.modelRegistry,
				settingsManager: h.settingsManager,
				sessionManager: h.sessionManager,
				resourceLoader: createTestResourceLoader(),
				tools,
			});
			try {
				if (tools) expect(session.getActiveToolNames()).toEqual(tools);
				else expect(session.getActiveToolNames()).toContain("subagent");
			} finally {
				session.dispose();
			}
		}
	});

	it("settles cancelled waits even if a host hangs and observes late failures", async () => {
		const abort = new AbortController();
		let reject!: (error: Error) => void;
		const operation = new Promise<never>((_resolve, fail) => {
			reject = fail;
		});
		const wait = awaitNativeOperation(operation, abort.signal);
		abort.abort();
		await expect(wait).rejects.toThrow("cancelled");
		reject(new Error("late failure"));
	});

	it("cancels late spawn admission without orphaning a child", async () => {
		const h = await createHarness();
		harnesses.push(h);
		let admit!: (handle: { rlm_child_id: string; name: string; session_dir: string; model: string }) => void;
		vi.spyOn(h.session, "runRlmChild").mockImplementation(
			() =>
				new Promise((resolve) => {
					admit = resolve;
				}),
		);
		const cancel = vi.spyOn(h.session, "cancelRlmChildRun").mockReturnValue(true);
		const abort = new AbortController();
		const operation = h.session.state.tools
			.find((tool) => tool.name === "subagent")!
			.execute("spawn", { action: "spawn", prompt: "review" }, abort.signal);
		await vi.waitFor(() => expect(admit).toBeDefined());
		abort.abort();
		await expect(operation).rejects.toThrow("cancelled");
		admit({ rlm_child_id: "late-child", name: "late", session_dir: "dir", model: "faux/test" });
		await vi.waitFor(() => expect(cancel).toHaveBeenCalledWith("late-child", "Native spawn cancelled"));
	});

	it("requires manual approval and cancels a hung confirmation", async () => {
		const h = await createHarness();
		harnesses.push(h);
		h.session.setSessionMode("manual");
		const spawn = vi
			.spyOn(h.session, "runRlmChild")
			.mockResolvedValue({ rlm_child_id: "child", name: "worker", session_dir: "dir", model: "faux/test" });
		const ctx = h.session.extensionRunner.createContext();
		const confirm = vi.fn().mockResolvedValue(false);
		const manualCtx = { ...ctx, hasUI: true, ui: { ...ctx.ui, confirm } };
		const definition = h.session.getToolDefinition("subagent")!;
		expect(
			(await definition.execute("declined", { action: "spawn", prompt: "review" }, undefined, undefined, manualCtx))
				.details,
		).toMatchObject({ harmBlocked: true });
		expect(spawn).not.toHaveBeenCalled();
		confirm.mockResolvedValue(true);
		await definition.execute("approved", { action: "spawn", prompt: "review" }, undefined, undefined, manualCtx);
		expect(spawn).toHaveBeenCalledTimes(1);
		confirm.mockImplementation(() => new Promise(() => {}));
		const abort = new AbortController();
		const operation = definition.execute(
			"cancelled",
			{ action: "spawn", prompt: "review" },
			abort.signal,
			undefined,
			manualCtx,
		);
		abort.abort();
		await expect(operation).rejects.toThrow();
		expect(spawn).toHaveBeenCalledTimes(1);
	});

	it("requires manual approval for read-only native tools", async () => {
		const h = await createHarness({
			resourceLoader: createTestResourceLoader({ skills: [skill("agent-message")] }),
			agentMessageController: {
				listAgents: () => ({ agents: [] }),
				roster: () => ({ current: { name: "parent", id: "parent", depth: 0 }, entries: [] }),
				sendAgentMessage: async () => {
					throw new Error("not used");
				},
			},
		});
		harnesses.push(h);
		h.session.setSessionMode("manual");
		await writeFile(join(h.tempDir, "read.txt"), "content");
		const ctx = h.session.extensionRunner.createContext();
		const confirm = vi.fn().mockResolvedValue(false);
		const manualCtx = { ...ctx, hasUI: true, ui: { ...ctx.ui, confirm } };
		for (const [name, params] of [
			["read_file", { path: "read.txt" }],
			["coordination", { action: "inspect" }],
			["subagent", { action: "list" }],
			["advisor", {}],
			["load_skill", { name: "unknown" }],
			["write_file", { path: "write.txt", content: "blocked" }],
			["code_map", { action: "map" }],
			["agent_message", { action: "list" }],
		] as const) {
			const definition = h.session.getToolDefinition(name)!;
			expect((await definition.execute(name, params, undefined, undefined, manualCtx)).details).toMatchObject({
				harmBlocked: true,
			});
		}
		expect(confirm).toHaveBeenCalledTimes(8);
	});

	it("does not create coordination state for a tool-free prompt", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const { session } = await createAgentSession({
			cwd: h.tempDir,
			model: h.getModel(),
			modelRegistry: h.session.modelRegistry,
			settingsManager: h.settingsManager,
			sessionManager: h.sessionManager,
			resourceLoader: createTestResourceLoader(),
			tools: [],
		});
		try {
			h.setResponses([fauxAssistantMessage("tool-free")]);
			await session.prompt("answer without tools");
			await expect(readdir(join(h.tempDir, ".zero/coordination"))).rejects.toThrow();
		} finally {
			session.dispose();
		}
	});

	it("degrades read_file when coordination storage is read-only", async () => {
		const h = await createHarness();
		harnesses.push(h);
		await writeFile(join(h.tempDir, "read-only.txt"), "readable");
		const error = Object.assign(new Error("read-only coordination storage"), { code: "EROFS" });
		vi.spyOn(h.session, "getCoordination").mockRejectedValue(error);
		const tool = h.session.state.tools.find((candidate) => candidate.name === "read_file")!;
		const result = await tool.execute("read-only", { path: "read-only.txt" });
		expect(result.content).toEqual([{ type: "text", text: "readable" }]);
		expect(result.details).toMatchObject({ evidence: "uncoordinated-read" });
	});

	it("does not fail an ordinary prompt when optional lifecycle coordination is read-only", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const error = Object.assign(new Error("read-only coordination storage"), { code: "EROFS" });
		vi.spyOn(h.session, "getCoordination").mockRejectedValue(error);
		h.setResponses([fauxAssistantMessage("continued")]);

		await expect(h.session.prompt("answer normally")).resolves.toBeUndefined();
		expect(h.session.getLastAssistantText()).toBe("continued");
	});

	it("marks a failed prompt cancelled instead of done", async () => {
		const h = await createHarness();
		harnesses.push(h);
		h.setResponses([fauxAssistantMessage("failed", { stopReason: "error", errorMessage: "provider failed" })]);
		await h.session.prompt("fail");
		const graph = await h.session.getCoordinationGraph();
		const task = Object.values(graph.tasks).find((candidate) => candidate.title === "fail");
		expect(task?.status).toBe("cancelled");
	});

	it("marks a prompt cancelled when execution fails before the agent starts", async () => {
		const h = await createHarness();
		harnesses.push(h);
		vi.spyOn(h.session.agent, "prompt").mockRejectedValueOnce(new Error("failed before start"));

		await expect(h.session.prompt("never started")).rejects.toThrow("failed before start");
		const graph = await h.session.getCoordinationGraph();
		const task = Object.values(graph.tasks).find((candidate) => candidate.title === "never started");
		expect(task?.status).toBe("cancelled");
	});

	it("rejects terminal coordination status while a native tool turn is executing", async () => {
		const h = await createHarness();
		harnesses.push(h);
		h.setResponses([
			fauxAssistantMessage([fauxToolCall("coordination", { action: "status", status: "done" })], {
				stopReason: "toolUse",
			}),
			fauxAssistantMessage("finished"),
		]);
		await h.session.prompt("work");
		const result = h.session.messages.find(
			(message) => message.role === "toolResult" && message.toolName === "coordination",
		);
		expect(result).toMatchObject({ isError: true });
		expect(JSON.stringify(result)).toContain("execution continues");
	});

	function skill(name: string, hidden = false): Skill {
		return {
			name,
			description: "fixture",
			kind: "markdown",
			filePath: join(process.cwd(), "test/suite/native-tools.test.ts"),
			baseDir: process.cwd(),
			sourceInfo: createSyntheticSourceInfo("<test>", { source: "test" }),
			disableModelInvocation: hidden,
		};
	}

	it("loads visible instructions and withholds disabled skills", async () => {
		const h = await createHarness({
			resourceLoader: createTestResourceLoader({ skills: [skill("visible"), skill("hidden", true)] }),
		});
		harnesses.push(h);
		const tool = h.session.state.tools.find((t) => t.name === "load_skill")!;
		expect((await tool.execute("visible", { name: "visible" })).content).toEqual([
			expect.objectContaining({ text: expect.stringContaining("References are relative to") }),
		]);
		await expect(tool.execute("hidden", { name: "hidden" })).rejects.toThrow("not visible");
	});

	it("uses family resolution and existing receipts, and tracks explicit parent replies", async () => {
		const send = vi.fn<AgentSessionMessageController["sendAgentMessage"]>().mockResolvedValue({
			id: "receipt",
			source: "agent_message",
			target: { activeSessionId: "active-parent", sessionId: "parent" },
			message: "answer",
			deliveryStatus: "queued",
		});
		const controller: AgentSessionMessageController = {
			listAgents: () => ({ agents: [] }),
			roster: () => ({
				current: { name: "child", id: "child", depth: 1 },
				entries: [{ relationship: "parent", name: "parent", id: "parent", depth: 0, status: "idle" }],
			}),
			sendAgentMessage: send,
		};
		const h = await createHarness({
			rlmDepth: 1,
			agentMessageController: controller,
			resourceLoader: createTestResourceLoader({ skills: [skill("agent-message")] }),
		});
		harnesses.push(h);
		const tool = h.session.state.tools.find((t) => t.name === "agent_message")!;
		expect(
			(await tool.execute("send", { action: "send", message: "answer", receiver_role: "parent" })).details,
		).toMatchObject({ id: "receipt", deliveryStatus: "queued" });
		expect(send).toHaveBeenCalledWith({ target: "parent", message: "answer" });
		expect(h.session.repliedToParentSinceTask).toBe(true);
		await expect(
			tool.execute("unrelated", {
				action: "send",
				message: "answer",
				receiver_role: "child",
				receiver_name: "unrelated",
			}),
		).rejects.toThrow("No child matches");
		h.session.setSessionMode("plan");
		expect(
			(await tool.execute("blocked", { action: "send", message: "answer", receiver_role: "parent" })).details,
		).toMatchObject({ harmBlocked: true });
		expect(send).toHaveBeenCalledTimes(1);
	});

	it("advisor uses the existing consultation service and receives cancellation", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const consult = vi
			.spyOn(h.session, "handleAdvisorHostRequest")
			.mockResolvedValue({ advice: "review", outcome: "complete", error_message: null });
		const abort = new AbortController();
		expect(
			(
				await h.session.state.tools
					.find((t) => t.name === "advisor")!
					.execute("advisor", { question: "risk?" }, abort.signal)
			).details,
		).toMatchObject({ advice: "review" });
		expect(consult).toHaveBeenCalledWith({ question: "risk?" }, abort.signal);
	});

	it("cancellation during family lookup prevents a later message send", async () => {
		let finishRoster!: () => void;
		const rosterReady = new Promise<void>((resolve) => {
			finishRoster = resolve;
		});
		const send = vi.fn<AgentSessionMessageController["sendAgentMessage"]>();
		let lookupStarted = false;
		const h = await createHarness({
			resourceLoader: createTestResourceLoader({ skills: [skill("agent-message")] }),
			agentMessageController: {
				listAgents: () => ({ agents: [] }),
				roster: async () => {
					lookupStarted = true;
					await rosterReady;
					return {
						current: { name: "child", id: "child", depth: 1 },
						entries: [{ relationship: "parent", name: "parent", id: "parent", depth: 0, status: "idle" }],
					};
				},
				sendAgentMessage: send,
			},
		});
		harnesses.push(h);
		const abort = new AbortController();
		const operation = h.session.state.tools
			.find((tool) => tool.name === "agent_message")!
			.execute("send", { action: "send", message: "answer", receiver_role: "parent" }, abort.signal);
		await vi.waitFor(() => expect(lookupStarted).toBe(true));
		abort.abort();
		await expect(operation).rejects.toThrow("cancelled");
		finishRoster();
		await rosterReady;
		await new Promise((resolve) => setImmediate(resolve));
		expect(send).not.toHaveBeenCalled();
	});

	it("real child admission preserves active tools and mode", async () => {
		const h = await createHarness({ persistSession: true });
		harnesses.push(h);
		let child: AgentSession | undefined;
		h.session.setSubagentRuntimeHost({
			createRlmSubagentRuntime: async (options) => {
				expect(options.activeToolNames).toEqual(h.session.getActiveToolNames());
				expect(options.mode).toBe("auto");
				const ch = await createHarness({ tools: [], rlmDepth: options.rlmDepth, rlmMaxDepth: options.rlmMaxDepth });
				harnesses.push(ch);
				ch.session.dispose();
				const runtimeChild = new AgentSession({
					agent: ch.session.agent,
					sessionManager: ch.sessionManager,
					settingsManager: ch.settingsManager,
					cwd: ch.tempDir,
					resourceLoader: createTestResourceLoader(),
					modelRegistry: ch.session.modelRegistry,
					rlmSessionDir: options.sessionDir,
					rlmDepth: options.rlmDepth,
					rlmMaxDepth: options.rlmMaxDepth,
					initialActiveToolNames: options.activeToolNames,
					allowedToolNames: options.allowedToolNames,
					mode: options.mode,
				});
				child = runtimeChild;
				h.session.registerDisposeCallback(() => runtimeChild.dispose());
				ch.setResponses([
					fauxAssistantMessage([fauxToolCall("write_file", { path: "child.txt", content: "child wrote" })], {
						stopReason: "toolUse",
					}),
					fauxAssistantMessage("child answer"),
				]);
				return { session: runtimeChild };
			},
			deleteRlmSubagentRuntime: async () => {},
		});
		const result = await h.session.state.tools
			.find((t) => t.name === "subagent")!
			.execute("spawn", {
				action: "spawn",
				prompt: "review",
				name: "worker",
				writeFiles: ["child.txt"],
				priority: 4,
			});
		expect(result.details).toMatchObject({ name: "worker" });
		const id = (result.details as { rlm_child_id: string }).rlm_child_id;
		await vi.waitFor(() => expect(child?.getLastAssistantText()).toBe("child answer"));
		await vi.waitFor(
			async () => {
				const done = Object.values((await h.session.getCoordinationGraph()).tasks).find(
					(task) => task.agentId === child?.sessionId && task.id === `spawn:${id}`,
				);
				expect(done?.status).toBe("done");
			},
			{ timeout: 15_000 },
		);
		expect((await h.session.listRlmSubagents()).subagents.some((entry) => entry.rlm_child_id === id)).toBe(true);
		const parentService = await h.session.getCoordination();
		const childService = await child!.getCoordination();
		expect(childService.options.familyId).toBe(parentService.options.familyId);
		expect(childService.options.storageDir).toBe(parentService.options.storageDir);
		expect(childService.options.parentId).toBe(h.session.sessionId);
		const graph = await h.session.getCoordinationGraph();
		expect(graph.agents[child!.sessionId]).toMatchObject({ parentId: h.session.sessionId, status: "done" });
		expect(Object.values(graph.tasks)).toEqual(
			expect.arrayContaining([
				expect.objectContaining({ agentId: child!.sessionId, status: "done", priority: 4, writePolicy: "scoped" }),
			]),
		);
		expect(await childService.read("child.txt")).toBe("child wrote");
		await h.session.deleteRlmSubagent(id);
	});

	it("session cancellation releases native waits and leaves no owner or waiter behind", async () => {
		const h = await createHarness();
		harnesses.push(h);
		const service = await h.session.getCoordination();
		await service.write("held.txt", "before");
		let release!: () => void;
		let entered!: () => void;
		const ready = new Promise<void>((resolve) => {
			entered = resolve;
		});
		const writer = service.withFile("held.txt", async () => {
			entered();
			await new Promise<void>((resolve) => {
				release = resolve;
			});
		});
		await ready;
		const reader = h.session.state.tools
			.find((tool) => tool.name === "read_file")!
			.execute("waiting", { path: "held.txt" });
		const rejected = expect(reader).rejects.toThrow();
		try {
			await vi.waitFor(async () =>
				expect((await service.graph()).locks.some((lock) => lock.waiters.length > 0)).toBe(true),
			);
			h.session.requestAbort();
			await rejected;
		} finally {
			release();
			await writer;
		}
		expect((await service.graph()).locks).toEqual([]);
		expect(await service.read("held.txt")).toBe("before");
	});

	it("exposes a read-only compiler-resolved code map over the session workspace", async () => {
		const h = await createHarness();
		harnesses.push(h);
		await writeFile(join(h.tempDir, "map-a.ts"), `import { mapB } from "./map-b.js";\nconsole.log(mapB);\n`);
		await writeFile(join(h.tempDir, "map-b.ts"), `export const mapB = 1;\n`);
		const tool = h.session.state.tools.find((tool) => tool.name === "code_map")!;
		const dependencies = (await tool.execute("deps", { action: "dependencies", path: "map-a.ts" })).details as {
			neighbors: { path: string }[];
		};
		expect(dependencies.neighbors.map((neighbor) => neighbor.path)).toEqual(["map-b.ts"]);
		const dependents = (await tool.execute("rev", { action: "dependents", path: "map-b.ts" })).details as {
			neighbors: { path: string }[];
		};
		expect(dependents.neighbors.map((neighbor) => neighbor.path)).toEqual(["map-a.ts"]);
		await expect(tool.execute("outside", { action: "dependencies", path: "../outside.ts" })).rejects.toThrow();
	});
});
