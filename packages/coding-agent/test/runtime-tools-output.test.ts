import { validateToolArguments } from "@zero-agent/ai";
import { describe, expect, it, vi } from "vitest";
import type { ExtensionContext } from "../src/core/extensions/types.js";
import { type KernelAttachment, KernelManager } from "../src/core/kernel/index.js";
import { createIpythonToolDefinition, type IpythonKernelProvisioner } from "../src/core/tools/ipython.js";
import { createHostRuntimeTools } from "../src/core/tools/runtime-operations.js";
import { runtimePythonCode } from "../src/core/tools/runtime-python-tools.js";
import { normalizeKernelOutput } from "../src/modes/interactive/components/ipython-cell.js";

const ctx = {} as ExtensionContext;
describe("direct runtime operations", () => {
	it("routes goal actions and mutation permissions", async () => {
		const handler = vi.fn(async () => ({ goal: "saved" }));
		const permission = vi.fn(async () => undefined);
		const goal = createHostRuntimeTools(
			() => ({ "goal.get": handler, "goal.create": handler }),
			permission,
			async (p) => p,
		)[0];
		expect(goal.parameters).toMatchObject({
			type: "object",
			properties: expect.objectContaining({ objective: expect.any(Object) }),
			required: expect.arrayContaining(["action"]),
		});
		expect(() =>
			validateToolArguments(goal, { type: "toolCall", id: "bad", name: "goal", arguments: { action: "create" } }),
		).toThrow();
		await goal.execute("id", { action: "create", objective: "Ship" }, undefined, undefined, ctx);
		expect(handler).toHaveBeenCalledWith({ objective: "Ship" });
		expect(permission).toHaveBeenLastCalledWith(ctx, "goal", true, undefined);
		await goal.execute("id", { action: "get" }, undefined, undefined, ctx);
		expect(permission).toHaveBeenLastCalledWith(ctx, "goal", false, undefined);
	});
	it("does not execute after a block or abort", async () => {
		const handler = vi.fn(async () => ({}));
		const block = {
			content: [{ type: "text" as const, text: "blocked" }],
			details: { harmBlocked: true, action: "hard_block" },
			isError: true,
		};
		const tool = createHostRuntimeTools(
			() => ({ "goal.get": handler }),
			async () => block,
			async (p) => p,
		)[0];
		expect(await tool.execute("id", { action: "get" }, undefined, undefined, ctx)).toEqual(block);
		const controller = new AbortController();
		controller.abort();
		await expect(tool.execute("id", { action: "get" }, controller.signal, undefined, ctx)).rejects.toThrow();
		expect(handler).not.toHaveBeenCalled();
	});
	it("returns browser screenshots as images without base64 metadata", async () => {
		const tools = createHostRuntimeTools(
			() => ({ "browser.navigate": async () => ({}), "browser.screenshot": async () => ({ data: "AAAA" }) }),
			async () => undefined,
			async (p) => p,
		);
		const result = await tools[0].execute("id", { action: "screenshot" }, undefined, undefined, ctx);
		expect(result.content).toEqual([{ type: "image", mimeType: "image/png", data: "AAAA" }]);
		expect(result.details).toEqual({ captured: true });
	});
	it("omits unavailable operations", () => {
		expect(
			createHostRuntimeTools(
				() => ({}),
				async () => undefined,
				async (p) => p,
			),
		).toEqual([]);
	});
	it("encodes Python arguments as data", () => {
		const params = { new_str: "\"\n__import__('os').system('false')", path: "a\\b", flag: true, nothing: null };
		const code = runtimePythonCode("await edit(**_zero_tool_args)", params);
		const encoded = code.split("\n")[1].slice("_zero_tool_args = _zero_tool_json.loads(".length, -1);
		expect(JSON.parse(JSON.parse(encoded))).toEqual(params);
		expect(code.split("\n")).toHaveLength(3);
	});
});

describe("kernel output snapshots", () => {
	it("accumulates streams, bounds reprs and honors delayed clearing", () => {
		const manager = new KernelManager({ cwd: process.cwd() });
		const onOutput = vi.fn();
		const execution = {
			requestMsgId: "cell",
			stdout: "",
			stderr: "",
			result: undefined as string | undefined,
			maxChars: 8,
			stdoutTruncated: false,
			stderrTruncated: false,
			opts: { onOutput },
			diffs: [],
			attachments: [] as KernelAttachment[],
			sentAgentMessages: [],
		};
		const internals = manager as unknown as {
			activeExecution: typeof execution;
			handleExecutionMessage: (msg: unknown) => void;
		};
		internals.activeExecution = execution;
		const send = (type: string, content: Record<string, unknown>, parent = "cell") =>
			internals.handleExecutionMessage({
				header: { msg_type: type },
				parent_header: { msg_id: parent },
				metadata: {},
				content,
			});
		send("stream", { name: "stdout", text: "one" });
		send("stream", { name: "stdout", text: "two" });
		expect(onOutput).toHaveBeenLastCalledWith({ stdout: "onetwo", stderr: "", result: undefined });
		send("stream", { name: "stdout", text: "12345" });
		expect(execution.stdout).toBe("onetwo12");
		expect(execution.stdoutTruncated).toBe(true);
		send("execute_result", { data: { "text/plain": "a".repeat(1000) } });
		expect(execution.result).toContain("truncated at 8 chars");
		send("clear_output", { wait: true });
		expect(execution.stdout).toBe("onetwo12");
		send("display_data", { data: { "text/plain": "fresh" } });
		expect(execution.stdout).toBe("");
		expect(execution.stdoutTruncated).toBe(false);
		expect(execution.result).toBe("fresh");
		send("display_data", { data: { "image/png": "AAAA" } });
		expect(execution.attachments).toEqual([{ mimeType: "image/png", data: "AAAA", path: undefined }]);
		send("stream", { name: "stderr", text: "warning" }, "other-cell");
		expect(execution.stderr).toBe("");
		send("clear_output", { wait: false });
		expect(onOutput).toHaveBeenLastCalledWith({ stdout: "", stderr: "", result: undefined });
	});
	it("coalesces cumulative updates and cancels pending updates after completion", async () => {
		const execute: KernelManager["execute"] = async (_code, options) => {
			options?.onOutput?.({ stdout: "a", stderr: "" });
			options?.onOutput?.({ stdout: "ab", stderr: "warning" });
			await new Promise((resolve) => setTimeout(resolve, 70));
			options?.onOutput?.({ stdout: "final", stderr: "warning", result: "42" });
			return { stdout: "final", stderr: "warning", result: "42", status: "ok", durationMs: 70 };
		};
		const provisioner = { ensure: async () => ({ execute }) } as unknown as IpythonKernelProvisioner;
		const tool = createIpythonToolDefinition(process.cwd(), { provisioner });
		const update = vi.fn();
		const result = await tool.execute("cell", { code: "42" }, undefined, update, ctx);
		expect(update).toHaveBeenCalledTimes(1);
		expect(update.mock.calls[0][0].details).toMatchObject({ stdout: "ab", stderr: "warning" });
		expect(result.details).toMatchObject({ stdout: "final", result: "42" });
		await new Promise((resolve) => setTimeout(resolve, 70));
		expect(update).toHaveBeenCalledTimes(1);
	});

	it("normalizes progress and control characters", () => {
		expect(normalizeKernelOutput("10%\r100%\r\n\x1b[31merror\x1b[0m\x07")).toBe("100%\nerror");
	});
});
