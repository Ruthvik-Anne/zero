import { setKeybindings, visibleWidth } from "@zero-agent/tui";
import stripAnsi from "strip-ansi";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { KeybindingsManager } from "../src/core/keybindings.js";
import type { AgentConnectionRlmChildAgentSnapshot } from "../src/modes/agent-connection/types.js";
import {
	countDirectSubagentStatuses,
	listDirectSubagentEntries,
	SubagentSummaryLine,
} from "../src/modes/interactive/components/subagent-summary-line.js";
import { InteractiveMode, RenderOnceContainer } from "../src/modes/interactive/interactive-mode.js";
import { initTheme } from "../src/modes/interactive/theme/theme.js";

function child(
	id: string,
	status: AgentConnectionRlmChildAgentSnapshot["status"],
	overrides: Partial<AgentConnectionRlmChildAgentSnapshot> = {},
): AgentConnectionRlmChildAgentSnapshot {
	return { id, label: id, status, sessionDir: `/tmp/${id}`, ...overrides };
}

describe("SubagentSummaryLine", () => {
	beforeAll(() => {
		initTheme("dark");
		setKeybindings(new KeybindingsManager());
	});

	it("renders no subagent line without children and uses singular and plural labels", () => {
		const line = new SubagentSummaryLine();
		expect(line.render(120)).toEqual([]);

		line.setSubagentCounts({ total: 1, running: 1, idle: 0, inactive: 0 });
		let rendered = line.render(120).map(stripAnsi);
		expect(rendered).toHaveLength(1);
		expect(rendered[0]).toContain("1 subagent: 1 running · 0 idle · 0 inactive");

		line.setSubagentCounts({ total: 2, running: 1, idle: 1, inactive: 0 });
		rendered = line.render(120).map(stripAnsi);
		expect(rendered[0]).toContain("2 subagents: 1 running · 1 idle · 0 inactive");
	});

	it("counts only direct children using running, idle, and inactive status projections", () => {
		const children = [
			child("running", "running"),
			child("queued", "queued"),
			child("active", "done", { activity: { kind: "writing" } }),
			child("heartbeat", "done", { activeSessionId: "heartbeat-session" }),
			child("idle-done", "done", { activeSessionId: "idle-done-session" }),
			child("idle-error", "error", { activeSessionId: "idle-error-session" }),
			child("inactive-done", "done"),
			child("inactive-error", "error"),
			child("cancelled", "cancelled"),
			child("grandchild", "running", { parentId: "running" }),
		];

		expect(countDirectSubagentStatuses(children, undefined, new Set(["heartbeat-session"]))).toEqual({
			total: 8,
			running: 4,
			idle: 2,
			inactive: 2,
		});
	});

	it("shows children by default and toggles the inline list on Enter or Right", () => {
		const line = new SubagentSummaryLine();
		line.setSubagentCounts({ total: 2, running: 1, idle: 1, inactive: 0 });
		line.setSubagentEntries([
			{ id: "a", label: "a", status: "running" },
			{ id: "b", label: "b", status: "idle", recap: "wrote the report" },
		]);

		let rendered = line.render(100).map(stripAnsi);
		expect(rendered).toHaveLength(3);
		expect(rendered[1]).toContain("a — running");
		expect(rendered[2]).toContain("b — idle");
		expect(rendered[2]).toContain("wrote the report");

		line.handleInput("\r");
		rendered = line.render(100).map(stripAnsi);
		expect(rendered).toHaveLength(1);
		line.setSubagentEntries([{ id: "a", label: "updated", status: "idle" }]);
		expect(line.render(100)).toHaveLength(1);
		line.handleInput("\x1b[C");
		expect(stripAnsi(line.render(100)[1])).toContain("updated");
	});

	it("bounds expanded rows and widths as the terminal shrinks and grows", () => {
		let rows = 4;
		const line = new SubagentSummaryLine(
			() => "location",
			undefined,
			undefined,
			() => rows,
		);
		line.setSubagentCounts({ total: 5, running: 5, idle: 0, inactive: 0 });
		line.setSubagentEntries(
			Array.from({ length: 5 }, (_, i) => ({
				id: String(i),
				label: `long-worker-${i}`,
				status: "running" as const,
			})),
		);
		expect(line.render(30)).toHaveLength(4);
		expect(stripAnsi(line.render(30).at(-1)!)).toContain("4 more");
		for (const width of [1, 8, 30]) {
			expect(line.render(width).every((text) => visibleWidth(text) <= width)).toBe(true);
		}
		rows = 2;
		expect(line.render(30)).toHaveLength(2);
		rows = 10;
		expect(line.render(30)).toHaveLength(7);
	});

	it("pads focused and child rows by terminal display width", () => {
		const line = new SubagentSummaryLine();
		line.focused = true;
		line.setSubagentCounts({ total: 1, running: 1, idle: 0, inactive: 0 });
		line.setSubagentEntries([{ id: "wide", label: "界-worker", status: "running", recap: "✅ ready" }]);

		const rendered = line.render(32);
		expect(rendered).toHaveLength(2);
		for (const row of rendered) expect(visibleWidth(row)).toBe(32);
	});

	it("measures a component for row budgeting without rendering it twice in the frame", () => {
		const child = {
			invalidate: vi.fn(),
			render: vi.fn((width: number) => ["first".padEnd(width), "second".padEnd(width)]),
		};
		const container = new RenderOnceContainer();
		container.addChild(child);

		expect(container.measureNextRender(40)).toBe(2);
		expect(container.render(40)).toHaveLength(2);
		expect(child.render).toHaveBeenCalledTimes(1);
		container.render(40);
		expect(child.render).toHaveBeenCalledTimes(2);
	});

	it("budgets rows from the rendered editor and a custom footer with one render each", () => {
		const editor = {
			invalidate: vi.fn(),
			render: vi.fn(() => ["editor", "editor"]),
		};
		const customFooter = {
			invalidate: vi.fn(),
			render: vi.fn(() => ["footer", "footer", "footer"]),
		};
		const editorContainer = new RenderOnceContainer();
		const footerSlot = new RenderOnceContainer();
		editorContainer.addChild(editor);
		footerSlot.addChild(customFooter);
		const mode = Object.assign(Object.create(InteractiveMode.prototype), {
			editorContainer,
			footerSlot,
			ui: { terminal: { columns: 80, rows: 24 } },
		});
		const getMaxRows = Reflect.get(InteractiveMode.prototype, "getSubagentMaxRows") as (this: typeof mode) => number;

		editorContainer.render(80);
		expect(getMaxRows.call(mode)).toBe(8);
		footerSlot.render(80);
		expect(editor.render).toHaveBeenCalledTimes(1);
		expect(customFooter.render).toHaveBeenCalledTimes(1);
	});

	it("collapses before returning focus and does not reopen on status updates", () => {
		const line = new SubagentSummaryLine();
		line.setSubagentCounts({ total: 1, running: 1, idle: 0, inactive: 0 });
		line.setSubagentEntries([{ id: "a", label: "a", status: "running" }]);
		line.onCancel = vi.fn();
		line.handleInput("\x1b");
		line.setSubagentCounts({ total: 1, running: 0, idle: 1, inactive: 0 });
		expect(line.render(100)).toHaveLength(1);
		expect(line.onCancel).not.toHaveBeenCalled();
		line.handleInput("\x1b");
		expect(line.onCancel).toHaveBeenCalledOnce();
	});

	it("stays visible but non-expandable with no subagents", () => {
		const line = new SubagentSummaryLine();
		line.setSubagentCounts({ total: 0, running: 0, idle: 0, inactive: 0 });

		expect(line.isSelectable()).toBe(false);
		line.handleInput("\r");
		expect(line.render(100)).toEqual([]);
	});

	it("updates the rendered counts from consecutive child-status events", () => {
		const line = new SubagentSummaryLine();
		const mode = Object.create(InteractiveMode.prototype) as InteractiveMode & Record<string, unknown>;
		Object.assign(mode, {
			subagentSnapshots: new Map<string, AgentConnectionRlmChildAgentSnapshot>(),
			rlmNodeId: undefined,
			heartbeatCatalog: [],
			subagentSummaryLine: line,
			updateScopedHeartbeats: vi.fn(),
			updateWorkingPulse: vi.fn(),
			syncWorkingLoader: vi.fn(),
			updateWorkingLoaderMessage: vi.fn(),
			ui: { requestRender: vi.fn() },
		});
		const update = Reflect.get(InteractiveMode.prototype, "updateSubagentSummary") as (
			this: typeof mode,
			value: AgentConnectionRlmChildAgentSnapshot,
		) => void;

		update.call(mode, child("worker", "running"));
		expect(stripAnsi(line.render(100).join("\n"))).toContain("1 running · 0 idle · 0 inactive");

		update.call(mode, child("worker", "done", { activeSessionId: "active-worker" }));
		expect(stripAnsi(line.render(100).join("\n"))).toContain("0 running · 1 idle · 0 inactive");
	});

	it("counts a retained completed child as running while a follow-up turn is active", () => {
		const line = new SubagentSummaryLine();
		const mode = Object.create(InteractiveMode.prototype) as InteractiveMode & Record<string, unknown>;
		Object.assign(mode, {
			subagentSnapshots: new Map<string, AgentConnectionRlmChildAgentSnapshot>(),
			rlmNodeId: undefined,
			heartbeatCatalog: [],
			subagentSummaryLine: line,
			updateScopedHeartbeats: vi.fn(),
			updateWorkingPulse: vi.fn(),
			syncWorkingLoader: vi.fn(),
			updateWorkingLoaderMessage: vi.fn(),
			ui: { requestRender: vi.fn() },
		});
		const update = Reflect.get(InteractiveMode.prototype, "updateSubagentSummary") as (
			this: typeof mode,
			value: AgentConnectionRlmChildAgentSnapshot,
		) => void;

		update.call(mode, child("worker", "done", { activeSessionId: "resident-worker" }));
		expect(stripAnsi(line.render(100).join("\n"))).toContain("0 running · 1 idle · 0 inactive");

		update.call(mode, child("worker", "done", { activeSessionId: "resident-worker", activity: { kind: "waiting" } }));
		expect(stripAnsi(line.render(100).join("\n"))).toContain("1 running · 0 idle · 0 inactive");

		update.call(mode, child("worker", "done", { activeSessionId: "resident-worker" }));
		expect(stripAnsi(line.render(100).join("\n"))).toContain("0 running · 1 idle · 0 inactive");
	});

	it("refreshes counts when startup seeding follows an early live child update", () => {
		const line = new SubagentSummaryLine();
		const mode = Object.create(InteractiveMode.prototype) as InteractiveMode & Record<string, unknown>;
		Object.assign(mode, {
			subagentSnapshots: new Map<string, AgentConnectionRlmChildAgentSnapshot>(),
			rlmNodeId: undefined,
			heartbeatCatalog: [],
			subagentSummaryLine: line,
			updateScopedHeartbeats: vi.fn(),
			updateWorkingPulse: vi.fn(),
			syncWorkingLoader: vi.fn(),
			updateWorkingLoaderMessage: vi.fn(),
			ui: { requestRender: vi.fn() },
		});
		const worker = child("worker", "done", { parentId: "me" });
		const update = Reflect.get(InteractiveMode.prototype, "updateSubagentSummary") as (
			this: typeof mode,
			value: AgentConnectionRlmChildAgentSnapshot,
		) => void;
		const seed = Reflect.get(InteractiveMode.prototype, "seedSubagentSummary") as (
			this: typeof mode,
			children: readonly AgentConnectionRlmChildAgentSnapshot[],
		) => void;

		update.call(mode, worker);
		expect(line.render(100)).toEqual([]);
		Reflect.set(mode, "rlmNodeId", "me");
		seed.call(mode, [worker]);

		expect(stripAnsi(line.render(100).join("\n"))).toContain("1 subagent:");
	});

	it("clears a resident session id when a terminal update reports an evicted child", () => {
		const line = new SubagentSummaryLine();
		const mode = Object.create(InteractiveMode.prototype) as InteractiveMode & Record<string, unknown>;
		Object.assign(mode, {
			subagentSnapshots: new Map<string, AgentConnectionRlmChildAgentSnapshot>(),
			rlmNodeId: undefined,
			heartbeatCatalog: [],
			subagentSummaryLine: line,
			updateScopedHeartbeats: vi.fn(),
			updateWorkingPulse: vi.fn(),
			syncWorkingLoader: vi.fn(),
			updateWorkingLoaderMessage: vi.fn(),
			ui: { requestRender: vi.fn() },
		});
		const update = Reflect.get(InteractiveMode.prototype, "updateSubagentSummary") as (
			this: typeof mode,
			value: AgentConnectionRlmChildAgentSnapshot,
		) => void;

		update.call(mode, child("worker", "running", { activeSessionId: "resident-worker" }));
		// Active partial updates retain the last known resident id.
		update.call(mode, child("worker", "running"));
		update.call(mode, child("worker", "done"));

		expect(stripAnsi(line.render(100).join("\n"))).toContain("0 running · 0 idle · 1 inactive");
	});

	it("lists direct children with labels, status, and recap for the inline expansion", () => {
		const children = [
			child("worker-a", "running", { label: "worker-a" }),
			child("worker-b", "done", { label: "worker-b", activeSessionId: "b-session", recap: "done reviewing" }),
			child("grandchild", "running", { parentId: "worker-a" }),
			child("elsewhere", "running", { parentId: "someone-else" }),
		];

		expect(listDirectSubagentEntries(children, undefined, new Set())).toEqual([
			{ id: "worker-a", label: "worker-a", status: "running", recap: undefined },
			{ id: "worker-b", label: "worker-b", status: "idle", recap: "done reviewing" },
		]);
	});
});
