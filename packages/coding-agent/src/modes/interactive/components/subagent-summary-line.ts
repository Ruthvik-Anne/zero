import { type Component, type Focusable, getKeybindings, truncateToWidth, visibleWidth } from "@zero-agent/tui";
import type { AgentConnectionRlmChildAgentSnapshot } from "../../agent-connection/index.js";
import { theme } from "../theme/theme.js";
import { keyText } from "./keybinding-hints.js";

export interface SubagentSummaryCounts {
	total: number;
	running: number;
	idle: number;
	inactive: number;
}

export type SubagentDisplayStatus = "running" | "idle" | "inactive";

export interface SubagentDisplayEntry {
	id: string;
	label: string;
	status: SubagentDisplayStatus;
	recap?: string;
}

function classifySubagentStatus(
	child: AgentConnectionRlmChildAgentSnapshot,
	activeHeartbeatSessionIds: ReadonlySet<string>,
): SubagentDisplayStatus {
	const isRunning =
		child.status === "running" ||
		child.status === "queued" ||
		child.activity !== undefined ||
		(child.activeSessionId !== undefined && activeHeartbeatSessionIds.has(child.activeSessionId));
	if (isRunning) return "running";
	if ((child.status === "done" || child.status === "error") && child.activeSessionId !== undefined) return "idle";
	return "inactive";
}

export function countDirectSubagentStatuses(
	children: Iterable<AgentConnectionRlmChildAgentSnapshot>,
	parentId: string | undefined,
	activeHeartbeatSessionIds: ReadonlySet<string>,
): SubagentSummaryCounts {
	let total = 0;
	let running = 0;
	let idle = 0;
	for (const child of children) {
		if (child.parentId !== parentId || child.status === "cancelled") continue;
		total += 1;
		const status = classifySubagentStatus(child, activeHeartbeatSessionIds);
		if (status === "running") running += 1;
		else if (status === "idle") idle += 1;
	}
	return { total, running, idle, inactive: total - running - idle };
}

/** Direct, non-cancelled children in display order, for the inline expanded list. */
export function listDirectSubagentEntries(
	children: Iterable<AgentConnectionRlmChildAgentSnapshot>,
	parentId: string | undefined,
	activeHeartbeatSessionIds: ReadonlySet<string>,
): SubagentDisplayEntry[] {
	const entries: SubagentDisplayEntry[] = [];
	for (const child of children) {
		if (child.parentId !== parentId || child.status === "cancelled") continue;
		entries.push({
			id: child.id,
			label: child.label,
			status: classifySubagentStatus(child, activeHeartbeatSessionIds),
			recap: child.recap ?? child.answerPreview,
		});
	}
	return entries;
}

/**
 * Live subagent status, rendered directly below the chat input. Enter/toggle
 * expands the count line into one line per direct subagent in place — there
 * is no separate screen for this; subagents are never individually
 * resumable/attachable from here (see AgentSession's own cleanup retention,
 * which stays as-is — this widget only reports status, never exposes a way
 * to reattach to a finished child).
 */
export class SubagentSummaryLine implements Component, Focusable {
	focused = false;
	private counts: SubagentSummaryCounts = { total: 0, running: 0, idle: 0, inactive: 0 };
	private entries: SubagentDisplayEntry[] = [];
	private expanded = false;

	onCancel?: () => void;
	onChatAction?: (data: string) => void;

	constructor(
		private readonly getLocationLabel: () => string | undefined = () => undefined,
		private readonly getContextLabel: () => string | undefined = () => undefined,
		private readonly getOverrideLabel: () => string | undefined = () => undefined,
	) {}

	setSubagentCounts(counts: SubagentSummaryCounts): void {
		this.counts = counts;
	}

	setSubagentEntries(entries: SubagentDisplayEntry[]): void {
		this.entries = entries;
	}

	isSelectable(): boolean {
		return this.counts.total > 0;
	}

	handleInput(data: string): void {
		const keybindings = getKeybindings();
		if (keybindings.matches(data, "tui.select.confirm") || keybindings.matches(data, "app.agents.open")) {
			if (this.isSelectable()) this.expanded = !this.expanded;
			return;
		}
		if (
			keybindings.matches(data, "tui.select.up") ||
			keybindings.matches(data, "tui.select.cancel") ||
			keybindings.matches(data, "app.agents.back")
		) {
			if (this.expanded) {
				this.expanded = false;
				return;
			}
			this.onCancel?.();
			return;
		}
		this.onChatAction?.(data);
	}

	render(width: number): string[] {
		const lines = this.renderInfoLine(width);
		if (this.counts.total === 0) return lines;
		const summary = `${this.counts.total} subagent${this.counts.total === 1 ? "" : "s"}: ${this.counts.running} running · ${this.counts.idle} idle · ${this.counts.inactive} inactive`;
		const toggleHint = `  ${keyText("tui.select.confirm")} or ${keyText("app.agents.open")} to ${this.expanded ? "collapse" : "expand"}`;
		const text = `${this.focused ? "▸" : " "} ${summary}${toggleHint}`;
		const line = truncateToWidth(text, width, "…");
		lines.push(this.focused ? theme.bg("selectedBg", line.padEnd(width)) : theme.fg("dim", line));
		if (this.expanded) {
			for (const entry of this.entries) {
				lines.push(this.renderEntryLine(entry, width));
			}
		}
		return lines;
	}

	private renderEntryLine(entry: SubagentDisplayEntry, width: number): string {
		const recap = entry.recap?.trim() ? `  ${entry.recap.trim()}` : "";
		const text = `    · ${entry.label} — ${entry.status}${recap}`;
		const line = truncateToWidth(text, width, "…");
		return theme.fg("dim", line.padEnd(width));
	}

	private renderInfoLine(width: number): string[] {
		const overrideLabel = this.getOverrideLabel()?.trim();
		const locationLabel = this.getLocationLabel()?.trim();
		const contextLabel = this.getContextLabel()?.trim();
		const left = overrideLabel || locationLabel || "";
		if (!left && !contextLabel) return [];
		const safeWidth = Math.max(1, width);
		const right = contextLabel ?? "";
		const gap = left && right ? 2 : 0;
		const rightWidth = Math.min(visibleWidth(right), Math.max(0, safeWidth - gap));
		const leftWidth = Math.max(0, safeWidth - rightWidth - gap);
		const renderedLeft = truncateToWidth(left, leftWidth, "…");
		const renderedRight = truncateToWidth(right, rightWidth, "…");
		const padding = Math.max(0, safeWidth - visibleWidth(renderedLeft) - visibleWidth(renderedRight));
		return [theme.fg("muted", `${renderedLeft}${" ".repeat(padding)}${renderedRight}`)];
	}

	invalidate(): void {
		// Render output is derived from counts/entries and focus state.
	}
}
