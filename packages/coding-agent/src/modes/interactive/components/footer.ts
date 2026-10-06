import { type Component, truncateToWidth, visibleWidth } from "@zero-agent/tui";
import type { ReadonlyFooterDataProvider } from "../../../core/footer-data-provider.js";
import { theme } from "../theme/theme.js";
import { keyText } from "./keybinding-hints.js";

/** Live status getters, same pattern as SubagentSummaryLine. All optional: the bar renders only what is available. */
export interface FooterStatusGetters {
	getModeLabel?: () => string | undefined;
	getModelLabel?: () => string | undefined;
	getContextLabel?: () => string | undefined;
	getContextPercent?: () => number | undefined;
}

const FULL_WIDTH = 100;
const COMPACT_WIDTH = 60;

function modeDotColor(mode: string): "success" | "warning" | "accent" | "muted" {
	switch (mode.trim().toLowerCase()) {
		case "auto":
			return "success";
		case "plan":
			return "warning";
		case "manual":
			return "accent";
		default:
			return "muted";
	}
}

/**
 * Status bar for the zero TUI: a divider plus one responsive line with mode,
 * model, git branch, context usage and provider count. Renders nothing when
 * no status data is available, preserving the previous empty behavior.
 */
export class FooterComponent implements Component {
	private cached:
		| {
				width: number;
				mode?: string;
				model?: string;
				context?: string;
				percent?: number;
				branch?: string;
				providerCount: number;
				extensionStatuses: ReadonlyMap<string, string>;
				cycleKey: string;
				lines: string[];
		  }
		| undefined;

	constructor(
		private footerData: ReadonlyFooterDataProvider,
		private readonly getters: FooterStatusGetters = {},
	) {
		void this.footerData;
	}

	setAutoCompactEnabled(_enabled: boolean): void {
		// no-op: tiers already adapt to terminal width
	}

	/**
	 * Drop the memoized render so the next render recomputes.
	 * Git branch caching stays in the provider.
	 */
	invalidate(): void {
		this.cached = undefined;
	}

	/**
	 * Clean up resources.
	 * Git watcher cleanup now handled by provider
	 */
	dispose(): void {
		this.cached = undefined;
	}

	render(width: number): string[] {
		const safeWidth = Math.max(1, Math.floor(width));
		const mode = this.getters.getModeLabel?.()?.trim() || undefined;
		const model = this.getters.getModelLabel?.()?.trim() || undefined;
		const context = this.getters.getContextLabel?.()?.trim() || undefined;
		const percent = this.getters.getContextPercent?.();
		const branch = this.footerData.getGitBranch()?.trim() || undefined;
		const providerCount = this.footerData.getAvailableProviderCount();
		const extensionStatuses = this.footerData.getExtensionStatuses();
		const cycleKey = keyText("app.mode.cycle") || "Shift+Tab";
		const cached = this.cached;
		if (
			cached?.width === safeWidth &&
			cached.mode === mode &&
			cached.model === model &&
			cached.context === context &&
			cached.percent === percent &&
			cached.branch === branch &&
			cached.providerCount === providerCount &&
			cached.extensionStatuses === extensionStatuses &&
			cached.cycleKey === cycleKey
		) {
			return cached.lines;
		}
		const extensions = [...extensionStatuses.values()].map((status) => status.trim()).filter(Boolean);
		const lines = this.buildLines(safeWidth, {
			mode,
			model,
			context,
			percent,
			branch,
			providerCount,
			extensions,
			cycleKey,
		});
		this.cached = {
			width: safeWidth,
			mode,
			model,
			context,
			percent,
			branch,
			providerCount,
			extensionStatuses,
			cycleKey,
			lines,
		};
		return lines;
	}

	private buildLines(
		width: number,
		status: {
			mode?: string;
			model?: string;
			context?: string;
			percent?: number;
			branch?: string;
			providerCount: number;
			extensions: string[];
			cycleKey: string;
		},
	): string[] {
		const segments: string[] = [];
		if (status.mode) segments.push(theme.fg(modeDotColor(status.mode), "●"), theme.fg("text", status.mode));
		if (status.model) segments.push(theme.fg("text", status.model));
		if (status.branch && width >= COMPACT_WIDTH) segments.push(theme.fg("accent", `⎇ ${status.branch}`));
		if (status.context) {
			const color =
				status.percent !== undefined && status.percent >= 90
					? "error"
					: status.percent !== undefined && status.percent >= 75
						? "warning"
						: "muted";
			segments.push(theme.fg(color, status.context));
		}
		if (status.providerCount > 0 && width >= FULL_WIDTH)
			segments.push(theme.fg("muted", `${status.providerCount} provider${status.providerCount === 1 ? "" : "s"}`));
		if (status.extensions.length > 0 && width < FULL_WIDTH) {
			segments.push(theme.fg("dim", status.extensions.join(", ")));
		}
		if (segments.length === 0 && status.extensions.length === 0) return [];
		const separator = theme.fg("dim", " · ");
		const left = segments.join(separator);
		let right = "";
		if (width >= FULL_WIDTH) {
			const hint = status.extensions.length > 0 ? status.extensions.join(", ") : `${status.cycleKey} cycle mode`;
			right = theme.fg("dim", hint);
		}
		const gap = left && right ? 2 : 0;
		const rightWidth = Math.min(visibleWidth(right), Math.max(0, width - gap));
		const leftWidth = Math.max(0, width - rightWidth - gap);
		const renderedLeft = truncateToWidth(left, leftWidth, "…");
		const renderedRight = truncateToWidth(right, rightWidth, "…");
		const padding = Math.max(0, width - visibleWidth(renderedLeft) - visibleWidth(renderedRight));
		return [theme.fg("borderMuted", "─".repeat(width)), `${renderedLeft}${" ".repeat(padding)}${renderedRight}`];
	}
}
