import { setKeybindings, visibleWidth } from "@zero-agent/tui";
import stripAnsi from "strip-ansi";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { ReadonlyFooterDataProvider } from "../src/core/footer-data-provider.js";
import { KeybindingsManager } from "../src/core/keybindings.js";
import { FooterComponent } from "../src/modes/interactive/components/footer.js";
import { initTheme } from "../src/modes/interactive/theme/theme.js";

function createProvider(
	branch: string | null,
	providerCount: number,
	extensionStatuses: ReadonlyMap<string, string> = new Map(),
): ReadonlyFooterDataProvider {
	return {
		getGitBranch: () => branch,
		getExtensionStatuses: () => extensionStatuses,
		getAvailableProviderCount: () => providerCount,
		onBranchChange: () => () => {},
	};
}

function createFooter() {
	return new FooterComponent(createProvider("main", 3), {
		getModeLabel: () => "auto",
		getModelLabel: () => "sonnet",
		getContextLabel: () => "128k (64%)",
		getContextPercent: () => 64,
	});
}

describe("FooterComponent status bar", () => {
	beforeAll(() => {
		initTheme(undefined, false);
		setKeybindings(new KeybindingsManager());
	});

	it("renders a divider plus model, branch and context on wide terminals", () => {
		const lines = createFooter().render(120);
		expect(lines).toHaveLength(2);
		expect(lines[0]).toMatch(/─{10,}/);
		expect(lines[1]).toContain("sonnet");
		expect(lines[1]).toContain("main");
		expect(lines[1]).toContain("128k (64%)");
		expect(lines[1]).toContain("3 providers");
		for (const line of lines) expect(visibleWidth(line)).toBeLessThanOrEqual(120);
	});

	it("drops providers and hints on compact terminals", () => {
		const lines = createFooter().render(70);
		expect(lines).toHaveLength(2);
		expect(lines[1]).toContain("sonnet");
		expect(lines[1]).toContain("main");
		expect(lines[1]).toContain("64%");
		expect(lines[1]).not.toContain("providers");
		for (const line of lines) expect(visibleWidth(line)).toBeLessThanOrEqual(70);
	});

	it("renders a minimal model and context line on narrow terminals", () => {
		const lines = createFooter().render(40);
		expect(lines).toHaveLength(2);
		expect(lines[1]).toContain("sonnet");
		expect(lines[1]).toContain("64%");
		for (const line of lines) expect(visibleWidth(line)).toBeLessThanOrEqual(40);
	});

	it("renders nothing when no status data is available", () => {
		const footer = new FooterComponent(createProvider(null, 0));
		expect(footer.render(120)).toEqual([]);
	});

	it("reads live authoritative model and context values without inventing a session mode", () => {
		let model = "sonnet";
		let context = "32k (16%)";
		const footer = new FooterComponent(createProvider(null, 0), {
			getModelLabel: () => model,
			getContextLabel: () => context,
			getContextPercent: () => 16,
		});

		expect(stripAnsi(footer.render(80)[1]!)).toContain("sonnet");
		expect(stripAnsi(footer.render(80)[1]!)).not.toContain("auto");
		model = "opus";
		context = "64k (32%)";
		const updated = stripAnsi(footer.render(80)[1]!);
		expect(updated).toContain("opus");
		expect(updated).toContain("64k (32%)");
	});

	it("renders extension-only status at wide and compact widths", () => {
		const footer = new FooterComponent(createProvider(null, 0, new Map([["sync", "Indexing"]])));
		expect(stripAnsi(footer.render(120)[1]!)).toContain("Indexing");
		expect(stripAnsi(footer.render(50)[1]!)).toContain("Indexing");
	});

	it("reuses the cached render while inputs are unchanged", () => {
		const footer = createFooter();
		const buildLines = vi.spyOn(footer as unknown as { buildLines: (...args: unknown[]) => string[] }, "buildLines");
		const first = footer.render(120);
		expect(footer.render(120)).toBe(first);
		expect(buildLines).toHaveBeenCalledTimes(1);
	});

	it("includes the configurable mode-cycle key in cache invalidation and the rendered reference", () => {
		const footer = createFooter();
		const first = stripAnsi(footer.render(120)[1]!);
		expect(first).toContain("Shift+Tab cycle mode");

		setKeybindings(new KeybindingsManager({ "app.mode.cycle": "alt+m" }));
		const second = stripAnsi(footer.render(120)[1]!);
		expect(second).toContain("Alt+M cycle mode");
		expect(second).not.toBe(first);
		setKeybindings(new KeybindingsManager());
	});
});
