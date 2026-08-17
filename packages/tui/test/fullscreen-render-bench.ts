/**
 * Benchmark: full-frame re-render cost of the FULLSCREEN viewport path when a
 * long transcript of already-rendered, unchanged messages (each a Box
 * wrapping a Markdown child, matching the real shape of
 * UserMessageComponent/CompactionOutcomeMessage/etc. in packages/coding-agent)
 * sits in the scroll container while something unrelated (a spinner in the
 * dock) keeps triggering doRender() every frame.
 *
 * Unlike frame-render-bench.ts (inline path), only a small viewport-sized
 * slice of the transcript is ever visible on screen here, so this isolates
 * whether renderFullscreen() still pays a cost proportional to the FULL
 * transcript (re-flattening every message's lines every frame) or only to
 * the visible window.
 *
 * Run with:
 *
 *   npx tsx test/fullscreen-render-bench.ts [--messages N] [--frames N] [--streaming]
 */
import { performance } from "node:perf_hooks";
import { Box } from "../src/components/box.js";
import { Markdown } from "../src/components/markdown.js";
import type { Terminal, TerminalStopOptions } from "../src/terminal.js";
import { type Component, Container, TUI } from "../src/tui.js";
import { defaultMarkdownTheme } from "./test-themes.js";

function argNum(flag: string, fallback: number): number {
	const idx = process.argv.indexOf(flag);
	return idx !== -1 ? Number(process.argv[idx + 1]) : fallback;
}

const messageCount = argNum("--messages", 300);
const frameCount = argNum("--frames", 300);
const streaming = process.argv.includes("--streaming");
const width = 100;
const height = 40;

class BenchmarkTerminal implements Terminal {
	altScreenActive = false;
	mouseTrackingActive = false;
	readonly kittyProtocolActive = false;

	constructor(
		readonly columns: number,
		readonly rows: number,
	) {}

	start(_onInput: (data: string) => void, _onResize: () => void): void {}
	stop(_options?: TerminalStopOptions): void {}
	async drainInput(): Promise<void> {}
	write(_data: string): void {}
	moveBy(_lines: number): void {}
	hideCursor(): void {}
	showCursor(): void {}
	clearLine(): void {}
	clearFromCursor(): void {}
	clearScreen(): void {}
	setTitle(_title: string): void {}
	setProgress(_active: boolean): void {}
	enterAltScreen(): void {
		this.altScreenActive = true;
	}
	leaveAltScreen(): void {
		this.altScreenActive = false;
	}
	setMouseTracking(enabled: boolean): void {
		this.mouseTrackingActive = enabled;
	}
}

/** Mimics Loader: a single line that changes every frame, forcing requestRender(). */
class TickingSpinner implements Component {
	private frame = 0;
	private readonly frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

	tick(): void {
		this.frame = (this.frame + 1) % this.frames.length;
	}

	render(_width: number): string[] {
		return [`${this.frames[this.frame]} working...`];
	}

	invalidate(): void {}
}

interface ImmediateTuiRender {
	doRender(): void;
}

function buildTui(): { tui: TUI; spinner: TickingSpinner; tailMarkdown: Markdown | null } {
	const terminal = new BenchmarkTerminal(width, height);
	const tui = new TUI(terminal);

	const transcript = new Container();
	let tailMarkdown: Markdown | null = null;
	for (let i = 0; i < messageCount; i++) {
		const box = new Box(2, 1, (t) => t);
		const markdown = new Markdown(
			`Message ${i}: some representative user message content that wraps across a couple of lines of terminal output.`,
			0,
			0,
			defaultMarkdownTheme,
		);
		box.addChild(markdown);
		transcript.addChild(box);
		if (i === messageCount - 1) tailMarkdown = markdown;
	}

	const spinner = new TickingSpinner();
	const dock = new Box(1, 0);
	dock.addChild(spinner);

	tui.enterFullscreen({ scroll: [transcript], dock, mouse: false });

	return { tui, spinner, tailMarkdown: streaming ? tailMarkdown : null };
}

function percentile(sorted: number[], p: number): number {
	const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
	return sorted[idx];
}

function run(): void {
	const { tui, spinner, tailMarkdown } = buildTui();
	const render = (tui as unknown as ImmediateTuiRender).doRender.bind(tui);

	// Prime: first render lays down the initial frame (following == scrolled to bottom).
	render();

	const durations: number[] = [];
	for (let f = 0; f < frameCount; f++) {
		// Only the spinner in the dock changes; every historical boxed message
		// (all scrolled out of view except the last ~40) is unchanged. With
		// --streaming, the last (currently "streaming") message's text also
		// changes every frame, the worst case for any unchanged-content cache.
		spinner.tick();
		tailMarkdown?.setText(`Message tail: streaming update ${f}`);
		const start = performance.now();
		render();
		durations.push(performance.now() - start);
	}
	tui.stop({ flushFullscreen: false });

	const sorted = [...durations].sort((a, b) => a - b);
	const total = durations.reduce((a, b) => a + b, 0);
	const label = streaming ? "static boxed messages + 1 streaming tail" : "static boxed messages";
	console.log(
		`${messageCount} ${label} (fullscreen), ${frameCount} idle-except-spinner frames:\n` +
			`  total:    ${total.toFixed(2)} ms\n` +
			`  mean:     ${(total / frameCount).toFixed(4)} ms/frame\n` +
			`  p50:      ${percentile(sorted, 50).toFixed(4)} ms\n` +
			`  p95:      ${percentile(sorted, 95).toFixed(4)} ms\n` +
			`  p99:      ${percentile(sorted, 99).toFixed(4)} ms`,
	);
}

run();
