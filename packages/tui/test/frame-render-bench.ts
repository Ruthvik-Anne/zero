/**
 * Benchmark: full-frame re-render cost when a long transcript of already-
 * rendered, unchanged messages (each wrapped in a Box, as user messages /
 * slash-command output / compaction summaries are) sits in the tree while
 * something unrelated (a spinner) keeps triggering doRender() every frame.
 *
 * This exercises the whole inline differential-render path (Box.render(),
 * the line diff, applyLineResets, collectKittyImageIds) rather than a single
 * stage in isolation, so the numbers reflect what actually runs per frame.
 *
 * Run with:
 *
 *   npx tsx test/frame-render-bench.ts [--messages N] [--frames N]
 */
import { performance } from "node:perf_hooks";
import { Box } from "../src/components/box.js";
import { Text } from "../src/components/text.js";
import type { Terminal, TerminalStopOptions } from "../src/terminal.js";
import { type Component, Container, TUI } from "../src/tui.js";

function argNum(flag: string, fallback: number): number {
	const idx = process.argv.indexOf(flag);
	return idx !== -1 ? Number(process.argv[idx + 1]) : fallback;
}

const messageCount = argNum("--messages", 300);
const frameCount = argNum("--frames", 300);
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

function buildTui(): { tui: TUI; spinner: TickingSpinner } {
	const terminal = new BenchmarkTerminal(width, height);
	const tui = new TUI(terminal);

	const chat = new Container();
	for (let i = 0; i < messageCount; i++) {
		const box = new Box(2, 1, (t) => t);
		const text = new Text(
			`Message ${i}: some representative user message content that wraps across a couple of lines of terminal output.`,
			1,
			0,
		);
		box.addChild(text);
		chat.addChild(box);
	}
	tui.addChild(chat);

	const spinner = new TickingSpinner();
	tui.addChild(spinner);

	return { tui, spinner };
}

function percentile(sorted: number[], p: number): number {
	const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
	return sorted[idx];
}

function run(): void {
	const { tui, spinner } = buildTui();
	const render = (tui as unknown as ImmediateTuiRender).doRender.bind(tui);

	// Prime: first render lays down the initial frame.
	render();

	const durations: number[] = [];
	for (let f = 0; f < frameCount; f++) {
		// Only the spinner changes; every historical boxed message is unchanged.
		spinner.tick();
		const start = performance.now();
		render();
		durations.push(performance.now() - start);
	}
	tui.stop();

	const sorted = [...durations].sort((a, b) => a - b);
	const total = durations.reduce((a, b) => a + b, 0);
	console.log(
		`${messageCount} static boxed messages, ${frameCount} idle-except-spinner frames:\n` +
			`  total:    ${total.toFixed(2)} ms\n` +
			`  mean:     ${(total / frameCount).toFixed(4)} ms/frame\n` +
			`  p50:      ${percentile(sorted, 50).toFixed(4)} ms\n` +
			`  p95:      ${percentile(sorted, 95).toFixed(4)} ms\n` +
			`  p99:      ${percentile(sorted, 99).toFixed(4)} ms`,
	);
}

run();
