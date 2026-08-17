import type { TableCellSelectionRegion } from "../selection-metadata.js";
import type { Component } from "../tui.js";
import { applyBackgroundToLine, visibleWidth } from "../utils.js";

type RenderCache = {
	// Raw per-child output arrays (pre-leftPad), by reference. Text/Box (and
	// well-behaved components generally) return the exact same array
	// instance when their own render output is unchanged and a brand-new
	// array otherwise, so reference equality here is a sound "did anything
	// change" signal without re-deriving and comparing the padded content.
	childOutputs: string[][];
	width: number;
	bgSample: string | undefined;
	lines: string[];
	selectionRegions: TableCellSelectionRegion[];
};

/**
 * Box component - a container that applies padding and background to all children
 */
export class Box implements Component {
	children: Component[] = [];
	private paddingX: number;
	private paddingY: number;
	private bgFn?: (text: string) => string;

	// Cache for rendered output
	private cache?: RenderCache;

	constructor(paddingX = 1, paddingY = 1, bgFn?: (text: string) => string) {
		this.paddingX = paddingX;
		this.paddingY = paddingY;
		this.bgFn = bgFn;
	}

	addChild(component: Component): void {
		this.children.push(component);
		this.invalidateCache();
	}

	removeChild(component: Component): void {
		const index = this.children.indexOf(component);
		if (index !== -1) {
			this.children.splice(index, 1);
			this.invalidateCache();
		}
	}

	clear(): void {
		this.children = [];
		this.invalidateCache();
	}

	setBgFn(bgFn?: (text: string) => string): void {
		this.bgFn = bgFn;
		// Don't invalidate here - we'll detect bgFn changes by sampling output
	}

	private invalidateCache(): void {
		this.cache = undefined;
	}

	invalidate(): void {
		this.invalidateCache();
		for (const child of this.children) {
			child.invalidate?.();
		}
	}

	render(width: number): string[] {
		if (this.children.length === 0) {
			this.cache = undefined;
			return [];
		}

		const contentWidth = Math.max(1, width - this.paddingX * 2);
		const leftPad = " ".repeat(this.paddingX);
		const cache = this.cache;

		// Render all children, tracking each child's raw output array by
		// reference so an unchanged tree can skip the leftPad concat +
		// background/padding pass below entirely (the dominant per-frame
		// cost when hundreds/thousands of static boxes sit in a transcript
		// and only something unrelated elsewhere forces a re-render).
		const childOutputs: string[][] = [];
		const selectionRegions: TableCellSelectionRegion[] = [];
		let totalLines = 0;
		let sameChildOutputs = !!cache && cache.childOutputs.length === this.children.length;
		for (let i = 0; i < this.children.length; i++) {
			const child = this.children[i];
			const lines = child.render(contentWidth);
			childOutputs.push(lines);
			if (sameChildOutputs && cache!.childOutputs[i] !== lines) {
				sameChildOutputs = false;
			}
			for (const region of child.getSelectionRegions?.() ?? []) {
				selectionRegions.push({
					...region,
					line: region.line + totalLines + this.paddingY,
					col: region.col + this.paddingX,
					tableTop: region.tableTop + totalLines + this.paddingY,
					tableBottom: region.tableBottom + totalLines + this.paddingY,
					tableLeft: region.tableLeft + this.paddingX,
					tableRight: region.tableRight + this.paddingX,
				});
			}
			totalLines += lines.length;
		}

		if (totalLines === 0) {
			this.cache = undefined;
			return [];
		}

		// Check if bgFn output changed by sampling
		const bgSample = this.bgFn ? this.bgFn("test") : undefined;

		// Fast path: every child returned the exact same array it did last
		// render, and width/background are unchanged, so the padded output
		// is provably identical too. Selection regions are always freshly
		// recomputed above regardless of this branch.
		if (sameChildOutputs && cache && cache.width === width && cache.bgSample === bgSample) {
			cache.selectionRegions = selectionRegions;
			return cache.lines;
		}

		// Slow path: at least one child's content changed (or this is the
		// first render, or width/background changed) - rebuild from scratch.
		const childLines: string[] = [];
		for (const lines of childOutputs) {
			for (const line of lines) {
				childLines.push(leftPad + line);
			}
		}

		// Apply background and padding
		const result: string[] = [];

		// Top padding
		for (let i = 0; i < this.paddingY; i++) {
			result.push(this.applyBg("", width));
		}

		// Content
		for (const line of childLines) {
			result.push(this.applyBg(line, width));
		}

		// Bottom padding
		for (let i = 0; i < this.paddingY; i++) {
			result.push(this.applyBg("", width));
		}

		// Update cache
		this.cache = { childOutputs, width, bgSample, lines: result, selectionRegions };

		return result;
	}

	getSelectionRegions(): ReadonlyArray<TableCellSelectionRegion> {
		return this.cache?.selectionRegions ?? [];
	}

	private applyBg(line: string, width: number): string {
		const visLen = visibleWidth(line);
		const padNeeded = Math.max(0, width - visLen);
		const padded = line + " ".repeat(padNeeded);

		if (this.bgFn) {
			return applyBackgroundToLine(padded, width, this.bgFn);
		}
		return padded;
	}
}
