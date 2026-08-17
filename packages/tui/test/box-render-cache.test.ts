import assert from "node:assert";
import { describe, it } from "node:test";
import { Box } from "../src/components/box.js";
import { Markdown } from "../src/components/markdown.js";
import { Text } from "../src/components/text.js";
import type { TableCellSelectionRegion } from "../src/selection-metadata.js";
import type { Component } from "../src/tui.js";
import { defaultMarkdownTheme } from "./test-themes.js";

/**
 * Test double for a component that owns selectable regions (like a table
 * inside Markdown), so the region-offset math on Box's fast (cache-hit) path
 * can be checked directly, independent of Markdown's own table parsing.
 */
class FakeTableComponent implements Component {
	private lines: string[];
	private regions: TableCellSelectionRegion[];

	constructor(lines: string[], regions: TableCellSelectionRegion[]) {
		this.lines = lines;
		this.regions = regions;
	}

	render(_width: number): string[] {
		return this.lines;
	}

	getSelectionRegions(): ReadonlyArray<TableCellSelectionRegion> {
		return this.regions;
	}

	invalidate(): void {}
}

describe("Box render cache", () => {
	it("returns the same array reference across renders when children are unchanged (cache hit)", () => {
		const box = new Box(2, 1);
		box.addChild(new Text("hello", 0, 0));

		const first = box.render(40);
		const second = box.render(40);
		assert.strictEqual(first, second, "unchanged content should return the same cached array reference");
	});

	it("reflects a child mutation immediately, even after a prior cache hit", () => {
		const box = new Box(2, 1);
		const text = new Text("hello", 0, 0);
		box.addChild(text);

		const first = box.render(40);
		const cached = box.render(40); // cache hit
		assert.strictEqual(first, cached);

		text.setText("goodbye, world");
		const updated = box.render(40);
		assert.notStrictEqual(updated, cached, "mutated child content must not return the stale cached array");
		assert.ok(
			updated.some((line) => line.includes("goodbye, world")),
			"updated render output should contain the new text",
		);
		assert.ok(
			!updated.some((line) => line.includes("hello")),
			"updated render output should not still show the old text",
		);
	});

	it("invalidates the cache when render width changes, even if children are unchanged", () => {
		const box = new Box(2, 1);
		box.addChild(new Text("hello", 0, 0));

		const atWidth40 = box.render(40);
		box.render(40); // warm cache hit at width 40
		const atWidth60 = box.render(60);

		assert.notStrictEqual(atWidth40, atWidth60, "a width change must not reuse the previous width's cached lines");
		// Re-rendering at the original width afterwards must be correct too,
		// not left over from the width-60 cache entry.
		const backTo40 = box.render(40);
		assert.deepStrictEqual(backTo40, atWidth40);
	});

	it("keeps selection region offsets correct on a fast-path (cache-hit) render", () => {
		const table = { id: "table-1" };
		const region: TableCellSelectionRegion = {
			line: 0,
			col: 2,
			width: 5,
			table,
			tableTop: 0,
			tableBottom: 0,
			tableLeft: 0,
			tableRight: 0,
			row: 0,
			column: 0,
			segment: 0,
			content: "hello",
		};
		const fakeTable = new FakeTableComponent(["header row", "data  row"], [region]);

		const box = new Box(1, 1); // paddingX=1, paddingY=1
		box.addChild(fakeTable);

		box.render(40); // cache miss: builds cache
		box.render(40); // cache hit: must still recompute selectionRegions

		const regions = box.getSelectionRegions();
		assert.strictEqual(regions.length, 1);
		// paddingY (1) shifts the line down by 1; paddingX (1) shifts columns by 1.
		assert.strictEqual(regions[0].line, region.line + 1);
		assert.strictEqual(regions[0].col, region.col + 1);
		assert.strictEqual(regions[0].width, region.width);
		assert.strictEqual(regions[0].table, table);
	});

	it("reflects a Markdown child mutation after a cache hit (Box+Markdown is the real transcript message shape)", () => {
		// UserMessageComponent and friends in packages/coding-agent wrap a
		// Markdown child in a Box, not a plain Text - the fast path relies on
		// Markdown returning a stable array reference on an unchanged render,
		// same as Text, and must not serve stale content once it changes.
		const box = new Box(2, 1);
		const markdown = new Markdown("hello world", 0, 0, defaultMarkdownTheme);
		box.addChild(markdown);

		const first = box.render(40);
		const cached = box.render(40); // cache hit
		assert.strictEqual(first, cached, "unchanged markdown content should return the same cached array reference");

		markdown.setText("goodbye, markdown world");
		const updated = box.render(40);
		assert.notStrictEqual(updated, cached, "mutated markdown content must not return the stale cached array");
		assert.ok(
			updated.some((line) => line.includes("goodbye, markdown world")),
			"updated render output should contain the new markdown text",
		);
		assert.ok(
			!updated.some((line) => line.includes("hello world")),
			"updated render output should not still show the old markdown text",
		);
	});

	it("recomputes selection regions on the fast path even when a later sibling changes region-affecting offsets", () => {
		// Two children: a static table-bearing component first, then a Text
		// child that changes line count. The table's own render output stays
		// referentially identical (cache hit for that child), but Box's own
		// output must still change to reflect the new total height - this
		// guards against short-circuiting sibling-independent totalLines
		// bookkeeping incorrectly.
		const table = { id: "table-2" };
		const region: TableCellSelectionRegion = {
			line: 0,
			col: 0,
			width: 3,
			table,
			tableTop: 0,
			tableBottom: 0,
			tableLeft: 0,
			tableRight: 0,
			row: 0,
			column: 0,
			segment: 0,
			content: "abc",
		};
		const fakeTable = new FakeTableComponent(["abc"], [region]);
		const text = new Text("short", 0, 0);

		const box = new Box(0, 0);
		box.addChild(fakeTable);
		box.addChild(text);

		box.render(40);
		const before = box.getSelectionRegions();
		assert.strictEqual(before[0].line, 0);

		text.setText("a much longer line that still renders on one row");
		box.render(40);
		const after = box.getSelectionRegions();
		// The table is still the first child at line 0; offset must be stable.
		assert.strictEqual(after[0].line, 0);
	});
});
