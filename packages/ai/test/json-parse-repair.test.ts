import { describe, expect, it } from "vitest";
import { parseJsonWithRepair, repairJson } from "../src/utils/json-parse.js";

// B12: repairJson could not repair the exact malformed \u escape it exists to
// handle. VALID_JSON_ESCAPES contains "u" (a bare valid escape character), so a
// malformed \uZZZZ (not 4 hex digits) fell through to that check and matched,
// re-emitting "\u" verbatim instead of being treated as invalid — leaving
// repairedJson === json, which made parseJsonWithRepair rethrow instead of
// repairing.
describe("repairJson (B12)", () => {
	it("repairs a malformed \\u escape instead of re-emitting it unrepaired", () => {
		const input = '{"a":"\\uZZZZ"}';
		const repaired = repairJson(input);

		expect(repaired).not.toBe(input);
		expect(() => JSON.parse(repaired)).not.toThrow();
	});

	it("parseJsonWithRepair repairs rather than throwing for a malformed \\u escape", () => {
		expect(() => parseJsonWithRepair('{"a":"\\uZZZZ"}')).not.toThrow();
		expect(parseJsonWithRepair<{ a: string }>('{"a":"\\uZZZZ"}').a).toBe("\\uZZZZ");
	});

	it("still passes through a valid \\u escape unchanged", () => {
		const input = '{"a":"\\u00e9"}';
		expect(repairJson(input)).toBe(input);
		expect(parseJsonWithRepair<{ a: string }>(input).a).toBe("é");
	});
});
