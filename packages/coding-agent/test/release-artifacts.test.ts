import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { stageReleaseArtifacts } from "../src/utils/release-artifacts.js";

function mainPackageTarball(): Buffer {
	const directory = mkdtempSync(join(tmpdir(), "zero-release-fixture-"));
	mkdirSync(join(directory, "package"));
	writeFileSync(join(directory, "package", "package.json"), JSON.stringify({ name: "zero", version: "1.2.4" }));
	execFileSync("tar", ["-czf", "zero-1.2.4.tgz", "package"], { cwd: directory });
	return readFileSync(join(directory, "zero-1.2.4.tgz"));
}

describe("stageReleaseArtifacts", () => {
	it("repacks the verified siblings inside the main package for npm to resolve", async () => {
		const files = new Map<string, Buffer>([
			["zero-1.2.4.tgz", mainPackageTarball()],
			["zero-ai-1.2.4.tgz", Buffer.from("ai")],
			["zero-core-1.2.4.tgz", Buffer.from("core")],
			["zero-tui-1.2.4.tgz", Buffer.from("tui")],
		]);
		const sums = [...files]
			.map(([name, content]) => `${createHash("sha256").update(content).digest("hex")}  ${name}`)
			.join("\n");
		const artifacts = [...files.keys(), "SHA256SUMS"].map((name) => ({
			name,
			url: `https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/${name}`,
		}));
		const fetchMock = vi.fn(async (url: string | URL | Request) => {
			const name = new URL(String(url)).pathname.split("/").at(-1)!;
			return new Response(name === "SHA256SUMS" ? sums : files.get(name));
		});

		const staged = await stageReleaseArtifacts(artifacts, "zero-1.2.4.tgz", { fetch: fetchMock });
		try {
			const listing = execFileSync("tar", ["-tzf", basename(staged.installSpec)], {
				cwd: dirname(staged.installSpec),
				encoding: "utf8",
			});
			expect(listing).toContain("package/package.json");
			expect(listing).toContain("package/zero-ai-1.2.4.tgz");
			expect(listing).toContain("package/zero-core-1.2.4.tgz");
			expect(listing).toContain("package/zero-tui-1.2.4.tgz");
			expect(fetchMock).toHaveBeenCalledTimes(5);
		} finally {
			await staged.cleanup();
		}
		expect(existsSync(staged.installSpec)).toBe(false);
	});

	it("rejects a bundle whose checksum does not match", async () => {
		const artifacts = [
			{
				name: "zero-1.2.4.tgz",
				url: "https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/zero-1.2.4.tgz",
			},
			{ name: "SHA256SUMS", url: "https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/SHA256SUMS" },
		];
		const fetchMock = vi.fn(
			async (url: string | URL | Request) =>
				new Response(String(url).endsWith("SHA256SUMS") ? `${"0".repeat(64)}  zero-1.2.4.tgz\n` : "tampered"),
		);

		await expect(stageReleaseArtifacts(artifacts, "zero-1.2.4.tgz", { fetch: fetchMock })).rejects.toThrow(
			"checksum",
		);
	});
});
