import { afterEach, describe, expect, it, vi } from "vitest";
import {
	checkForNewPiVersion,
	comparePackageVersions,
	getLatestPiRelease,
	getLatestPiVersion,
	isNewerPackageVersion,
} from "../src/utils/version-check.js";

const testDownloadBaseUrl = "https://downloads.example.test/zero";
const originalSkipVersionCheck = process.env.ZERO_SKIP_VERSION_CHECK;
const originalOffline = process.env.ZERO_OFFLINE;
const originalDownloadBaseUrl = process.env.ZERO_DOWNLOAD_BASE_URL;

function restoreEnv(name: string, value: string | undefined): void {
	if (value === undefined) {
		delete process.env[name];
		return;
	}
	process.env[name] = value;
}

afterEach(() => {
	vi.unstubAllGlobals();
	restoreEnv("ZERO_SKIP_VERSION_CHECK", originalSkipVersionCheck);
	restoreEnv("ZERO_OFFLINE", originalOffline);
	restoreEnv("ZERO_DOWNLOAD_BASE_URL", originalDownloadBaseUrl);
});

describe("version checks", () => {
	it("compares package versions", () => {
		expect(comparePackageVersions("0.70.6", "0.70.5")).toBeGreaterThan(0);
		expect(comparePackageVersions("0.70.5", "0.70.5")).toBe(0);
		expect(comparePackageVersions("0.70.4", "0.70.5")).toBeLessThan(0);
		expect(comparePackageVersions("0.70.5-beta.10.1.abcdef0", "0.70.5-beta.9.1.1234567")).toBeGreaterThan(0);
		expect(isNewerPackageVersion("0.70.5", "0.70.5")).toBe(false);
		expect(isNewerPackageVersion("0.70.6", "0.70.5")).toBe(true);
		expect(isNewerPackageVersion("not-a-version", "0.70.5")).toBe(false);
		expect(isNewerPackageVersion("01.2.3", "0.70.5")).toBe(false);
		expect(isNewerPackageVersion("1.2.3-alpha..1", "0.70.5")).toBe(false);
		expect(isNewerPackageVersion("1.2.3+", "0.70.5")).toBe(false);
		expect(isNewerPackageVersion("9007199254740993.0.0", "9007199254740992.0.0")).toBe(true);
	});

	it("skips the version check entirely when ZERO_SKIP_VERSION_CHECK or ZERO_OFFLINE is set", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		process.env.ZERO_SKIP_VERSION_CHECK = "1";
		await expect(getLatestPiVersion("1.2.3")).resolves.toBeUndefined();
		delete process.env.ZERO_SKIP_VERSION_CHECK;

		process.env.ZERO_OFFLINE = "1";
		await expect(getLatestPiVersion("1.2.3")).resolves.toBeUndefined();

		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("falls back to the GitHub releases API when no download base URL is configured (Zero's default)", async () => {
		const fetchMock = vi.fn(async () =>
			Response.json({
				tag_name: "v1.2.4",
				assets: [
					{
						name: "zero-1.2.4.tgz",
						browser_download_url: "https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/zero-1.2.4.tgz",
					},
				],
			}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.3")).resolves.toBe("1.2.4");
		await expect(getLatestPiRelease("1.2.3")).resolves.toEqual({
			version: "1.2.4",
		});
		expect(fetchMock).toHaveBeenCalledWith(
			"https://api.github.com/repos/Ruthvik-Anne/zero/releases/latest",
			expect.objectContaining({
				headers: expect.objectContaining({ accept: "application/vnd.github+json" }),
			}),
		);
	});

	it("does not trust a mismatched GitHub release asset as the install package", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () =>
				Response.json({
					tag_name: "v1.2.4",
					assets: [
						{
							name: "zero-1.2.5.tgz",
							browser_download_url: "https://example.test/wrong.tgz",
						},
					],
				}),
			),
		);

		await expect(getLatestPiRelease("1.2.3")).resolves.toEqual({ version: "1.2.4" });
	});

	it("returns a complete checksummed GitHub release bundle for installation", async () => {
		const names = ["zero-1.2.4.tgz", "zero-ai-1.2.4.tgz", "zero-core-1.2.4.tgz", "zero-tui-1.2.4.tgz", "SHA256SUMS"];
		vi.stubGlobal(
			"fetch",
			vi.fn(async () =>
				Response.json({
					tag_name: "v1.2.4",
					assets: names.map((name) => ({
						name,
						browser_download_url: `https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/${name}`,
					})),
				}),
			),
		);

		await expect(getLatestPiRelease("1.2.3")).resolves.toEqual({
			version: "1.2.4",
			packageName: "zero",
			mainArtifactName: "zero-1.2.4.tgz",
			artifacts: names.map((name) => ({
				name,
				url: `https://github.com/Ruthvik-Anne/zero/releases/download/v1.2.4/${name}`,
			})),
		});
	});

	it("returns undefined when the GitHub releases API request fails", async () => {
		const fetchMock = vi.fn(async () => new Response(null, { status: 404 }));
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.3")).resolves.toBeUndefined();
	});

	it("returns only newer versions once a download base URL is configured", async () => {
		process.env.ZERO_DOWNLOAD_BASE_URL = testDownloadBaseUrl;
		const fetchMock = vi.fn(async () => Response.json({ version: "v1.2.3" }));
		vi.stubGlobal("fetch", fetchMock);

		await expect(checkForNewPiVersion("1.2.3")).resolves.toBeUndefined();
		await expect(checkForNewPiVersion("1.2.2")).resolves.toBe("1.2.3");
	});

	it("uses the configured release manifest with a Zero user agent", async () => {
		process.env.ZERO_DOWNLOAD_BASE_URL = testDownloadBaseUrl;
		const fetchMock = vi.fn(async () => Response.json({ version: "v1.2.4" }));
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.3")).resolves.toBe("1.2.4");
		expect(fetchMock).toHaveBeenCalledWith(
			`${testDownloadBaseUrl}/latest.json`,
			expect.objectContaining({
				headers: expect.objectContaining({
					"User-Agent": expect.stringMatching(/^zero\/1\.2\.3 /),
					accept: "application/json",
				}),
			}),
		);
	});

	it("keeps beta installations on the beta release manifest", async () => {
		process.env.ZERO_DOWNLOAD_BASE_URL = testDownloadBaseUrl;
		const fetchMock = vi.fn(async () => Response.json({ version: "v1.2.4-beta.124.1.abcdef0" }));
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.4-beta.123.1.1234567")).resolves.toBe("1.2.4-beta.124.1.abcdef0");
		expect(fetchMock).toHaveBeenCalledWith(`${testDownloadBaseUrl}/beta.json`, expect.any(Object));
	});

	it("returns the active package and tarball install spec from the release manifest", async () => {
		process.env.ZERO_DOWNLOAD_BASE_URL = testDownloadBaseUrl;
		const fetchMock = vi.fn(async () =>
			Response.json({
				package: "zero",
				tarball: "releases/v1.2.4/zero-1.2.4.tgz",
				version: "v1.2.4",
			}),
		);
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiRelease("1.2.3")).resolves.toEqual({
			installSpec: `${testDownloadBaseUrl}/releases/v1.2.4/zero-1.2.4.tgz`,
			packageName: "zero",
			version: "1.2.4",
		});
	});

	it("skips api calls when version checks are disabled", async () => {
		process.env.ZERO_DOWNLOAD_BASE_URL = testDownloadBaseUrl;
		process.env.ZERO_SKIP_VERSION_CHECK = "1";
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.3")).resolves.toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
	});
});
