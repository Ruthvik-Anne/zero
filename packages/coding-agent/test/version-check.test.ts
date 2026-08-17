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
	});

	it("skips the version check entirely when no download base URL is configured (Zero's default)", async () => {
		const fetchMock = vi.fn();
		vi.stubGlobal("fetch", fetchMock);

		await expect(getLatestPiVersion("1.2.3")).resolves.toBeUndefined();
		expect(fetchMock).not.toHaveBeenCalled();
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
