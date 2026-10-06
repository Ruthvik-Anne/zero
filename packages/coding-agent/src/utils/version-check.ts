import { getZeroUserAgent } from "./zero-user-agent.js";

// Zero has no release CDN of its own (unlike upstream's Prime Intellect-hosted
// bucket): ZERO_DOWNLOAD_BASE_URL opts into a self-hosted latest.json/beta.json
// manifest when set, and otherwise falls back to this fork's own GitHub
// Releases (not a third party — it's where this fork's own builds land, see
// .github/workflows/build-binaries.yml), never a release feed the user hasn't
// pointed this fork at themselves.
const STABLE_VERSION_MANIFEST_PATH = "latest.json";
const BETA_VERSION_MANIFEST_PATH = "beta.json";
const DEFAULT_VERSION_CHECK_TIMEOUT_MS = 10000;
const DEFAULT_GITHUB_REPO = "Ruthvik-Anne/zero";
const GITHUB_API_BASE_URL = "https://api.github.com";

export interface LatestPiRelease {
	version: string;
	packageName?: string;
	installSpec?: string;
	artifacts?: ReleaseArtifact[];
	mainArtifactName?: string;
}

export interface ReleaseArtifact {
	name: string;
	url: string;
}

interface ParsedVersion {
	major: bigint;
	minor: bigint;
	patch: bigint;
	prerelease?: string;
}

function comparePrereleaseIdentifiers(leftPrerelease: string, rightPrerelease: string): number {
	const leftIdentifiers = leftPrerelease.split(".");
	const rightIdentifiers = rightPrerelease.split(".");
	const length = Math.max(leftIdentifiers.length, rightIdentifiers.length);

	for (let index = 0; index < length; index += 1) {
		const left = leftIdentifiers[index];
		const right = rightIdentifiers[index];
		if (left === right) continue;
		if (left === undefined) return -1;
		if (right === undefined) return 1;

		const leftIsNumeric = /^\d+$/.test(left);
		const rightIsNumeric = /^\d+$/.test(right);
		if (leftIsNumeric && rightIsNumeric) {
			const leftNumber = left.replace(/^0+(?=\d)/, "");
			const rightNumber = right.replace(/^0+(?=\d)/, "");
			if (leftNumber.length !== rightNumber.length) return leftNumber.length - rightNumber.length;
			const comparison = leftNumber.localeCompare(rightNumber);
			if (comparison !== 0) return comparison;
			continue;
		}
		if (leftIsNumeric) return -1;
		if (rightIsNumeric) return 1;
		return left.localeCompare(right);
	}

	return 0;
}

function parsePackageVersion(version: string): ParsedVersion | undefined {
	const match = version
		.trim()
		.match(
			/^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/,
		);
	if (!match) {
		return undefined;
	}
	if (
		match[4]
			?.split(".")
			.some((identifier) => /^\d+$/.test(identifier) && identifier.length > 1 && identifier[0] === "0")
	)
		return undefined;
	return {
		major: BigInt(match[1]),
		minor: BigInt(match[2]),
		patch: BigInt(match[3]),
		prerelease: match[4],
	};
}

export function comparePackageVersions(leftVersion: string, rightVersion: string): number | undefined {
	const left = parsePackageVersion(leftVersion);
	const right = parsePackageVersion(rightVersion);
	if (!left || !right) {
		return undefined;
	}

	if (left.major !== right.major) return left.major > right.major ? 1 : -1;
	if (left.minor !== right.minor) return left.minor > right.minor ? 1 : -1;
	if (left.patch !== right.patch) return left.patch > right.patch ? 1 : -1;
	if (left.prerelease === right.prerelease) return 0;
	if (!left.prerelease) return 1;
	if (!right.prerelease) return -1;
	return comparePrereleaseIdentifiers(left.prerelease, right.prerelease);
}

export function isNewerPackageVersion(candidateVersion: string, currentVersion: string): boolean {
	const comparison = comparePackageVersions(candidateVersion, currentVersion);
	return comparison !== undefined && comparison > 0;
}

function getZeroDownloadBaseUrl(): string | undefined {
	const configured = process.env.ZERO_DOWNLOAD_BASE_URL?.trim();
	return configured ? configured.replace(/\/+$/, "") : undefined;
}

function getZeroGithubRepo(): string {
	return process.env.ZERO_GITHUB_REPO?.trim() || DEFAULT_GITHUB_REPO;
}

function isBetaVersion(version: string): boolean {
	return !!parsePackageVersion(version)?.prerelease?.match(/^beta(?:\.|$)/);
}

function normalizeReleaseVersion(version: string): string {
	return version.trim().replace(/^v/, "");
}

function getReleaseManifestPath(currentVersion: string): string {
	return isBetaVersion(currentVersion) ? BETA_VERSION_MANIFEST_PATH : STABLE_VERSION_MANIFEST_PATH;
}

function resolveReleaseUrl(baseUrl: string, pathOrUrl: string): string | undefined {
	const trimmed = pathOrUrl.trim();
	if (!trimmed) return undefined;
	try {
		let resolved: URL;
		try {
			resolved = new URL(trimmed);
		} catch {
			resolved = new URL(trimmed.replace(/^\/+/, ""), `${baseUrl.replace(/\/+$/, "")}/`);
		}
		return resolved.protocol === "https:" ? resolved.toString() : undefined;
	} catch {
		return undefined;
	}
}

export async function getLatestPiRelease(
	currentVersion: string,
	options: { timeoutMs?: number } = {},
): Promise<LatestPiRelease | undefined> {
	if (process.env.ZERO_SKIP_VERSION_CHECK || process.env.ZERO_OFFLINE) return undefined;

	const timeoutMs = options.timeoutMs ?? DEFAULT_VERSION_CHECK_TIMEOUT_MS;
	const baseUrl = getZeroDownloadBaseUrl();
	if (baseUrl) {
		return getLatestReleaseFromManifest(currentVersion, baseUrl, timeoutMs);
	}
	return getLatestReleaseFromGithub(currentVersion, timeoutMs);
}

async function getLatestReleaseFromManifest(
	currentVersion: string,
	baseUrl: string,
	timeoutMs: number,
): Promise<LatestPiRelease | undefined> {
	const response = await fetch(`${baseUrl}/${getReleaseManifestPath(currentVersion)}`, {
		headers: {
			"User-Agent": getZeroUserAgent(currentVersion),
			accept: "application/json",
		},
		signal: AbortSignal.timeout(timeoutMs),
	});
	if (!response.ok) return undefined;

	const data = (await response.json()) as {
		package?: unknown;
		packageName?: unknown;
		tarball?: unknown;
		version?: unknown;
	};
	if (typeof data.version !== "string" || !data.version.trim()) {
		return undefined;
	}
	const packageName =
		typeof data.package === "string" && data.package.trim()
			? data.package.trim()
			: typeof data.packageName === "string" && data.packageName.trim()
				? data.packageName.trim()
				: undefined;
	const installSpec = typeof data.tarball === "string" ? resolveReleaseUrl(baseUrl, data.tarball) : undefined;
	const version = normalizeReleaseVersion(data.version);
	if (!parsePackageVersion(version)) return undefined;
	const release: LatestPiRelease = { version };
	if (packageName) {
		release.packageName = packageName;
	}
	if (installSpec) {
		release.installSpec = installSpec;
	}
	return release;
}

interface GithubReleaseAsset {
	name?: unknown;
	browser_download_url?: unknown;
}

interface GithubReleaseResponse {
	tag_name?: unknown;
	assets?: unknown;
}

function githubAsset(assets: unknown, name: string, repo: string): ReleaseArtifact | undefined {
	if (!Array.isArray(assets)) return undefined;
	const asset = (assets as GithubReleaseAsset[]).find((candidate) => candidate.name === name);
	if (typeof asset?.browser_download_url !== "string") return undefined;
	try {
		const url = new URL(asset.browser_download_url);
		if (
			url.protocol !== "https:" ||
			url.hostname !== "github.com" ||
			!url.pathname.toLowerCase().startsWith(`/${repo.toLowerCase()}/releases/download/`)
		)
			return undefined;
		return { name, url: url.toString() };
	} catch {
		return undefined;
	}
}

function githubReleaseBundle(
	assets: unknown,
	version: string,
	repo: string,
): Pick<LatestPiRelease, "artifacts" | "mainArtifactName" | "packageName"> {
	const mainArtifactName = `zero-${version}.tgz`;
	const names = [
		mainArtifactName,
		`zero-ai-${version}.tgz`,
		`zero-core-${version}.tgz`,
		`zero-tui-${version}.tgz`,
		"SHA256SUMS",
	];
	const releaseArtifacts = names.map((name) => githubAsset(assets, name, repo));
	if (releaseArtifacts.some((asset) => asset === undefined)) return {};
	return { artifacts: releaseArtifacts as ReleaseArtifact[], mainArtifactName, packageName: "zero" };
}

// Exact release assets are installable for this public repository. Do not use
// similarly named or off-repository URLs as package-manager input.
async function getLatestReleaseFromGithub(
	currentVersion: string,
	timeoutMs: number,
): Promise<LatestPiRelease | undefined> {
	const repo = getZeroGithubRepo();
	const beta = isBetaVersion(currentVersion);
	const apiPath = beta ? `releases/tags/beta` : "releases/latest";
	let response: Response;
	try {
		response = await fetch(`${GITHUB_API_BASE_URL}/repos/${repo}/${apiPath}`, {
			headers: {
				"User-Agent": getZeroUserAgent(currentVersion),
				accept: "application/vnd.github+json",
				"X-GitHub-Api-Version": "2026-03-10",
			},
			signal: AbortSignal.timeout(timeoutMs),
		});
	} catch {
		return undefined;
	}
	if (!response.ok) return undefined;

	const data = (await response.json()) as GithubReleaseResponse;
	if (beta) {
		const assets = Array.isArray(data.assets) ? (data.assets as GithubReleaseAsset[]) : [];
		const versionedAsset = assets.find(
			(asset): asset is { name: string } => typeof asset.name === "string" && /^zero-\d[^/]*\.tgz$/.test(asset.name),
		);
		if (!versionedAsset) return undefined;
		const version = versionedAsset.name.replace(/^zero-/, "").replace(/\.tgz$/, "");
		if (!parsePackageVersion(version)) return undefined;
		return { version, ...githubReleaseBundle(data.assets, version, repo) };
	}
	if (typeof data.tag_name !== "string" || !data.tag_name.trim()) return undefined;
	const version = normalizeReleaseVersion(data.tag_name);
	if (!parsePackageVersion(version)) return undefined;
	return { version, ...githubReleaseBundle(data.assets, version, repo) };
}

export async function getLatestPiVersion(
	currentVersion: string,
	options: { timeoutMs?: number } = {},
): Promise<string | undefined> {
	return (await getLatestPiRelease(currentVersion, options))?.version;
}

export async function checkForNewPiVersion(currentVersion: string): Promise<string | undefined> {
	try {
		const latestVersion = await getLatestPiVersion(currentVersion);
		if (latestVersion && isNewerPackageVersion(latestVersion, currentVersion)) {
			return latestVersion;
		}
		return undefined;
	} catch {
		return undefined;
	}
}
