import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { promisify } from "node:util";
import type { ReleaseArtifact } from "./version-check.js";

const execFileAsync = promisify(execFile);

const MAX_ARTIFACT_BYTES = 256 * 1024 * 1024;
const DOWNLOAD_TIMEOUT_MS = 30_000;

export interface StagedReleaseArtifacts {
	installSpec: string;
	cleanup: () => Promise<void>;
}

async function responseBytes(response: Response, name: string): Promise<Buffer> {
	if (!response.ok) throw new Error(`Failed to download ${name}: HTTP ${response.status}`);
	const declaredSize = Number(response.headers.get("content-length"));
	if (Number.isFinite(declaredSize) && declaredSize > MAX_ARTIFACT_BYTES) throw new Error(`${name} is too large`);
	if (!response.body) throw new Error(`Failed to download ${name}: empty response`);
	const reader = response.body.getReader();
	const chunks: Buffer[] = [];
	let size = 0;
	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > MAX_ARTIFACT_BYTES) {
			await reader.cancel();
			throw new Error(`${name} is too large`);
		}
		chunks.push(Buffer.from(value));
	}
	return Buffer.concat(chunks, size);
}

function expectedChecksums(text: string): Map<string, string> {
	const checksums = new Map<string, string>();
	for (const line of text.split(/\r?\n/)) {
		const match = line.match(/^([a-fA-F0-9]{64})\s+\*?([^/\\]+)$/);
		if (match) checksums.set(match[2], match[1].toLowerCase());
	}
	return checksums;
}

export async function stageReleaseArtifacts(
	artifacts: ReleaseArtifact[],
	mainArtifactName: string,
	options: { fetch?: typeof fetch; timeoutMs?: number } = {},
): Promise<StagedReleaseArtifacts> {
	if (basename(mainArtifactName) !== mainArtifactName) throw new Error("Invalid main release artifact name");
	const names = new Set<string>();
	for (const artifact of artifacts) {
		if (basename(artifact.name) !== artifact.name || names.has(artifact.name))
			throw new Error("Invalid release artifact set");
		names.add(artifact.name);
	}
	if (!names.has(mainArtifactName) || !names.has("SHA256SUMS")) throw new Error("Incomplete release artifact set");

	const directory = await mkdtemp(join(tmpdir(), "zero-update-"));
	const fetcher = options.fetch ?? fetch;
	const download = async (artifact: ReleaseArtifact) =>
		responseBytes(
			await fetcher(artifact.url, {
				redirect: "follow",
				signal: AbortSignal.timeout(options.timeoutMs ?? DOWNLOAD_TIMEOUT_MS),
			}),
			artifact.name,
		);
	try {
		const checksumArtifact = artifacts.find((artifact) => artifact.name === "SHA256SUMS")!;
		const checksums = expectedChecksums((await download(checksumArtifact)).toString("utf8"));
		for (const artifact of artifacts) {
			if (artifact.name === "SHA256SUMS") continue;
			const expected = checksums.get(artifact.name);
			if (!expected) throw new Error(`SHA256SUMS has no entry for ${artifact.name}`);
			const content = await download(artifact);
			const actual = createHash("sha256").update(content).digest("hex");
			if (actual !== expected) throw new Error(`Release artifact checksum mismatch for ${artifact.name}`);
			await writeFile(join(directory, artifact.name), content, { flag: "wx", mode: 0o600 });
		}
		// The main package resolves its internal dependencies as file:./<sibling>.tgz relative
		// to its own root, so the verified siblings must be repacked inside the main package.
		const packageDir = join(directory, "package");
		await mkdir(packageDir, { mode: 0o700 });
		// Relative names only: GNU tar on Windows reads "C:" in an argument as a remote host.
		await execFileAsync("tar", ["-xzf", mainArtifactName, "-C", "package", "--strip-components=1"], {
			cwd: directory,
		});
		for (const artifact of artifacts) {
			if (artifact.name === mainArtifactName || artifact.name === "SHA256SUMS") continue;
			await copyFile(join(directory, artifact.name), join(packageDir, artifact.name));
		}
		const repackedName = `repacked-${mainArtifactName}`;
		await execFileAsync("tar", ["-czf", repackedName, "package"], { cwd: directory });
		return {
			installSpec: join(directory, repackedName),
			cleanup: () => rm(directory, { force: true, recursive: true }),
		};
	} catch (error) {
		await rm(directory, { force: true, recursive: true });
		throw error;
	}
}
