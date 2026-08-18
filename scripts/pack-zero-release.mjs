#!/usr/bin/env node

// TODO: Remove this tarball packer once zero and its internal workspace
// dependencies are published through a real npm release flow.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
	cpSync,
	existsSync,
	mkdirSync,
	renameSync,
	readFileSync,
	rmSync,
	statSync,
	writeFileSync,
} from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultOutputDir = join(root, "packages", "coding-agent", "release");
const publicPackageName = process.env.ZERO_PACKAGE_NAME || "zero";
const publicCommandName = process.env.ZERO_CMD || "zero";

const releasePackages = [
	{ packageDir: "ai", publicName: undefined, artifactName: "zero-ai" },
	{ packageDir: "tui", publicName: undefined, artifactName: "zero-tui" },
	{ packageDir: "agent", publicName: undefined, artifactName: "zero-core" },
	{ packageDir: "coding-agent", publicName: publicPackageName, artifactName: publicPackageName },
];

function parseArgs(args) {
	const parsed = {
		outDir: defaultOutputDir,
		version: undefined,
	};

	for (let i = 0; i < args.length; i += 1) {
		const arg = args[i];
		switch (arg) {
			case "--out-dir": {
				const value = args[i + 1];
				if (!value) throw new Error("--out-dir requires a value");
				parsed.outDir = resolve(root, value);
				i += 1;
				break;
			}
			case "--version": {
				const value = args[i + 1];
				if (!value) throw new Error("--version requires a value");
				parsed.version = normalizeVersion(value);
				i += 1;
				break;
			}
			case "--help":
			case "-h":
				printHelp();
				process.exit(0);
				break;
			default:
				throw new Error(`Unknown argument: ${arg}`);
		}
	}

	return parsed;
}

function printHelp() {
	console.log(`Usage: node scripts/pack-zero-release.mjs [--version x.y.z] [--out-dir path]

Creates npm tarballs for GitHub Release distribution. The coding-agent
tarball's internal @zero-agent/* dependencies are rewritten to relative
file: references, so installing it works as long as all four tarballs sit
in the same directory (exactly how they land after a GitHub Release download):

  <out-dir>/artifacts/zero-<version>.tgz
  <out-dir>/artifacts/zero-ai-<version>.tgz
  <out-dir>/artifacts/zero-core-<version>.tgz
  <out-dir>/artifacts/zero-tui-<version>.tgz
  <out-dir>/artifacts/SHA256SUMS
`);
}

function normalizeVersion(version) {
	const normalized = version.startsWith("v") ? version.slice(1) : version;
	if (!/^[0-9A-Za-z.-]+$/.test(normalized)) {
		throw new Error(`Invalid release version: ${version}`);
	}
	return normalized;
}

function readJson(path) {
	return JSON.parse(readFileSync(path, "utf8"));
}

function writeJson(path, value) {
	writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function packagePath(packageDir) {
	return join(root, "packages", packageDir);
}

function assertSafeOutputDir(outDir) {
	const relativeToReleaseRoot = relative(defaultOutputDir, outDir);
	if (relativeToReleaseRoot === "" || (!relativeToReleaseRoot.startsWith("..") && !isAbsolute(relativeToReleaseRoot))) {
		return;
	}
	throw new Error(`Refusing to remove output directory outside ${defaultOutputDir}: ${outDir}`);
}

function packageJsonPath(packageDir) {
	return join(packagePath(packageDir), "package.json");
}

function requireBuiltPackage(packageDir) {
	const dist = join(packagePath(packageDir), "dist");
	if (!existsSync(dist)) {
		throw new Error(`Missing ${dist}. Run npm run build before packing a release.`);
	}
}

function copyIfExists(source, target) {
	if (existsSync(source)) {
		cpSync(source, target, { recursive: true });
	}
}

function npmTarballName(packageName, version) {
	return `${packageName.replace(/^@/, "").replace("/", "-")}-${version}.tgz`;
}

function rewriteInternalDependencies(dependencies, internalPackageUrls) {
	if (!dependencies) return undefined;
	const rewritten = {};
	for (const [name, range] of Object.entries(dependencies)) {
		rewritten[name] = internalPackageUrls.get(name) || range;
	}
	return rewritten;
}

function releaseScripts(sourceScripts) {
	if (!sourceScripts?.postinstall) return undefined;
	return {
		postinstall: sourceScripts.postinstall,
	};
}

function createReleasePackageJson(sourcePackage, packageName, releaseVersion, internalPackageUrls) {
	const packageJson = {
		...sourcePackage,
		name: packageName,
		version: releaseVersion,
		dependencies: rewriteInternalDependencies(sourcePackage.dependencies, internalPackageUrls),
		optionalDependencies: rewriteInternalDependencies(sourcePackage.optionalDependencies, internalPackageUrls),
		scripts: releaseScripts(sourcePackage.scripts),
	};

	delete packageJson.devDependencies;
	delete packageJson.overrides;
	delete packageJson.private;

	if (packageName === publicPackageName) {
		packageJson.bin = {
			[publicCommandName]: "dist/bundle/cli.js",
		};
		packageJson.piConfig = {
			...(packageJson.piConfig || {}),
			name: publicCommandName,
			// Must track config.ts's CONFIG_DIR_NAME default — this script doesn't
			// import config.ts, so it can't derive this and has to be kept in sync
			// by hand. A stale value here would silently un-rebrand every install
			// that goes through this release path (task #37/A1's config-dir move).
			configDir: ".zero/agent",
		};
	}

	return packageJson;
}

function copyPackageContents(sourceDir, targetDir, packageJson) {
	mkdirSync(targetDir, { recursive: true });
	writeJson(join(targetDir, "package.json"), packageJson);

	for (const entry of ["dist", "docs", "examples", "skills", "postinstall.cjs", "README.md", "CHANGELOG.md"]) {
		copyIfExists(join(sourceDir, entry), join(targetDir, entry));
	}
}

function run(command, args, cwd) {
	const result = spawnSync(command, args, {
		cwd,
		stdio: "pipe",
		encoding: "utf8",
		windowsHide: true,
	});

	if (result.status !== 0) {
		if (result.stdout) process.stdout.write(result.stdout);
		if (result.stderr) process.stderr.write(result.stderr);
		throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status}`);
	}

	if (result.stderr) process.stderr.write(result.stderr);
	return result.stdout.trim();
}

function sha256File(path) {
	const hash = createHash("sha256");
	hash.update(readFileSync(path));
	return hash.digest("hex");
}

function main() {
	const args = parseArgs(process.argv.slice(2));
	const sourcePackages = new Map(
		releasePackages.map((releasePackage) => [
			releasePackage.packageDir,
			readJson(packageJsonPath(releasePackage.packageDir)),
		]),
	);
	const cliPackage = sourcePackages.get("coding-agent");
	const releaseVersion = args.version || normalizeVersion(process.env.ZERO_VERSION || cliPackage.version);

	for (const releasePackage of releasePackages) {
		requireBuiltPackage(releasePackage.packageDir);
	}

	// Dependency keys stay on the source package names so existing compiled imports
	// keep resolving, while release package names and artifact filenames are branded.
	const sourcePackageNames = new Map();
	const packageNames = new Map();
	const artifactFiles = new Map();
	for (const releasePackage of releasePackages) {
		const sourcePackage = sourcePackages.get(releasePackage.packageDir);
		const packageName = releasePackage.publicName || releasePackage.artifactName || sourcePackage.name;
		sourcePackageNames.set(releasePackage.packageDir, sourcePackage.name);
		packageNames.set(releasePackage.packageDir, packageName);
		artifactFiles.set(
			releasePackage.packageDir,
			npmTarballName(releasePackage.artifactName || packageName, releaseVersion),
		);
	}

	// A relative file: reference, not an absolute path — resolves against
	// wherever the depending tarball ends up installed from, which is exactly
	// "the same directory" once a GitHub Release download drops all four
	// tarballs side by side. Verified empirically: `npm install -g` correctly
	// follows a sibling file: dependency packed this way.
	const internalPackageUrls = new Map();
	for (const releasePackage of releasePackages) {
		if (releasePackage.packageDir === "coding-agent") continue;
		const sourcePackageName = sourcePackageNames.get(releasePackage.packageDir);
		const artifactFile = artifactFiles.get(releasePackage.packageDir);
		internalPackageUrls.set(sourcePackageName, `file:./${artifactFile}`);
	}

	const stagingRoot = join(args.outDir, "packages");
	const artifactsDir = join(args.outDir, "artifacts");
	assertSafeOutputDir(args.outDir);
	rmSync(args.outDir, { force: true, recursive: true });
	mkdirSync(stagingRoot, { recursive: true });
	mkdirSync(artifactsDir, { recursive: true });

	const tarballs = [];
	for (const releasePackage of releasePackages) {
		const sourcePackage = sourcePackages.get(releasePackage.packageDir);
		const packageName = packageNames.get(releasePackage.packageDir);
		const stagingDir = join(stagingRoot, releasePackage.packageDir);
		const packageJson = createReleasePackageJson(
			sourcePackage,
			packageName,
			releaseVersion,
			internalPackageUrls,
		);

		copyPackageContents(packagePath(releasePackage.packageDir), stagingDir, packageJson);

		const tarballName = run("npm", ["pack", stagingDir, "--pack-destination", artifactsDir, "--silent"], root)
			.split("\n")
			.at(-1);
		if (!tarballName) {
			throw new Error(`npm pack did not report a tarball name for ${packageName}`);
		}

		const tarballPath = join(artifactsDir, basename(tarballName));
		if (!existsSync(tarballPath) || !statSync(tarballPath).isFile()) {
			throw new Error(`npm pack did not create ${tarballPath}`);
		}

		const artifactFile = artifactFiles.get(releasePackage.packageDir);
		const artifactPath = join(artifactsDir, artifactFile);
		if (tarballPath !== artifactPath) {
			rmSync(artifactPath, { force: true });
			renameSync(tarballPath, artifactPath);
		}

		tarballs.push({
			name: packageName,
			file: artifactFile,
			sha256: sha256File(artifactPath),
		});
	}

	tarballs.sort((left, right) => left.file.localeCompare(right.file));
	writeFileSync(
		join(artifactsDir, "SHA256SUMS"),
		tarballs.map((tarball) => `${tarball.sha256}  ${tarball.file}`).join("\n") + "\n",
	);

	for (const tarball of tarballs) {
		console.log(`Created ${join(artifactsDir, tarball.file)}`);
	}
}

try {
	main();
} catch (error) {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
}
