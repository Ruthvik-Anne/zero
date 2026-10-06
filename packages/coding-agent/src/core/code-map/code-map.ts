import { constants, type Dirent, readFileSync, realpathSync, statSync } from "node:fs";
import { lstat, open, readdir, realpath, stat } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import ts from "typescript-code-map";

// Original Zero implementation. Static file/dependency map only: edges record what the
// source text references, never task relationships. TypeScript/JavaScript edges are
// compiler-parsed and compiler-resolved; Python edges are syntactic (see grade field).

export interface CodeMapOptions {
	workspace: string;
	maxFiles?: number;
	maxBytesPerFile?: number;
	maxTotalBytes?: number;
	maxEdges?: number;
}

export type CodeEdgeGrade = "compiler" | "syntactic";
export type CodeEdgeKind =
	| "import"
	| "export-from"
	| "require"
	| "dynamic-import"
	| "type-import"
	| "python-import"
	| "python-from";

export interface CodeMapEdge {
	from: string;
	to: string | null;
	specifier: string;
	kind: CodeEdgeKind;
	line: number;
	grade: CodeEdgeGrade;
	external?: string;
	unresolved?: string;
}

export interface CodeMapSkipped {
	path: string;
	reason: string;
}

export interface CodeMapResult {
	root: string;
	files: string[];
	edges: CodeMapEdge[];
	skipped: CodeMapSkipped[];
	truncated: boolean;
}

export interface CodeMapNeighbor {
	path: string;
	depth: number;
	via: CodeMapEdge;
}

const DEFAULT_MAX_FILES = 2000;
const DEFAULT_MAX_BYTES = 512 * 1024;
const DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const DEFAULT_MAX_EDGES = 20_000;
const EXCLUDED_DIRS = new Set([
	"node_modules",
	".git",
	".zero",
	"dist",
	"build",
	"coverage",
	".turbo",
	".next",
	"__pycache__",
	".venv",
	"venv",
	".tox",
]);
const TS_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".d.ts"]);
const JS_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs"]);

function isExcludedDirectory(name: string): boolean {
	return EXCLUDED_DIRS.has(name.toLowerCase());
}

function toPosix(path: string): string {
	return path.split(sep).join("/");
}

function inside(root: string, path: string): boolean {
	const part = relative(root, path);
	return part !== "" && part !== ".." && !part.startsWith(`..${sep}`) && !isAbsolute(part);
}

function containedPath(root: string, path: string): boolean {
	const absolute = resolve(path);
	return absolute === root || inside(root, absolute);
}

function canonicalContainedSync(root: string, path: string): string | undefined {
	try {
		if (!containedPath(root, path)) return undefined;
		const canonical = realpathSync(path);
		return containedPath(root, canonical) ? canonical : undefined;
	} catch {
		return undefined;
	}
}

function resolutionHost(root: string): ts.ModuleResolutionHost {
	return {
		fileExists: (file) => {
			try {
				return containedPath(root, file) && statSync(file).isFile();
			} catch {
				return false;
			}
		},
		readFile: (file) => {
			try {
				const canonical = canonicalContainedSync(root, file);
				return canonical === undefined ? undefined : readFileSync(canonical, "utf8");
			} catch {
				return undefined;
			}
		},
		directoryExists: (directory) => {
			try {
				return containedPath(root, directory) && statSync(directory).isDirectory();
			} catch {
				return false;
			}
		},
		getCurrentDirectory: () => root,
		getDirectories: () => [],
		useCaseSensitiveFileNames: () => ts.sys.useCaseSensitiveFileNames,
		realpath: (path) => canonicalContainedSync(root, path) ?? path,
	};
}

function compilerOptionsFor(root: string): (file: string) => ts.CompilerOptions {
	const host = resolutionHost(root);
	const configCache = new Map<string, ts.CompilerOptions>();
	const directoryCache = new Map<string, string | undefined>();
	const findConfig = (file: string): string | undefined => {
		const start = dirname(file);
		if (directoryCache.has(start)) return directoryCache.get(start);
		let directory = start;
		while (containedPath(root, directory)) {
			const candidate = join(directory, "tsconfig.json");
			if (host.fileExists?.(candidate)) {
				directoryCache.set(start, candidate);
				return candidate;
			}
			if (directory === root) break;
			directory = dirname(directory);
		}
		directoryCache.set(start, undefined);
		return undefined;
	};
	return (file) => {
		const configFile = findConfig(file);
		if (!configFile) return { allowJs: true, moduleResolution: ts.ModuleResolutionKind.Node10 };
		const cached = configCache.get(configFile);
		if (cached) return cached;
		const loaded = ts.readConfigFile(configFile, (path) => host.readFile?.(path));
		if (loaded.error) return { allowJs: true, moduleResolution: ts.ModuleResolutionKind.Node10 };
		const parsed = ts.parseJsonConfigFileContent(
			loaded.config,
			{
				fileExists: (path) => host.fileExists?.(path) ?? false,
				readFile: (path) => host.readFile?.(path),
				readDirectory: () => [],
				useCaseSensitiveFileNames: ts.sys.useCaseSensitiveFileNames,
			},
			dirname(configFile),
			{ allowJs: true },
			configFile,
		);
		configCache.set(configFile, parsed.options);
		return parsed.options;
	};
}

function packageNameOf(specifier: string): string {
	const parts = specifier.split("/");
	return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : parts[0];
}

function hasNodeModules(root: string, path: string): boolean {
	return relative(root, path)
		.split(sep)
		.some((part) => part.toLowerCase() === "node_modules");
}

function sameFile(left: Awaited<ReturnType<typeof stat>>, right: Awaited<ReturnType<typeof stat>>): boolean {
	return left.dev === right.dev && left.ino === right.ino;
}

type SafeReadResult =
	| { text: string; bytes: number }
	| { reason: "binary" | "exceeds-size-limit" | "outside-workspace" | "race-detected" | "unreadable" };

async function readSourceFile(
	root: string,
	path: string,
	maxBytes: number,
	signal?: AbortSignal,
): Promise<SafeReadResult> {
	let handle: Awaited<ReturnType<typeof open>> | undefined;
	try {
		const entryStat = await lstat(path);
		if (!entryStat.isFile() || entryStat.isSymbolicLink()) return { reason: "race-detected" };
		const before = await realpath(path);
		if (!containedPath(root, before)) return { reason: "outside-workspace" };
		handle = await open(before, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
		const openedStat = await handle.stat();
		if (!openedStat.isFile()) return { reason: "unreadable" };
		if (openedStat.size > maxBytes) return { reason: "exceeds-size-limit" };
		const beforeRead = await realpath(path);
		const beforeReadStat = await stat(beforeRead);
		if (beforeRead !== before || !sameFile(openedStat, beforeReadStat)) return { reason: "race-detected" };
		const buffer = await handle.readFile({ signal });
		const after = await realpath(path);
		const afterStat = await stat(after);
		if (after !== before || !sameFile(openedStat, afterStat)) return { reason: "race-detected" };
		if (buffer.byteLength > maxBytes) return { reason: "exceeds-size-limit" };
		const text = buffer.toString("utf8");
		return text.includes("\u0000") ? { reason: "binary" } : { text, bytes: buffer.byteLength };
	} catch (error) {
		if ((error as Error).name === "AbortError") throw error;
		return { reason: "unreadable" };
	} finally {
		await handle?.close().catch(() => undefined);
	}
}

interface ResolvedTarget {
	to: string | null;
	external?: string;
	unresolved?: string;
}

async function classifyResolvedTarget(
	root: string,
	fileName: string | undefined,
	specifier: string,
	isBare: boolean,
): Promise<ResolvedTarget> {
	if (!fileName) {
		return {
			to: null,
			...(isBare ? { external: packageNameOf(specifier) } : {}),
			unresolved: "not-found",
		};
	}
	try {
		const canonical = await realpath(fileName);
		if (!containedPath(root, canonical)) return { to: null, unresolved: "outside-workspace" };
		if (hasNodeModules(root, canonical)) {
			return {
				to: null,
				...(isBare ? { external: packageNameOf(specifier) } : {}),
				...(isBare ? {} : { unresolved: "node-modules" }),
			};
		}
		if (!(await stat(canonical)).isFile()) return { to: null, unresolved: "not-found" };
		return { to: toPosix(relative(root, canonical)) };
	} catch {
		return { to: null, unresolved: "not-found" };
	}
}

async function pathEscapesWorkspace(root: string, path: string): Promise<boolean> {
	let candidate = path;
	while (containedPath(root, candidate)) {
		try {
			return !containedPath(root, await realpath(candidate));
		} catch {
			const parent = dirname(candidate);
			if (parent === candidate) break;
			candidate = parent;
		}
	}
	return false;
}

interface RawReference {
	specifier: string;
	kind: CodeEdgeKind;
	line: number;
	fallbackSpecifier?: string;
}

function collectTsReferences(sourceFile: ts.SourceFile): RawReference[] {
	const references: RawReference[] = [];
	const lineOf = (node: ts.Node): number =>
		sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
	const specifierOf = (expression: ts.Expression | undefined): string | undefined =>
		expression && ts.isStringLiteralLike(expression) ? expression.text : undefined;
	const visit = (node: ts.Node): void => {
		if (ts.isImportDeclaration(node)) {
			const specifier = specifierOf(node.moduleSpecifier);
			if (specifier !== undefined && !node.importClause?.isTypeOnly)
				references.push({ specifier, kind: "import", line: lineOf(node) });
			else if (specifier !== undefined) references.push({ specifier, kind: "type-import", line: lineOf(node) });
		} else if (ts.isExportDeclaration(node)) {
			const specifier = node.moduleSpecifier ? specifierOf(node.moduleSpecifier) : undefined;
			if (specifier !== undefined) references.push({ specifier, kind: "export-from", line: lineOf(node) });
		} else if (ts.isImportEqualsDeclaration(node)) {
			if (ts.isExternalModuleReference(node.moduleReference)) {
				const specifier = specifierOf(node.moduleReference.expression);
				if (specifier !== undefined) references.push({ specifier, kind: "require", line: lineOf(node) });
			}
		} else if (ts.isCallExpression(node)) {
			if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
				const [first] = node.arguments;
				const specifier = specifierOf(first as ts.Expression | undefined);
				if (specifier !== undefined) references.push({ specifier, kind: "dynamic-import", line: lineOf(node) });
			} else if (ts.isIdentifier(node.expression) && node.expression.text === "require") {
				const [first] = node.arguments;
				const specifier = specifierOf(first as ts.Expression | undefined);
				if (specifier !== undefined && !specifier.startsWith("node:"))
					references.push({ specifier, kind: "require", line: lineOf(node) });
			}
		} else if (ts.isImportTypeNode(node)) {
			if (ts.isLiteralTypeNode(node.argument) && ts.isStringLiteralLike(node.argument.literal))
				references.push({ specifier: node.argument.literal.text, kind: "type-import", line: lineOf(node) });
		}
		ts.forEachChild(node, visit);
	};
	ts.forEachChild(sourceFile, visit);
	return references;
}

function stripPythonNoise(text: string): string[] {
	const lines: string[] = [];
	let inTriple: string | undefined;
	for (const raw of text.split("\n")) {
		let line = raw;
		if (inTriple) {
			const end = line.indexOf(inTriple);
			if (end < 0) continue;
			line = line.slice(end + inTriple.length);
			inTriple = undefined;
		}
		for (;;) {
			const single = line.indexOf('"""') >= 0 ? '"""' : line.indexOf("'''") >= 0 ? "'''" : undefined;
			if (!single) break;
			const start = line.indexOf(single);
			const end = line.indexOf(single, start + 3);
			if (end < 0) {
				line = line.slice(0, start);
				inTriple = single;
				break;
			}
			line = line.slice(0, start) + line.slice(end + 3);
		}
		const hash = line.indexOf("#");
		lines.push(hash < 0 ? line : line.slice(0, hash));
	}
	return lines;
}

function collectPythonReferences(text: string): RawReference[] {
	const references: RawReference[] = [];
	const lines = stripPythonNoise(text);
	lines.forEach((line, index) => {
		const lineNumber = index + 1;
		const importMatch = /^\s*import\s+([A-Za-z0-9_.]+(?:\s*,\s*[A-Za-z0-9_.]+)*)/.exec(line);
		if (importMatch) {
			for (const specifier of importMatch[1]
				.split(",")
				.map((part) => part.trim())
				.filter(Boolean))
				references.push({ specifier, kind: "python-import", line: lineNumber });
			return;
		}
		const fromMatch = /^\s*from\s+(\.*[A-Za-z0-9_.]*)\s+import\s+(.+)$/.exec(line);
		if (!fromMatch) return;
		const module = fromMatch[1];
		for (const imported of fromMatch[2]
			.replace(/[()]/g, "")
			.split(",")
			.map((part) => part.trim().split(/\s+as\s+/)[0])
			.filter((part) => part.length > 0 && part !== "*")) {
			const separator = module.endsWith(".") ? "" : ".";
			references.push({
				specifier: `${module}${separator}${imported}`,
				fallbackSpecifier: module,
				kind: "python-from",
				line: lineNumber,
			});
		}
	});
	return references;
}

async function resolvePythonSpecifier(
	root: string,
	fromFile: string,
	specifier: string,
	fallbackSpecifier?: string,
): Promise<string | undefined> {
	const candidates: string[] = [];
	for (const candidateSpecifier of [specifier, fallbackSpecifier]) {
		if (!candidateSpecifier) continue;
		if (candidateSpecifier.startsWith(".")) {
			const level = candidateSpecifier.match(/^\.+/)![0].length;
			const rest = candidateSpecifier.slice(level);
			let base = dirname(fromFile);
			for (let i = 1; i < level; i++) base = dirname(base);
			const parts = rest ? rest.split(".") : [];
			candidates.push(join(base, ...parts));
		} else {
			const parts = candidateSpecifier.split(".");
			candidates.push(join(dirname(fromFile), ...parts), join(root, ...parts));
		}
	}
	for (const candidate of candidates) {
		for (const file of [`${candidate}.py`, join(candidate, "__init__.py")]) {
			try {
				const absolute = resolve(root, file);
				if (!inside(root, absolute) && absolute !== root) continue;
				if (!(await stat(absolute)).isFile()) continue;
				const canonical = await realpath(absolute);
				if (!containedPath(root, canonical) || hasNodeModules(root, canonical)) continue;
				return toPosix(relative(root, canonical));
			} catch {
				// Try the next candidate.
			}
		}
	}
	return undefined;
}

export async function buildCodeMap(options: CodeMapOptions, signal?: AbortSignal): Promise<CodeMapResult> {
	if (!options.workspace || options.workspace.length > 4096) throw new Error("Invalid workspace");
	const root = await realpath(options.workspace);
	const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
	const maxBytes = options.maxBytesPerFile ?? DEFAULT_MAX_BYTES;
	const maxTotalBytes = options.maxTotalBytes ?? DEFAULT_MAX_TOTAL_BYTES;
	const maxEdges = options.maxEdges ?? DEFAULT_MAX_EDGES;
	for (const [name, value] of Object.entries({ maxFiles, maxBytesPerFile: maxBytes, maxTotalBytes, maxEdges })) {
		if (!Number.isSafeInteger(value) || value < 0) throw new Error(`Invalid ${name}`);
	}
	const optionsForFile = compilerOptionsFor(root);
	const host = resolutionHost(root);
	const files: string[] = [];
	const edges: CodeMapEdge[] = [];
	const skipped: CodeMapSkipped[] = [];
	let truncated = false;
	let totalBytes = 0;
	const stack: string[] = [root];
	scan: while (stack.length > 0) {
		signal?.throwIfAborted();
		const directory = stack.pop()!;
		let canonicalDirectory: string;
		try {
			canonicalDirectory = await realpath(directory);
			if (!containedPath(root, canonicalDirectory)) continue;
		} catch {
			continue;
		}
		const entries: Dirent[] = await readdir(canonicalDirectory, { withFileTypes: true }).catch(() => []);
		for (const entry of entries) {
			signal?.throwIfAborted();
			const absolute = join(canonicalDirectory, entry.name);
			const rel = toPosix(relative(root, absolute));
			const entryStat = await lstat(absolute).catch(() => undefined);
			if (!entryStat) continue;
			if (entryStat.isSymbolicLink()) {
				skipped.push({ path: rel, reason: "symlink-not-followed" });
				continue;
			}
			if (entryStat.isDirectory()) {
				if (!isExcludedDirectory(entry.name)) {
					try {
						const canonical = await realpath(absolute);
						if (canonical === absolute && containedPath(root, canonical)) stack.push(canonical);
					} catch {
						// Ignore directories that disappear or change while scanning.
					}
				}
				continue;
			}
			if (!entryStat.isFile()) continue;
			const extension = entry.name.endsWith(".d.ts")
				? ".d.ts"
				: basename(absolute).includes(".")
					? `.${basename(absolute).split(".").pop()}`
					: "";
			const language =
				TS_EXTENSIONS.has(extension) || JS_EXTENSIONS.has(extension)
					? "ts"
					: extension === ".py"
						? "py"
						: undefined;
			if (!language) continue;
			if (files.length >= maxFiles) {
				truncated = true;
				break scan;
			}
			const source = await readSourceFile(root, absolute, maxBytes, signal);
			if (!("text" in source)) {
				skipped.push({ path: rel, reason: source.reason });
				continue;
			}
			if (totalBytes + source.bytes > maxTotalBytes) {
				skipped.push({ path: rel, reason: "exceeds-total-size-limit" });
				truncated = true;
				break scan;
			}
			totalBytes += source.bytes;
			const text = source.text;
			files.push(rel);
			if (language === "py") {
				for (const reference of collectPythonReferences(text)) {
					if (edges.length >= maxEdges) {
						truncated = true;
						break scan;
					}
					const resolved = await resolvePythonSpecifier(
						root,
						absolute,
						reference.specifier,
						reference.fallbackSpecifier,
					);
					edges.push({
						from: rel,
						to: resolved ?? null,
						specifier: reference.specifier,
						kind: reference.kind,
						line: reference.line,
						grade: "syntactic",
						...(resolved ? {} : { unresolved: "not-found" }),
					});
				}
				continue;
			}
			const sourceFile = ts.createSourceFile(absolute, text, ts.ScriptTarget.Latest, true);
			const compilerOptions = optionsForFile(absolute);
			for (const reference of collectTsReferences(sourceFile)) {
				signal?.throwIfAborted();
				if (edges.length >= maxEdges) {
					truncated = true;
					break scan;
				}
				const isBare =
					!ts.isExternalModuleNameRelative(reference.specifier) && !reference.specifier.startsWith("/");
				const lexical = isBare ? undefined : resolve(dirname(absolute), reference.specifier);
				const target =
					lexical !== undefined && (!containedPath(root, lexical) || (await pathEscapesWorkspace(root, lexical)))
						? { to: null, unresolved: "outside-workspace" }
						: await classifyResolvedTarget(
								root,
								ts.resolveModuleName(reference.specifier, absolute, compilerOptions, host).resolvedModule
									?.resolvedFileName,
								reference.specifier,
								isBare,
							);
				edges.push({
					from: rel,
					...target,
					specifier: reference.specifier,
					kind: reference.kind,
					line: reference.line,
					grade: "compiler",
				});
			}
		}
	}
	return { root, files, edges, skipped, truncated };
}

function normalizeMapPath(path: string): string {
	return toPosix(path).replace(/^\.\//, "");
}

function walkGraph(map: CodeMapResult, start: string, forward: boolean, maxDepth: number): CodeMapNeighbor[] {
	const origin = normalizeMapPath(start);
	const visited = new Set<string>([origin]);
	const queue: { path: string; depth: number }[] = [{ path: origin, depth: 0 }];
	const neighbors: CodeMapNeighbor[] = [];
	const adjacency = new Map<string, { target: string; edge: CodeMapEdge }[]>();
	for (const edge of map.edges) {
		const source = forward ? edge.from : edge.to;
		const target = forward ? edge.to : edge.from;
		if (source === null || target === null) continue;
		const adjacent = adjacency.get(source) ?? [];
		adjacent.push({ target, edge });
		adjacency.set(source, adjacent);
	}
	let head = 0;
	while (head < queue.length) {
		const current = queue[head++];
		if (current.depth >= maxDepth) continue;
		for (const { target, edge } of adjacency.get(current.path) ?? []) {
			if (visited.has(target)) continue;
			visited.add(target);
			neighbors.push({ path: target, depth: current.depth + 1, via: edge });
			queue.push({ path: target, depth: current.depth + 1 });
		}
	}
	return neighbors;
}

export function dependenciesOf(
	map: CodeMapResult,
	path: string,
	maxDepth = Number.POSITIVE_INFINITY,
): CodeMapNeighbor[] {
	return walkGraph(map, path, true, maxDepth);
}

export function dependentsOf(map: CodeMapResult, path: string, maxDepth = Number.POSITIVE_INFINITY): CodeMapNeighbor[] {
	return walkGraph(map, path, false, maxDepth);
}

export function isCodeMapPath(value: unknown): value is string {
	return typeof value === "string" && value.length > 0 && value.length <= 4096 && !/[\x00-\x1f]/.test(value);
}

export async function canonicalMapPath(root: string, raw: string): Promise<string> {
	if (!isCodeMapPath(raw)) throw new Error("Invalid file path");
	const absolute = resolve(root, raw);
	if (!inside(root, absolute) && absolute !== root) throw new Error("File path outside workspace");
	const parts = relative(root, absolute).split(sep);
	if (parts.some((part) => [".zero", ".git", "node_modules"].includes(part.toLowerCase())))
		throw new Error("Private file path denied");
	return toPosix(relative(root, absolute));
}
