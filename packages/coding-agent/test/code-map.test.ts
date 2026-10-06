import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, expect, it } from "vitest";
import {
	buildCodeMap,
	type CodeMapEdge,
	type CodeMapResult,
	dependenciesOf,
	dependentsOf,
} from "../src/core/code-map/code-map.js";

const directories: string[] = [];
afterEach(async () => {
	for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true });
});

async function fixture(files: Record<string, string>): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), "zero-code-map-"));
	directories.push(directory);
	for (const [name, content] of Object.entries(files)) {
		const path = join(directory, name);
		await mkdir(join(path, ".."), { recursive: true });
		await writeFile(path, content);
	}
	return directory;
}

const TS_FILES = {
	"a.ts": `import { b } from "./b.js";\nimport type { C } from "./c";\nexport * from "./d";\nconsole.log(b);\n`,
	"b.ts": `export const b = 1;\nimport "./side-effect";\n`,
	"c.ts": `export interface C { x: number }\n`,
	"d.ts": `export const d = 2;\n`,
	"side-effect.ts": `console.log("side");\n`,
	"dynamic.ts": `export async function load() { const m = await import("./b.js"); return m; }\n`,
	"legacy.cjs": `const { b } = require("./b.js");\nmodule.exports = { b };\n`,
	"missing.ts": `import "./does-not-exist";\nimport "some-uninstalled-package";\n`,
	"cycle1.ts": `import "./cycle2";\nexport const one = 1;\n`,
	"cycle2.ts": `import "./cycle1";\nexport const two = 2;\n`,
	"main.py": `import helper\nfrom pkg import thing\n`,
	"helper.py": `VALUE = 1\n`,
	"pkg/__init__.py": ``,
	"pkg/thing.py": `X = 2\n`,
};

it("maps compiler-resolved TypeScript imports, exports and require calls", async () => {
	const workspace = await fixture(TS_FILES);
	const map = await buildCodeMap({ workspace });
	const edge = (from: string, specifier: string) =>
		map.edges.find((e) => e.from === from && e.specifier === specifier);
	expect(edge("a.ts", "./b.js")).toMatchObject({ to: "b.ts", kind: "import", grade: "compiler", line: 1 });
	expect(edge("a.ts", "./c")).toMatchObject({ to: "c.ts", kind: "type-import", grade: "compiler" });
	expect(edge("a.ts", "./d")).toMatchObject({ to: "d.ts", kind: "export-from", grade: "compiler" });
	expect(edge("b.ts", "./side-effect")).toMatchObject({ to: "side-effect.ts", kind: "import" });
	expect(edge("dynamic.ts", "./b.js")).toMatchObject({ to: "b.ts", kind: "dynamic-import" });
	expect(edge("legacy.cjs", "./b.js")).toMatchObject({ to: "b.ts", kind: "require" });
	expect(map.files).toContain("a.ts");
});

it("reports unresolved specifiers instead of inventing edges", async () => {
	const workspace = await fixture(TS_FILES);
	const map = await buildCodeMap({ workspace });
	const missing = map.edges.filter((e) => e.from === "missing.ts");
	expect(missing).toHaveLength(2);
	expect(missing[0]).toMatchObject({ to: null });
	expect(missing[0].unresolved).toMatch(/not-found|unresolved/i);
	expect(missing[1]).toMatchObject({ to: null, external: "some-uninstalled-package" });
	expect(dependenciesOf(map, "missing.ts")).toEqual([]);
});

it("walks forward dependencies and reverse dependents through cycles without looping", async () => {
	const workspace = await fixture(TS_FILES);
	const map = await buildCodeMap({ workspace });
	expect(
		dependenciesOf(map, "a.ts")
			.map((d) => d.path)
			.sort(),
	).toEqual(["b.ts", "c.ts", "d.ts", "side-effect.ts"]);
	expect(
		dependentsOf(map, "b.ts")
			.map((d) => d.path)
			.sort(),
	).toEqual(["a.ts", "dynamic.ts", "legacy.cjs"]);
	expect(dependenciesOf(map, "cycle1.ts").map((d) => d.path)).toEqual(["cycle2.ts"]);
	expect(dependentsOf(map, "cycle1.ts").map((d) => d.path)).toEqual(["cycle2.ts"]);
});

it("resolves tsconfig path aliases within the workspace only", async () => {
	const workspace = await fixture({
		...TS_FILES,
		"tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "@app/*": ["src/*"] } } }),
		"src/util.ts": `export const util = 1;\n`,
		"entry.ts": `import { util } from "@app/util";\nconsole.log(util);\n`,
	});
	const map = await buildCodeMap({ workspace });
	expect(map.edges.find((e) => e.from === "entry.ts")).toMatchObject({ to: "src/util.ts", grade: "compiler" });
});

it("uses inherited and package-level Node16 resolution options", async () => {
	const workspace = await fixture({
		"tsconfig.json": JSON.stringify({ extends: "./config/base.json" }),
		"config/base.json": JSON.stringify({ compilerOptions: { strict: true } }),
		"packages/app/tsconfig.json": JSON.stringify({
			extends: "../../tsconfig.json",
			compilerOptions: {
				module: "Node16",
				moduleResolution: "Node16",
				baseUrl: ".",
				paths: { "@app/*": ["src/*"] },
			},
		}),
		"packages/app/package.json": JSON.stringify({
			name: "@fixture/app",
			type: "module",
			exports: { "./util": "./src/util.ts" },
		}),
		"packages/app/src/util.ts": `export const util = 1;\n`,
		"packages/app/src/main.ts": `import { util as aliased } from "@app/util";\nimport { util } from "@fixture/app/util";\nconsole.log(aliased, util);\n`,
	});
	const map = await buildCodeMap({ workspace });
	const edges = map.edges.filter((edge) => edge.from === "packages/app/src/main.ts");
	expect(edges.find((edge) => edge.specifier === "@app/util")).toMatchObject({
		to: "packages/app/src/util.ts",
	});
	expect(edges.find((edge) => edge.specifier === "@fixture/app/util")).toMatchObject({
		to: "packages/app/src/util.ts",
	});
});

it("maps Python imports syntactically and labels the grade honestly", async () => {
	const workspace = await fixture(TS_FILES);
	const map = await buildCodeMap({ workspace });
	const edges = map.edges.filter((e) => e.from === "main.py");
	expect(edges.find((e) => e.specifier === "helper")).toMatchObject({
		to: "helper.py",
		kind: "python-import",
		grade: "syntactic",
	});
	expect(edges.find((e) => e.specifier === "pkg.thing" || e.specifier === "pkg")).toMatchObject({
		kind: "python-from",
		grade: "syntactic",
	});
});

it("resolves Python relative imports and imported child modules", async () => {
	const workspace = await fixture({
		"pkg/__init__.py": `from . import child\n`,
		"pkg/child.py": `VALUE = 1\n`,
		"main.py": `from pkg import child\n`,
	});
	const map = await buildCodeMap({ workspace });
	expect(map.edges.find((edge) => edge.from === "pkg/__init__.py")).toMatchObject({
		specifier: ".child",
		to: "pkg/child.py",
		kind: "python-from",
	});
	expect(map.edges.find((edge) => edge.from === "main.py")).toMatchObject({
		specifier: "pkg.child",
		to: "pkg/child.py",
		kind: "python-from",
	});
});

it("refuses symlinks, private paths and traversal without following them", async () => {
	const workspace = await fixture(TS_FILES);
	await symlink(join(workspace, "a.ts"), join(workspace, "link.ts"), "junction").catch(() =>
		symlink(join(workspace, "a.ts"), join(workspace, "link.ts")),
	);
	const map = await buildCodeMap({ workspace });
	expect(map.files).not.toContain("link.ts");
	expect(map.skipped.some((s) => s.path === "link.ts")).toBe(true);
});

it("rejects symlink escapes and modules under nested node_modules", async () => {
	const outside = await fixture({ "secret.ts": `export const secret = 1;\n` });
	const workspace = await fixture({
		"src/main.ts": `import "./linked/secret.js";\nimport "hidden";\nimport "./node_modules/hidden/index.js";\n`,
		"src/node_modules/hidden/package.json": JSON.stringify({ types: "index.ts" }),
		"src/node_modules/hidden/index.ts": `export default 1;\n`,
	});
	await symlink(outside, join(workspace, "src", "linked"), "junction");
	const map = await buildCodeMap({ workspace });
	expect(map.files).not.toContain("src/linked/secret.ts");
	expect(map.files).not.toContain("src/node_modules/hidden/index.ts");
	expect(map.edges.find((edge) => edge.specifier === "./linked/secret.js")).toMatchObject({
		to: null,
		unresolved: "outside-workspace",
	});
	expect(map.edges.find((edge) => edge.specifier === "hidden")).toMatchObject({
		to: null,
		external: "hidden",
	});
	expect(map.edges.find((edge) => edge.specifier === "./node_modules/hidden/index.js")).toMatchObject({
		to: null,
		unresolved: "node-modules",
	});
});

it("honors cancellation and file bounds", async () => {
	const workspace = await fixture(TS_FILES);
	const abort = new AbortController();
	abort.abort();
	await expect(buildCodeMap({ workspace }, abort.signal)).rejects.toThrow();
	const bounded = await buildCodeMap({ workspace, maxFiles: 2 });
	expect(bounded.truncated).toBe(true);
	expect(bounded.files.length).toBeLessThanOrEqual(2);
});

it("bounds aggregate bytes and emitted edges", async () => {
	const workspace = await fixture({
		"a.ts": `import "./b";\nimport "./c";\nimport "./d";\n`,
	});
	const bytesBounded = await buildCodeMap({ workspace, maxTotalBytes: 1 });
	expect(bytesBounded.files).toEqual([]);
	expect(bytesBounded.truncated).toBe(true);
	expect(bytesBounded.skipped).toContainEqual({ path: "a.ts", reason: "exceeds-total-size-limit" });

	const edgesBounded = await buildCodeMap({ workspace, maxEdges: 2 });
	expect(edgesBounded.edges).toHaveLength(2);
	expect(edgesBounded.truncated).toBe(true);
});

it("indexes graph edges once per traversal", () => {
	const edges: CodeMapEdge[] = [];
	for (let index = 0; index < 100; index++) {
		edges.push({
			from: `file-${index}.ts`,
			to: `file-${index + 1}.ts`,
			specifier: `./file-${index + 1}`,
			kind: "import",
			line: 1,
			grade: "compiler",
		});
	}
	let iterations = 0;
	const observedEdges = new Proxy(edges, {
		get(target, property, receiver) {
			if (property === Symbol.iterator) iterations++;
			return Reflect.get(target, property, receiver);
		},
	});
	const map: CodeMapResult = {
		root: "fixture",
		files: [],
		edges: observedEdges,
		skipped: [],
		truncated: false,
	};

	expect(dependenciesOf(map, "file-0.ts")).toHaveLength(100);
	expect(iterations).toBe(1);
});
