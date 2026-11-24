// Golden-fixture check: the TypeScript reader must decode exactly what the Rust
// writer produced, byte for byte at the JSON level.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { decodeAll, encode } from "./reader.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const golden = path.resolve(here, "..", "golden");
let checked = 0;

// Structural comparison: JSON object key order is not part of the schema.
function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false;
  return ka.every((k) => deepEqual(a[k], b[k]));
}

for (const file of fs.readdirSync(golden)) {
  if (!file.endsWith(".bin")) continue;
  const bin = fs.readFileSync(path.join(golden, file));
  const expected = JSON.parse(fs.readFileSync(path.join(golden, file.replace(/\.bin$/, ".json")), "utf8"));
  const frames = decodeAll(bin);
  if (frames.length !== expected.length) {
    throw new Error(`${file}: decoded ${frames.length}, expected ${expected.length}`);
  }
  frames.forEach((frame, i) => {
    if (!deepEqual(frame, expected[i])) {
      throw new Error(`${file}[${i}] differs:\n${JSON.stringify(frame)}\n${JSON.stringify(expected[i])}`);
    }
  });
  // Re-encoding must reproduce the same bytes.
  const reencoded = Buffer.concat(frames.map(encode));
  if (!reencoded.equals(bin)) throw new Error(`${file}: re-encoding differs`);
  checked += 1;
}

if (checked === 0) {
  console.error("no golden fixtures found");
  process.exit(1);
}
console.log(`typescript reader: ${checked} golden fixture file(s) decoded and re-encoded identically`);
