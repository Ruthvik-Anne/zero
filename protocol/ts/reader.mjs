// Protocol reader (TypeScript/JavaScript projection) for the golden fixtures.
// Mirrors zero_types::proto: u32 big-endian length, then UTF-8 JSON.
import fs from "node:fs";

export function decodeAll(buf) {
  const frames = [];
  let offset = 0;
  while (offset < buf.length) {
    if (buf.length - offset < 4) {
      throw new Error(`truncated length prefix at byte ${offset}`);
    }
    const len = buf.readUInt32BE(offset);
    offset += 4;
    if (len > 8 * 1024 * 1024) {
      throw new Error(`declared frame length ${len} exceeds limit`);
    }
    if (buf.length - offset < len) {
      throw new Error(`truncated frame body at byte ${offset}`);
    }
    const text = buf.subarray(offset, offset + len).toString("utf8");
    const frame = JSON.parse(text);
    if (frame.v !== 1) {
      throw new Error(`unsupported protocol version ${frame.v}`);
    }
    frames.push(frame);
    offset += len;
  }
  return frames;
}

export function encode(frame) {
  const body = Buffer.from(JSON.stringify(frame), "utf8");
  if (body.length > 8 * 1024 * 1024) {
    throw new Error("frame too large");
  }
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32BE(body.length, 0);
  return Buffer.concat([prefix, body]);
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || process.argv[1]?.endsWith("reader.mjs")) {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: node protocol/ts/reader.mjs <frames.bin>");
    process.exit(2);
  }
  const frames = decodeAll(fs.readFileSync(path));
  process.stdout.write(JSON.stringify(frames, null, 2) + "\n");
}
