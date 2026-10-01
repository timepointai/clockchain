// Runs the wasm32 build of cc-wasm-vectors and requires every vector to match.
import { readFile } from 'node:fs/promises';
const path = process.argv[2];
const { instance } = await WebAssembly.instantiate(await readFile(path), {});
const mask = instance.exports.cc_rule_vectors();
console.log(`wasm rule vectors mask 0x${mask.toString(16)}`);
if (mask !== 0xff) process.exit(1);
