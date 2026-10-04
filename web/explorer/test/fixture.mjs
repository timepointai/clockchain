// Shared helpers: the recorded synthetic fixture, read from disk, and a
// fetch stand-in that serves files from the explorer directory.
import { readFile, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const explorer = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const root = path.resolve(explorer, '../..');
export const fixtureDir = path.join(explorer, 'fixtures/synthetic');

export async function text(rel) {
  return readFile(path.join(fixtureDir, rel), 'utf8');
}
export async function json(rel) {
  return JSON.parse(await text(rel));
}
export async function files(sub) {
  return (await readdir(path.join(fixtureDir, sub))).sort();
}

// `fetch` over the explorer directory: 200 with the file, 404 when absent.
export async function fileFetch(url) {
  const rel = url.replace(/^\.\//, '');
  try {
    const body = await readFile(path.join(explorer, rel), 'utf8');
    return { ok: true, status: 200, text: async () => body };
  } catch {
    return { ok: false, status: 404, text: async () => 'not found' };
  }
}

// The release wasm32 build of cc-wasm-verify, or CC_VERIFY_WASM.
export async function wasmBytes() {
  const p = process.env.CC_VERIFY_WASM ?? path.join(root, 'target/wasm32-unknown-unknown/release/cc_wasm_verify.wasm');
  return readFile(p);
}
