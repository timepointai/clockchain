// Cross-target parity check for the consensus rule.
//
// The whole reason `cc-filter` is an isolated pure crate is that the same
// compiled logic must reach the same verdict on a server, in a batch backfill,
// and inside an embedded wasm mirror. That claim is only worth anything if it is
// checked against the artifacts, so this script checks two things about the
// `wasm32-unknown-unknown` build:
//
//   1. It imports nothing. A module with an empty host-import table cannot
//      consult `Date.now`, a random source, or any wall clock — so "the filter
//      cannot secretly read live time" becomes a property of the binary rather
//      than a promise in a review comment. A filter that read wall-clock time
//      would leak the live graph into a t_q-pinned verdict and break monotonicity
//      at the root.
//   2. Its golden digest equals the native one. That digest folds every golden
//      judgment's consensus projection — verdict kind, supp(Φ), filter version —
//      and deliberately excludes Φ's magnitude, whose float smoothing is not
//      guaranteed bit-identical across targets and is harmless because it never
//      gates.
//
// Usage:  node tools/wasm-parity.mjs <module.wasm> <expected-hex-digest>

import { readFile } from "node:fs/promises";

const [, , wasmPath, expected] = process.argv;
if (!wasmPath || !expected) {
  console.error("usage: node wasm-parity.mjs <module.wasm> <expected-hex-digest>");
  process.exit(2);
}

const bytes = await readFile(wasmPath);
const module = await WebAssembly.compile(bytes);

const imports = WebAssembly.Module.imports(module);
if (imports.length > 0) {
  console.error("FAIL: the filter module imports host functionality:");
  for (const i of imports) console.error(`  ${i.module}.${i.name} (${i.kind})`);
  process.exit(1);
}

const instance = await WebAssembly.instantiate(module, {});
const word = instance.exports.cc_filter_golden_digest_word;
if (typeof word !== "function") {
  console.error("FAIL: cc_filter_golden_digest_word is not exported");
  process.exit(1);
}

let digest = "";
for (let i = 0; i < 8; i++) {
  digest += (word(i) >>> 0).toString(16).padStart(8, "0");
}

if (digest !== expected) {
  console.error(`FAIL: wasm digest ${digest} != native digest ${expected}`);
  process.exit(1);
}

console.log(`ok: no host imports; wasm and native agree on ${digest}`);
