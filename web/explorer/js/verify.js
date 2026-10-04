// The cc-wasm-verify module, loaded from bytes. The module imports nothing
// from the host: it gets bytes in and gives JSON out, and that is all.
//
// What it does and does not recompute is stated by the module itself
// (`about().not_recomputed`, and every report's `not_recomputed`); the UI
// shows that text verbatim rather than paraphrasing it.

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export async function loadVerifier(bytes) {
  const { instance } = await WebAssembly.instantiate(bytes, {});
  const x = instance.exports;
  const output = (len) => JSON.parse(decoder.decode(new Uint8Array(x.memory.buffer, x.cc_output_ptr(), len)));
  const call = (fn, input) => {
    const data = typeof input === 'string' ? encoder.encode(input) : input;
    const ptr = x.cc_alloc(data.length);
    new Uint8Array(x.memory.buffer, ptr, data.length).set(data);
    return output(fn(ptr, data.length));
  };
  return {
    // `input`: {health, snapshot, export?, reads?}, each document as response text.
    verify: (input) => call(x.cc_verify, JSON.stringify(input)),
    ttKind: (kind) => call(x.cc_tt_kind, kind),
    taxonomyPinned: (bytes) => call(x.cc_taxonomy, bytes).pinned === true,
    about: () => output(x.cc_about()),
  };
}
