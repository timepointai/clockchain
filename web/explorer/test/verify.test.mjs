// The release wasm32 build of cc-wasm-verify, driven exactly as the page
// drives it, against the recorded synthetic fixture.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { loadVerifier } from '../js/verify.js';
import { text, files, wasmBytes, root } from './fixture.mjs';

const bytes = await wasmBytes();
const v = await loadVerifier(bytes);
const health = await text('health.json');
const snapshot = await text('snapshot.json');
const exportText = await text('export.json');
const reads = [];
for (const f of await files('subjects')) reads.push({ kind: 'subject', body: await text(`subjects/${f}`) });
for (const r of await files('revisions')) reads.push({ kind: 'prose', body: await text(`revisions/${r}/prose.json`) });
for (const f of await files('support')) reads.push({ kind: 'support', body: await text(`support/${f}`) });
const status = (report, name) => report.checks.find((c) => c.name === name)?.status;
const edit = (s, f) => {
  const v = JSON.parse(s);
  f(v);
  return JSON.stringify(v);
};

test('the module imports nothing from the host', () => {
  const mod = new WebAssembly.Module(bytes);
  assert.deepEqual(WebAssembly.Module.imports(mod), []);
  const names = WebAssembly.Module.exports(mod).map((e) => e.name).sort();
  assert.deepEqual(names, ['cc_about', 'cc_alloc', 'cc_output_len', 'cc_output_ptr', 'cc_taxonomy', 'cc_tt_kind', 'cc_verify', 'memory']);
});

test('the recorded fixture verifies in wasm, signatures included', () => {
  const r = v.verify({ health, snapshot, export: exportText, reads });
  assert.equal(r.outcome, 'verified', JSON.stringify(r.checks, null, 1));
  assert.equal(r.checks.length, 10 + reads.length);
  assert.ok(r.checks.every((c) => c.status === 'pass'));
  assert.equal(r.recomputed.commitment, JSON.parse(snapshot).commitment);
  assert.equal(r.recomputed.signatures, 9);
});

test('without the export, signatures are not checked and the outcome is partial', () => {
  const r = v.verify({ health, snapshot, reads });
  assert.equal(r.outcome, 'partial');
  assert.equal(status(r, 'signatures'), 'not_checked');
});

test('a flipped signature bit fails in wasm', () => {
  const ex = edit(exportText, (m) => {
    const e = m.envelopes[0];
    m.envelopes[0] = e.slice(0, -1) + (e.at(-1) === '0' ? '1' : '0');
  });
  const r = v.verify({ health, snapshot, export: ex });
  assert.equal(r.outcome, 'failed');
  assert.equal(status(r, 'signatures'), 'fail');
});

test('a tampered projection row fails the commitment in wasm', () => {
  const s = edit(snapshot, (x) => {
    x.subjects[0].frozen = !x.subjects[0].frozen;
  });
  const r = v.verify({ health, snapshot: s });
  assert.equal(status(r, 'event_ids'), 'pass');
  assert.equal(status(r, 'view_commitment'), 'fail');
  assert.equal(r.outcome, 'failed');
});

test('a malformed request is an error object, not a trap', () => {
  assert.match(v.verify({ health }).error, /missing field `snapshot`/);
  const r = v.verify({ health: '{}', snapshot: '{}' });
  assert.equal(r.outcome, 'failed');
  assert.equal(status(r, 'health'), 'fail');
});

test('the verifier states what it does not recompute, the fold first', () => {
  const about = v.about();
  assert.equal(about.fold_version.version, 1);
  assert.equal(about.fold_version.manifest, JSON.parse(health).fold_version.manifest);
  assert.match(about.not_recomputed[0], /^The fold itself\./);
  assert.match(about.not_recomputed[0], /wasm-clean projection crate, which is a future owner decision/);
});

test('TT kind path and pinned taxonomy check', async () => {
  const k = v.ttKind('printing-and-publishing');
  assert.equal(k.valid, true);
  assert.equal(k.path.at(-1), 'printing-and-publishing');
  assert.equal(k.path.length, 3);
  assert.equal(v.ttKind('not-a-kind').valid, false);
  const tax = await readFile(path.join(root, 'vendor/tt/taxonomy-v2.1.json'));
  assert.equal(v.taxonomyPinned(tax), true);
  const altered = Buffer.concat([tax, Buffer.from(' ')]);
  assert.equal(v.taxonomyPinned(altered), false);
});
