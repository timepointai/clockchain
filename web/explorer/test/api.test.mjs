import test from 'node:test';
import assert from 'node:assert/strict';
import { client } from '../js/api.js';
import { fileFetch, files, text } from './fixture.mjs';

test('fixture mode serves the recorded files and only those', async () => {
  const api = client({ fixture: './fixtures/synthetic', fetchImpl: fileFetch });
  const [a, b] = (await files('subjects')).filter((f) => !f.includes('.as_of.')).map((f) => f.replace('.json', ''));
  const s = await api.snapshot();
  assert.equal(s.status, 200);
  assert.equal(s.text, await text('snapshot.json'));
  assert.equal((await api.subject(a)).json.subject, a);
  assert.equal((await api.support(a, b)).json.from, a);
  // A recorded as_of read is served as recorded; an unrecorded one is refused,
  // never answered from the current reading.
  const recorded = (await files('subjects')).find((f) => f.startsWith(`${a}.as_of.`));
  const q = recorded.slice(-69, -5);
  const hit = await api.subject(a, q);
  assert.equal(hit.json.as_of, q);
  assert.equal(hit.json.visibility, 'after_as_of');
  const asOf = await api.subject(a, 'f'.repeat(64));
  assert.equal(asOf.status, 404);
  assert.deepEqual(asOf.json, { error: 'not_recorded' });
  assert.equal((await api.subject('0'.repeat(64))).status, 404);
});

test('gateway mode builds the /public/v1 contract URLs', async () => {
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(url);
    return { ok: true, status: 200, text: async () => '{}' };
  };
  const api = client({ base: '/public/v1', fetchImpl });
  const a = 'a'.repeat(64), b = 'b'.repeat(64), t = 'c'.repeat(64);
  await api.health();
  await api.snapshot();
  await api.subject(a);
  await api.subject(a, t);
  await api.prose(b);
  await api.support(a, b);
  await api.support(a, b, t);
  assert.deepEqual(seen, [
    '/public/v1/health',
    '/public/v1/snapshot',
    `/public/v1/subjects/${a}`,
    `/public/v1/subjects/${a}?as_of=${t}`,
    `/public/v1/revisions/${b}/prose`,
    `/public/v1/support?from=${a}&to=${b}`,
    `/public/v1/support?from=${a}&to=${b}&as_of=${t}`,
  ]);
  // The export is not a public route; the gateway client never asks for it.
  assert.equal((await api.export()).status, 404);
  assert.equal(seen.length, 7);
});
