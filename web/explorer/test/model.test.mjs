import test from 'node:test';
import assert from 'node:assert/strict';
import * as m from '../js/model.js';
import { json, files } from './fixture.mjs';

const snapshot = await json('snapshot.json');
const [A, B] = (await files('subjects')).map((f) => f.replace('.json', ''));
const subjectA = await json(`subjects/${A}.json`);

test('hex converts canonical byte arrays and rejects other shapes', () => {
  assert.equal(m.hex([0, 15, 255]), '000fff');
  assert.equal(m.hex('ab'), 'ab');
  assert.throws(() => m.hex({}), TypeError);
  assert.ok(m.isHex32('a'.repeat(64)));
  assert.ok(!m.isHex32('A'.repeat(64)));
  assert.ok(!m.isHex32('a'.repeat(63)));
});

test('asserted time renders the coordinates Rust wrote, and parses back to them', () => {
  // The fixture's coordinates were computed in Rust (tests/fixture.rs) from
  // these calendar days; this is an independent implementation agreeing.
  const byCalendar = new Map(snapshot.revisions.map((r) => [m.renderAssertedTime(r.asserted_time), m.hex(r.asserted_time.coordinate)]));
  assert.deepEqual([...byCalendar.keys()].sort(), ['1901-03-04', '1901-03-05', '1902-06-01']);
  for (const [cal, coord] of byCalendar) {
    assert.deepEqual(m.parseAssertedTime(cal), { coordinate: coord, precision: 'day' });
  }
});

test('asserted time handles years, months, BCE years and refuses malformed input', () => {
  for (const t of ['2000', '1999-12', '-0043-03-15', '0000-01-01', '1968-12-09', '2024-02-29']) {
    const p = m.parseAssertedTime(t);
    assert.ok(p, t);
    assert.equal(m.renderAssertedTime(p), t);
  }
  // J2000.0 is noon; midnight 2000-01-01 is 43,200 s before it: sign-flipped
  // top byte, sign-extended whole seconds (-43200 = 0x...ff5740), zero fraction.
  const c = m.parseAssertedTime('2000-01-01').coordinate;
  assert.equal(c, '7f' + 'ff'.repeat(15) + 'ffffffffffff5740' + '00'.repeat(8));
  for (const bad of ['1999-13', '2023-02-29', '-0000', '99', '2000-1-1', '2000-01-01T00', ' 2000']) {
    assert.equal(m.parseAssertedTime(bad), null, bad);
  }
  // A coordinate off midnight, or a precision it does not match, is not rendered.
  const p = m.parseAssertedTime('2000-02-03');
  assert.equal(m.renderAssertedTime({ ...p, precision: 'month' }), null);
  assert.equal(m.renderAssertedTime({ coordinate: p.coordinate.slice(0, -1) + '1', precision: 'day' }), null);
});

test('subject view: claim key, revisions, frontier, events, edges, media', () => {
  const v = m.subjectView(snapshot, A, subjectA);
  assert.equal(v.key.kind, 'printing-and-publishing');
  assert.equal(v.label, 'synthetic/harbour-press');
  assert.equal(v.state, 'resolved');
  assert.equal(v.visibility, 'visible');
  assert.deepEqual(v.frontier, subjectA.frontier);
  assert.equal(v.revisions.length, 2);
  const current = v.revisions.filter((r) => r.current);
  assert.equal(current.length, 1);
  assert.equal(current[0].id, m.hex(subjectA.revision.id));
  assert.equal(current[0].assertedTime.calendar, '1901-03-05');
  const kinds = v.events.map((e) => `${e.kind}:${e.state}`).sort();
  assert.deepEqual(kinds, ['Correction:pending', 'Correction:superseded', 'Delegate:head', 'Genesis:superseded']);
  assert.deepEqual(v.events.find((e) => e.state === 'pending').missing, ['4d'.repeat(32)]);
  assert.deepEqual(v.edges.map((e) => e.relation).sort(), ['disputes', 'influence']);
  assert.equal(v.media.length, 1);
  assert.equal(v.media[0].artifactKind, 'image/png');
  assert.equal(m.subjectView(snapshot, '0'.repeat(64), null), null);
});

test('edges and support views resolve subjects and keep disputes out of support', async () => {
  const edges = m.edgesView(snapshot);
  const influence = edges.find((e) => e.relation === 'influence');
  assert.equal(influence.sourceLabel, 'synthetic/harbour-press');
  assert.equal(influence.targetLabel, 'synthetic/reading-society');
  const s = m.supportView(await json(`support/${A}-${B}.json`), snapshot);
  assert.equal(s.verdict, 'supported');
  assert.deepEqual(s.path.map((e) => e.relation), ['influence']);
  assert.deepEqual(s.reasons.map((r) => r.code), ['excluded_edge:disputes_not_support']);
});

test('causal DAG: parents point to strictly earlier columns, ghosts for missing parents', () => {
  const g = m.dag(snapshot);
  assert.equal(g.nodes.filter((n) => !n.ghost).length, snapshot.rows.length);
  const depth = new Map(g.nodes.map((n) => [n.id, n.depth]));
  for (const l of g.links) assert.ok(depth.get(l.from) > depth.get(l.to), JSON.stringify(l));
  const ghosts = g.nodes.filter((n) => n.ghost);
  assert.deepEqual(ghosts.map((n) => [n.id, n.state]), [['4d'.repeat(32), 'missing']]);
  assert.equal(g.links.filter((l) => l.type === 'pin').length, 4);
  // Positions are unique.
  const cells = new Set(g.nodes.map((n) => `${n.depth}/${n.lane}`));
  assert.equal(cells.size, g.nodes.length);
  // One subject: its events plus the edges pinning it.
  const one = m.dag(snapshot, B);
  assert.deepEqual(one.nodes.filter((n) => !n.ghost).map((n) => n.kind).sort(), ['EdgeAssert', 'EdgeAssert', 'Genesis']);
});

test('a parent cycle in served rows is refused rather than drawn', () => {
  const rows = structuredClone(snapshot.rows.slice(0, 2));
  rows[0].envelope.parents = [rows[1].event];
  rows[1].envelope.parents = [rows[0].event];
  assert.throws(() => m.dag({ ...snapshot, rows }), /cycle/);
});

test('kind view takes ids from the verifier path and labels from the taxonomy', () => {
  const tax = { nodes: [{ id: 'b', label: 'Branch', level: 'branch' }, { id: 'k', label: 'Kind', level: 'species', definition: 'd' }] };
  const v = m.kindView({ kind: 'k', valid: true, current: 'k', lens: 'A', path: ['b', 'k'], taxonomy: 'x' }, tax);
  assert.deepEqual(v.path.map((n) => n.label), ['Branch', 'Kind']);
  assert.equal(v.retired, false);
  assert.deepEqual(m.kindView({ kind: 'r', valid: true, current: 's', lens: 'A', path: ['r'], taxonomy: 'x' }, null).path[0].label, null);
});
