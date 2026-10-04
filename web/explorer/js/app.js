// Explorer UI. Every served string reaches the page through textContent or an
// attribute value, never through HTML parsing.
import { client } from './api.js';
import { loadVerifier } from './verify.js';
import * as m from './model.js';

const params = new URLSearchParams(location.search);
const fixtureName = params.get('fixture');
const api = client({
  base: document.querySelector('meta[name="cc-api-base"]')?.content || '/public/v1',
  fixture: fixtureName && /^[a-z0-9-]+$/.test(fixtureName) ? `./fixtures/${fixtureName}` : null,
});

const state = { health: null, snapshot: null, verifier: null, taxonomy: null, lastReport: null };

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const code = (s, title = null) => h('code', { title }, s);
const hash = (s) => code(m.short(s), m.hex(s));
const badge = (s, kind = s) => h('span', { class: `badge ${String(kind).replace(/[^a-z_]/gi, '')}` }, s);
const link = (href, ...c) => h('a', { href }, ...c);
const subjectLink = (id, label) => link(`#/subject/${id}`, label ?? m.short(id));

function dl(pairs) {
  return h('dl', {}, pairs.filter(Boolean).map(([k, v]) => [h('dt', {}, k), h('dd', {}, v)]));
}
function section(title, ...body) {
  return h('section', {}, h('h2', {}, title), ...body);
}
function refusal(r) {
  const why = r.json?.error ?? `HTTP ${r.status}`;
  return h('p', { class: 'error' }, `The read was refused: ${why}.`);
}

// Cross-check the reads this page is about to display against the served
// snapshot, in the verifier, using the exact response texts that are shown.
// Snapshot-level checks run too, so a failing commitment is never hidden
// behind a passing read.
async function checkReads(reads) {
  try {
    const v = await verifier();
    const r = v.verify({ health: state.health.text, snapshot: state.snapshot.text, reads });
    if (r.error) throw new Error(r.error);
    return r;
  } catch (err) {
    return { error: err.message };
  }
}
const SNAPSHOT_CHECKS = ['health', 'fold_version', 'filter_version', 'snapshot', 'snapshot_rule', 'canonical_form', 'event_ids', 'corpus_digest', 'view_commitment'];
function readStatus(report) {
  if (report.error) return h('p', { class: 'check' }, badge('not_checked'), ` Reads on this page were not checked: ${report.error}.`);
  const bad = report.checks.filter((c) => c.status === 'fail' && SNAPSHOT_CHECKS.includes(c.name));
  const reads = report.checks.filter((c) => c.name.startsWith('read:'));
  return h('div', { class: 'check' },
    bad.length ? h('p', {}, badge('fail'), ` The served snapshot does not verify (${bad.map((c) => c.name).join(', ')}); nothing below is consistent with a commitment.`) : null,
    h('ul', {}, reads.map((c) => h('li', {}, badge(c.status), ' ', code(c.name), ' ', c.detail))),
  );
}

async function load(force = false) {
  if (!force && state.snapshot) return;
  const [health, snapshot] = await Promise.all([api.health(), api.snapshot()]);
  if (!health.ok || !snapshot.ok) throw new Error(`health ${health.status}, snapshot ${snapshot.status}`);
  state.health = health;
  state.snapshot = snapshot;
  state.lastReport = null;
  renderIdentity();
}

async function verifier() {
  if (!state.verifier) {
    const r = await fetch('./cc_wasm_verify.wasm');
    if (!r.ok) throw new Error(`verifier module: HTTP ${r.status}`);
    state.verifier = await loadVerifier(await r.arrayBuffer());
  }
  return state.verifier;
}

async function taxonomy() {
  if (state.taxonomy === null) {
    const v = await verifier();
    const r = await fetch('./taxonomy-v2.1.json');
    const bytes = new Uint8Array(await r.arrayBuffer());
    // Labels are used only from the exact taxonomy the verifier pins.
    state.taxonomy = r.ok && v.taxonomyPinned(bytes) ? JSON.parse(new TextDecoder().decode(bytes)) : false;
  }
  return state.taxonomy || null;
}

function renderIdentity() {
  const hj = state.health.json;
  const el = document.getElementById('identity');
  el.replaceChildren(
    h('span', {}, 'fold_version ', code(String(hj.fold_version?.version))),
    h('span', {}, ' · filter_version ', hash(hj.filter_version)),
    h('span', {}, ` · ${hj.curators?.length ?? 0} curator keys · max_hops ${hj.max_hops}`),
    h('span', {}, ' · served commitment ', hash(state.snapshot.json.commitment)),
    state.lastReport ? h('span', {}, ' · ', badge(state.lastReport.outcome)) : h('span', {}, ' · ', link('#/verify', 'not verified yet')),
  );
}

// --- views ------------------------------------------------------------------

function subjectsView() {
  const ix = m.index(state.snapshot.json);
  return section(
    'Subjects',
    h('p', {}, `${ix.subjects.length} subjects, ${state.snapshot.json.rows.length} events in the served snapshot.`),
    h('table', {},
      h('thead', {}, h('tr', {}, ['Subject', 'Kind', 'State', 'Frontier', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, ix.subjects.map((s) => h('tr', {},
        h('td', {}, subjectLink(s.id, s.label)),
        h('td', {}, s.key ? link(`#/kind/${s.id}`, s.key.kind) : '—'),
        h('td', {}, badge(s.state), s.frozen ? badge('frozen') : null),
        h('td', {}, s.frontier.map(hash)),
        h('td', {}, link(`#/dag/${s.id}`, 'DAG')),
      ))),
    ),
  );
}

async function subjectView(id, asOf) {
  if (!m.isHex32(id)) return h('p', { class: 'error' }, 'Not a subject id.');
  const read = await api.subject(id, asOf);
  if (!read.ok && read.status !== 404) return refusal(read);
  const v = m.subjectView(state.snapshot.json, id, read.json);
  if (!v) return h('p', { class: 'error' }, 'This subject is not in the served snapshot.');
  const prose = m.isHex32(v.current) ? await api.prose(v.current) : null;
  const current = v.revisions.find((r) => r.current);
  const checked = await checkReads([
    { kind: 'subject', body: read.text },
    ...(prose ? [{ kind: 'prose', body: prose.text }] : []),
  ]);
  const proseOk = checked.checks?.some((c) => c.name === 'read:prose' && c.status === 'pass');
  const asOfForm = h('form', { class: 'inline', onsubmit: (e) => {
    e.preventDefault();
    const t = e.target.elements.asof.value.trim();
    const p = t ? m.parseAssertedTime(t) : null;
    if (t && !p) return void (e.target.querySelector('.hint').textContent = 'Use YYYY, YYYY-MM or YYYY-MM-DD.');
    location.hash = p ? `#/subject/${id}/as_of/${p.coordinate}` : `#/subject/${id}`;
  } },
    h('label', {}, 'Read as of ', h('input', { name: 'asof', placeholder: 'YYYY-MM-DD', size: 12 })),
    h('button', { type: 'submit' }, 'Read'),
    h('span', { class: 'hint' }, asOf ? `as_of ${m.renderAssertedTime({ coordinate: asOf, precision: 'day' }) ?? m.short(asOf)}` : 'current reading'),
  );
  return h('div', {},
    section(v.label,
      dl([
        ['Subject key', v.key ? h('span', {}, code(v.key.kind), ' / ', code(v.key.namespace), ' / ', code(v.key.value)) : '—'],
        ['Subject id', code(v.id)],
        ['State', h('span', {}, badge(v.state), v.frozen ? badge('frozen') : null)],
        ['Visibility', v.visibility ? badge(v.visibility) : '—'],
        ['Frontier', h('span', {}, v.frontier.map(hash))],
        ['TT kind', v.key ? link(`#/kind/${v.id}`, `${v.key.kind} path`) : '—'],
        ['Causal DAG', link(`#/dag/${v.id}`, 'events and parents')],
      ]),
      asOfForm,
      readStatus(checked),
    ),
    section('Claim',
      !current ? h('p', {}, read.json?.visibility === 'visible' ? 'No current revision.' : `No visible revision (${read.json?.visibility ?? 'unknown'}).`) :
      h('div', {},
        prose?.json?.availability === 'available'
          ? h('div', {},
            h('blockquote', {}, prose.json.prose),
            h('p', { class: 'muted' }, proseOk ? 'This text hashes to the committed body (checked in your browser).' : 'This text was NOT confirmed against the committed body; see the checks below.'))
          : h('p', { class: 'muted' }, `Prose ${prose?.json?.availability ?? 'unavailable'}; the claim is committed by its body hash.`),
        dl([
          ['Asserted time', current.assertedTime ? h('span', {}, current.assertedTime.calendar ?? 'non-calendar coordinate', ` (${current.assertedTime.precision}) `, hash(current.assertedTime.coordinate)) : 'none'],
          ['Body sha256', code(current.body)],
          ['Revision', code(current.id)],
        ]),
      ),
    ),
    section('Revisions',
      h('table', {},
        h('thead', {}, h('tr', {}, ['Revision', 'Asserted time', 'Creating event', 'Event state', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, v.revisions.map((r) => h('tr', {},
          h('td', {}, hash(r.id)),
          h('td', {}, r.assertedTime ? `${r.assertedTime.calendar ?? 'coordinate'} (${r.assertedTime.precision})` : '—'),
          h('td', {}, hash(r.creatingEvent)),
          h('td', {}, badge(r.state)),
          h('td', {}, r.current ? badge('current') : ''),
        ))),
      ),
    ),
    section('Events',
      h('table', {},
        h('thead', {}, h('tr', {}, ['Event', 'Kind', 'State', 'Reason', 'Parents'].map((t) => h('th', {}, t)))),
        h('tbody', {}, v.events.map((e) => h('tr', {},
          h('td', {}, hash(e.id)), h('td', {}, e.kind), h('td', {}, badge(e.state), e.frontier ? badge('frontier') : null),
          h('td', {}, e.reason || '—'), h('td', {}, e.parents.map(hash), e.missing.length ? badge('missing parent', 'missing') : null),
        ))),
      ),
    ),
    v.edges.length ? section('Edges', edgesTable(v.edges)) : null,
    v.media.length ? section('Media attestations',
      h('ul', {}, v.media.map((x) => h('li', {}, `${x.artifactKind} `, hash(x.artifact), ' on ', x.targetKind, ' ', x.revision ? hash(x.revision) : '')))) : null,
  );
}

function edgesTable(edges) {
  return h('table', {},
    h('thead', {}, h('tr', {}, ['Relation', 'Source', 'Target', 'Status', 'Reasons', 'Edge'].map((t) => h('th', {}, t)))),
    h('tbody', {}, edges.map((e) => h('tr', {},
      h('td', {}, e.relation), h('td', {}, subjectLink(e.source, e.sourceLabel)), h('td', {}, subjectLink(e.target, e.targetLabel)),
      h('td', {}, badge(e.status), e.conflict ? badge('conflict') : null), h('td', {}, e.reasons.join(', ') || '—'), h('td', {}, hash(e.id)),
    ))),
  );
}

function edgesView() {
  const ix = m.index(state.snapshot.json);
  // "to" starts on the second subject: a subject is never its own support query.
  const options = (name, first) => h('select', { name }, ix.subjects.map((s, i) => h('option', { value: s.id, selected: i === Math.min(first, ix.subjects.length - 1) }, s.label)));
  const out = h('div', { id: 'support-result' });
  const form = h('form', { class: 'inline', onsubmit: async (e) => {
    e.preventDefault();
    const f = e.target.elements;
    const t = f.asof.value.trim();
    const p = t ? m.parseAssertedTime(t) : null;
    if (t && !p) return void out.replaceChildren(h('p', { class: 'error' }, 'Use YYYY, YYYY-MM or YYYY-MM-DD.'));
    const r = await api.support(f.from.value, f.to.value, p?.coordinate ?? null);
    if (!r.ok) return void out.replaceChildren(refusal(r));
    const s = m.supportView(r.json, state.snapshot.json);
    const checked = await checkReads([{ kind: 'support', body: r.text }]);
    out.replaceChildren(
      h('p', {}, 'Verdict: ', badge(s.verdict), s.asOf ? ` as of ${m.short(s.asOf)}` : ''),
      s.path.length ? h('ol', {}, s.path.map((e) => h('li', {}, `${e.relation}: `, e.sourceLabel ?? '', ' – ', e.targetLabel ?? '', ' ', hash(e.id)))) : null,
      s.reasons.length ? h('ul', {}, s.reasons.map((x) => h('li', {}, code(x.code), x.edge ? [' edge ', hash(x.edge)] : '', x.subject ? [' subject ', hash(x.subject)] : ''))) : null,
      readStatus(checked),
      h('p', { class: 'muted' }, 'The verdict is derived by the node’s fold and is not recomputed here; the check above confirms only that this read names the served snapshot’s rule, corpus digest and commitment.'),
    );
  } },
    h('label', {}, 'From ', options('from', 0)), h('label', {}, ' to ', options('to', 1)),
    h('label', {}, ' as of ', h('input', { name: 'asof', placeholder: 'optional', size: 12 })),
    h('button', { type: 'submit' }, 'Query support'),
  );
  return h('div', {}, section('Edges', edgesTable(m.edgesView(state.snapshot.json))), section('Support query', form, out));
}

function dagView(subject) {
  const g = m.dag(state.snapshot.json, subject && m.isHex32(subject) ? subject : null);
  const W = 190, H = 54, pad = 16;
  const NS = 'http://www.w3.org/2000/svg';
  const s = (tag, attrs, ...kids) => {
    const el = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    for (const k of kids) el.append(k instanceof Node ? k : document.createTextNode(String(k)));
    return el;
  };
  const pos = new Map(g.nodes.map((n) => [n.id, { x: pad + n.depth * W, y: pad + n.lane * H }]));
  const svg = s('svg', { viewBox: `0 0 ${pad * 2 + g.columns * W} ${pad * 2 + Math.max(1, g.lanes) * H}`, class: 'dag', role: 'img', 'aria-label': 'Causal DAG of served events' });
  svg.append(s('defs', {}, s('marker', { id: 'arrow', viewBox: '0 0 8 8', refX: 8, refY: 4, markerWidth: 6, markerHeight: 6, orient: 'auto' }, s('path', { d: 'M0,0 L8,4 L0,8 z', class: 'arrowhead' }))));
  for (const l of g.links) {
    const a = pos.get(l.from), b = pos.get(l.to);
    svg.append(s('line', { x1: a.x, y1: a.y + 18, x2: b.x + 150, y2: b.y + 18, class: `link ${l.type}`, 'marker-end': 'url(#arrow)' }));
  }
  for (const n of g.nodes) {
    const p = pos.get(n.id);
    const node = s('g', { class: `node ${n.state}`, transform: `translate(${p.x},${p.y})` },
      s('title', {}, `${n.kind} ${n.id}\nstate: ${n.state}${n.reason ? ` (${n.reason})` : ''}`),
      s('rect', { width: 150, height: 36, rx: 4 }),
      s('text', { x: 8, y: 15 }, n.kind),
      s('text', { x: 8, y: 29, class: 'sub' }, `${m.short(n.id)} · ${n.state}`));
    svg.append(node);
  }
  return section(subject ? 'Causal DAG for one subject' : 'Causal DAG',
    h('p', { class: 'muted' }, 'Solid arrows point from an event to its signed parents; dashed arrows from an edge event to the basis events its pins name. Ghost boxes are parents a pending event is missing. Columns are the longest parent chain; event ids order nothing.'),
    h('div', { class: 'scroll' }, svg),
    subject ? link('#/dag', 'Whole corpus') : null);
}

async function kindView(id) {
  const ix = m.index(state.snapshot.json);
  const subject = ix.subjects.find((s) => s.id === id);
  if (!subject?.key) return h('p', { class: 'error' }, 'This subject has no subject key in the served snapshot.');
  const v = await verifier();
  const tax = await taxonomy();
  const k = m.kindView(v.ttKind(subject.key.kind), tax);
  return section(`TT kind: ${k.kind}`,
    dl([
      ['Subject', subjectLink(id, subject.label)],
      ['In the pinned taxonomy', k.valid ? 'yes' : 'no: not a node id of the pinned TT taxonomy'],
      k.retired ? ['Retired', `successor ${k.current}`] : null,
      ['Lens', k.lens ?? '—'],
      ['Taxonomy sha256', code(k.taxonomy)],
    ]),
    k.path.length ? h('ol', { class: 'kind-path' }, k.path.map((n) => h('li', {},
      h('strong', {}, n.label ?? n.id), ' ', code(n.id), n.level ? ` (${n.level})` : '',
      n.definition ? h('p', { class: 'muted' }, n.definition) : null))) : null,
    tax ? null : h('p', { class: 'muted' }, 'Labels unavailable: the served taxonomy file is missing or is not the pinned one.'),
  );
}

function verifyView() {
  const out = h('div', { id: 'verify-result' });
  const exportInput = h('input', { type: 'file', accept: 'application/json,.json', name: 'export' });
  const wasmInput = h('input', { type: 'file', accept: '.wasm,application/wasm', name: 'wasm' });
  const useRecorded = api.mode === 'fixture' ? h('label', {}, h('input', { type: 'checkbox', name: 'recorded', checked: true }), ' use the fixture’s recorded export manifest') : null;
  const run = async (e) => {
    e.preventDefault();
    out.replaceChildren(h('p', {}, 'Verifying…'));
    try {
      if (wasmInput.files[0]) state.verifier = await loadVerifier(await wasmInput.files[0].arrayBuffer());
      const v = await verifier();
      await load(true);
      let exportText = exportInput.files[0] ? await exportInput.files[0].text() : null;
      if (!exportText && useRecorded?.querySelector('input').checked) exportText = (await api.export()).text;
      // Two requests: health and snapshot. Subject, prose and support reads are
      // checked on the page that displays them, from the same response text.
      const report = v.verify({ health: state.health.text, snapshot: state.snapshot.text, export: exportText, reads: [] });
      if (report.error) throw new Error(report.error);
      state.lastReport = report;
      renderIdentity();
      out.replaceChildren(reportView(report));
    } catch (err) {
      out.replaceChildren(h('p', { class: 'error' }, `Verification could not run: ${err.message}`));
    }
  };
  return h('div', {},
    section('Verify in your browser',
      h('p', {}, 'The verifier is the cc-wasm-verify WebAssembly module, built from the same cc-core and cc-filter code the node runs. It imports nothing from the page and makes no requests; the page fetches /health and /snapshot and passes their text in. Every subject, prose and support read is also checked against this snapshot on the page that displays it.'),
      h('form', { onsubmit: run },
        h('p', {}, h('label', {}, 'Export manifest (optional, for signatures): ', exportInput)),
        useRecorded ? h('p', {}, useRecorded) : null,
        h('p', {}, h('label', {}, 'Your own build of the verifier (optional .wasm): ', wasmInput)),
        h('button', { type: 'submit', class: 'primary' }, 'Verify in your browser'),
      ),
      out,
    ),
    section('What is not recomputed', notRecomputed()),
  );
}

function notRecomputed() {
  const list = h('ul', {}, h('li', {}, 'Loading the verifier’s own statement…'));
  verifier().then((v) => list.replaceChildren(...v.about().not_recomputed.map((t) => h('li', {}, t))))
    .catch((e) => list.replaceChildren(h('li', { class: 'error' }, `Verifier unavailable: ${e.message}`)));
  return list;
}

function reportView(r) {
  return h('div', {},
    h('p', { class: 'outcome' }, 'Outcome: ', badge(r.outcome),
      r.outcome === 'partial' ? ' — nothing failed, but some checks could not run (see below).' : ''),
    h('table', {},
      h('thead', {}, h('tr', {}, ['Check', 'Result', 'Detail'].map((t) => h('th', {}, t)))),
      h('tbody', {}, r.checks.map((c) => h('tr', {}, h('td', {}, code(c.name)), h('td', {}, badge(c.status)), h('td', {}, c.detail))))),
    dl([
      ['Recomputed filter_version', r.recomputed.filter_version ? code(r.recomputed.filter_version) : '—'],
      ['Recomputed corpus digest', r.recomputed.corpus_digest ? code(r.recomputed.corpus_digest) : '—'],
      ['Recomputed view commitment', r.recomputed.commitment ? code(r.recomputed.commitment) : '—'],
      ['Event ids recomputed', String(r.recomputed.events)],
      ['Signatures verified', String(r.recomputed.signatures)],
      ['Fold manifest (this verifier)', code(r.recomputed.fold_manifest)],
      ['TT taxonomy (this verifier)', code(r.recomputed.ontology)],
    ]),
    h('p', { class: 'muted' }, 'This report does not cover what is listed under “What is not recomputed” below.'),
  );
}

// --- routing ------------------------------------------------------------------

async function route() {
  const view = document.getElementById('view');
  const parts = location.hash.replace(/^#\/?/, '').split('/');
  for (const a of document.querySelectorAll('nav a')) a.classList.toggle('active', a.getAttribute('href') === `#/${parts[0]}`);
  try {
    await load();
    let el;
    switch (parts[0]) {
      case 'subject': el = await subjectView(parts[1], parts[2] === 'as_of' && m.isHex32(parts[3]) ? parts[3] : null); break;
      case 'dag': el = dagView(parts[1] ?? null); break;
      case 'edges': el = edgesView(); break;
      case 'kind': el = await kindView(parts[1]); break;
      case 'verify': el = verifyView(); break;
      default: el = subjectsView();
    }
    view.replaceChildren(el);
  } catch (err) {
    view.replaceChildren(h('p', { class: 'error' }, `Could not load the public reads: ${err.message}`));
  }
}

document.getElementById('source').textContent = api.mode === 'fixture' ? `synthetic fixture “${fixtureName}”` : 'public gateway';
window.addEventListener('hashchange', route);
route();
