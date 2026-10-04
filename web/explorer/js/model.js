// Pure view models over the /public/v1 documents. No DOM, no network: every
// function here takes parsed JSON and returns plain data, so it runs under
// node:test as it runs in the browser.
//
// Hashes that are direct fields of a read are lowercase hex. Projection content
// (rows, subjects, revisions, edges, media, authority) keeps its canonical
// serde form, where a hash is an array of 32 byte values; `hex` converts.

export function hex(bytes) {
  if (typeof bytes === 'string') return bytes;
  if (!Array.isArray(bytes)) throw new TypeError('not a byte array');
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function short(h) {
  const s = hex(h);
  return s.length > 16 ? `${s.slice(0, 8)}…${s.slice(-6)}` : s;
}

const HEX32 = /^[0-9a-f]{64}$/;
export function isHex32(s) {
  return typeof s === 'string' && HEX32.test(s);
}

// ---------------------------------------------------------------------------
// Asserted time. A coordinate is a cc_core::Tick: whole seconds since J2000.0
// (2000-01-01T12:00:00 UTC, every day 86,400 s) shifted left by the governed
// 64 fractional bits, as 32 bytes of offset-binary big-endian. The calendar is
// proleptic Gregorian with astronomical years (0000 is 1 BCE). This mirrors
// the publisher's `--asserted-time` syntax; it is for display and for building
// `as_of` queries, and never decides anything the node decides.
// ---------------------------------------------------------------------------

const UNIX_TO_J2000 = 946728000n;
const TWO_256 = 1n << 256n;

function daysFromCivil(y, m, d) {
  y = m <= 2 ? y - 1n : y;
  const era = (y >= 0n ? y : y - 399n) / 400n;
  const yoe = y - era * 400n;
  const mp = (m + 9n) % 12n;
  const doy = (153n * mp + 2n) / 5n + d - 1n;
  const doe = yoe * 365n + yoe / 4n - yoe / 100n + doy;
  return era * 146097n + doe - 719468n;
}

function civilFromDays(z) {
  z += 719468n;
  const era = (z >= 0n ? z : z - 146096n) / 146097n;
  const doe = z - era * 146097n;
  const yoe = (doe - doe / 1460n + doe / 36524n - doe / 146096n) / 365n;
  const doy = doe - (365n * yoe + yoe / 4n - yoe / 100n);
  const mp = (5n * doy + 2n) / 153n;
  const d = doy - (153n * mp + 2n) / 5n + 1n;
  const m = mp < 10n ? mp + 3n : mp - 9n;
  return [yoe + era * 400n + (m <= 2n ? 1n : 0n), m, d];
}

function daysInMonth(y, m) {
  const leap = ((y % 4n) + 4n) % 4n === 0n && (((y % 100n) + 100n) % 100n !== 0n || ((y % 400n) + 400n) % 400n === 0n);
  if (m === 2n) return leap ? 29n : 28n;
  return [4n, 6n, 9n, 11n].includes(m) ? 30n : 31n;
}

// `YYYY`, `YYYY-MM` or `YYYY-MM-DD` (optional leading '-') to
// `{coordinate: hex, precision}`; null when malformed.
export function parseAssertedTime(text) {
  const m = /^(-?)(\d{4})(?:-(\d{2})(?:-(\d{2}))?)?$/.exec(text);
  if (!m) return null;
  if (m[1] === '-' && m[2] === '0000') return null;
  const y = BigInt(m[1] + m[2]);
  const mo = BigInt(m[3] ?? '1');
  const d = BigInt(m[4] ?? '1');
  if (mo < 1n || mo > 12n || d < 1n || d > daysInMonth(y, mo)) return null;
  const seconds = daysFromCivil(y, mo, d) * 86400n - UNIX_TO_J2000;
  let v = seconds << 64n;
  if (v < 0n) v += TWO_256;
  const bytes = [];
  for (let i = 0; i < 32; i++) bytes.unshift(Number((v >> BigInt(8 * i)) & 0xffn));
  bytes[0] ^= 0x80;
  const precision = m[4] ? 'day' : m[3] ? 'month' : 'year';
  return { coordinate: hex(bytes), precision };
}

// The calendar form of an asserted time, or null when its coordinate is not
// exactly the instant its precision names.
export function renderAssertedTime(t) {
  if (!t) return null;
  const c = typeof t.coordinate === 'string' ? t.coordinate : hex(t.coordinate);
  if (!isHex32(c) || !c.endsWith('0'.repeat(16))) return null;
  const b = c.match(/../g).map((x) => parseInt(x, 16));
  b[0] ^= 0x80;
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  if (v >= 1n << 255n) v -= TWO_256;
  const seconds = (v >> 64n) + UNIX_TO_J2000;
  if (((seconds % 86400n) + 86400n) % 86400n !== 0n) return null;
  const days = seconds >= 0n ? seconds / 86400n : -((-seconds) / 86400n);
  const [y, mo, d] = civilFromDays(days);
  if (y < -9999n || y > 9999n) return null;
  const yy = y < 0n ? `-${String(-y).padStart(4, '0')}` : String(y).padStart(4, '0');
  const mm = String(mo).padStart(2, '0');
  const dd = String(d).padStart(2, '0');
  let text;
  if (t.precision === 'year' && mo === 1n && d === 1n) text = yy;
  else if (t.precision === 'month' && d === 1n) text = `${yy}-${mm}`;
  else if (t.precision === 'day') text = `${yy}-${mm}-${dd}`;
  else return null;
  return text;
}

// ---------------------------------------------------------------------------
// Snapshot indexes
// ---------------------------------------------------------------------------

export function payloadKind(envelope) {
  return Object.keys(envelope.payload)[0];
}

// The subject an event belongs to: a Genesis is its own subject.
export function subjectOf(row) {
  const e = row.envelope;
  if (e.subject) return hex(e.subject);
  return payloadKind(e) === 'Genesis' ? hex(row.event) : null;
}

export function index(snapshot) {
  const rows = new Map(snapshot.rows.map((r) => [hex(r.event), r]));
  const revisions = new Map(snapshot.revisions.map((r) => [hex(r.id), r]));
  const subjects = snapshot.subjects.map((s) => {
    const id = hex(s.subject);
    const genesis = rows.get(id);
    const key = genesis?.envelope.subject_key ?? null;
    return {
      id,
      state: s.state,
      frozen: s.frozen,
      frontier: s.frontier.map(hex),
      key,
      label: key ? `${key.namespace}/${key.value}` : short(id),
    };
  });
  return { rows, revisions, subjects };
}

// Everything the subject page shows that the snapshot alone determines.
// `read` is the subject read (`/public/v1/subjects/{id}`), which carries the
// current revision under `as_of`.
export function subjectView(snapshot, id, read) {
  const ix = index(snapshot);
  const subject = ix.subjects.find((s) => s.id === id);
  if (!subject) return null;
  const events = snapshot.rows
    .filter((r) => subjectOf(r) === id)
    .map((r) => ({
      id: hex(r.event),
      kind: payloadKind(r.envelope),
      state: r.state,
      reason: r.reason,
      frontier: r.frontier,
      revision: r.revision ? hex(r.revision) : null,
      author: hex(r.envelope.author),
      parents: r.envelope.parents.map(hex),
      missing: r.missing.map(hex),
    }));
  const current = read?.revision ? hex(read.revision.id) : null;
  const revisions = snapshot.revisions
    .filter((r) => hex(r.subject) === id)
    .map((r) => ({
      id: hex(r.id),
      creatingEvent: hex(r.creating_event),
      body: hex(r.body),
      assertedTime: r.asserted_time
        ? {
            coordinate: hex(r.asserted_time.coordinate),
            precision: r.asserted_time.precision,
            calendar: renderAssertedTime(r.asserted_time),
          }
        : null,
      state: ix.rows.get(hex(r.creating_event))?.state ?? 'unknown',
      current: hex(r.id) === current,
    }));
  const edges = snapshot.edges
    .filter((e) => e.pins.some((p) => hex(p.source.subject) === id || hex(p.target.subject) === id))
    .map((e) => edgeView(e, ix));
  const media = snapshot.media
    .filter((m) => revisions.some((r) => r.id === hex(m.revision ?? [])) || events.some((e) => e.id === hex(m.target)))
    .map((m) => ({
      attestation: hex(m.attestation),
      artifactKind: m.artifact_kind,
      artifact: hex(m.artifact),
      targetKind: m.target_kind,
      revision: m.revision ? hex(m.revision) : null,
    }));
  return {
    ...subject,
    visibility: read?.visibility ?? null,
    asOf: read?.as_of ?? null,
    current,
    events,
    revisions,
    edges,
    media,
  };
}

// What a subject page may claim about the reads it displays. `report` is the
// verifier's report over exactly those response texts. The prose is shown as
// the subject's claim only when every link holds: the snapshot verified, the
// subject read answers the subject and as_of that were requested and verified,
// and the prose read is for that read's current revision and verified.
export const SNAPSHOT_CHECKS = ['health', 'fold_version', 'filter_version', 'snapshot', 'snapshot_rule', 'canonical_form', 'event_ids', 'corpus_digest', 'view_commitment'];
export function pageChecks(report, { id, asOf = null, subjectRead, proseRead = null }) {
  const status = (name) => report?.checks?.find((c) => c.name === name)?.status ?? 'not_checked';
  const problems = [];
  if (!report || report.error) problems.push('the verifier did not run');
  const failed = (report?.checks ?? []).filter((c) => c.status === 'fail' && SNAPSHOT_CHECKS.includes(c.name));
  if (failed.length) problems.push(`the served snapshot does not verify (${failed.map((c) => c.name).join(', ')})`);
  if (subjectRead?.subject !== id) problems.push('the subject read names another subject than the one requested');
  if ((subjectRead?.as_of ?? null) !== (asOf ?? null)) problems.push('the subject read answers another as_of than the one requested');
  if (status('read:subject') !== 'pass') problems.push('the subject read did not verify');
  const current = subjectRead?.revision ? hex(subjectRead.revision.id) : null;
  let claim = false;
  if (proseRead) {
    if (!current || hex(proseRead.revision.id) !== current) problems.push('the prose read is for another revision than the current one');
    if (status('read:prose') !== 'pass') problems.push('the prose read did not verify');
    claim = problems.length === 0;
  }
  return { ok: problems.length === 0, claim, problems };
}

export function edgeView(e, ix) {
  const label = (s) => ix.subjects.find((x) => x.id === hex(s))?.label ?? short(s);
  // Every committed edge reading has at least one head's pins; refuse rather
  // than guess when one does not.
  if (!e.pins.length) throw new Error('edge reading without pins');
  const p = e.pins[0];
  return {
    id: hex(e.edge),
    relation: e.relation,
    status: e.status,
    reasons: e.reasons,
    author: hex(e.author),
    source: hex(p.source.subject),
    target: hex(p.target.subject),
    sourceLabel: label(p.source.subject),
    targetLabel: label(p.target.subject),
    heads: e.heads.map(hex),
    conflict: e.heads.length > 1,
  };
}

export function edgesView(snapshot) {
  const ix = index(snapshot);
  return snapshot.edges.map((e) => edgeView(e, ix));
}

// The support read's verdict, flattened for display.
export function supportView(read, snapshot) {
  const ix = index(snapshot);
  const edges = new Map(snapshot.edges.map((e) => [hex(e.edge), e]));
  const reason = (r) => ({
    code: r.code,
    subject: r.subject ? hex(r.subject) : null,
    edge: r.edge ? hex(r.edge) : null,
  });
  const [verdict, body] = Object.entries(read.support)[0];
  return {
    verdict: verdict.toLowerCase(),
    from: read.from,
    to: read.to,
    asOf: read.as_of,
    path: (body.path ?? []).map((id) => {
      const e = edges.get(hex(id));
      return e ? edgeView(e, ix) : { id: hex(id), relation: 'unknown' };
    }),
    reasons: (body.excluded ?? body.reasons ?? []).map(reason),
  };
}

// ---------------------------------------------------------------------------
// Causal DAG: one node per served row, a link to each signed parent, a dashed
// link from an edge event to the basis events its pins name, and a ghost node
// for each parent a pending row is missing. Depth is the longest parent chain,
// so every link points to a strictly smaller column.
// ---------------------------------------------------------------------------

export function dag(snapshot, subject = null) {
  const keep = (r) => subject === null || subjectOf(r) === subject || pinSubjects(r).includes(subject);
  const rows = snapshot.rows.filter(keep);
  const nodes = new Map();
  for (const r of rows) {
    nodes.set(hex(r.event), {
      id: hex(r.event),
      kind: payloadKind(r.envelope),
      state: r.state,
      reason: r.reason,
      subject: subjectOf(r),
      ghost: false,
    });
  }
  const links = [];
  for (const r of rows) {
    const id = hex(r.event);
    for (const p of r.envelope.parents.map(hex)) {
      if (!nodes.has(p)) {
        const served = snapshot.rows.some((x) => hex(x.event) === p);
        nodes.set(p, { id: p, kind: served ? 'outside' : 'missing', state: served ? 'outside' : 'missing', reason: '', subject: null, ghost: true });
      }
      links.push({ from: id, to: p, type: 'parent' });
    }
    for (const b of pinBases(r)) {
      if (nodes.has(b)) links.push({ from: id, to: b, type: 'pin' });
    }
  }
  // Longest parent chain, iteratively (Kahn's order over child -> parent
  // links), so a deep chain cannot exhaust the call stack.
  const out = new Map([...nodes.keys()].map((id) => [id, []]));
  const pending = new Map([...nodes.keys()].map((id) => [id, 0]));
  for (const l of links) {
    out.get(l.from).push(l.to);
    pending.set(l.from, pending.get(l.from) + 1);
  }
  const into = new Map([...nodes.keys()].map((id) => [id, []]));
  for (const l of links) into.get(l.to).push(l.from);
  const depth = new Map();
  const ready = [...nodes.keys()].filter((id) => pending.get(id) === 0);
  while (ready.length) {
    const id = ready.pop();
    depth.set(id, out.get(id).reduce((d, p) => Math.max(d, depth.get(p) + 1), 0));
    for (const child of into.get(id)) {
      pending.set(child, pending.get(child) - 1);
      if (pending.get(child) === 0) ready.push(child);
    }
  }
  if (depth.size !== nodes.size) throw new Error('cycle in served parents');
  const lanes = new Map();
  const ordered = [...nodes.values()].sort((a, b) => depth.get(a.id) - depth.get(b.id) || (a.id < b.id ? -1 : 1));
  for (const n of ordered) {
    const col = depth.get(n.id);
    n.depth = col;
    n.lane = lanes.get(col) ?? 0;
    lanes.set(col, n.lane + 1);
  }
  let columns = 0;
  let lanesMax = 0;
  for (const [col, n] of lanes) {
    columns = Math.max(columns, col + 1);
    lanesMax = Math.max(lanesMax, n);
  }
  return { nodes: ordered, links, columns, lanes: lanesMax };
}

function pins(r) {
  const p = r.envelope.payload;
  if (p.EdgeAssert) return [p.EdgeAssert.pins];
  if (p.EdgeReaffirm) return [p.EdgeReaffirm.new];
  return [];
}
function pinSubjects(r) {
  return pins(r).flatMap((p) => [hex(p.source.subject), hex(p.target.subject)]);
}
function pinBases(r) {
  return pins(r).flatMap((p) => [hex(p.source.basis), hex(p.target.basis)]);
}

// ---------------------------------------------------------------------------
// TT kind path: ids from the verifier (cc-filter's pinned tables), labels and
// definitions from the taxonomy file, used only once the verifier confirms
// the file is the pinned one.
// ---------------------------------------------------------------------------

export function kindView(kindPath, taxonomy) {
  const nodes = new Map((taxonomy?.nodes ?? []).map((n) => [n.id, n]));
  return {
    kind: kindPath.kind,
    valid: kindPath.valid,
    current: kindPath.current,
    retired: kindPath.current !== kindPath.kind,
    lens: kindPath.lens,
    taxonomy: kindPath.taxonomy,
    path: kindPath.path.map((id) => ({
      id,
      label: nodes.get(id)?.label ?? null,
      level: nodes.get(id)?.level ?? null,
      definition: nodes.get(id)?.definition ?? null,
    })),
  };
}
