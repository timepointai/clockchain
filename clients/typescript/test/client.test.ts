/**
 * Client tests against the recorded synthetic fixtures shared with the Python
 * client (clients/fixtures/v1). Each case mirrors one in
 * clients/python/tests/test_client.py: the client gets recorded bytes, or
 * recorded bytes with one field changed, and the test asserts on a value the
 * client could get wrong.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingHttpHeaders, Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, beforeEach, describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  HEADERS,
  ProtocolError,
  PublicApiError,
  PublicClient,
  bytesHash,
  healthCall,
  parse,
  retryAfterSeconds,
  snapshotCall,
  subjectCall,
  summarizeSubjects,
  supportCall,
} from "../src/index.ts";
import type { Transport } from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../fixtures/v1/", import.meta.url));
const BASE = "https://gateway.invalid/prefix";

// Fixture documents are test data that the tests tamper with freely.
type Doc = any;

interface Entry {
  asserted_time: { calendar: string; coordinate: string; precision: string };
  author: string;
  body_sha256: string;
  event: string;
  revision: string;
  subject: string;
  subject_key: { kind: string; namespace: string; value: string };
}

function load(name: string): Doc {
  return JSON.parse(readFileSync(`${FIXTURES}${name}.json`, "utf8"));
}

const META: { entries: Entry[]; fixtures: string[] } = load("_meta");
const A = META.entries[0]!;
const B = META.entries[1]!;

function hexToBytes(hex: string): number[] {
  return Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

function compare(x: [string, string], y: [string, string]): number {
  return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0;
}

/** The query of a URL as sorted `[name, value]` pairs. */
function queryOf(url: string): Array<[string, string]> {
  return [...new URL(url).searchParams].sort(compare);
}

/** Path plus sorted query: the key a recorded answer is served under. */
function key(url: string): string {
  return JSON.stringify([new URL(url).pathname, queryOf(url)]);
}

/**
 * Serves every fixture at `BASE + request.path?query`, recording calls.
 * `override` replaces the answer for one fixture name.
 */
class Recorded {
  readonly calls: Array<[string, Record<string, string>]> = [];
  readonly routes = new Map<
    string,
    { status: number; body: string; headers: Record<string, string> }
  >();

  constructor(override: Record<string, Doc> = {}) {
    for (const name of META.fixtures) {
      if (name === "rate_limited") {
        continue; // same URL as health; tests install it explicitly
      }
      const doc = Object.hasOwn(override, name) ? override[name] : load(name);
      const query = new URLSearchParams(doc.request.query).toString();
      const url = BASE + doc.request.path + (query ? `?${query}` : "");
      this.routes.set(key(url), {
        status: doc.status,
        body: JSON.stringify(doc.body),
        headers: { ...(doc.headers ?? {}) },
      });
    }
  }

  readonly send: Transport = async (url, headers) => {
    this.calls.push([url, { ...headers }]);
    const answer = this.routes.get(key(url));
    if (answer === undefined) {
      assert.fail(`no fixture for ${url}`);
    }
    return answer;
  };
}

function client(override?: Record<string, Doc>): [PublicClient, Recorded] {
  const t = new Recorded(override);
  return [new PublicClient(BASE, { transport: t.send }), t];
}

const DELETE = Symbol("delete");

function tampered(name: string, changes: Record<string, unknown>): Record<string, Doc> {
  const doc = structuredClone(load(name));
  for (const [k, v] of Object.entries(changes)) {
    if (v === DELETE) {
      delete doc.body[k];
    } else {
      doc.body[k] = v;
    }
  }
  return { [name]: doc };
}

type ErrorClass = new (...args: never[]) => Error;

/** The promise rejects with an instance of `cls` whose message matches. */
async function rejectsWith(promise: Promise<unknown>, cls: ErrorClass, pattern?: RegExp): Promise<Error> {
  let caught: unknown;
  await assert.rejects(promise, (e: unknown) => {
    caught = e;
    return true;
  });
  assert.ok(caught instanceof cls, `expected ${cls.name}, got ${String(caught)}`);
  if (pattern) {
    assert.match(caught.message, pattern);
  }
  return caught;
}

function apiError(e: Error): [number, string] {
  assert.ok(e instanceof PublicApiError);
  return [e.status, e.error];
}

function parseFixture(name: string, call: Parameters<typeof parse>[0]): unknown {
  const doc = load(name);
  return parse(call, doc.status, JSON.stringify(doc.body));
}

describe("FixtureSet", () => {
  test("index matches files", () => {
    const onDisk = readdirSync(FIXTURES)
      .filter((f) => f.endsWith(".json"))
      .map((f) => f.slice(0, -".json".length))
      .filter((f) => f !== "_meta")
      .sort();
    assert.deepEqual(onDisk, META.fixtures);
    assert.equal(onDisk.length, 18);
  });

  test("every contract route has a fixture", () => {
    const routes = new Set(META.fixtures.map((f) => load(f).request.path.split("/")[3]));
    assert.deepEqual(
      [...routes].sort(),
      ["health", "receipts", "revisions", "snapshot", "subjects", "support"],
    );
  });

  test("recorded health is public shape", () => {
    const body = load("health").body;
    assert.ok(!Object.hasOwn(body, "instance"));
    assert.equal(body.ledger, "v1");
  });
});

describe("Health", () => {
  test("decodes every field", async () => {
    const [c, t] = client();
    const h = await c.health();
    const body = load("health").body;
    assert.equal(h.ledger, "v1");
    assert.equal(h.build, load("health").body.build);
    assert.equal(h.posture, body.posture);
    assert.equal(h.fold_version.version, 1);
    assert.equal(h.fold_version.manifest, body.fold_version.manifest);
    assert.equal(h.filter_version, body.filter_version);
    assert.deepEqual(h.curators, [A.author]);
    assert.equal(h.max_hops, 4);
    assert.equal(h.semantic, "ready");
    assert.equal(t.calls[0]![0], `${BASE}/public/v1/health`);
  });

  test("refuses an instance", async () => {
    const [c] = client(tampered("health", { instance: "00".repeat(32) }));
    await rejectsWith(c.health(), ProtocolError, /instance/);
  });

  test("refuses a legacy ledger", async () => {
    const [c] = client(tampered("health", { ledger: "v0" }));
    await rejectsWith(c.health(), ProtocolError, /ledger/);
  });

  test("refuses a missing field", async () => {
    const [c] = client(tampered("health", { filter_version: DELETE }));
    await rejectsWith(c.health(), ProtocolError, /filter_version/);
  });

  test("refuses a bool for a number", async () => {
    const [c] = client(tampered("health", { max_hops: true }));
    await rejectsWith(c.health(), ProtocolError, /max_hops/);
  });

  test("refuses a fraction for an integer", async () => {
    const [c] = client(tampered("health", { max_hops: 4.5 }));
    await rejectsWith(c.health(), ProtocolError, /max_hops/);
  });

  test("refuses a build that is not a string", async () => {
    const [c] = client(tampered("health", { build: 7 }));
    await rejectsWith(c.health(), ProtocolError, /build/);
  });
});

describe("Snapshot", () => {
  test("decodes revisions to hex", async () => {
    const [c] = client();
    const s = await c.snapshot();
    assert.deepEqual(s.revisions.map((r) => r.id).sort(), [A.revision, B.revision].sort());
    const byId = new Map(s.revisions.map((r) => [r.id, r]));
    const a = byId.get(A.revision)!;
    assert.equal(a.subject, A.subject);
    assert.equal(a.body, A.body_sha256);
    assert.equal(a.asserted_time?.coordinate, A.asserted_time.coordinate);
    assert.equal(byId.get(B.revision)!.asserted_time?.precision, "year");
    assert.equal(s.subjects.length, 2);
    assert.deepEqual(s.edges, []);
    assert.equal(s.commitment, load("snapshot").body.commitment);
  });

  test("pinned fold is sent and checked", async () => {
    const manifest: string = load("health").body.fold_version.manifest;
    const [c, t] = client();
    const s = await c.snapshot(1, manifest);
    assert.equal(s.rule.fold_manifest, manifest);
    assert.deepEqual(queryOf(t.calls[0]![0]), [
      ["fold_manifest", manifest],
      ["fold_version", "1"],
    ]);
  });

  test("unsupported fold is a 409", async () => {
    const [c] = client();
    const e = await rejectsWith(c.snapshot(1, "0".repeat(64)), PublicApiError);
    assert.deepEqual(apiError(e), [409, "unsupported_fold_version"]);
  });

  test("answer for another fold is refused", async () => {
    const manifest: string = load("health").body.fold_version.manifest;
    const doc = structuredClone(load("snapshot_fold_pinned"));
    doc.body.rule.fold_manifest = "1".repeat(64);
    const [c] = client({ snapshot_fold_pinned: doc });
    await rejectsWith(c.snapshot(1, manifest), ProtocolError, /fold/);
  });

  test("half a fold is refused before sending", async () => {
    const [c, t] = client();
    await rejectsWith(c.snapshot(1), TypeError);
    await rejectsWith(c.snapshot(undefined, "0".repeat(64)), TypeError);
    await rejectsWith(c.snapshot(1, null), TypeError);
    assert.deepEqual(t.calls, []);
  });

  test("fold version is checked before sending", async () => {
    const [c, t] = client();
    await rejectsWith(c.snapshot(0x10000, "0".repeat(64)), RangeError);
    await rejectsWith(c.snapshot(-1, "0".repeat(64)), RangeError);
    await rejectsWith(c.snapshot(1.5, "0".repeat(64)), TypeError);
    await rejectsWith(c.snapshot(true as unknown as number, "0".repeat(64)), TypeError);
    await rejectsWith(c.snapshot(1, "0".repeat(63)), TypeError);
    assert.deepEqual(t.calls, []);
  });

  test("half fold answer is typed", () => {
    assert.throws(
      () => parseFixture("snapshot_fold_half", snapshotCall()),
      (e: unknown) => e instanceof PublicApiError && e.error === "invalid_fold_request",
    );
  });
});

describe("Summaries", () => {
  test("lists each subject with its signed key", async () => {
    const [c] = client();
    const summaries = summarizeSubjects(await c.snapshot());
    const got = new Map(summaries.map((s) => [s.subject, s]));
    assert.deepEqual([...got.keys()].sort(), [A.subject, B.subject].sort());
    const a = got.get(A.subject)!;
    assert.deepEqual(
      [a.key.kind, a.key.namespace, a.key.value],
      [A.subject_key.kind, A.subject_key.namespace, A.subject_key.value],
    );
    assert.equal(a.key.value, "fixture-a");
    assert.equal(a.state, "resolved");
    assert.equal(a.revision?.id, A.revision);
    assert.equal(got.get(B.subject)!.revision?.id, B.revision);
    assert.equal(got.get(B.subject)!.key.value, "fixture-b");
  });

  test("missing genesis is refused", async () => {
    const doc = structuredClone(load("snapshot"));
    const aEvent = JSON.stringify(hexToBytes(A.event));
    doc.body.rows = doc.body.rows.filter((r: Doc) => JSON.stringify(r.event) !== aEvent);
    assert.equal(doc.body.rows.length, 1);
    const [c] = client({ snapshot: doc });
    const snapshot = await c.snapshot();
    assert.throws(() => summarizeSubjects(snapshot), (e: unknown) =>
      e instanceof ProtocolError && /Genesis/.test(e.message));
  });

  test("head without revision is refused", async () => {
    const doc = structuredClone(load("snapshot"));
    doc.body.revisions = doc.body.revisions.slice(0, 1);
    const [c] = client({ snapshot: doc });
    const snapshot = await c.snapshot();
    assert.throws(() => summarizeSubjects(snapshot), (e: unknown) =>
      e instanceof ProtocolError && /no served revision/.test(e.message));
  });

  test("contested subject has no revision", async () => {
    const doc = structuredClone(load("snapshot"));
    for (const s of doc.body.subjects) {
      s.state = "contested";
    }
    const [c] = client({ snapshot: doc });
    const summaries = summarizeSubjects(await c.snapshot());
    assert.deepEqual(summaries.map((s) => s.revision), [null, null]);
    assert.deepEqual(summaries.map((s) => s.state), ["contested", "contested"]);
  });
});

describe("Subject", () => {
  test("current reading", async () => {
    const [c, t] = client();
    const r = await c.subject(A.subject);
    assert.equal(r.known, true);
    assert.deepEqual([r.state, r.visibility], ["resolved", "visible"]);
    assert.equal(r.revision?.id, A.revision);
    assert.equal(r.revision?.creating_event, A.event);
    assert.equal(r.as_of, null);
    assert.deepEqual(r.frontier, [A.event]);
    // An absent as_of is omitted, not sent as an empty or "undefined" value.
    assert.equal(t.calls[0]![0], `${BASE}/public/v1/subjects/${A.subject}`);
  });

  test("a null as_of is omitted too", async () => {
    const [c, t] = client();
    await c.subject(A.subject, null);
    assert.equal(t.calls[0]![0], `${BASE}/public/v1/subjects/${A.subject}`);
  });

  test("as_of after assertion is visible", async () => {
    const [c, t] = client();
    const r = await c.subject(A.subject, B.asserted_time.coordinate);
    assert.equal(r.visibility, "visible");
    assert.equal(r.as_of, B.asserted_time.coordinate);
    assert.ok(t.calls[0]![0].includes(`as_of=${B.asserted_time.coordinate}`));
  });

  test("as_of before assertion hides the revision", async () => {
    const [c] = client();
    const r = await c.subject(B.subject, A.asserted_time.coordinate);
    assert.equal(r.visibility, "after_as_of");
    assert.equal(r.revision, null);
    assert.equal(r.known, true);
  });

  test("unknown subject is a read, not an error", async () => {
    const [c] = client();
    const r = await c.subject("ab".repeat(32));
    assert.equal(r.known, false);
    assert.equal(r.visibility, "subject_unknown");
    assert.deepEqual(r.frontier, []);
    assert.equal(r.revision, null);
  });

  test("identifiers are checked before sending", async () => {
    const [c, t] = client();
    for (const bad of ["not-hex", "AB".repeat(32), "ab".repeat(31), "ab".repeat(33), 7]) {
      await rejectsWith(c.subject(bad as string), TypeError);
    }
    await rejectsWith(c.subject(A.subject, "1"), TypeError);
    assert.deepEqual(t.calls, []);
  });

  test("bad id answer is typed", () => {
    assert.throws(
      () => parseFixture("subject_bad_id", subjectCall(A.subject)),
      (e: unknown) => e instanceof PublicApiError && e.status === 400 && e.error === "invalid_subject_id",
    );
  });

  test("answer for another subject is refused", async () => {
    const other = structuredClone(load("subject"));
    other.body.subject = B.subject;
    const [c] = client({ subject: other });
    await rejectsWith(c.subject(A.subject), ProtocolError, /another subject/);
  });

  test("revision of another subject is refused", async () => {
    const doc = structuredClone(load("subject"));
    doc.body.revision.subject = hexToBytes(B.subject);
    const [c] = client({ subject: doc });
    await rejectsWith(c.subject(A.subject), ProtocolError, /another subject/);
  });

  test("answer for another as_of is refused", async () => {
    const doc = structuredClone(load("subject_as_of_after"));
    doc.body.as_of = null;
    const [c] = client({ subject_as_of_after: doc });
    await rejectsWith(c.subject(A.subject, B.asserted_time.coordinate), ProtocolError, /as_of/);
  });

  test("status and visibility must agree", async () => {
    const doc = structuredClone(load("subject"));
    doc.status = 404;
    const [c1] = client({ subject: doc });
    await rejectsWith(c1.subject(A.subject), ProtocolError, /404/);
    const unknown = structuredClone(load("subject_unknown"));
    unknown.status = 200;
    const [c2] = client({ subject_unknown: unknown });
    await rejectsWith(c2.subject("ab".repeat(32)), ProtocolError, /disagree/);
  });

  test("hidden subject with a revision is refused", async () => {
    const doc = structuredClone(load("subject_as_of_before"));
    doc.body.revision = load("subject").body.revision;
    const [c] = client({ subject_as_of_before: doc });
    await rejectsWith(c.subject(B.subject, A.asserted_time.coordinate), ProtocolError, /not visible/);
  });

  test("malformed frontier is refused", async () => {
    const [c] = client(tampered("subject", { frontier: ["XYZ"] }));
    await rejectsWith(c.subject(A.subject), ProtocolError, /frontier/);
  });
});

describe("Prose", () => {
  test("text is the signed body", async () => {
    const [c, t] = client();
    const p = await c.prose(A.revision);
    assert.equal(p.availability, "available");
    assert.equal(p.prose, "Synthetic fixture entry A. Not a historical claim.\n");
    assert.equal(p.revision.body, A.body_sha256);
    assert.equal(t.calls[0]![0], `${BASE}/public/v1/revisions/${A.revision}/prose`);
  });

  test("unknown revision is a typed 404", async () => {
    const [c] = client();
    const e = await rejectsWith(c.prose("cd".repeat(32)), PublicApiError);
    assert.deepEqual(apiError(e), [404, "revision_unknown"]);
  });

  test("prose for another revision is refused", async () => {
    const doc = structuredClone(load("prose"));
    doc.body.revision.id = hexToBytes(B.revision);
    const [c] = client({ prose: doc });
    await rejectsWith(c.prose(A.revision), ProtocolError, /another revision/);
  });

  test("availability must match prose", async () => {
    const [c] = client(tampered("prose", { availability: "unavailable" }));
    await rejectsWith(c.prose(A.revision), ProtocolError, /disagree/);
  });
});

describe("Support", () => {
  test("unsupported with reason", async () => {
    const [c, t] = client();
    const s = await c.support(A.subject, B.subject);
    assert.equal(s.supported, false);
    assert.deepEqual(s.path, []);
    assert.deepEqual(s.reasons, [{ code: "no_current_support_path", subject: null, edge: null }]);
    assert.deepEqual([s.from, s.to], [A.subject, B.subject]);
    assert.deepEqual(queryOf(t.calls[0]![0]), [
      ["from", A.subject],
      ["to", B.subject],
    ]);
  });

  test("as_of is sent and echoed", async () => {
    const [c, t] = client();
    const s = await c.support(A.subject, B.subject, B.asserted_time.coordinate);
    assert.equal(s.as_of, B.asserted_time.coordinate);
    assert.deepEqual(queryOf(t.calls[0]![0])[0], ["as_of", B.asserted_time.coordinate]);
  });

  test("swapped endpoints are refused", async () => {
    const [c] = client(tampered("support", { from: B.subject, to: A.subject }));
    await rejectsWith(c.support(A.subject, B.subject), ProtocolError, /another from/);
  });

  test("answer for another as_of is refused", async () => {
    const doc = structuredClone(load("support_as_of"));
    doc.body.as_of = A.asserted_time.coordinate;
    const [c] = client({ support_as_of: doc });
    await rejectsWith(c.support(A.subject, B.subject, B.asserted_time.coordinate), ProtocolError, /as_of/);
  });

  test("supported verdict decodes its path", async () => {
    const doc = structuredClone(load("support"));
    const edge = Array.from({ length: 32 }, (_, i) => i);
    doc.body.support = { Supported: { path: [edge], excluded: [] } };
    const [c] = client({ support: doc });
    const s = await c.support(A.subject, B.subject);
    assert.equal(s.supported, true);
    assert.deepEqual(s.path, ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"]);
  });

  test("unknown verdict is refused", async () => {
    const [c] = client(tampered("support", { support: { Contradicted: {} } }));
    await rejectsWith(c.support(A.subject, B.subject), ProtocolError, /verdict/);
  });

  test("two verdicts are refused", async () => {
    const both = { Supported: { path: [], excluded: [] }, Unsupported: { reasons: [] } };
    const [c] = client(tampered("support", { support: both }));
    await rejectsWith(c.support(A.subject, B.subject), ProtocolError, /verdict/);
  });

  test("missing endpoint answer is typed", () => {
    assert.throws(
      () => parseFixture("support_missing_to", supportCall(A.subject, B.subject)),
      (e: unknown) => e instanceof PublicApiError && e.error === "invalid_support_query",
    );
  });

  test("endpoints are checked before sending", async () => {
    const [c, t] = client();
    await rejectsWith(c.support(A.subject, "x"), TypeError);
    await rejectsWith(c.support("X".repeat(64), B.subject), TypeError);
    await rejectsWith(c.support(A.subject, B.subject, "z".repeat(64)), TypeError);
    assert.deepEqual(t.calls, []);
  });
});

describe("Errors", () => {
  test("invalid query is typed", () => {
    assert.throws(
      () => parseFixture("invalid_query", snapshotCall()),
      (e: unknown) => e instanceof PublicApiError && e.status === 400 && e.error === "invalid_query",
    );
  });

  test("rate limited carries retry after", () => {
    // A real 429 recorded from cc-gateway at one request a minute.
    const doc = load("rate_limited");
    const after = Number(doc.headers?.["retry-after"]);
    assert.ok(Number.isInteger(after) && after > 0);
    assert.throws(
      () => parse(healthCall(), doc.status, JSON.stringify(doc.body), doc.headers),
      (e: unknown) =>
        e instanceof PublicApiError &&
        e.status === 429 &&
        e.error === "rate_limited" &&
        e.retryAfter === after,
    );
  });

  test("rate limited through the client", async () => {
    const doc = load("rate_limited");
    const [c] = client({ health: doc });
    const e = (await rejectsWith(c.health(), PublicApiError)) as PublicApiError;
    assert.equal(e.retryAfter, Number(doc.headers?.["retry-after"]));
  });

  test("retry after forms", () => {
    assert.equal(retryAfterSeconds({ "Retry-After": "7" }), 7);
    assert.equal(retryAfterSeconds({ "retry-after": " 0 " }), 0);
    const now = Date.parse("Wed, 21 Oct 2015 07:27:30 GMT");
    assert.equal(retryAfterSeconds({ "retry-after": "Wed, 21 Oct 2015 07:28:00 GMT" }, now), 30);
    assert.equal(retryAfterSeconds({ "retry-after": "Wed, 21 Oct 2015 07:28:00 GMT" }), 0);
    for (const bad of [undefined, {}, { "retry-after": "-1" }, { "retry-after": "soon" },
      { "retry-after": "1.5" }, { "retry-after": "\u0661" }]) {
      assert.equal(retryAfterSeconds(bad), null, JSON.stringify(bad));
    }
    assert.throws(
      () => parse(healthCall(), 429, '{"error":"rate_limited"}'),
      (e: unknown) => e instanceof PublicApiError && e.retryAfter === null,
    );
  });

  test("receipt is 404 until G4", async () => {
    const [c] = client();
    const e = await rejectsWith(c.receipt(A.event), PublicApiError);
    assert.deepEqual(apiError(e), [404, "no_such_route"]);
  });

  test("receipt id is checked before sending", async () => {
    const [c, t] = client();
    await rejectsWith(c.receipt("00"), TypeError);
    assert.deepEqual(t.calls, []);
  });

  test("fail closed on bad bodies", () => {
    const cases: Array<[number, string]> = [
      [200, "<html>"],
      [200, "[]"],
      [200, "null"],
      [503, "{}"],
      [502, ""],
      [302, ""],
      [0, ""],
    ];
    for (const [status, raw] of cases) {
      assert.throws(() => parse(snapshotCall(), status, raw), ProtocolError, `${status} ${JSON.stringify(raw)}`);
    }
  });

  test("bytesHash is strict", () => {
    assert.equal(bytesHash(new Array(32).fill(0)), "00".repeat(32));
    assert.equal(bytesHash(new Array(32).fill(255)), "ff".repeat(32));
    const bad: unknown[] = [
      new Array(31).fill(0),
      [256, ...new Array(31).fill(0)],
      [true, ...new Array(31).fill(0)],
      [1.5, ...new Array(31).fill(0)],
      [-1, ...new Array(31).fill(0)],
      ["0", ...new Array(31).fill(0)],
      "00".repeat(32),
      null,
    ];
    for (const value of bad) {
      assert.throws(() => bytesHash(value), ProtocolError);
    }
  });
});

describe("Requests", () => {
  test("every request carries only Accept", async () => {
    const [c, t] = client();
    await c.health();
    await c.snapshot();
    await c.subject(A.subject);
    await c.prose(A.revision);
    await c.support(A.subject, B.subject);
    assert.equal(t.calls.length, 5);
    for (const [, headers] of t.calls) {
      assert.deepEqual(headers, { Accept: "application/json" });
    }
  });

  test("base URL rules", () => {
    assert.equal(new PublicClient("https://h.invalid/").base, "https://h.invalid");
    assert.equal(new PublicClient("http://h.invalid:8080/p/").base, "http://h.invalid:8080/p");
    for (const bad of [
      "ftp://h.invalid",
      "h.invalid",
      "https://u:p@h.invalid",
      "https://h.invalid/?q=1",
      "https://h.invalid/#f",
      " https://h.invalid",
      "https://h.invalid\\p",
    ]) {
      assert.throws(() => new PublicClient(bad), TypeError, bad);
    }
  });
});

describe("RealTransport", () => {
  // The default fetch transport against a loopback HTTP server.
  const seen: Array<{ method: string; path: string; headers: IncomingHttpHeaders }> = [];
  let server: Server;
  let base: string;

  before(async () => {
    server = createServer((req, res) => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers });
      if (req.url?.endsWith("/health")) {
        res.writeHead(302, { Location: "/elsewhere" });
        res.end();
        return;
      }
      if (req.url?.endsWith("/snapshot")) {
        const limited = '{"error":"rate_limited"}';
        res.writeHead(429, { "Retry-After": "7", "Content-Length": Buffer.byteLength(limited) });
        res.end(limited);
        return;
      }
      const body = JSON.stringify(load("subject").body);
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      });
      res.end(body);
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });

  beforeEach(() => {
    seen.length = 0;
  });

  test("GET without credentials", async () => {
    const r = await new PublicClient(base).subject(A.subject);
    assert.equal(r.revision?.id, A.revision);
    assert.equal(seen.length, 1);
    const [{ method, path, headers }] = seen as [(typeof seen)[number]];
    assert.deepEqual([method, path], ["GET", `/public/v1/subjects/${A.subject}`]);
    assert.equal(headers["accept"], "application/json");
    assert.ok(!("authorization" in headers));
    assert.ok(!("cookie" in headers));
    assert.ok(!("proxy-authorization" in headers));
  });

  test("retry after reaches the error", async () => {
    const e = (await rejectsWith(new PublicClient(base).snapshot(), PublicApiError)) as PublicApiError;
    assert.deepEqual([e.status, e.retryAfter], [429, 7]);
  });

  test("redirect is not followed", async () => {
    await rejectsWith(new PublicClient(base).health(), ProtocolError);
    assert.deepEqual(seen.map((s) => s.path), ["/public/v1/health"]);
  });
});

describe("Async", () => {
  test("same decoding over a caller's async transport", async () => {
    const t = new Recorded();
    const send: Transport = async (url, headers) => {
      await new Promise((resolve) => setImmediate(resolve));
      return t.send(url, headers);
    };
    const c = new PublicClient(BASE, { transport: send });
    const r = await c.subject(A.subject);
    const s = await c.support(A.subject, B.subject);
    assert.equal(r.revision?.id, A.revision);
    assert.equal(s.supported, false);
    assert.deepEqual(t.calls.map(([, h]) => h), [{ ...HEADERS }, { ...HEADERS }]);
  });
});
