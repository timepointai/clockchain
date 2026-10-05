/**
 * Typed client for the Clockchain v1 public read API (`/public/v1`).
 *
 * A port of `clients/python/clockchain_public/client.py`. The contract is
 * STAGE-G.md, G5: an unauthenticated, read-only, GET-only API whose JSON
 * equals the node's v1 read routes minus `instance`. This client:
 *
 * - sends GET only, and never an `Authorization` header or any credential;
 * - refuses redirects, so a response always comes from the URL that was asked;
 * - validates every identifier before a request is made (64 lowercase hex);
 * - fails closed: a response that is not JSON, lacks a required field, carries
 *   a malformed hash, or answers for a different subject, revision, coordinate
 *   or fold than the one requested rejects with {@link ProtocolError};
 * - returns the node's typed refusals (`{"error": code}`) as
 *   {@link PublicApiError}, never as an empty result.
 *
 * Direct hashes are lowercase hex. Projection objects embedded in a response
 * keep the node's canonical form, where a hash is an array of 32 byte values;
 * this client converts the ones it types (revisions, support reasons and
 * paths) to hex and leaves the rest of a snapshot as the node served it.
 * Every identifier and hash is a string, never a number.
 *
 * Argument errors are `TypeError` (wrong type or identifier format) or
 * `RangeError` (a number out of range); they reject before any request.
 *
 * Reading from this API does not verify anything: a corpus digest or
 * commitment read here is what the gateway answered, not a recomputation.
 */

import { sha256Hex } from "./sha256.ts";

export const PREFIX = "/public/v1";
const HEX64 = /^[0-9a-f]{64}$/;

/** Any JSON value, as `JSON.parse` returns it. */
export type Json = null | boolean | number | string | Json[] | JsonObject;
export type JsonObject = { [key: string]: Json };

/**
 * `(url, headers) -> {status, body, headers?}`. Injected for tests; the
 * default ({@link fetchTransport}) uses `fetch` with redirects refused. A
 * transport must send a GET with exactly `headers` and must not follow
 * redirects. The answer's `headers` map lowercase response header names to
 * values; only `retry-after` is read.
 */
export type Transport = (
  url: string,
  headers: Record<string, string>,
) => Promise<TransportResponse>;

export interface TransportResponse {
  readonly status: number;
  readonly body: string;
  readonly headers?: Readonly<Record<string, string>>;
}

/** Base class for every error this client raises after argument checks. */
export class ClientError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ClientError";
  }
}

/**
 * The API answered with a non-success status and a typed refusal.
 * `retryAfter` is the response's `Retry-After` in whole seconds (the gateway
 * sends it with 429 `rate_limited`), or null when absent or not a valid
 * delay. Wait at least that long before asking again.
 */
export class PublicApiError extends ClientError {
  readonly status: number;
  readonly error: string;
  readonly retryAfter: number | null;

  constructor(status: number, error: string, retryAfter: number | null = null) {
    super(`HTTP ${status}: ${error}` + (retryAfter === null ? "" : ` (retry after ${retryAfter} s)`));
    this.name = "PublicApiError";
    this.status = status;
    this.error = error;
    this.retryAfter = retryAfter;
  }
}

/**
 * `Retry-After` as delay-seconds (RFC 9110 10.2.3) or an IMF-fixdate,
 * converted to whole seconds from `now` (never negative); null otherwise.
 */
export function retryAfterSeconds(
  headers: Readonly<Record<string, string>> | undefined,
  now: number = Date.now(),
): number | null {
  if (headers === undefined) {
    return null;
  }
  const entry = Object.entries(headers).find(([k]) => k.toLowerCase() === "retry-after");
  if (entry === undefined) {
    return null;
  }
  const value = entry[1].trim();
  if (/^[0-9]+$/.test(value)) {
    const n = Number(value);
    return Number.isSafeInteger(n) ? n : null;
  }
  // IMF-fixdate only, e.g. "Wed, 21 Oct 2015 07:28:00 GMT".
  if (!/^[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$/.test(value)) {
    return null;
  }
  const when = Date.parse(value);
  return Number.isNaN(when) ? null : Math.max(0, Math.ceil((when - now) / 1000));
}

/** The response does not match the contract; nothing is returned. */
export class ProtocolError extends ClientError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "ProtocolError";
  }
}

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

function requireHex64(name: string, value: unknown): string {
  if (!isHex64(value)) {
    throw new TypeError(`${name} must be exactly 64 lowercase hex characters`);
  }
  return value;
}

// --------------------------------------------------------------------------
// Response types
// --------------------------------------------------------------------------

export interface FoldVersion {
  readonly version: number;
  readonly manifest: string;
}

export interface Health {
  readonly ledger: string;
  readonly build: string | null;
  readonly posture: string;
  readonly fold_version: FoldVersion;
  readonly filter_version: string;
  readonly curators: readonly string[];
  readonly max_hops: number;
  readonly semantic: string;
}

export interface Rule {
  readonly fold_version: number;
  readonly fold_manifest: string;
  readonly filter_version: string;
}

export interface AssertedTime {
  readonly coordinate: string;
  readonly precision: string;
}

export interface Revision {
  readonly id: string;
  readonly subject: string;
  readonly creating_event: string;
  readonly body: string;
  readonly asserted_time: AssertedTime | null;
}

export interface Snapshot {
  readonly rule: Rule;
  readonly corpus_digest: string;
  readonly commitment: string;
  readonly rows: Json[];
  readonly subjects: Json[];
  readonly revisions: readonly Revision[];
  readonly edges: Json[];
  readonly media: Json[];
  readonly authority: JsonObject;
}

export interface SubjectRead {
  readonly rule: Rule;
  readonly corpus_digest: string;
  readonly commitment: string;
  readonly as_of: string | null;
  readonly subject: string;
  readonly state: string;
  readonly frontier: readonly string[];
  readonly revision: Revision | null;
  readonly visibility: string;
  /** `false` only for the 404 `subject_unknown` read. */
  readonly known: boolean;
}

export interface Prose {
  readonly rule: Rule;
  readonly corpus_digest: string;
  readonly commitment: string;
  readonly revision: Revision;
  readonly availability: string;
  readonly prose: string | null;
}

export interface Reason {
  readonly code: string;
  readonly subject: string | null;
  readonly edge: string | null;
}

export interface InitialAdmission {
  readonly state: "valid" | "pending" | "invalid";
  readonly reason: string;
  readonly missing: readonly string[];
}

/**
 * One `NodeReceiptV1` as the node serves it. `receipt` is the signed bytes as
 * hex and is authoritative; the other fields are the node's decoding of them.
 * This client checks that `receipt_digest` is the SHA-256 of those bytes but
 * does not verify the node's signature. `received_at` is when the node saw the
 * event, in Unix microseconds, not a claimed historical time.
 */
export interface NodeReceipt {
  readonly receipt: string;
  readonly receipt_digest: string;
  readonly node_key: string;
  readonly event: string;
  readonly received_at: number;
  readonly encoding_version: number;
  readonly fold_version: FoldVersion;
  readonly initial_admission_result: InitialAdmission;
}

export interface Receipts {
  readonly event: string;
  readonly receipts: readonly NodeReceipt[];
}

export interface SupportRead {
  readonly rule: Rule;
  readonly corpus_digest: string;
  readonly commitment: string;
  readonly as_of: string | null;
  readonly from: string;
  readonly to: string;
  readonly supported: boolean;
  readonly path: readonly string[];
  readonly reasons: readonly Reason[];
}

// --------------------------------------------------------------------------
// Decoding (fail closed)
// --------------------------------------------------------------------------

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** An own property of a JSON object, or `undefined`; never an inherited one. */
function own(doc: JsonObject, key: string): Json | undefined {
  return Object.hasOwn(doc, key) ? doc[key] : undefined;
}

function field(doc: unknown, key: string): Json {
  if (!isObject(doc) || !Object.hasOwn(doc, key)) {
    throw new ProtocolError(`response lacks '${key}'`);
  }
  return doc[key] as Json;
}

function wrongType(key: string): ProtocolError {
  return new ProtocolError(`'${key}' has the wrong type`);
}

function str(doc: unknown, key: string): string {
  const value = field(doc, key);
  if (typeof value !== "string") throw wrongType(key);
  return value;
}

function optStr(doc: unknown, key: string): string | null {
  const value = field(doc, key);
  if (value !== null && typeof value !== "string") throw wrongType(key);
  return value;
}

/** An integer; `true`, `1.5` and unsafe magnitudes are refused. */
function int(doc: unknown, key: string): number {
  const value = field(doc, key);
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw wrongType(key);
  return value;
}

function obj(doc: unknown, key: string): JsonObject {
  const value = field(doc, key);
  if (!isObject(value)) throw wrongType(key);
  return value;
}

function optObj(doc: unknown, key: string): JsonObject | null {
  const value = field(doc, key);
  if (value !== null && !isObject(value)) throw wrongType(key);
  return value;
}

function arr(doc: unknown, key: string): Json[] {
  const value = field(doc, key);
  if (!Array.isArray(value)) throw wrongType(key);
  return value;
}

function optArr(doc: unknown, key: string): Json[] | null {
  const value = field(doc, key);
  if (value !== null && !Array.isArray(value)) throw wrongType(key);
  return value;
}

function hex(doc: unknown, key: string): string {
  const value = str(doc, key);
  if (!isHex64(value)) {
    throw new ProtocolError(`'${key}' is not 64 lowercase hex`);
  }
  return value;
}

function optHex(doc: unknown, key: string): string | null {
  return optStr(doc, key) === null ? null : hex(doc, key);
}

/** A canonical-form hash (an array of 32 byte values) as lowercase hex. */
export function bytesHash(value: unknown, what: string = "hash"): string {
  if (
    !Array.isArray(value) ||
    value.length !== 32 ||
    !value.every((b) => typeof b === "number" && Number.isInteger(b) && b >= 0 && b <= 255)
  ) {
    throw new ProtocolError(`${what} is not a list of 32 byte values`);
  }
  return (value as number[]).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function rule(doc: unknown): Rule {
  const r = obj(doc, "rule");
  return {
    fold_version: int(r, "fold_version"),
    fold_manifest: hex(r, "fold_manifest"),
    filter_version: hex(r, "filter_version"),
  };
}

function revision(value: unknown): Revision {
  if (!isObject(value)) {
    throw new ProtocolError("revision is not an object");
  }
  const t = optObj(value, "asserted_time");
  let asserted: AssertedTime | null = null;
  if (t !== null) {
    asserted = {
      coordinate: bytesHash(arr(t, "coordinate"), "asserted_time.coordinate"),
      precision: str(t, "precision"),
    };
  }
  return {
    id: bytesHash(arr(value, "id"), "revision.id"),
    subject: bytesHash(arr(value, "subject"), "revision.subject"),
    creating_event: bytesHash(arr(value, "creating_event"), "revision.creating_event"),
    body: bytesHash(arr(value, "body"), "revision.body"),
    asserted_time: asserted,
  };
}

function optBytesHash(doc: unknown, key: string): string | null {
  const value = optArr(doc, key);
  return value === null ? null : bytesHash(value, key);
}

function reason(value: unknown): Reason {
  if (!isObject(value)) {
    throw new ProtocolError("support reason is not an object");
  }
  return {
    code: str(value, "code"),
    subject: optBytesHash(value, "subject"),
    edge: optBytesHash(value, "edge"),
  };
}

/** `{"Supported": {path, excluded}}` or `{"Unsupported": {reasons}}`. */
function support(value: JsonObject): [boolean, string[], Reason[]] {
  const verdicts = Object.keys(value);
  if (verdicts.length !== 1) {
    throw new ProtocolError("support is not exactly one verdict");
  }
  const verdict = verdicts[0]!;
  const body = value[verdict];
  if (verdict === "Supported") {
    const path = arr(body, "path").map((h) => bytesHash(h, "support.path"));
    const reasons = arr(body, "excluded").map(reason);
    return [true, path, reasons];
  }
  if (verdict === "Unsupported") {
    return [false, [], arr(body, "reasons").map(reason)];
  }
  throw new ProtocolError(`unknown support verdict ${JSON.stringify(verdict)}`);
}

function hexList(values: Json[], what: string): string[] {
  const out: string[] = [];
  for (const v of values) {
    if (!isHex64(v)) {
      throw new ProtocolError(`a ${what} entry is not 64 lowercase hex`);
    }
    out.push(v);
  }
  return out;
}

// --------------------------------------------------------------------------
// Calls (sans-IO): what to request and how to decode the answer
// --------------------------------------------------------------------------

/** Headers on every request. There is deliberately no way to add a credential. */
export const HEADERS: Readonly<Record<string, string>> = Object.freeze({
  Accept: "application/json",
});

/**
 * One request: `route` below `/public/v1`, the query with absent parameters
 * already removed, the statuses that carry a body to decode, and the decoder
 * for that body.
 */
export interface Call<T> {
  readonly route: string;
  readonly query: Readonly<Record<string, string>>;
  readonly ok: readonly number[];
  readonly decode: (status: number, doc: JsonObject) => T;
}

function call<T>(
  route: string,
  query: Record<string, string | null | undefined>,
  decode: (status: number, doc: JsonObject) => T,
  ok: readonly number[] = [200],
): Call<T> {
  const present: Record<string, string> = {};
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null) present[k] = v;
  }
  return Object.freeze({
    route,
    query: Object.freeze(present),
    ok: Object.freeze([...ok]),
    decode,
  });
}

function expect(what: string, served: unknown, asked: unknown): void {
  if (served !== asked) {
    throw new ProtocolError(`response answers for another ${what}`);
  }
}

export function healthCall(): Call<Health> {
  const decode = (_: number, d: JsonObject): Health => {
    if (Object.hasOwn(d, "instance")) {
      throw new ProtocolError("public health must not carry the instance");
    }
    const ledger = str(d, "ledger");
    if (ledger !== "v1") {
      throw new ProtocolError(`ledger is ${JSON.stringify(ledger)}, not 'v1'`);
    }
    const fold = obj(d, "fold_version");
    const curators = arr(d, "curators");
    for (const c of curators) {
      if (!isHex64(c)) {
        throw new ProtocolError("a curator is not 64 lowercase hex");
      }
    }
    const build = own(d, "build") ?? null;
    if (build !== null && typeof build !== "string") {
      throw wrongType("build");
    }
    return {
      ledger,
      build,
      posture: str(d, "posture"),
      fold_version: { version: int(fold, "version"), manifest: hex(fold, "manifest") },
      filter_version: hex(d, "filter_version"),
      curators: curators as string[],
      max_hops: int(d, "max_hops"),
      semantic: str(d, "semantic"),
    };
  };
  return call("/health", {}, decode);
}

/**
 * Pin both fold arguments or neither. A pinned fold the API cannot answer is
 * `PublicApiError(409, "unsupported_fold_version")`.
 */
export function snapshotCall(
  foldVersion?: number | null,
  foldManifest?: string | null,
): Call<Snapshot> {
  const pinned = foldVersion !== undefined && foldVersion !== null;
  if (pinned !== (foldManifest !== undefined && foldManifest !== null)) {
    throw new TypeError("foldVersion and foldManifest go together");
  }
  let query: Record<string, string> = {};
  if (pinned) {
    if (typeof foldVersion !== "number" || !Number.isInteger(foldVersion)) {
      throw new TypeError("foldVersion must be an integer in 0..65535");
    }
    if (foldVersion < 0 || foldVersion > 0xffff) {
      throw new RangeError("foldVersion must be an integer in 0..65535");
    }
    query = {
      fold_version: String(foldVersion),
      fold_manifest: requireHex64("foldManifest", foldManifest),
    };
  }

  const decode = (_: number, d: JsonObject): Snapshot => {
    const r = rule(d);
    if (pinned) {
      expect("fold", r.fold_version, foldVersion);
      expect("fold", r.fold_manifest, foldManifest);
    }
    return {
      rule: r,
      corpus_digest: hex(d, "corpus_digest"),
      commitment: hex(d, "commitment"),
      rows: arr(d, "rows"),
      subjects: arr(d, "subjects"),
      revisions: arr(d, "revisions").map(revision),
      edges: arr(d, "edges"),
      media: arr(d, "media"),
      authority: obj(d, "authority"),
    };
  };
  return call("/snapshot", query, decode);
}

/**
 * An unknown subject is a 404 whose body is still a complete read; it is
 * returned with `known === false`, not raised.
 */
export function subjectCall(subject: string, asOf?: string | null): Call<SubjectRead> {
  requireHex64("subject", subject);
  const askedAsOf = asOf ?? null;
  if (askedAsOf !== null) {
    requireHex64("asOf", askedAsOf);
  }

  const decode = (status: number, d: JsonObject): SubjectRead => {
    if (status === 404 && own(d, "visibility") !== "subject_unknown") {
      const error = own(d, "error");
      if (typeof error !== "string") {
        throw new ProtocolError("HTTP 404 without a typed error");
      }
      throw new PublicApiError(404, error);
    }
    const rev = optObj(d, "revision");
    const r = rule(d);
    const corpusDigest = hex(d, "corpus_digest");
    const commitment = hex(d, "commitment");
    const servedAsOf = optHex(d, "as_of");
    const servedSubject = hex(d, "subject");
    const state = str(d, "state");
    const frontier = hexList(arr(d, "frontier"), "frontier");
    const decoded = rev === null ? null : revision(rev);
    const visibility = str(d, "visibility");
    expect("subject", servedSubject, subject);
    expect("as_of", servedAsOf, askedAsOf);
    if ((status === 404) !== (visibility === "subject_unknown")) {
      throw new ProtocolError("status and visibility disagree");
    }
    if (decoded !== null) {
      if (visibility !== "visible") {
        throw new ProtocolError("a revision is served for a subject that is not visible");
      }
      expect("subject", decoded.subject, subject);
    }
    return {
      rule: r,
      corpus_digest: corpusDigest,
      commitment,
      as_of: servedAsOf,
      subject: servedSubject,
      state,
      frontier,
      revision: decoded,
      visibility,
      known: visibility !== "subject_unknown",
    };
  };
  return call(`/subjects/${subject}`, { as_of: askedAsOf }, decode, [200, 404]);
}

export function proseCall(revisionId: string): Call<Prose> {
  requireHex64("revision", revisionId);

  const decode = (_: number, d: JsonObject): Prose => {
    const rev = revision(obj(d, "revision"));
    expect("revision", rev.id, revisionId);
    const availability = str(d, "availability");
    const prose = optStr(d, "prose");
    if ((availability === "available") !== (prose !== null)) {
      throw new ProtocolError("prose and availability disagree");
    }
    return {
      rule: rule(d),
      corpus_digest: hex(d, "corpus_digest"),
      commitment: hex(d, "commitment"),
      revision: rev,
      availability,
      prose,
    };
  };
  return call(`/revisions/${revisionId}/prose`, {}, decode);
}

export function supportCall(from: string, to: string, asOf?: string | null): Call<SupportRead> {
  requireHex64("from", from);
  requireHex64("to", to);
  const askedAsOf = asOf ?? null;
  if (askedAsOf !== null) {
    requireHex64("asOf", askedAsOf);
  }

  const decode = (_: number, d: JsonObject): SupportRead => {
    const [supported, path, reasons] = support(obj(d, "support"));
    const read: SupportRead = {
      rule: rule(d),
      corpus_digest: hex(d, "corpus_digest"),
      commitment: hex(d, "commitment"),
      as_of: optHex(d, "as_of"),
      from: hex(d, "from"),
      to: hex(d, "to"),
      supported,
      path,
      reasons,
    };
    expect("from", read.from, from);
    expect("to", read.to, to);
    expect("as_of", read.as_of, askedAsOf);
    return read;
  };
  return call("/support", { from, to, as_of: askedAsOf }, decode);
}

const ADMISSION_STATES = ["valid", "pending", "invalid"] as const;

function hexBytes(hexText: string): Uint8Array {
  const out = new Uint8Array(hexText.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hexText.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

function nodeReceipt(value: unknown, event: string): NodeReceipt {
  if (!isObject(value)) {
    throw new ProtocolError("receipt is not an object");
  }
  const raw = str(value, "receipt");
  if (raw.length === 0 || raw.length % 2 !== 0 || !/^[0-9a-f]+$/.test(raw)) {
    throw new ProtocolError("'receipt' is not lowercase hex bytes");
  }
  const digest = hex(value, "receipt_digest");
  if (sha256Hex(hexBytes(raw)) !== digest) {
    throw new ProtocolError("receipt_digest is not the SHA-256 of the receipt");
  }
  const receivedAt = int(value, "received_at");
  if (receivedAt < 0) {
    throw new ProtocolError("'received_at' is negative");
  }
  const fold = obj(value, "fold_version");
  const initial = obj(value, "initial_admission_result");
  const state = str(initial, "state");
  if (!(ADMISSION_STATES as readonly string[]).includes(state)) {
    throw new ProtocolError(`unknown admission state ${JSON.stringify(state)}`);
  }
  const r: NodeReceipt = {
    receipt: raw,
    receipt_digest: digest,
    node_key: hex(value, "node_key"),
    event: hex(value, "event"),
    received_at: receivedAt,
    encoding_version: int(value, "encoding_version"),
    fold_version: { version: int(fold, "version"), manifest: hex(fold, "manifest") },
    initial_admission_result: {
      state: state as InitialAdmission["state"],
      reason: str(initial, "reason"),
      missing: hexList(arr(initial, "missing"), "missing"),
    },
  };
  expect("event", r.event, event);
  return r;
}

/**
 * Every `NodeReceiptV1` the node retains for one admitted event (Stage (g)
 * G4), as `{event, receipts}`. An event with none, including every event on a
 * node without a receipt key, is `PublicApiError(404, "no_receipt")`.
 */
export function receiptCall(event: string): Call<Receipts> {
  requireHex64("event", event);
  return call(`/receipts/${event}`, {}, (_, d) => {
    const served = hex(d, "event");
    expect("event", served, event);
    const items = arr(d, "receipts");
    if (items.length === 0) {
      throw new ProtocolError("a 200 receipts answer lists no receipt");
    }
    return { event: served, receipts: items.map((r) => nodeReceipt(r, event)) };
  });
}

/** Decode one response, failing closed. */
export function parse<T>(
  c: Call<T>,
  status: number,
  raw: string,
  headers?: Readonly<Record<string, string>>,
): T {
  if (typeof raw !== "string") {
    throw new ProtocolError(`HTTP ${status}: response body is not text`);
  }
  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch (e) {
    throw new ProtocolError(`HTTP ${status}: response is not JSON`, { cause: e });
  }
  if (!isObject(doc)) {
    throw new ProtocolError(`HTTP ${status}: response is not a JSON object`);
  }
  if (c.ok.includes(status)) {
    return c.decode(status, doc);
  }
  const error = own(doc, "error");
  if (typeof error !== "string") {
    throw new ProtocolError(`HTTP ${status} without a typed error`);
  }
  throw new PublicApiError(status, error, retryAfterSeconds(headers));
}

/** Scheme, host, optional port and path prefix; nothing else. */
export function normalizeBase(baseUrl: string): string {
  // WHATWG URL parsing silently drops tabs and newlines, trims spaces and
  // reads `\` as `/`; refuse such input instead of guessing what was meant.
  if (typeof baseUrl !== "string" || /[\u0000- \u007f\\]/.test(baseUrl)) {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  if ((url.protocol !== "http:" && url.protocol !== "https:") || !url.hostname) {
    throw new TypeError("baseUrl must be an absolute http(s) URL");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new TypeError("baseUrl must not carry credentials, a query or a fragment");
  }
  return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
}

export function buildUrl(base: string, c: Call<unknown>): string {
  const query = new URLSearchParams(c.query).toString();
  return `${base}${PREFIX}${c.route}${query ? `?${query}` : ""}`;
}

// --------------------------------------------------------------------------
// Snapshot helpers
// --------------------------------------------------------------------------

export interface SubjectKey {
  readonly kind: string;
  readonly namespace: string;
  readonly value: string;
}

/**
 * One subject of a snapshot, for listing and lookup. `revision` is the
 * current revision only for a `resolved` subject; a contested or bodiless
 * subject has none, and none is invented.
 */
export interface SubjectSummary {
  readonly subject: string;
  readonly state: string;
  readonly key: SubjectKey;
  readonly revision: Revision | null;
}

/**
 * Subjects in the order the snapshot lists them, each with the subject key
 * its Genesis signed. Throws `ProtocolError` if a subject has no Genesis row
 * or a resolved subject's head has no served revision.
 */
export function summarizeSubjects(snapshot: Snapshot): SubjectSummary[] {
  const rows = new Map<string, JsonObject>();
  for (const row of snapshot.rows) {
    if (!isObject(row)) {
      throw new ProtocolError("snapshot row is not an object");
    }
    rows.set(bytesHash(arr(row, "event"), "row.event"), row);
  }
  const revisions = new Map<string, Revision>();
  for (const r of snapshot.revisions) {
    revisions.set(r.id, r);
  }
  const out: SubjectSummary[] = [];
  for (const s of snapshot.subjects) {
    if (!isObject(s)) {
      throw new ProtocolError("snapshot subject is not an object");
    }
    const subject = bytesHash(arr(s, "subject"), "subject");
    const state = str(s, "state");
    const genesis = rows.get(subject); // a Genesis event id is its subject id
    const envelope = genesis === undefined ? null : obj(genesis, "envelope");
    if (envelope === null || !Object.hasOwn(obj(envelope, "payload"), "Genesis")) {
      throw new ProtocolError("subject has no Genesis row");
    }
    const k = obj(envelope, "subject_key");
    const key: SubjectKey = {
      kind: str(k, "kind"),
      namespace: str(k, "namespace"),
      value: str(k, "value"),
    };
    let rev: Revision | null = null;
    if (state === "resolved") {
      const frontier = arr(s, "frontier");
      if (frontier.length !== 1) {
        throw new ProtocolError("resolved subject without exactly one head");
      }
      const head = rows.get(bytesHash(frontier[0], "frontier"));
      const rid = head === undefined ? null : optArr(head, "revision");
      rev = rid === null ? null : (revisions.get(bytesHash(rid, "row.revision")) ?? null);
      if (rev === null || rev.subject !== subject) {
        throw new ProtocolError("resolved subject's head has no served revision");
      }
    }
    out.push({ subject, state, key, revision: rev });
  }
  return out;
}

// --------------------------------------------------------------------------
// Transport and client
// --------------------------------------------------------------------------

/**
 * GET over the global `fetch`, with redirects refused: a 3xx comes back as its
 * status (or, in a browser, an opaque redirect as status 0 with no body), and
 * either way `parse` turns it into an error. No credential is ever sent.
 * Node's `fetch` does not read `HTTP_PROXY`/`HTTPS_PROXY` unless the process
 * opts in with `NODE_USE_ENV_PROXY`; leave that unset for this client.
 */
export function fetchTransport(timeoutMs: number = 10_000): Transport {
  if (typeof timeoutMs !== "number" || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError("timeoutMs must be a positive number");
  }
  return async (url, headers) => {
    const response = await fetch(url, {
      method: "GET",
      headers: { ...headers },
      redirect: "manual",
      credentials: "omit",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (response.type === "opaqueredirect") {
      return { status: 0, body: "", headers: {} };
    }
    const bytes = await response.arrayBuffer();
    let body: string;
    try {
      body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch (e) {
      throw new ProtocolError(`HTTP ${response.status}: response is not UTF-8`, { cause: e });
    }
    const kept: Record<string, string> = {};
    const after = response.headers.get("retry-after");
    if (after !== null) {
      kept["retry-after"] = after;
    }
    return { status: response.status, body, headers: kept };
  };
}

export interface ClientOptions {
  /** Request timeout for the default transport, in milliseconds (default 10 s). */
  readonly timeoutMs?: number;
  /** For tests; leave unset. */
  readonly transport?: Transport;
}

/** Client for `/public/v1`. Every method returns a promise. */
export class PublicClient {
  readonly base: string;
  readonly #send: Transport;

  constructor(baseUrl: string, options: ClientOptions = {}) {
    this.base = normalizeBase(baseUrl);
    this.#send = options.transport ?? fetchTransport(options.timeoutMs);
  }

  async run<T>(c: Call<T>): Promise<T> {
    const { status, body, headers } = await this.#send(buildUrl(this.base, c), { ...HEADERS });
    return parse(c, status, body, headers);
  }

  async health(): Promise<Health> {
    return this.run(healthCall());
  }

  async snapshot(foldVersion?: number | null, foldManifest?: string | null): Promise<Snapshot> {
    return this.run(snapshotCall(foldVersion, foldManifest));
  }

  async subject(subject: string, asOf?: string | null): Promise<SubjectRead> {
    return this.run(subjectCall(subject, asOf));
  }

  async prose(revision: string): Promise<Prose> {
    return this.run(proseCall(revision));
  }

  async support(from: string, to: string, asOf?: string | null): Promise<SupportRead> {
    return this.run(supportCall(from, to, asOf));
  }

  async receipt(event: string): Promise<Receipts> {
    return this.run(receiptCall(event));
  }
}
