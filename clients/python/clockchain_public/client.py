"""Typed client for the Clockchain v1 public read API (`/public/v1`).

The contract is STAGE-G.md, G5: an unauthenticated, read-only, GET-only API
whose JSON equals the node's v1 read routes minus `instance`. This client:

- sends GET only, and never an `Authorization` header or any credential;
- refuses redirects, so a response always comes from the URL that was asked;
- validates every identifier before a request is made (64 lowercase hex);
- fails closed: a response that is not JSON, lacks a required field, carries a
  malformed hash, or answers for a different subject, revision, coordinate or
  fold than the one requested raises :class:`ProtocolError`;
- returns the node's typed refusals (`{"error": code}`) as
  :class:`PublicApiError`, never as an empty result.

Direct hashes are lowercase hex. Projection objects embedded in a response
keep the node's canonical form, where a hash is a list of 32 byte values; this
client converts the ones it types (revisions, support reasons and paths) to
hex and leaves the rest of a snapshot as the node served it.

Reading from this API does not verify anything: a corpus digest or commitment
read here is what the gateway answered, not a recomputation.
"""

from __future__ import annotations

import datetime
import email.utils
import json
import math
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Generic, Mapping, TypeVar

PREFIX = "/public/v1"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

T = TypeVar("T")

#: `(url, headers) -> (status, response headers, body bytes)`. Injected for
#: tests; the default uses urllib with redirects and proxies refused. `headers` maps lowercase
#: response header names to values; only `retry-after` is read.
Transport = Callable[[str, Mapping[str, str]], "tuple[int, Mapping[str, str], bytes]"]
AsyncTransport = Callable[
    [str, Mapping[str, str]], Awaitable["tuple[int, Mapping[str, str], bytes]"]
]


class ClientError(Exception):
    """Base class for every error this client raises after argument checks."""


class PublicApiError(ClientError):
    """The API answered with a non-success status and a typed refusal.

    `retry_after` is the response's `Retry-After` in whole seconds (the
    gateway sends it with 429 `rate_limited`), or None when absent or not a
    valid delay. Wait at least that long before asking again."""

    def __init__(self, status: int, error: str, retry_after: int | None = None):
        super().__init__(f"HTTP {status}: {error}"
                         + ("" if retry_after is None else f" (retry after {retry_after} s)"))
        self.status = status
        self.error = error
        self.retry_after = retry_after


def retry_after_seconds(headers: Mapping[str, str] | None) -> int | None:
    """`Retry-After` as delay-seconds (RFC 9110 10.2.3) or an HTTP-date,
    converted to whole seconds from now (never negative); None otherwise."""
    if not headers:
        return None
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        return int(value)
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        return None
    now = datetime.datetime.now(datetime.timezone.utc)
    return max(0, math.ceil((when - now).total_seconds()))


class ProtocolError(ClientError):
    """The response does not match the contract; nothing is returned."""


def is_hex64(value: object) -> bool:
    return isinstance(value, str) and _HEX64.match(value) is not None


def _require_hex64(name: str, value: object) -> str:
    if not is_hex64(value):
        raise ValueError(f"{name} must be exactly 64 lowercase hex characters")
    return value  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Response types
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class FoldVersion:
    version: int
    manifest: str


@dataclass(frozen=True)
class Health:
    ledger: str
    build: str | None
    posture: str
    fold_version: FoldVersion
    filter_version: str
    curators: tuple[str, ...]
    max_hops: int
    semantic: str


@dataclass(frozen=True)
class Rule:
    fold_version: int
    fold_manifest: str
    filter_version: str


@dataclass(frozen=True)
class AssertedTime:
    coordinate: str
    precision: str


@dataclass(frozen=True)
class Revision:
    id: str
    subject: str
    creating_event: str
    body: str
    asserted_time: AssertedTime | None


@dataclass(frozen=True)
class Snapshot:
    rule: Rule
    corpus_digest: str
    commitment: str
    rows: list[Any]
    subjects: list[Any]
    revisions: tuple[Revision, ...]
    edges: list[Any]
    media: list[Any]
    authority: dict[str, Any]


@dataclass(frozen=True)
class SubjectRead:
    rule: Rule
    corpus_digest: str
    commitment: str
    as_of: str | None
    subject: str
    state: str
    frontier: tuple[str, ...]
    revision: Revision | None
    visibility: str

    @property
    def known(self) -> bool:
        return self.visibility != "subject_unknown"


@dataclass(frozen=True)
class Prose:
    rule: Rule
    corpus_digest: str
    commitment: str
    revision: Revision
    availability: str
    prose: str | None


@dataclass(frozen=True)
class Reason:
    code: str
    subject: str | None
    edge: str | None


@dataclass(frozen=True)
class SupportRead:
    rule: Rule
    corpus_digest: str
    commitment: str
    as_of: str | None
    from_: str
    to: str
    supported: bool
    path: tuple[str, ...]
    reasons: tuple[Reason, ...]


# --------------------------------------------------------------------------
# Decoding (fail closed)
# --------------------------------------------------------------------------


def _field(doc: Mapping[str, Any], key: str, kind: type | tuple[type, ...]) -> Any:
    if not isinstance(doc, Mapping) or key not in doc:
        raise ProtocolError(f"response lacks {key!r}")
    value = doc[key]
    # bool is an int subclass; never accept it where a number is required.
    if isinstance(value, bool) and kind is not bool:
        raise ProtocolError(f"{key!r} has the wrong type")
    if not isinstance(value, kind):
        raise ProtocolError(f"{key!r} has the wrong type")
    return value


def _hex(doc: Mapping[str, Any], key: str) -> str:
    value = _field(doc, key, str)
    if not is_hex64(value):
        raise ProtocolError(f"{key!r} is not 64 lowercase hex")
    return value


def _opt_hex(doc: Mapping[str, Any], key: str) -> str | None:
    if _field(doc, key, (str, type(None))) is None:
        return None
    return _hex(doc, key)


def bytes_hash(value: object, what: str = "hash") -> str:
    """A canonical-form hash (a list of 32 byte values) as lowercase hex."""
    if (
        not isinstance(value, list)
        or len(value) != 32
        or not all(type(b) is int and 0 <= b <= 255 for b in value)
    ):
        raise ProtocolError(f"{what} is not a list of 32 byte values")
    return bytes(value).hex()


def _rule(doc: Mapping[str, Any]) -> Rule:
    r = _field(doc, "rule", dict)
    return Rule(
        fold_version=_field(r, "fold_version", int),
        fold_manifest=_hex(r, "fold_manifest"),
        filter_version=_hex(r, "filter_version"),
    )


def _revision(value: object) -> Revision:
    if not isinstance(value, dict):
        raise ProtocolError("revision is not an object")
    t = _field(value, "asserted_time", (dict, type(None)))
    asserted = None
    if t is not None:
        asserted = AssertedTime(
            coordinate=bytes_hash(_field(t, "coordinate", list), "asserted_time.coordinate"),
            precision=_field(t, "precision", str),
        )
    return Revision(
        id=bytes_hash(_field(value, "id", list), "revision.id"),
        subject=bytes_hash(_field(value, "subject", list), "revision.subject"),
        creating_event=bytes_hash(
            _field(value, "creating_event", list), "revision.creating_event"
        ),
        body=bytes_hash(_field(value, "body", list), "revision.body"),
        asserted_time=asserted,
    )


def _opt_bytes_hash(doc: Mapping[str, Any], key: str) -> str | None:
    value = _field(doc, key, (list, type(None)))
    return None if value is None else bytes_hash(value, key)


def _reason(value: object) -> Reason:
    if not isinstance(value, dict):
        raise ProtocolError("support reason is not an object")
    return Reason(
        code=_field(value, "code", str),
        subject=_opt_bytes_hash(value, "subject"),
        edge=_opt_bytes_hash(value, "edge"),
    )


def _support(value: object) -> tuple[bool, tuple[str, ...], tuple[Reason, ...]]:
    """`{"Supported": {path, excluded}}` or `{"Unsupported": {reasons}}`."""
    if not isinstance(value, dict) or len(value) != 1:
        raise ProtocolError("support is not exactly one verdict")
    (verdict, body), = value.items()
    if verdict == "Supported":
        path = tuple(bytes_hash(h, "support.path") for h in _field(body, "path", list))
        reasons = tuple(_reason(r) for r in _field(body, "excluded", list))
        return True, path, reasons
    if verdict == "Unsupported":
        return False, (), tuple(_reason(r) for r in _field(body, "reasons", list))
    raise ProtocolError(f"unknown support verdict {verdict!r}")


# --------------------------------------------------------------------------
# Calls (sans-IO): what to request and how to decode the answer
# --------------------------------------------------------------------------

#: Headers on every request. There is deliberately no way to add a credential.
HEADERS: Mapping[str, str] = {"Accept": "application/json"}


@dataclass(frozen=True)
class Call(Generic[T]):
    """One request: `route` below `/public/v1`, the query with absent
    parameters already removed, the statuses that carry a body to decode, and
    the decoder for that body."""

    route: str
    query: Mapping[str, str]
    ok: tuple[int, ...]
    decode: Callable[[int, dict], T]


def _call(route: str, query: Mapping[str, str | None], decode: Callable[[int, dict], T],
          ok: tuple[int, ...] = (200,)) -> Call[T]:
    return Call(route, {k: v for k, v in query.items() if v is not None}, ok, decode)


def _expect(field: str, served: object, asked: object) -> None:
    if served != asked:
        raise ProtocolError(f"response answers for another {field}")


def health_call() -> Call[Health]:
    def decode(_: int, d: dict) -> Health:
        if "instance" in d:
            raise ProtocolError("public health must not carry the instance")
        ledger = _field(d, "ledger", str)
        if ledger != "v1":
            raise ProtocolError(f"ledger is {ledger!r}, not 'v1'")
        fold = _field(d, "fold_version", dict)
        curators = _field(d, "curators", list)
        for c in curators:
            if not is_hex64(c):
                raise ProtocolError("a curator is not 64 lowercase hex")
        build = d.get("build")
        if build is not None and not isinstance(build, str):
            raise ProtocolError("'build' has the wrong type")
        return Health(
            ledger=ledger,
            build=build,
            posture=_field(d, "posture", str),
            fold_version=FoldVersion(
                version=_field(fold, "version", int), manifest=_hex(fold, "manifest")
            ),
            filter_version=_hex(d, "filter_version"),
            curators=tuple(curators),
            max_hops=_field(d, "max_hops", int),
            semantic=_field(d, "semantic", str),
        )

    return _call("/health", {}, decode)


def snapshot_call(fold_version: int | None = None,
                  fold_manifest: str | None = None) -> Call[Snapshot]:
    """Pin both fold arguments or neither. A pinned fold the API cannot answer
    is `PublicApiError(409, "unsupported_fold_version")`."""
    if (fold_version is None) != (fold_manifest is None):
        raise ValueError("fold_version and fold_manifest go together")
    query: dict[str, str | None] = {}
    if fold_version is not None:
        if isinstance(fold_version, bool) or not isinstance(fold_version, int) \
                or not 0 <= fold_version <= 0xFFFF:
            raise ValueError("fold_version must be an integer in 0..65535")
        query = {
            "fold_version": str(fold_version),
            "fold_manifest": _require_hex64("fold_manifest", fold_manifest),
        }

    def decode(_: int, d: dict) -> Snapshot:
        rule = _rule(d)
        if fold_version is not None:
            _expect("fold", (rule.fold_version, rule.fold_manifest),
                    (fold_version, fold_manifest))
        return Snapshot(
            rule=rule,
            corpus_digest=_hex(d, "corpus_digest"),
            commitment=_hex(d, "commitment"),
            rows=_field(d, "rows", list),
            subjects=_field(d, "subjects", list),
            revisions=tuple(_revision(r) for r in _field(d, "revisions", list)),
            edges=_field(d, "edges", list),
            media=_field(d, "media", list),
            authority=_field(d, "authority", dict),
        )

    return _call("/snapshot", query, decode)


def subject_call(subject: str, as_of: str | None = None) -> Call[SubjectRead]:
    """An unknown subject is a 404 whose body is still a complete read; it is
    returned with `known == False`, not raised."""
    _require_hex64("subject", subject)
    if as_of is not None:
        _require_hex64("as_of", as_of)

    def decode(status: int, d: dict) -> SubjectRead:
        if status == 404 and d.get("visibility") != "subject_unknown":
            error = d.get("error")
            if not isinstance(error, str):
                raise ProtocolError("HTTP 404 without a typed error")
            raise PublicApiError(404, error)
        revision = _field(d, "revision", (dict, type(None)))
        read = SubjectRead(
            rule=_rule(d),
            corpus_digest=_hex(d, "corpus_digest"),
            commitment=_hex(d, "commitment"),
            as_of=_opt_hex(d, "as_of"),
            subject=_hex(d, "subject"),
            state=_field(d, "state", str),
            frontier=_hex_list(_field(d, "frontier", list), "frontier"),
            revision=None if revision is None else _revision(revision),
            visibility=_field(d, "visibility", str),
        )
        _expect("subject", read.subject, subject)
        _expect("as_of", read.as_of, as_of)
        if (status == 404) != (read.visibility == "subject_unknown"):
            raise ProtocolError("status and visibility disagree")
        if read.revision is not None:
            if read.visibility != "visible":
                raise ProtocolError("a revision is served for a subject that is not visible")
            _expect("subject", read.revision.subject, subject)
        return read

    return _call(f"/subjects/{subject}", {"as_of": as_of}, decode, ok=(200, 404))


def prose_call(revision: str) -> Call[Prose]:
    _require_hex64("revision", revision)

    def decode(_: int, d: dict) -> Prose:
        rev = _revision(_field(d, "revision", dict))
        _expect("revision", rev.id, revision)
        availability = _field(d, "availability", str)
        prose = _field(d, "prose", (str, type(None)))
        if (availability == "available") != (prose is not None):
            raise ProtocolError("prose and availability disagree")
        return Prose(
            rule=_rule(d),
            corpus_digest=_hex(d, "corpus_digest"),
            commitment=_hex(d, "commitment"),
            revision=rev,
            availability=availability,
            prose=prose,
        )

    return _call(f"/revisions/{revision}/prose", {}, decode)


def support_call(from_: str, to: str, as_of: str | None = None) -> Call[SupportRead]:
    _require_hex64("from", from_)
    _require_hex64("to", to)
    if as_of is not None:
        _require_hex64("as_of", as_of)

    def decode(_: int, d: dict) -> SupportRead:
        supported, path, reasons = _support(_field(d, "support", dict))
        read = SupportRead(
            rule=_rule(d),
            corpus_digest=_hex(d, "corpus_digest"),
            commitment=_hex(d, "commitment"),
            as_of=_opt_hex(d, "as_of"),
            from_=_hex(d, "from"),
            to=_hex(d, "to"),
            supported=supported,
            path=path,
            reasons=reasons,
        )
        _expect("from", read.from_, from_)
        _expect("to", read.to, to)
        _expect("as_of", read.as_of, as_of)
        return read

    return _call("/support", {"from": from_, "to": to, "as_of": as_of}, decode)


def receipt_call(event: str) -> Call[dict]:
    """`NodeReceiptV1` for an admitted event, untyped: its schema is G4's.
    Until G4 merges the route is unmounted, a `PublicApiError(404, ...)`."""
    _require_hex64("event", event)
    return _call(f"/receipts/{event}", {}, lambda _, d: d)


def _hex_list(values: list[Any], what: str) -> tuple[str, ...]:
    for v in values:
        if not is_hex64(v):
            raise ProtocolError(f"a {what} entry is not 64 lowercase hex")
    return tuple(values)


def parse(call: Call[T], status: int, raw: bytes,
          headers: Mapping[str, str] | None = None) -> T:
    """Decode one response, failing closed. `headers` supplies `Retry-After`
    for a refusal."""
    try:
        doc = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise ProtocolError(f"HTTP {status}: response is not JSON") from e
    if not isinstance(doc, dict):
        raise ProtocolError(f"HTTP {status}: response is not a JSON object")
    if status in call.ok:
        return call.decode(status, doc)
    error = doc.get("error")
    if not isinstance(error, str):
        raise ProtocolError(f"HTTP {status} without a typed error")
    raise PublicApiError(status, error, retry_after_seconds(headers))


def normalize_base(base_url: str) -> str:
    """Scheme, host, optional port and path prefix; nothing else."""
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("base_url must be an absolute http(s) URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("base_url must not carry credentials, a query or a fragment")
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def build_url(base: str, call: Call[Any]) -> str:
    tail = "?" + urllib.parse.urlencode(call.query) if call.query else ""
    return f"{base}{PREFIX}{call.route}{tail}"


# --------------------------------------------------------------------------
# Transport and clients
# --------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urllib_transport(timeout: float) -> Transport:
    """GET with redirects refused (a 3xx comes back as its status) and with no
    proxy: `HTTP_PROXY`, `HTTPS_PROXY` and the rest of the environment are
    ignored, so nothing in between sees or changes the request."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def send(url: str, headers: Mapping[str, str]) -> tuple[int, Mapping[str, str], bytes]:
        req = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with opener.open(req, timeout=timeout) as r:
                return r.status, _lower(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, _lower(e.headers), e.read()

    return send


def _lower(headers) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()} if headers is not None else {}


class PublicClient:
    """Blocking client. `transport` exists for tests; leave it unset."""

    def __init__(self, base_url: str, *, timeout: float = 10.0,
                 transport: Transport | None = None):
        self.base = normalize_base(base_url)
        self._send = transport or urllib_transport(timeout)

    def run(self, call: Call[T]) -> T:
        status, headers, raw = self._send(build_url(self.base, call), HEADERS)
        return parse(call, status, raw, headers)

    def health(self) -> Health:
        return self.run(health_call())

    def snapshot(self, fold_version: int | None = None,
                 fold_manifest: str | None = None) -> Snapshot:
        return self.run(snapshot_call(fold_version, fold_manifest))

    def subject(self, subject: str, as_of: str | None = None) -> SubjectRead:
        return self.run(subject_call(subject, as_of))

    def prose(self, revision: str) -> Prose:
        return self.run(prose_call(revision))

    def support(self, from_: str, to: str, as_of: str | None = None) -> SupportRead:
        return self.run(support_call(from_, to, as_of))

    def receipt(self, event: str) -> dict:
        return self.run(receipt_call(event))


class AsyncPublicClient:
    """The same calls over an async transport, for asyncio applications:
    `async (url, headers) -> (status, response headers, body bytes)`. The
    transport must send a GET with exactly `headers`, must not follow
    redirects and should not use a proxy taken from the environment."""

    def __init__(self, base_url: str, transport: AsyncTransport):
        self.base = normalize_base(base_url)
        self._send = transport

    async def run(self, call: Call[T]) -> T:
        status, headers, raw = await self._send(build_url(self.base, call), HEADERS)
        return parse(call, status, raw, headers)

    async def health(self) -> Health:
        return await self.run(health_call())

    async def snapshot(self, fold_version: int | None = None,
                       fold_manifest: str | None = None) -> Snapshot:
        return await self.run(snapshot_call(fold_version, fold_manifest))

    async def subject(self, subject: str, as_of: str | None = None) -> SubjectRead:
        return await self.run(subject_call(subject, as_of))

    async def prose(self, revision: str) -> Prose:
        return await self.run(prose_call(revision))

    async def support(self, from_: str, to: str, as_of: str | None = None) -> SupportRead:
        return await self.run(support_call(from_, to, as_of))

    async def receipt(self, event: str) -> dict:
        return await self.run(receipt_call(event))


# --------------------------------------------------------------------------
# Snapshot helpers
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class SubjectKey:
    kind: str
    namespace: str
    value: str


@dataclass(frozen=True)
class SubjectSummary:
    """One subject of a snapshot, for listing and lookup. `revision` is the
    current revision only for a `resolved` subject; a contested or bodiless
    subject has none, and none is invented."""

    subject: str
    state: str
    key: SubjectKey
    revision: Revision | None


def summarize_subjects(snapshot: Snapshot) -> tuple[SubjectSummary, ...]:
    """Subjects in the order the snapshot lists them, each with the subject
    key its Genesis signed. Raises `ProtocolError` if a subject has no
    Genesis row or a resolved subject's head has no served revision."""
    rows: dict[str, dict] = {}
    for row in snapshot.rows:
        if not isinstance(row, dict):
            raise ProtocolError("snapshot row is not an object")
        rows[bytes_hash(_field(row, "event", list), "row.event")] = row
    revisions = {r.id: r for r in snapshot.revisions}
    out = []
    for s in snapshot.subjects:
        if not isinstance(s, dict):
            raise ProtocolError("snapshot subject is not an object")
        subject = bytes_hash(_field(s, "subject", list), "subject")
        state = _field(s, "state", str)
        genesis = rows.get(subject)  # a Genesis event id is its subject id
        envelope = None if genesis is None else _field(genesis, "envelope", dict)
        if envelope is None or "Genesis" not in _field(envelope, "payload", dict):
            raise ProtocolError("subject has no Genesis row")
        k = _field(envelope, "subject_key", dict)
        key = SubjectKey(_field(k, "kind", str), _field(k, "namespace", str),
                         _field(k, "value", str))
        revision = None
        if state == "resolved":
            frontier = _field(s, "frontier", list)
            if len(frontier) != 1:
                raise ProtocolError("resolved subject without exactly one head")
            head = rows.get(bytes_hash(frontier[0], "frontier"))
            rid = None if head is None else _field(head, "revision", (list, type(None)))
            revision = None if rid is None else revisions.get(bytes_hash(rid, "row.revision"))
            if revision is None or revision.subject != subject:
                raise ProtocolError("resolved subject's head has no served revision")
        out.append(SubjectSummary(subject, state, key, revision))
    return tuple(out)
