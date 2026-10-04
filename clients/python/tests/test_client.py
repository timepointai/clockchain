"""Python client tests against the recorded synthetic fixtures.

Fixtures are what a real v1 node answered (minus `instance` on /health, the
one change G5 makes); see clients/fixtures/record.py. Every test feeds the
client recorded bytes, or recorded bytes with one field changed, and asserts
on a value the client could get wrong.

    python3 -m unittest discover -s clients/python/tests -t clients/python
"""

from __future__ import annotations

import asyncio
import copy
import http.server
import json
import os
import threading
import unittest
import unittest.mock
import urllib.parse
from pathlib import Path

from clockchain_public import client as cp
from clockchain_public import (
    AsyncPublicClient,
    ProtocolError,
    PublicApiError,
    PublicClient,
    bytes_hash,
    coordinate_from_date,
    coordinate_from_datetime,
    coordinate_from_seconds,
    coordinate_from_ticks,
    parse,
    seconds_from_coordinate,
    snapshot_call,
    subject_call,
    summarize_subjects,
    health_call,
    retry_after_seconds,
    support_call,
    ticks_from_coordinate,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "v1"
BASE = "https://gateway.invalid/prefix"


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text())


META = load("_meta")
A, B = META["entries"]


def key(url: str) -> tuple[str, tuple]:
    parts = urllib.parse.urlsplit(url)
    return parts.path, tuple(sorted(urllib.parse.parse_qsl(parts.query, strict_parsing=False)))


class Recorded:
    """Serves every fixture at `BASE + request.path?query`, recording calls.
    `override` replaces the answer for one fixture name."""

    def __init__(self, override: dict | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.routes = {}
        for f in META["fixtures"]:
            if f == "rate_limited":
                continue  # same URL as health; tests install it explicitly
            doc = load(f)
            if override and f in override:
                doc = override[f]
            req = doc["request"]
            url = BASE + req["path"] + (
                "?" + urllib.parse.urlencode(req["query"]) if req["query"] else "")
            self.routes[key(url)] = (doc["status"], doc.get("headers", {}),
                                     json.dumps(doc["body"]).encode())

    def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        try:
            return self.routes[key(url)]
        except KeyError:
            raise AssertionError(f"no fixture for {url}") from None


def client(override: dict | None = None) -> tuple[PublicClient, Recorded]:
    t = Recorded(override)
    return PublicClient(BASE, transport=t), t


def tampered(name: str, **changes) -> dict:
    doc = copy.deepcopy(load(name))
    for k, v in changes.items():
        if v is KeyError:
            del doc["body"][k]
        else:
            doc["body"][k] = v
    return {name: doc}


class FixtureSet(unittest.TestCase):
    def test_index_matches_files(self):
        on_disk = sorted(p.stem for p in FIXTURES.glob("*.json") if p.stem != "_meta")
        self.assertEqual(on_disk, META["fixtures"])
        self.assertEqual(len(on_disk), 18)

    def test_every_contract_route_has_a_fixture(self):
        routes = {load(f)["request"]["path"].split("/")[3] for f in META["fixtures"]}
        self.assertEqual(routes, {"health", "snapshot", "subjects", "revisions",
                                  "support", "receipts"})

    def test_recorded_health_is_public_shape(self):
        body = load("health")["body"]
        self.assertNotIn("instance", body)
        self.assertEqual(body["ledger"], "v1")


class Health(unittest.TestCase):
    def test_decodes_every_field(self):
        c, t = client()
        h = c.health()
        body = load("health")["body"]
        self.assertEqual(h.ledger, "v1")
        self.assertEqual(h.posture, body["posture"])
        self.assertEqual(h.fold_version.version, 1)
        self.assertEqual(h.fold_version.manifest, body["fold_version"]["manifest"])
        self.assertEqual(h.filter_version, body["filter_version"])
        self.assertEqual(h.curators, (A["author"],))
        self.assertEqual(h.max_hops, 4)
        self.assertEqual(h.semantic, "ready")
        self.assertEqual(t.calls[0][0], BASE + "/public/v1/health")

    def test_refuses_an_instance(self):
        c, _ = client(tampered("health", instance="00" * 32))
        with self.assertRaisesRegex(ProtocolError, "instance"):
            c.health()

    def test_refuses_a_legacy_ledger(self):
        c, _ = client(tampered("health", ledger="v0"))
        with self.assertRaisesRegex(ProtocolError, "ledger"):
            c.health()

    def test_refuses_a_missing_field(self):
        c, _ = client(tampered("health", filter_version=KeyError))
        with self.assertRaisesRegex(ProtocolError, "filter_version"):
            c.health()

    def test_refuses_a_bool_for_a_number(self):
        c, _ = client(tampered("health", max_hops=True))
        with self.assertRaisesRegex(ProtocolError, "max_hops"):
            c.health()


class Snapshot(unittest.TestCase):
    def test_decodes_revisions_to_hex(self):
        c, _ = client()
        s = c.snapshot()
        self.assertEqual(sorted(r.id for r in s.revisions),
                         sorted([A["revision"], B["revision"]]))
        byid = {r.id: r for r in s.revisions}
        self.assertEqual(byid[A["revision"]].subject, A["subject"])
        self.assertEqual(byid[A["revision"]].body, A["body_sha256"])
        self.assertEqual(byid[A["revision"]].asserted_time.coordinate,
                         A["asserted_time"]["coordinate"])
        self.assertEqual(byid[B["revision"]].asserted_time.precision, "year")
        self.assertEqual(len(s.subjects), 2)
        self.assertEqual(s.edges, [])
        self.assertEqual(s.commitment, load("snapshot")["body"]["commitment"])

    def test_pinned_fold_is_sent_and_checked(self):
        manifest = load("health")["body"]["fold_version"]["manifest"]
        c, t = client()
        s = c.snapshot(1, manifest)
        self.assertEqual(s.rule.fold_manifest, manifest)
        self.assertEqual(key(t.calls[0][0])[1],
                         (("fold_manifest", manifest), ("fold_version", "1")))

    def test_unsupported_fold_is_a_409(self):
        c, _ = client()
        with self.assertRaises(PublicApiError) as e:
            c.snapshot(1, "0" * 64)
        self.assertEqual((e.exception.status, e.exception.error),
                         (409, "unsupported_fold_version"))

    def test_answer_for_another_fold_is_refused(self):
        manifest = load("health")["body"]["fold_version"]["manifest"]
        doc = copy.deepcopy(load("snapshot_fold_pinned"))
        doc["body"]["rule"]["fold_manifest"] = "1" * 64
        c, _ = client({"snapshot_fold_pinned": doc})
        with self.assertRaisesRegex(ProtocolError, "fold"):
            c.snapshot(1, manifest)

    def test_half_a_fold_is_refused_before_sending(self):
        c, t = client()
        with self.assertRaises(ValueError):
            c.snapshot(fold_version=1)
        with self.assertRaises(ValueError):
            c.snapshot(fold_manifest="0" * 64)
        self.assertEqual(t.calls, [])

    def test_half_fold_answer_is_typed(self):
        doc = load("snapshot_fold_half")
        with self.assertRaises(PublicApiError) as e:
            parse(snapshot_call(), doc["status"], json.dumps(doc["body"]).encode())
        self.assertEqual(e.exception.error, "invalid_fold_request")


class Summaries(unittest.TestCase):
    def test_lists_each_subject_with_its_signed_key(self):
        c, _ = client()
        got = {s.subject: s for s in summarize_subjects(c.snapshot())}
        self.assertEqual(set(got), {A["subject"], B["subject"]})
        a = got[A["subject"]]
        self.assertEqual((a.key.kind, a.key.namespace, a.key.value),
                         tuple(A["subject_key"][k] for k in ("kind", "namespace", "value")))
        self.assertEqual(a.state, "resolved")
        self.assertEqual(a.revision.id, A["revision"])
        self.assertEqual(got[B["subject"]].revision.id, B["revision"])

    def test_missing_genesis_is_refused(self):
        doc = copy.deepcopy(load("snapshot"))
        a_event = list(bytes.fromhex(A["event"]))
        doc["body"]["rows"] = [r for r in doc["body"]["rows"] if r["event"] != a_event]
        c, _ = client({"snapshot": doc})
        with self.assertRaisesRegex(ProtocolError, "Genesis"):
            summarize_subjects(c.snapshot())

    def test_head_without_revision_is_refused(self):
        doc = copy.deepcopy(load("snapshot"))
        doc["body"]["revisions"] = doc["body"]["revisions"][:1]
        c, _ = client({"snapshot": doc})
        with self.assertRaisesRegex(ProtocolError, "no served revision"):
            summarize_subjects(c.snapshot())

    def test_contested_subject_has_no_revision(self):
        doc = copy.deepcopy(load("snapshot"))
        for s in doc["body"]["subjects"]:
            s["state"] = "contested"
        c, _ = client({"snapshot": doc})
        self.assertEqual([s.revision for s in summarize_subjects(c.snapshot())],
                         [None, None])


class Subject(unittest.TestCase):
    def test_current_reading(self):
        c, t = client()
        r = c.subject(A["subject"])
        self.assertTrue(r.known)
        self.assertEqual((r.state, r.visibility), ("resolved", "visible"))
        self.assertEqual(r.revision.id, A["revision"])
        self.assertEqual(r.revision.creating_event, A["event"])
        self.assertIsNone(r.as_of)
        # An absent as_of is omitted, not sent as an empty or "None" value.
        self.assertEqual(t.calls[0][0], f"{BASE}/public/v1/subjects/{A['subject']}")

    def test_as_of_after_assertion_is_visible(self):
        c, t = client()
        r = c.subject(A["subject"], as_of=B["asserted_time"]["coordinate"])
        self.assertEqual(r.visibility, "visible")
        self.assertEqual(r.as_of, B["asserted_time"]["coordinate"])
        self.assertIn("as_of=" + B["asserted_time"]["coordinate"], t.calls[0][0])

    def test_as_of_before_assertion_hides_the_revision(self):
        c, _ = client()
        r = c.subject(B["subject"], as_of=A["asserted_time"]["coordinate"])
        self.assertEqual(r.visibility, "after_as_of")
        self.assertIsNone(r.revision)
        self.assertTrue(r.known)

    def test_unknown_subject_is_a_read_not_an_error(self):
        c, _ = client()
        r = c.subject("ab" * 32)
        self.assertFalse(r.known)
        self.assertEqual(r.frontier, ())
        self.assertIsNone(r.revision)

    def test_identifiers_are_checked_before_sending(self):
        c, t = client()
        for bad in ("not-hex", "AB" * 32, "ab" * 31, "ab" * 33, 7):
            with self.assertRaises(ValueError):
                c.subject(bad)
        with self.assertRaises(ValueError):
            c.subject(A["subject"], as_of="1")
        self.assertEqual(t.calls, [])

    def test_bad_id_answer_is_typed(self):
        doc = load("subject_bad_id")
        with self.assertRaises(PublicApiError) as e:
            parse(subject_call(A["subject"]), doc["status"], json.dumps(doc["body"]).encode())
        self.assertEqual((e.exception.status, e.exception.error), (400, "invalid_subject_id"))

    def test_answer_for_another_subject_is_refused(self):
        other = copy.deepcopy(load("subject"))
        other["body"]["subject"] = B["subject"]
        c, _ = client({"subject": other})
        with self.assertRaisesRegex(ProtocolError, "another subject"):
            c.subject(A["subject"])

    def test_revision_of_another_subject_is_refused(self):
        doc = copy.deepcopy(load("subject"))
        doc["body"]["revision"]["subject"] = list(bytes.fromhex(B["subject"]))
        c, _ = client({"subject": doc})
        with self.assertRaisesRegex(ProtocolError, "another subject"):
            c.subject(A["subject"])

    def test_answer_for_another_as_of_is_refused(self):
        doc = copy.deepcopy(load("subject_as_of_after"))
        doc["body"]["as_of"] = None
        c, _ = client({"subject_as_of_after": doc})
        with self.assertRaisesRegex(ProtocolError, "as_of"):
            c.subject(A["subject"], as_of=B["asserted_time"]["coordinate"])

    def test_status_and_visibility_must_agree(self):
        doc = copy.deepcopy(load("subject"))
        doc["status"] = 404
        c, _ = client({"subject": doc})
        with self.assertRaises((ProtocolError, PublicApiError)):
            c.subject(A["subject"])
        doc = copy.deepcopy(load("subject_unknown"))
        doc["status"] = 200
        c, _ = client({"subject_unknown": doc})
        with self.assertRaisesRegex(ProtocolError, "disagree"):
            c.subject("ab" * 32)

    def test_hidden_subject_with_a_revision_is_refused(self):
        doc = copy.deepcopy(load("subject_as_of_before"))
        doc["body"]["revision"] = load("subject")["body"]["revision"]
        c, _ = client({"subject_as_of_before": doc})
        with self.assertRaisesRegex(ProtocolError, "not visible"):
            c.subject(B["subject"], as_of=A["asserted_time"]["coordinate"])

    def test_malformed_frontier_is_refused(self):
        c, _ = client(tampered("subject", frontier=["XYZ"]))
        with self.assertRaisesRegex(ProtocolError, "frontier"):
            c.subject(A["subject"])


class Prose(unittest.TestCase):
    def test_text_is_the_signed_body(self):
        c, t = client()
        p = c.prose(A["revision"])
        self.assertEqual(p.availability, "available")
        self.assertEqual(p.prose, "Synthetic fixture entry A. Not a historical claim.\n")
        self.assertEqual(p.revision.body, A["body_sha256"])
        self.assertEqual(t.calls[0][0], f"{BASE}/public/v1/revisions/{A['revision']}/prose")

    def test_unknown_revision_is_a_typed_404(self):
        c, _ = client()
        with self.assertRaises(PublicApiError) as e:
            c.prose("cd" * 32)
        self.assertEqual((e.exception.status, e.exception.error), (404, "revision_unknown"))

    def test_prose_for_another_revision_is_refused(self):
        doc = copy.deepcopy(load("prose"))
        doc["body"]["revision"]["id"] = list(bytes.fromhex(B["revision"]))
        c, _ = client({"prose": doc})
        with self.assertRaisesRegex(ProtocolError, "another revision"):
            c.prose(A["revision"])

    def test_availability_must_match_prose(self):
        c, _ = client(tampered("prose", availability="unavailable"))
        with self.assertRaisesRegex(ProtocolError, "disagree"):
            c.prose(A["revision"])


class Support(unittest.TestCase):
    def test_unsupported_with_reason(self):
        c, t = client()
        s = c.support(A["subject"], B["subject"])
        self.assertFalse(s.supported)
        self.assertEqual(s.path, ())
        self.assertEqual([r.code for r in s.reasons], ["no_current_support_path"])
        self.assertEqual((s.from_, s.to), (A["subject"], B["subject"]))
        self.assertEqual(key(t.calls[0][0])[1],
                         (("from", A["subject"]), ("to", B["subject"])))

    def test_as_of_is_sent_and_echoed(self):
        c, _ = client()
        s = c.support(A["subject"], B["subject"], as_of=B["asserted_time"]["coordinate"])
        self.assertEqual(s.as_of, B["asserted_time"]["coordinate"])

    def test_answer_for_another_as_of_is_refused(self):
        c, _ = client(tampered("support_as_of", as_of=None))
        with self.assertRaisesRegex(ProtocolError, "as_of"):
            c.support(A["subject"], B["subject"], as_of=B["asserted_time"]["coordinate"])

    def test_swapped_endpoints_are_refused(self):
        c, _ = client(tampered("support", **{"from": B["subject"], "to": A["subject"]}))
        with self.assertRaisesRegex(ProtocolError, "another from"):
            c.support(A["subject"], B["subject"])

    def test_supported_verdict_decodes_its_path(self):
        doc = copy.deepcopy(load("support"))
        edge = list(range(32))
        doc["body"]["support"] = {"Supported": {"path": [edge], "excluded": []}}
        c, _ = client({"support": doc})
        s = c.support(A["subject"], B["subject"])
        self.assertTrue(s.supported)
        self.assertEqual(s.path, (bytes(range(32)).hex(),))

    def test_unknown_verdict_is_refused(self):
        c, _ = client(tampered("support", support={"Contradicted": {}}))
        with self.assertRaisesRegex(ProtocolError, "verdict"):
            c.support(A["subject"], B["subject"])

    def test_missing_endpoint_answer_is_typed(self):
        doc = load("support_missing_to")
        with self.assertRaises(PublicApiError) as e:
            parse(support_call(A["subject"], B["subject"]), doc["status"],
                  json.dumps(doc["body"]).encode())
        self.assertEqual(e.exception.error, "invalid_support_query")


class Errors(unittest.TestCase):
    def test_invalid_query_is_typed(self):
        doc = load("invalid_query")
        with self.assertRaises(PublicApiError) as e:
            parse(snapshot_call(), doc["status"], json.dumps(doc["body"]).encode())
        self.assertEqual((e.exception.status, e.exception.error), (400, "invalid_query"))

    def test_rate_limited_carries_retry_after(self):
        # A real 429 recorded from cc-gateway at one request a minute.
        doc = load("rate_limited")
        with self.assertRaises(PublicApiError) as e:
            parse(health_call(), doc["status"], json.dumps(doc["body"]).encode(),
                  doc["headers"])
        self.assertEqual((e.exception.status, e.exception.error), (429, "rate_limited"))
        self.assertEqual(e.exception.retry_after, int(doc["headers"]["retry-after"]))
        self.assertGreater(e.exception.retry_after, 0)

    def test_rate_limited_through_the_client(self):
        doc = load("rate_limited")
        c, _ = client({"health": doc})
        with self.assertRaises(PublicApiError) as e:
            c.health()
        self.assertEqual(e.exception.retry_after, int(doc["headers"]["retry-after"]))

    def test_retry_after_forms(self):
        self.assertEqual(retry_after_seconds({"Retry-After": "7"}), 7)
        self.assertEqual(retry_after_seconds({"retry-after": " 0 "}), 0)
        self.assertEqual(retry_after_seconds({"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}), 0)
        for bad in (None, {}, {"retry-after": "-1"}, {"retry-after": "soon"},
                    {"retry-after": "1.5"}, {"retry-after": "\u0661"}):
            self.assertIsNone(retry_after_seconds(bad), bad)
        # A refusal without the header has no retry_after.
        with self.assertRaises(PublicApiError) as e:
            parse(health_call(), 429, b'{"error":"rate_limited"}')
        self.assertIsNone(e.exception.retry_after)

    def test_receipt_is_404_until_g4(self):
        c, _ = client()
        with self.assertRaises(PublicApiError) as e:
            c.receipt(A["event"])
        self.assertEqual((e.exception.status, e.exception.error), (404, "no_such_route"))

    def test_fail_closed_on_bad_bodies(self):
        for status, raw in ((200, b"<html>"), (200, b"[]"), (503, b"{}"), (502, b"")):
            with self.assertRaises(ProtocolError):
                parse(snapshot_call(), status, raw)

    def test_bytes_hash_is_strict(self):
        self.assertEqual(bytes_hash([0] * 32), "00" * 32)
        for bad in ([0] * 31, [256] + [0] * 31, [True] + [0] * 31, "00" * 32, None):
            with self.assertRaises(ProtocolError):
                bytes_hash(bad)


class Requests(unittest.TestCase):
    def test_every_request_carries_only_accept(self):
        c, t = client()
        c.health(), c.snapshot(), c.subject(A["subject"]), c.prose(A["revision"])
        c.support(A["subject"], B["subject"])
        self.assertEqual(len(t.calls), 5)
        for _, headers in t.calls:
            self.assertEqual(headers, {"Accept": "application/json"})

    def test_base_url_rules(self):
        self.assertEqual(PublicClient("https://h.invalid/").base, "https://h.invalid")
        self.assertEqual(PublicClient("http://h.invalid:8080/p/").base,
                         "http://h.invalid:8080/p")
        for bad in ("ftp://h.invalid", "h.invalid", "https://u:p@h.invalid",
                    "https://h.invalid/?q=1", "https://h.invalid/#f"):
            with self.assertRaises(ValueError):
                PublicClient(bad)


class _Handler(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_GET(self):  # noqa: N802
        _Handler.seen.append((self.command, self.path, dict(self.headers)))
        if self.path.endswith("/snapshot"):
            body = b'{"error":"rate_limited"}'
            self.send_response(429)
            self.send_header("Retry-After", "7")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.endswith("/health"):
            self.send_response(302)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        body = json.dumps(load("subject")["body"]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class RealTransport(unittest.TestCase):
    """The default urllib transport against a loopback HTTP server."""

    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        _Handler.seen.clear()

    def test_get_without_credentials(self):
        r = PublicClient(self.base).subject(A["subject"])
        self.assertEqual(r.revision.id, A["revision"])
        (method, path, headers), = _Handler.seen
        self.assertEqual((method, path), ("GET", f"/public/v1/subjects/{A['subject']}"))
        self.assertNotIn("authorization", {k.lower() for k in headers})
        self.assertNotIn("cookie", {k.lower() for k in headers})

    def test_retry_after_reaches_the_error(self):
        with self.assertRaises(PublicApiError) as e:
            PublicClient(self.base).snapshot()
        self.assertEqual((e.exception.status, e.exception.retry_after), (429, 7))

    def test_proxy_environment_is_ignored(self):
        # A proxy from the environment would see (and here, break) the request.
        dead = "http://127.0.0.1:9"
        env = {"HTTP_PROXY": dead, "http_proxy": dead, "ALL_PROXY": dead,
               "all_proxy": dead, "NO_PROXY": "", "no_proxy": ""}
        with unittest.mock.patch.dict(os.environ, env):
            r = PublicClient(self.base).subject(A["subject"])
        self.assertEqual(r.revision.id, A["revision"])
        self.assertEqual(len(_Handler.seen), 1)

    def test_redirect_is_not_followed(self):
        with self.assertRaises(ProtocolError):
            PublicClient(self.base).health()
        self.assertEqual([p for _, p, _ in _Handler.seen], ["/public/v1/health"])


class Async(unittest.TestCase):
    def test_same_decoding(self):
        t = Recorded()

        async def send(url, headers):
            return t(url, headers)

        async def go():
            c = AsyncPublicClient(BASE, send)
            return await c.subject(A["subject"]), await c.support(A["subject"], B["subject"])

        r, s = asyncio.run(go())
        self.assertEqual(r.revision.id, A["revision"])
        self.assertFalse(s.supported)
        self.assertEqual([h for _, h in t.calls], [dict(cp.HEADERS)] * 2)


class Coordinates(unittest.TestCase):
    def test_publisher_worked_example(self):
        # docs/PUBLISHER-V1.md, "Asserted time", --asserted-time 1901-02-03
        c = coordinate_from_date(1901, 2, 3)
        self.assertEqual(c, "7fffffffffffffffffffffffffffffffffffffff45f44a400000000000000000")
        self.assertEqual(seconds_from_coordinate(c), -3_121_329_600)

    def test_agrees_with_the_rust_publisher(self):
        # _meta.json holds what cc-publisher (Rust) encoded for the fixtures.
        self.assertEqual(coordinate_from_date(1901, 2, 3), A["asserted_time"]["coordinate"])
        self.assertEqual(coordinate_from_date(1950), B["asserted_time"]["coordinate"])

    def test_cc_publisher_anchors(self):
        # crates/cc-publisher/tests/v1_offline.rs, the asserted-time anchors:
        # whole seconds from J2000.0 for each calendar input.
        anchors = [
            ((1901, 2, 3), -3_121_329_600), ((1901, 2), -3_121_502_400),
            ((1901,), -3_124_180_800), ((1970, 1, 1), -946_728_000),
            ((2000, 1, 1), -43_200), ((2000, 2, 29), 5_054_400),
            ((1600, 2, 29), -12_617_726_400), ((0,), -63_113_947_200),
            ((-1, 12, 31), -63_114_033_600), ((-43, 3, 15), -64_464_552_000),
            ((-9999,), -378_651_844_800), ((9999, 12, 31), 252_455_486_400),
        ]
        for date, seconds in anchors:
            self.assertEqual(seconds_from_coordinate(coordinate_from_date(*date)), seconds,
                             date)

    def test_every_year_against_a_day_count(self):
        # Walk -9999..9999 one year at a time with an independent day count.
        jan1 = -378_651_844_800  # -9999-01-01 (anchor above)
        for year in range(-9999, 10000):
            self.assertEqual(seconds_from_coordinate(coordinate_from_date(year)), jan1, year)
            leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
            self.assertEqual(seconds_from_coordinate(coordinate_from_date(year, 12, 31)),
                             jan1 + (364 + leap) * 86_400, year)
            jan1 += (365 + leap) * 86_400

    def test_epoch_and_order(self):
        self.assertEqual(coordinate_from_seconds(0), "80" + "00" * 31)
        self.assertEqual(coordinate_from_date(2000, 1, 1),
                         coordinate_from_seconds(-43_200))
        dates = [(-43, 3, 15), (0, 1, 1), (1, 1, 1), (1600, 2, 29), (1969, 7, 20),
                 (2000, 1, 2), (2026, 10, 2)]
        coords = [coordinate_from_date(*d) for d in dates]
        self.assertEqual(coords, sorted(coords))

    def test_malformed_coordinates_are_refused(self):
        good = coordinate_from_date(1901, 2, 3)  # has hex letters, so upper() differs
        self.assertEqual(ticks_from_coordinate(good), -3_121_329_600 << 64)
        for bad in (good.upper(), good[:-1], good + "0", " " + good[1:],
                    "80 " + "00" * 30 + "0", "g" * 64, 7):
            with self.assertRaises(ValueError):
                ticks_from_coordinate(bad)

    def test_round_trips(self):
        for raw in (0, 1, -1, (1 << 255) - 1, -(1 << 255), 12345 << 64):
            self.assertEqual(ticks_from_coordinate(coordinate_from_ticks(raw)), raw)
        with self.assertRaises(ValueError):
            coordinate_from_ticks(1 << 255)

    def test_datetime_and_calendar_errors(self):
        import datetime as dt
        when = dt.datetime(1969, 7, 20, 20, 17, 40, tzinfo=dt.timezone.utc)
        self.assertEqual(seconds_from_coordinate(coordinate_from_datetime(when)),
                         seconds_from_coordinate(coordinate_from_date(1969, 7, 20)) + 73060)
        with self.assertRaises(ValueError):
            coordinate_from_datetime(dt.datetime(2000, 1, 1))
        for bad in ((1900, 2, 29), (2001, 13, 1), (2001, 4, 31), (10000, 1, 1)):
            with self.assertRaises(ValueError):
                coordinate_from_date(*bad)
        self.assertTrue(coordinate_from_date(2000, 2, 29))


if __name__ == "__main__":
    unittest.main()
