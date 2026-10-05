#!/usr/bin/env python3
"""Record the synthetic fixtures the v1 public clients are tested against.

Runs a real `cc-node` in v1 mode over a throwaway local PostgreSQL database,
admits two synthetic Genesis entries with `cc-publisher v1`, starts the G5
`cc-gateway` in front of that node (only the gateway holds the node's read
key), and records every route of the `/public/v1` contract through it into
`clients/fixtures/v1/*.json`: request, status, the response headers a client
acts on (`retry-after`), and body. `rate_limited.json` is a real 429 from a
second gateway allowed one request a minute. The main node runs without
`CC_V1_NODE_SEED`, so its receipts route answers `404 no_receipt`;
`receipt.json` is a real 200 from a second node, given a synthetic seed, that
admits the same entry A. `legacy-probes.json` records what
the node itself answers on the legacy routes the audited consumers call.

`--node-only` records from the node's read routes minus `instance` instead,
the one change G5 makes, without a gateway (and without the 429 fixture).
`--check` records into a temporary directory and fails on any difference from
the committed fixtures except values that differ between runs: `/health`'s
`build`, `_meta.json`'s `source`, the exact `retry-after` seconds (which must be
a positive whole number), and a receipt's `received_at` with its signed bytes
and digest (the digest must be the SHA-256 of the bytes).

Everything is synthetic. The curator seed and the instance are SHA-256 hashes
of public labels in this file, the node credentials are random per run and
never written, and the database is dropped on exit. Nothing here can reach a
deployed node: the node it starts listens on loopback and the URL is built
from a local port.

    cargo build -p cc-node --bin cc-node -p cc-publisher --bin cc-publisher \\
        -p cc-gateway --bin cc-gateway
    python3 clients/fixtures/record.py

Environment: `FIXTURE_ADMIN_URL` (default
`postgres://clockchain:clockchain@localhost:5432/clockchain`) names a local
database the recorder may `CREATE DATABASE` from; `CARGO_TARGET_DIR` locates
the binaries.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OUT = HERE / "v1"

# Public labels; their SHA-256 is the synthetic seed and instance.
CURATOR_LABEL = b"clockchain g7 synthetic fixture curator seed"
# The node's receipt-signing seed (CC_V1_NODE_SEED) for the receipts fixture.
NODE_SEED_LABEL = b"clockchain g7 synthetic fixture node receipt seed"
INSTANCE_LABEL = b"clockchain g7 synthetic fixture instance"
NONCE_LABELS = (b"clockchain g7 synthetic nonce a", b"clockchain g7 synthetic nonce b")

# Two synthetic entries. Neither names a real person or a real record.
ENTRIES = (
    {
        "kind": "conflict-and-warfare",
        "namespace": "g7.synthetic",
        "value": "fixture-a",
        "body": "Synthetic fixture entry A. Not a historical claim.\n",
        "asserted": "1901-02-03",
    },
    {
        "kind": "conflict-and-warfare",
        "namespace": "g7.synthetic",
        "value": "fixture-b",
        "body": "Synthetic fixture entry B. Not a historical claim.\n",
        "asserted": "1950",
    },
)

ZERO = "0" * 64
LOCAL_ADMIN = "postgres://clockchain:clockchain@localhost:5432/clockchain"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def psql(admin_url: str, sql: str) -> None:
    subprocess.run(["psql", admin_url, "-v", "ON_ERROR_STOP=1", "-qc", sql], check=True)


# Response headers a client acts on; recorded when present.
KEPT_HEADERS = ("retry-after",)
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def http_full(url: str, token: str | None = None) -> tuple[int, dict, object]:
    """GET without any proxy: (status, kept headers, JSON body)."""
    req = urllib.request.Request(url, method="GET")
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _DIRECT.open(req, timeout=30) as r:
            status, headers, raw = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, headers, raw = e.code, e.headers, e.read()
    kept = {h: headers[h] for h in KEPT_HEADERS if headers.get(h) is not None}
    return status, kept, json.loads(raw)


def http(url: str, token: str | None = None) -> tuple[int, object]:
    status, _, body = http_full(url, token)
    return status, body


def wait_up(url: str, proc: subprocess.Popen, name: str) -> None:
    for _ in range(300):
        if proc.poll() is not None:
            raise SystemExit(f"{name} exited with {proc.returncode}")
        try:
            if http(url)[0] == 200:
                return
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(0.1)
    raise SystemExit(f"{name} did not become ready")


def publish(pub: Path, work: Path, base: str, env: dict, instance: str,
            entries: tuple = ENTRIES) -> list[dict]:
    seed = work / "curator.seed"
    seed.write_text(sha(CURATOR_LABEL) + "\n")
    seed.chmod(0o600)
    out = []
    for entry, nonce in zip(entries, NONCE_LABELS):
        body = work / f"{entry['value']}.txt"
        body.write_text(entry["body"])
        body.chmod(0o600)
        d = work / entry["value"]
        subprocess.run(
            [pub, "v1", "genesis", "--key", seed, "--instance", instance,
             "--kind", entry["kind"], "--namespace", entry["namespace"],
             "--value", entry["value"], "--body", body,
             "--asserted-time", entry["asserted"], "--nonce", sha(nonce),
             "--out", d],
            check=True, stdout=subprocess.DEVNULL,
        )
        subprocess.run([pub, "v1", "submit", "--node", base, "--dir", d],
                       check=True, env=env, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        out.append(json.loads((d / "preview.json").read_text()))
    return out


def cases(a: dict, b: dict) -> list[tuple[str, str, dict]]:
    """(fixture name, public path, query). The node path is derived from it."""
    return [
        ("health", "/public/v1/health", {}),
        ("snapshot", "/public/v1/snapshot", {}),
        ("snapshot_fold_pinned", "/public/v1/snapshot",
         {"fold_version": "1", "fold_manifest": "<manifest>"}),
        ("snapshot_fold_mismatch", "/public/v1/snapshot",
         {"fold_version": "1", "fold_manifest": ZERO}),
        ("snapshot_fold_half", "/public/v1/snapshot", {"fold_version": "1"}),
        ("subject", f"/public/v1/subjects/{a['subject']}", {}),
        ("subject_as_of_after", f"/public/v1/subjects/{a['subject']}",
         {"as_of": b["asserted_time"]["coordinate"]}),
        ("subject_as_of_before", f"/public/v1/subjects/{b['subject']}",
         {"as_of": a["asserted_time"]["coordinate"]}),
        ("subject_unknown", f"/public/v1/subjects/{'ab' * 32}", {}),
        ("subject_bad_id", "/public/v1/subjects/not-hex", {}),
        ("prose", f"/public/v1/revisions/{a['revision']}/prose", {}),
        ("prose_unknown", f"/public/v1/revisions/{'cd' * 32}/prose", {}),
        ("support", "/public/v1/support",
         {"from": a["subject"], "to": b["subject"]}),
        ("support_as_of", "/public/v1/support",
         {"from": a["subject"], "to": b["subject"],
          "as_of": b["asserted_time"]["coordinate"]}),
        ("support_missing_to", "/public/v1/support", {"from": a["subject"]}),
        ("invalid_query", "/public/v1/snapshot", {"unexpected": "1"}),
        # The main node runs without CC_V1_NODE_SEED, so it holds no receipt.
        ("receipt_no_receipt", f"/public/v1/receipts/{a['event']}", {}),
    ]


# Legacy routes the audited consumers call today (docs/INTEGRATIONS.md), with
# the credential style each sends. `read` is the node's real read key.
LEGACY_PROBES = (
    ("GET", "/api/v1/search?q=synthetic", "x-service-key"),
    ("GET", "/api/v1/moments/synthetic/path", "none"),
    ("GET", "/api/v1/browse", "x-service-key"),
    ("GET", "/api/v1/graph/neighbors/synthetic/path", "x-service-key"),
    ("GET", "/api/v1/figures/search?q=synthetic", "x-service-key"),
    ("POST", "/api/v1/figures/resolve/batch", "x-service-key"),
    ("POST", "/api/v1/index", "admin-bearer-unknown"),
    ("GET", "/api/v1/search?q=synthetic", "read"),
    ("GET", "/v1/entities/1?as_of=0", "read"),
    ("GET", "/mcp/", "none"),
    ("GET", "/health", "none"),
)


def probe_legacy(base: str, read_key: str, out_dir: Path) -> None:
    """What a v1 node answers on the routes consumers still call."""
    out = []
    for method, path, cred in LEGACY_PROBES:
        req = urllib.request.Request(base + path, method=method,
                                     data=b"{}" if method == "POST" else None)
        if cred == "read":
            req.add_header("Authorization", f"Bearer {read_key}")
        elif cred == "x-service-key":
            req.add_header("X-Service-Key", secrets.token_hex(32))
        elif cred == "admin-bearer-unknown":
            req.add_header("Authorization", f"Bearer {secrets.token_hex(32)}")
        try:
            with _DIRECT.open(req, timeout=30) as r:
                status, body = r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            status, body = e.code, json.loads(e.read())
        out.append({"method": method, "path": path, "credential": cred,
                    "status": status,
                    "error": body.get("error"), "ledger": body.get("ledger")})
    doc = {"schema": "cc.clients.legacy-probes.v1", "probes": out}
    (out_dir / "legacy-probes.json").write_text(json.dumps(doc, indent=2) + "\n")


def record(base: str, token: str | None, prefix: str, previews: list[dict],
           out: Path, extra: dict[str, dict] | None = None) -> None:
    status, health = http(f"{base}{prefix}/health")
    assert status == 200, health
    manifest = health["fold_version"]["manifest"]
    out.mkdir(parents=True, exist_ok=True)
    for old in out.glob("*.json"):
        old.unlink()
    index = []
    for name, public_path, query in cases(*previews):
        query = {k: (manifest if v == "<manifest>" else v) for k, v in query.items()}
        rest = public_path.removeprefix("/public/v1")
        if prefix:
            path = prefix + rest
        elif rest == "/health":
            path = "/health"
        else:
            path = "/v1" + rest
        url = base + path + ("?" + urllib.parse.urlencode(query) if query else "")
        auth = None if rest == "/health" else token
        status, headers, body = http_full(url, auth)
        if not prefix and rest == "/health":
            # The one transformation G5 applies to node read JSON.
            body.pop("instance")
        doc = {"request": {"method": "GET", "path": public_path, "query": query},
               "status": status, "headers": headers, "body": body}
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        index.append(name)
    for name, doc in sorted((extra or {}).items()):
        (out / f"{name}.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
        index.append(name)
    meta = {
        "schema": "cc.clients.fixtures.v1",
        "source": "gateway" if prefix else "node-minus-instance",
        "entries": [
            {k: p[k] for k in ("event", "subject", "revision", "author", "body_sha256",
                               "asserted_time", "subject_key")}
            for p in previews
        ],
        "fixtures": sorted(index),
    }
    (out / "_meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")


@contextlib.contextmanager
def gateway(binary: Path, node: str, read_key: str, rate: int):
    """A cc-gateway in front of `node`, holding its read key; yields its base."""
    port = free_port()
    env = {
        "PATH": os.environ["PATH"],
        "CC_GATEWAY_NODE_URL": node,
        "CC_GATEWAY_READ_KEY": read_key,
        "CC_GATEWAY_RATE_PER_MINUTE": str(rate),
        "PORT": str(port),
    }
    proc = subprocess.Popen([binary], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        base = f"http://127.0.0.1:{port}"
        wait_up(f"{base}/public/v1/health", proc, "cc-gateway")
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def rate_limited_answer(binary: Path, node: str, read_key: str) -> dict:
    """A real 429: a gateway allowing one request a minute, asked twice.
    `wait_up` spends the one token on /health, so the next read is limited."""
    with gateway(binary, node, read_key, 1) as gw:
        status, headers, body = http_full(f"{gw}/public/v1/health")
    assert status == 429, (status, body)
    return {"request": {"method": "GET", "path": "/public/v1/health", "query": {}},
            "status": status, "headers": headers, "body": body}


@contextlib.contextmanager
def v1_node(node_bin: Path, pub: Path, admin: str, work: Path, node_seed: str | None = None):
    """A provisioned, serving v1 node over its own throwaway database.
    Yields (base URL, write key, read key, instance)."""
    db = f"cc_g7_fixture_{os.getpid()}_{secrets.token_hex(4)}"
    db_url = urllib.parse.urlunsplit(urllib.parse.urlsplit(admin)._replace(path=f"/{db}"))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    instance = sha(INSTANCE_LABEL)
    api_key, read_key = secrets.token_hex(32), secrets.token_hex(32)
    work.mkdir(parents=True, exist_ok=True)
    seed = work / "pub.seed"
    seed.write_text(sha(CURATOR_LABEL) + "\n")
    seed.chmod(0o600)
    curator = subprocess.run([pub, "v1", "pubkey", "--key", seed], check=True,
                             capture_output=True, text=True).stdout.strip()
    env = {
        "PATH": os.environ["PATH"],
        "CC_NODE_LEDGER": "v1",
        "DATABASE_URL": db_url,
        "CC_V1_INSTANCE": instance,
        "CC_V1_CURATORS": curator,
        "CC_V1_MAX_HOPS": "4",
        "CC_NODE_API_KEY": api_key,
        "CC_NODE_READ_KEY": read_key,
        "CC_NODE_POSTURE": "live",
        "PORT": str(port),
    }
    if node_seed is not None:
        env["CC_V1_NODE_SEED"] = node_seed
    psql(admin, f"CREATE DATABASE {db}")
    proc = None
    try:
        subprocess.run([node_bin, "provision-v1"], check=True, env=env,
                       stdout=subprocess.DEVNULL)
        proc = subprocess.Popen([node_bin, "serve"], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_up(f"{base}/ready", proc, "cc-node")
        yield base, api_key, read_key, instance
    finally:
        if proc is not None:
            proc.terminate()
            proc.wait(timeout=10)
        psql(admin, f"DROP DATABASE IF EXISTS {db}")


def receipt_answer(node_bin: Path, pub: Path, admin: str, work: Path,
                   gateway_bin: Path | None) -> dict:
    """A real 200 receipt: a second node with a synthetic CC_V1_NODE_SEED
    admits the same deterministic entry A, which it then receipts."""
    with v1_node(node_bin, pub, admin, work, sha(NODE_SEED_LABEL)) as (base, key, read, inst):
        (a,) = publish(pub, work, base, {"PATH": os.environ["PATH"], "CC_NODE_API_KEY": key},
                       inst, ENTRIES[:1])
        path = f"/public/v1/receipts/{a['event']}"
        if gateway_bin is None:
            status, headers, body = http_full(f"{base}/v1/receipts/{a['event']}", read)
        else:
            with gateway(gateway_bin, base, read, 100_000) as gw:
                status, headers, body = http_full(gw + path)
    assert status == 200, (status, body)
    return {"request": {"method": "GET", "path": path, "query": {}},
            "status": status, "headers": headers, "body": body}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--node-only", action="store_true",
                    help="record from the node's read routes minus instance, without cc-gateway "
                         "(no rate_limited fixture)")
    ap.add_argument("--check", action="store_true",
                    help="record into a temporary directory and fail on any difference from "
                         "the committed fixtures except values that vary between runs")
    args = ap.parse_args()
    scratch = tempfile.TemporaryDirectory() if args.check else None
    root = Path(scratch.name) if scratch else HERE

    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug"
    node_bin, pub = target / "cc-node", target / "cc-publisher"
    gateway_bin = None if args.node_only else target / "cc-gateway"
    for b in (node_bin, pub, gateway_bin):
        if b is not None and not b.exists():
            raise SystemExit(f"missing {b}; build cc-node, cc-publisher and cc-gateway first")

    admin = os.environ.get("FIXTURE_ADMIN_URL", LOCAL_ADMIN)
    host = urllib.parse.urlsplit(admin).hostname
    if host not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit("FIXTURE_ADMIN_URL must name a local PostgreSQL")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        extra = {"receipt": receipt_answer(node_bin, pub, admin, work / "receipt", gateway_bin)}
        with v1_node(node_bin, pub, admin, work / "main") as (base, key, read, inst):
            previews = publish(pub, work / "main", base,
                               {"PATH": os.environ["PATH"], "CC_NODE_API_KEY": key}, inst)
            probe_legacy(base, read, root)
            if gateway_bin is None:
                record(base, read, "", previews, root / "v1", extra)
            else:
                with gateway(gateway_bin, base, read, 100_000) as gw:
                    extra["rate_limited"] = rate_limited_answer(gateway_bin, base, read)
                    record(gw, None, "/public/v1", previews, root / "v1", extra)
    if scratch is None:
        print(f"recorded {len(list(OUT.glob('*.json'))) - 1} fixtures into {OUT.relative_to(ROOT)}")
        return 0
    with scratch:
        return compare(Path(scratch.name))


def _without_build(path: Path) -> object:
    doc = json.loads(path.read_text())
    if path.name == "health.json":
        doc["body"].pop("build", None)
    if path.name == "receipt.json":
        _stable_receipts(doc["body"])
    after = doc.get("headers", {}).get("retry-after") if isinstance(doc, dict) else None
    if after is not None:
        # The wait depends on timing; it must be a positive whole number.
        doc["headers"]["retry-after"] = "positive" if after.isdigit() and int(after) > 0 else after
    if path.name == "_meta.json":
        doc.pop("source", None)
    return doc


def _stable_receipts(body: dict) -> None:
    """A receipt records when the node saw the event (`received_at`, Unix
    microseconds), so its signed bytes and digest differ on every run. Check
    them instead: the digest is the SHA-256 of the bytes and the time is a
    positive whole number. Anything else is left to differ."""
    for r in body.get("receipts", []):
        raw, digest, at = r.get("receipt"), r.get("receipt_digest"), r.get("received_at")
        try:
            ok = (hashlib.sha256(bytes.fromhex(raw)).hexdigest() == digest
                  and type(at) is int and at > 0)
        except (TypeError, ValueError):
            ok = False
        if ok:
            r["receipt"], r["receipt_digest"], r["received_at"] = "bytes", "sha256", "positive"


def compare(fresh: Path) -> int:
    """0 when the fresh recording equals the committed one (build aside)."""
    names = sorted(p.name for p in OUT.glob("*.json"))
    fresh_names = sorted(p.name for p in (fresh / "v1").glob("*.json"))
    diffs = [] if names == fresh_names else [f"fixture set differs: {names} != {fresh_names}"]
    for n in set(names) & set(fresh_names):
        if _without_build(OUT / n) != _without_build(fresh / "v1" / n):
            diffs.append(f"v1/{n} differs")
    if _without_build(HERE / "legacy-probes.json") != \
            _without_build(fresh / "legacy-probes.json"):
        diffs.append("legacy-probes.json differs")
    for d in diffs:
        print(f"record.py --check: {d}", file=sys.stderr)
    if not diffs:
        print(f"record.py --check: {len(names) - 1} fixtures reproduce")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
