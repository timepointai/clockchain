#!/usr/bin/env python3
"""Capture read-only feasibility queries using the browser's existing reader.

Input: JSON array of {id, subjects: [string, string], claim: TT-label}.
Output contains API certificates only, never model-generated claims.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import urllib.parse
import graphview
from evidence_eval import SCHEMA


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("queries", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--as-of", required=True)
    parser.add_argument("--node", default="http://127.0.0.1:18080")
    parser.add_argument("--ontology", type=Path, default=Path(__file__).resolve().parents[1] / "vendor/tt/taxonomy-v2.1.json")
    args = parser.parse_args()
    key = os.environ.get("CC_NODE_READ_KEY")
    if not key:
        parser.exit(2, "NOT RUN: CC_NODE_READ_KEY is unset\n")
    url = urllib.parse.urlsplit(args.node)
    if url.scheme != "https" or url.username or url.password or url.query or url.fragment:
        parser.error("node must be an HTTPS URL without credentials, query, or fragment")
    queries = json.loads(args.queries.read_text())
    if not queries or len({q["id"] for q in queries}) != len(queries):
        parser.error("queries must be nonempty with unique ids")
    for q in queries:
        if not isinstance(q["claim"], str) or not q["claim"] or len(q["subjects"]) != 2:
            parser.error("each query needs two subjects and a TT label string")
    cases = []
    for q in queries:
        response = graphview.feasibility(args.node.rstrip('/'), key, *q["subjects"], q["claim"], args.as_of)
        cases.append({"id": q["id"], "query": q, "response": response})
    versions = {c["response"]["filter_version"] for c in cases}
    if len(versions) != 1:
        parser.exit(1, "FAIL: filter version changed during capture\n")
    fixture = {"schema": SCHEMA, "manifest": {
        "source": args.node, "as_of": args.as_of,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "filter_version": versions.pop(),
        "ontology_sha256": hashlib.sha256(args.ontology.read_bytes()).hexdigest(),
        "ontology_scope": "local pinned artifact; not independently attested by this capture",
    }, "cases": cases}
    # Refuse to overwrite an earlier capture; private permissions from creation.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as out:
        json.dump(fixture, out, indent=2)
    print(f"captured {len(cases)} certificates; no ledger writes")


if __name__ == "__main__":
    main()
