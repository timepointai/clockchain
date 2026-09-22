#!/usr/bin/env python3
"""Offline, read-only evaluation of captured API certificates and external labels.

No generation, signing, ledger writes, database, or network access. Exit 0 PASS,
1 FAIL, 2 NOT RUN. A fixture proves only the checks named in its report.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path

SCHEMA = "cc.evidence-eval.v1"


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def evaluate(fixture):
    if fixture.get("schema") != SCHEMA:
        raise ValueError("unknown fixture schema")
    cases = fixture.get("cases", [])
    if not cases:
        return {"status": "NOT RUN", "reason": "empty case set", "denominator": 0}
    manifest = fixture["manifest"]
    for key in ("as_of", "filter_version", "ontology_sha256", "source", "captured_at"):
        if not manifest.get(key):
            raise ValueError("missing manifest field: " + key)
    if len({c["id"] for c in cases}) != len(cases):
        raise ValueError("duplicate case ids")
    findings = []
    for case in cases:
        response = case["response"]
        failures = []
        if response.get("filter_version") != manifest["filter_version"]:
            failures.append("filter_version mismatch")
        if not response.get("corpus_digest"):
            failures.append("missing corpus_digest")
        if response.get("evidence_scope") != "recorded_graph_feasibility":
            failures.append("missing evidence scope")
        if response.get("factual_verification") != "not_assessed":
            failures.append("unqualified factual verification")
        audit = response.get("audit", {})
        if audit.get("schema") != "cc.evidence-audit.v1":
            failures.append("missing audit schema")
        if not all(isinstance(audit.get(k), list) for k in ("absences", "contradictions")):
            failures.append("missing factor lists")
        if response.get("result") not in ("Supported", "Unsupported", "Contradicted"):
            failures.append("not a verdict")
        if response.get("verdict_policy") != "first_zero_in_factor_order":
            failures.append("missing governed verdict policy")
        for field, expected in case.get("expect", {}).items():
            actual = response.get(field)
            if field == "contradiction_count":
                actual = len(audit.get("contradictions", []))
            if actual != expected:
                failures.append(field + " differs from expected")
        findings.append({"id": case["id"], "status": "FAIL" if failures else "PASS",
                         "failures": failures, "corpus_digest": response.get("corpus_digest")})
    return {"status": "FAIL" if any(r["failures"] for r in findings) else "PASS",
            "fixture_sha256": digest(fixture), "denominator": len(cases),
            "integrity_scope": "API evidence contract only; no signature or ledger replay validation",
            "findings": findings, "quality": score(fixture, cases),
            "usefulness": usefulness(fixture, cases)}


def labeled(fixture, cases):
    registration = fixture.get("preregistration")
    if not registration:
        return None
    # Pin the exact externally prepared rubric and held-out case labels.
    if digest(registration["specification"]) != registration["sha256"]:
        raise ValueError("preregistration digest mismatch")
    labels = registration["specification"]["labels"]
    if set(labels) != {c["id"] for c in cases}:
        raise ValueError("labels must cover exactly the held-out cases")
    for label in labels.values():
        if not label.get("sources") or not label.get("reviewer"):
            raise ValueError("labels need sources and an external reviewer")
    return labels


def score(fixture, cases):
    labels = labeled(fixture, cases)
    if labels is None:
        return {"status": "NOT RUN", "reason": "no externally labeled preregistration"}
    correct = sum(c["response"]["result"] == labels[c["id"]]["expected_verdict"] for c in cases)
    return {"status": "MEASURED", "correct_verdicts": correct, "denominator": len(cases),
            "scope": "evidence-relative verdict agreement; not historical truth"}


def usefulness(fixture, cases):
    labels = labeled(fixture, cases)
    runs = fixture.get("consumer_runs")
    if labels is None or not runs:
        return {"status": "NOT RUN", "reason": "requires external labels and matched consumer runs"}
    arms = ("generation", "retrieval", "clockchain")
    if set(runs) != set(arms):
        raise ValueError("all three comparison arms are required")
    ids = {c["id"] for c in cases}
    results = {}
    for arm in arms:
        rows = runs[arm]
        if len(rows) != len(ids) or {r["id"] for r in rows} != ids:
            raise ValueError("comparison arms must use identical case sets")
        for row in rows:
            policy = fixture.get("model_policy", {}).get(row["model"])
            if not policy or policy.get("downstream_training_allowed") is not True:
                raise ValueError("model is not approved for downstream training")
            if not all(policy.get(k) for k in ("license_url", "terms_sha256", "reviewed_by", "reviewed_at")):
                raise ValueError("model approval lacks reviewed license evidence")
            if type(row["correct"]) is not bool or type(row["abstained"]) is not bool:
                raise ValueError("correct and abstained must be booleans")
            for field in ("latency_ms", "cost_usd"):
                value = row[field]
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise ValueError("cost and latency must be finite nonnegative numbers")
        answered = [r for r in rows if not r["abstained"]]
        results[arm] = {"denominator": len(rows), "answered": len(answered),
                        "correct_answers": sum(r["correct"] for r in answered),
                        "incorrect_answers": sum(not r["correct"] for r in answered),
                        "abstentions": len(rows) - len(answered),
                        "mean_latency_ms": sum(r["latency_ms"] for r in rows) / len(rows),
                        "cost_usd": sum(r["cost_usd"] for r in rows)}
    return {"status": "MEASURED", "arms": results,
            "scope": "externally graded observations; no significance or causal claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(json.loads(args.fixture.read_text()))
    except (OSError, ValueError, KeyError, TypeError) as error:
        result = {"status": "FAIL", "reason": str(error)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "NOT RUN": 2}[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
