#!/usr/bin/env python3
"""Probe (a′): trace an abstention end to end, on a DECLARED calibration input.

    python3 ops/abstain-trace.py

Telemetry's amended probe: one calibration input, **labeled as such**, run
through the whole pipeline — classifier -> parse -> validate -> admission
verdict — showing `abstain: true` reaching the would-store decision. It is
**never minted into the chain as a historical claim.**

## Why this input is a fixture and says so

`CALIBRATION_MOMENT` below is written by hand. It is deliberately
under-determined: a real record fragment shape, with no actors, no outcome, and
no institution named. Nothing in the chain looks like this, because everything
in the chain was generated to be classifiable.

An earlier version of this experiment used four moments, two of which I had
quietly shortened myself, under a comment claiming nothing was engineered. That
comment was false and the run measured my prompt rather than the pipeline. The
distinction telemetry drew is the one that matters and it is the whole reason
this file exists: **a fixture is a fabrication only when it claims to be the
corpus. A declared fixture is a probe.** So this one is declared, in the code,
in the output, and in anything the output is pasted into.

## What it does NOT show

Not a rate. Not evidence that the corpus contains abstentions — it does not:
**0 of 322 stored claims abstain**, and that count is true and is not to be
"fixed". See the caveat printed at the end of every run.
"""

import json
import os
import re
import subprocess
import sys
import urllib.request

CC = os.path.expanduser("~/dev/GitHub/timepointai/clockchain")
BUNDLE = f"{CC}/vendor/tt/taxonomy-v2.1.json"
MIGRATOR = f"{CC}/target/debug/cc-migrator"
MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
# The 600-perm file first, the environment second — deliberately that order.
# A stale OPENROUTER_API_KEY was exported in this shell and returned 401 while a
# working key sat in the file; preferring the env var meant the wrong credential
# won silently. The file is the one that was verified.
KEY = (open(os.path.expanduser("~/.clockchain/orkey")).read().strip()
       if os.path.exists(os.path.expanduser("~/.clockchain/orkey"))
       else os.environ["OPENROUTER_API_KEY"])

# THE CALIBRATION INPUT. Hand-written. Not from the chain. Never minted.
CALIBRATION_MOMENT = {
    "_fixture": "calibration input for probe (a'); hand-written, never minted",
    "title": "Undated Deposit at an Unnamed Site",
    "year": -800,
    "summary": "A layer containing worked material was recorded. Its makers, "
               "purpose and relation to surrounding layers are not established.",
}

b = json.load(open(BUNDLE))
LENSES = b["lenses"]
CANDIDATES_A = ["conflict-and-warfare", "politics-governance-and-law",
                "religious-life", "invention-and-technology",
                "disaster-disease-and-environment", "enterprise-and-commerce"]
CANDIDATES_B = ["bonding-and-kinship", "movement-and-dwelling",
                "making-and-cultivating", "knowing-and-meaning",
                "striving-and-harm", "work-and-provision"]

PROMPT = """You are classifying a historical moment under the TT taxonomy.

Lens A — {la}: {qa}
Lens B — {lb}: {qb}

Candidate ids, lens A (use these exact strings):
{ca}

Candidate ids, lens B (use these exact strings):
{cb}

THE MOMENT
  title: {title}
  year: {year}
  summary: {summary}

Return ONLY a JSON object with exactly these keys:
  "lens_a": object of id -> mass, at most 3 entries, masses in (0,1], summing to at most 1.0
  "lens_b": same, for lens B
  "abstain": boolean

**Declining is a valid and expected answer.** If this description does not give
you enough to say what the record kept, or what people were doing, set
"abstain": true and leave BOTH lens objects empty ({{}}). Do not guess to fill
the form. An abstention is a real reading; a fabricated mass is not.

JSON only, no prose."""


def price_is_zero():
    d = json.load(urllib.request.urlopen(
        "https://openrouter.ai/api/v1/models", timeout=60))["data"]
    m = [x for x in d if x["id"] == MODEL]
    if not m:
        return False, "not listed"
    p = m[0]["pricing"]
    return (float(p.get("prompt", 1) or 0) == 0
            and float(p.get("completion", 1) or 0) == 0), \
           f"prompt={p.get('prompt')} completion={p.get('completion')}"


def main():
    ok, detail = price_is_zero()
    print(f"STAGE 0  free-tier check      {detail} -> {'FREE' if ok else 'NOT FREE'}")
    if not ok:
        return 1

    m = CALIBRATION_MOMENT
    print(f"STAGE 1  calibration input    {m['_fixture']}")
    print(f"         title               {m['title']!r}")
    print(f"         summary             {m['summary']!r}")

    p = PROMPT.format(la=LENSES["A"]["label"], qa=LENSES["A"]["question"],
                      lb=LENSES["B"]["label"], qb=LENSES["B"]["question"],
                      ca="\n".join(f"  {i}" for i in CANDIDATES_A),
                      cb="\n".join(f"  {i}" for i in CANDIDATES_B),
                      title=m["title"], year=m["year"], summary=m["summary"])
    body = json.dumps({"model": MODEL, "temperature": 0.3,
                       "messages": [{"role": "user", "content": p}]}).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions", data=body,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        txt = ((json.load(r).get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    print(f"STAGE 2  classifier           {MODEL}")

    mm = re.search(r"\{.*\}", txt, re.S)
    if not mm:
        print(f"STAGE 3  parse                FAILED — no JSON: {txt[:120]!r}")
        return 1
    profile = json.loads(mm.group(0))
    print(f"STAGE 3  parse                {json.dumps(profile, separators=(',', ':'))}")

    v = subprocess.run([MIGRATOR, "classify", "-"], input=json.dumps(profile),
                       capture_output=True, text=True, timeout=60)
    if v.returncode != 0:
        print(f"STAGE 4  tt validate          REJECTED\n         {v.stderr.strip()}")
        return 1
    normalized = json.loads(v.stdout)
    print(f"STAGE 4  tt validate          ACCEPTED, bundle stamped")
    print(f"         {json.dumps(normalized, separators=(',', ':'))}")

    # The would-store decision: a full entry carrying this profile, through the
    # admission gate. Dry-run — nothing is written.
    entry = {
        "title": m["title"], "year": m["year"],
        "claim_type": "invention-and-technology", "lens": "A",
        "summary": m["summary"], "date_is_known": True,
        "temporal_kind": "event", "observed_count": 1,
        "tt_release": "tt-ontology/2.1.0",
        "tt_bundle_sha256": "31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113",
        "prov_measured": {"text_model": MODEL, "provider": "openrouter",
                          "method": "probe (a') calibration trace", "run": "abstain-trace",
                          "generated_at": "2026-08-17"},
        "prov_asserted": {"historical_claim": "CALIBRATION FIXTURE — not a historical claim"},
        "classification": normalized,
    }
    tmp = "/tmp/abstain-trace-entry.json"
    with open(tmp, "w") as f:
        json.dump({"entries": [entry], "edges": []}, f)
    a = subprocess.run([MIGRATOR, "mint", "--path", tmp],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "DATABASE_URL": "postgres://unreachable",
                            "MIGRATOR_SECRET_KEY": "x"})
    verdict = [ln for ln in (a.stdout + a.stderr).splitlines()
               if "admission" in ln or "classification:" in ln or "REFUSED" in ln]
    print("STAGE 5  admission verdict    " + ("\n         ".join(verdict) or "(no verdict line)"))
    print("         (stops at the database on purpose — nothing is written)")

    abst = normalized.get("abstain") is True
    print()
    print(f"RESULT   abstain reached the would-store decision: {abst}")
    print()
    print("CAVEAT, and it travels with any number taken from this run:")
    print("  This is a DECLARED CALIBRATION FIXTURE, not a corpus measurement.")
    print("  At rest the chain holds 0 abstaining of 322. That count is true and")
    print("  is not to be 'fixed': this corpus was generated to be classifiable,")
    print("  so its 0% abstain rate describes the generator, not the reader.")
    return 0 if abst else 1


if __name__ == "__main__":
    sys.exit(main())
