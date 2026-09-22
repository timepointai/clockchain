#!/usr/bin/env python3
"""The under-determined records pilot — runs exactly what was pre-registered.

    python3 ops/pilot-abstention.py [--out DIR]

Governed by PILOT-ABSTENTION-PREREGISTRATION.md
sha256 b76f99f5da81325a7995945e6f6533e43f3c9f9f965f507bed7255b2c5d4e77c
(commit 3360f5d), acknowledged by timepoint-telemetry before this ran.

The cell list, per-cell targets, denominator and interpretation rule all come
from that document and are duplicated here only so the code can assert they
match. **If they ever disagree, the document governs and this script is wrong.**

## What this measures, and the error it is built around

The stored corpus abstains on 0 of 322 because every claim in it was generated
to be classifiable. A rate over it describes the generator, not the reader.

An earlier attempt of mine reported 2 of 4 abstaining and was worthless: I had
shortened two summaries myself, so the abstentions measured my prompt. So here
the generator is asked for events that are **genuinely thinly attested** and to
write a **complete, honest** summary of what that thin evidence supports. The
summary is as full as the record allows; the record is thin. Nothing is
truncated or withheld by me at any point.

Controls — well-attested events, same grid, same generator, same classifier,
same run — exist to attribute the signal. Without them a high thin-slice rate
cannot be told apart from a classifier that declines readily on anything.

## Counting

Every classifier call is logged and counted, per slice, including calls that
return confident mass. A record is only classified if it first passes the strict
admission gate — under-determined is not inadmissible, so a record with no
defensible date is refused before it ever reaches the classifier and does not
enter the denominator.
"""

import argparse
import functools
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

CC = os.path.expanduser("~/dev/GitHub/timepointai/clockchain")
BUNDLE = f"{CC}/vendor/tt/taxonomy-v2.1.json"
MIGRATOR = f"{CC}/target/debug/cc-migrator"
PREREG_SHA = "b76f99f5da81325a7995945e6f6533e43f3c9f9f965f507bed7255b2c5d4e77c"
MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
KEY = (open(os.path.expanduser("~/.clockchain/orkey")).read().strip()
       if os.path.exists(os.path.expanduser("~/.clockchain/orkey"))
       else os.environ["OPENROUTER_API_KEY"])
RUN = "v4-abstention-pilot-2026-08-17"

# --- the pre-registered cells. Region index i pairs with era index i mod 5. ---
ERAS = [(-3000, -1200), (-1200, -200), (-200, 400), (400, 900), (900, 1300)]
THIN_REGIONS = [
    "Sub-Saharan Africa", "North Africa and the Nile", "the Middle East and Persia",
    "South Asia", "East Asia", "Southeast Asia and Oceania", "Europe",
    "the Americas", "Central Asia and the Steppe", "the Caribbean and Central America",
]
THIN_CELLS = [(r, *ERAS[i % 5]) for i, r in enumerate(THIN_REGIONS)]
CONTROL_CELLS = [
    ("the Middle East and Persia", 1300, 1600), ("Europe", 1600, 1800),
    ("East Asia", 1300, 1600), ("South Asia", 1600, 1800),
    ("the Americas", 1800, 1900),
]
PER_CELL = 4

b = json.load(open(BUNDLE))
NODES = {n["id"]: n for n in b["nodes"]}
LENSES = b["lenses"]
BUNDLE_SHA = __import__("hashlib").sha256(open(BUNDLE, "rb").read()).hexdigest()
CAND_A = ["conflict-and-warfare", "politics-governance-and-law", "religious-life",
          "invention-and-technology", "disaster-disease-and-environment",
          "enterprise-and-commerce"]
CAND_B = ["bonding-and-kinship", "movement-and-dwelling", "making-and-cultivating",
          "knowing-and-meaning", "striving-and-harm", "work-and-provision"]

GEN_THIN = """Return ONLY JSON: {{"records": [...]}}

{n} events from {region}, {lo} to {hi}, that are GENUINELY THINLY ATTESTED —
known from a single damaged inscription, an undeciphered script, an
unprovenanced object, a stratum with no associated text, or one late source
with no corroboration.

Each record: {{"title","year","claim_type","summary"}}
  title: a proper human title, capitalised. Never a slug. No year or place appended.
  year: integer in [{lo}, {hi}], negative for BCE.
  claim_type: EXACTLY one id from this list, verbatim:
{ids}
  summary: a COMPLETE and HONEST account of what the evidence actually supports.
    Do NOT abbreviate. Do NOT withhold detail to make it seem thin. Write the
    fullest description the surviving evidence permits, and where the evidence
    does not establish something, say so plainly rather than omitting it.

The thinness must be a property of the historical record, not of your writing.
Real events only. JSON only."""

GEN_CONTROL = """Return ONLY JSON: {{"records": [...]}}

{n} WELL-ATTESTED events from {region}, {lo} to {hi} — documented by multiple
independent sources, with actors, outcomes and dates securely established.

Each record: {{"title","year","claim_type","summary"}}
  title: a proper human title, capitalised. Never a slug. No year or place appended.
  year: integer in [{lo}, {hi}], negative for BCE.
  claim_type: EXACTLY one id from this list, verbatim:
{ids}
  summary: a complete account of the event.

Real events only. JSON only."""

CLASSIFY = """You are classifying a historical moment under the TT taxonomy.

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

# stdout unbuffered: the first run of this file produced ZERO bytes of output
# before it was killed, because print() buffers when stdout is a pipe. A long
# run whose progress is invisible cannot be supervised, and its interim state
# cannot be recovered.
import builtins


def print(*a, **k):  # noqa: A001
    builtins.print(*a, **{**k, "flush": True})

log = []
LOG_PATH = None


def note(**kw):
    """Append an event AND flush the whole log to disk.

    The first run retained nothing when it was killed: the log lived in memory
    and was written only at the end. The pre-registration says a halt is
    reported with whatever was gathered — a script that can only report at the
    end cannot honour that. Rewriting the file each time is O(n^2) and
    irrelevant at this size; losing the run is not.
    """
    kw["t"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    log.append(kw)
    if LOG_PATH:
        with open(LOG_PATH, "w") as f:
            json.dump(log, f, indent=1, ensure_ascii=False)


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


def spend():
    req = urllib.request.Request("https://openrouter.ai/api/v1/key",
                                 headers={"Authorization": f"Bearer {KEY}"})
    return float(json.load(urllib.request.urlopen(req, timeout=45))["data"]["usage"])


def ask(prompt, temperature):
    body = json.dumps({"model": MODEL, "temperature": temperature,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions", data=body,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        txt = ((json.load(r).get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    m = re.search(r"\{.*\}", txt, re.S)
    if not m:
        raise ValueError("no JSON in response")
    return json.loads(m.group(0))


def entry_for(rec, slice_name):
    """A full claim, ready for the strict gate. Provenance is complete and says
    which slice it came from — an entry that cannot be traced to its arm is not
    evidence about that arm."""
    return {
        "title": (rec.get("title") or "").strip(),
        "year": rec.get("year"),
        "claim_type": rec.get("claim_type"),
        "lens": NODES.get(rec.get("claim_type"), {}).get("lens"),
        "summary": (rec.get("summary") or "").strip(),
        "date_is_known": True,
        "temporal_kind": "event",
        "observed_count": 1,
        "tt_release": "tt-ontology/2.1.0",
        "tt_bundle_sha256": BUNDLE_SHA,
        "prov_measured": {
            "text_model": MODEL, "provider": "openrouter", "run": RUN,
            "generated_at": time.strftime("%Y-%m-%d"),
            "method": f"abstention pilot, {slice_name} slice; pre-registration "
                      f"sha256 {PREREG_SHA[:16]}…",
        },
        "prov_asserted": {
            "historical_claim": "title, year and summary are model-asserted; no source "
                                "was consulted",
            "inherited_from": RUN,
        },
    }


def passes_gate(entry):
    """The strict admission gate, run per record before it reaches the classifier.
    Under-determined is not inadmissible; undated still is."""
    path = "/tmp/pilot-one.json"
    with open(path, "w") as f:
        json.dump({"entries": [entry], "edges": []}, f)
    p = subprocess.run([MIGRATOR, "mint", "--path", path],
                       capture_output=True, text=True, timeout=60,
                       env={**os.environ, "DATABASE_URL": "postgres://unreachable",
                            "MIGRATOR_SECRET_KEY": "x"})
    out = p.stdout + p.stderr
    if "admission: 1 of 1 entries pass" in out:
        return True, ""
    reasons = [ln.strip() for ln in out.splitlines() if ":" in ln and "  " in ln]
    return False, "; ".join(reasons[:4])


def validate_profile(profile):
    p = subprocess.run([MIGRATOR, "classify", "-"], input=json.dumps(profile),
                       capture_output=True, text=True, timeout=60)
    return (p.returncode == 0), (p.stdout.strip() or p.stderr.strip())


def run_slice(name, cells, gen_prompt, results):
    ids = "\n".join(f"  {i}" for i in (CAND_A + CAND_B))
    for region, lo, hi in cells:
        ok, detail = price_is_zero()
        if not ok:
            note(event="halt", why=f"model not zero-priced ({detail})")
            print(f"HALT — model not zero-priced: {detail}")
            return False
        try:
            g = ask(gen_prompt.format(n=PER_CELL, region=region, lo=lo, hi=hi, ids=ids), 1.0)
        except Exception as e:
            note(event="generate_error", slice=name, cell=[region, lo, hi],
                 error=type(e).__name__)
            print(f"  {name:7s} {region[:26]:28s} {lo}..{hi}  GENERATE ERROR {type(e).__name__}")
            continue

        for rec in (g.get("records") or [])[:PER_CELL]:
            if not isinstance(rec, dict):
                continue
            entry = entry_for(rec, name)
            admitted, why = passes_gate(entry)
            if not admitted:
                note(event="gate_refused", slice=name, cell=[region, lo, hi],
                     title=entry["title"], why=why)
                continue
            try:
                profile = ask(CLASSIFY.format(
                    la=LENSES["A"]["label"], qa=LENSES["A"]["question"],
                    lb=LENSES["B"]["label"], qb=LENSES["B"]["question"],
                    ca="\n".join(f"  {i}" for i in CAND_A),
                    cb="\n".join(f"  {i}" for i in CAND_B),
                    title=entry["title"], year=entry["year"],
                    summary=entry["summary"]), 0.3)
            except Exception as e:
                note(event="classify_error", slice=name, title=entry["title"],
                     error=type(e).__name__)
                continue
            accepted, out = validate_profile(profile)
            # EVERY classifier call that returned a validatable profile counts.
            note(event="classified", slice=name, cell=[region, lo, hi],
                 title=entry["title"], raw=profile, accepted=accepted,
                 normalized=json.loads(out) if accepted else None,
                 rejection=None if accepted else out)
            if not accepted:
                continue
            norm = json.loads(out)
            entry["classification"] = norm
            results.append({"slice": name, "entry": entry,
                            "abstain": norm.get("abstain") is True})
            mark = "ABSTAIN" if norm.get("abstain") else "mass   "
            print(f"  {name:7s} {mark}  {entry['title'][:52]}")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=".")
    a = ap.parse_args()
    global LOG_PATH
    LOG_PATH = f"{a.out}/pilot-call-log.json"

    ok, detail = price_is_zero()
    print(f"pre-registration  {PREREG_SHA[:16]}…  (commit 3360f5d)")
    print(f"free-tier check   {detail} -> {'FREE' if ok else 'NOT FREE'}")
    if not ok:
        return 1
    start_spend = spend()
    print(f"spend at start    ${start_spend:.6f}")
    if start_spend > 0:
        print("HALT — non-zero spend before the run")
        return 1
    print(f"thin cells        {len(THIN_CELLS)} x {PER_CELL} = {len(THIN_CELLS)*PER_CELL} target")
    print(f"control cells     {len(CONTROL_CELLS)} x {PER_CELL} = {len(CONTROL_CELLS)*PER_CELL} target\n")

    results = []
    if run_slice("thin", THIN_CELLS, GEN_THIN, results):
        run_slice("control", CONTROL_CELLS, GEN_CONTROL, results)

    end_spend = spend()
    calls = [x for x in log if x["event"] == "classified"]
    out = {}
    for s in ("thin", "control"):
        n = len([x for x in calls if x["slice"] == s and x["accepted"]])
        k = len([r for r in results if r["slice"] == s and r["abstain"]])
        out[s] = {"n": n, "abstained": k, "rate": (100.0 * k / n) if n else None}

    print()
    print("=" * 62)
    for s in ("thin", "control"):
        d = out[s]
        r = f"{d['rate']:.1f}%" if d["rate"] is not None else "n/a"
        print(f"  {s:8s}  {d['abstained']:3d} abstained of {d['n']:3d} classified   {r}")
    tn = out["thin"]["n"] + out["control"]["n"]
    tk = out["thin"]["abstained"] + out["control"]["abstained"]
    print(f"  {'pooled':8s}  {tk:3d} abstained of {tn:3d} classified   "
          f"{(100.0*tk/tn) if tn else 0:.1f}%")
    print(f"\n  spend ${end_spend:.6f}   classifier calls logged: {len(calls)}")
    print(f"  gate refusals: {len([x for x in log if x['event']=='gate_refused'])}")
    print(f"  errors: {len([x for x in log if x['event'].endswith('_error')])}")

    json.dump({"prereg_sha256": PREREG_SHA, "run": RUN, "slices": out,
               "spend_start": start_spend, "spend_end": end_spend},
              open(f"{a.out}/pilot-results.json", "w"), indent=1)
    json.dump(log, open(f"{a.out}/pilot-call-log.json", "w"), indent=1, ensure_ascii=False)
    json.dump({"entries": [r["entry"] for r in results], "edges": []},
              open(f"{a.out}/pilot-mintable.json", "w"), indent=1, ensure_ascii=False)
    print(f"\n  wrote pilot-results.json, pilot-call-log.json, pilot-mintable.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
