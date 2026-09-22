"""Make abstention REACHABLE by the pipeline, not merely representable.

Telemetry's probe (c): "Abstention must be reachable by the pipeline, not merely
representable by the schema." A schema that can express abstention while no
generation path ever produces one has closed nothing.

So this is a real classification run over moments already in the chain: the
model is shown the TT lens definitions and the candidate ids, and is told
explicitly that declining is a valid answer when the record does not support a
reading. Whatever comes back — abstention or mass — is validated by
`cc-migrator classify` (TT's rules, our port) before anything is kept.

Free tier only: pricing is re-read from the API and the run refuses unless both
prompt and completion are zero.
"""
import json
import os
import re
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
# Key from the environment, or a 600-perm file. Never in argv, never committed.
# The 600-perm file first, the environment second — deliberately that order.
# A stale OPENROUTER_API_KEY was exported in this shell and returned 401 while a
# working key sat in the file; preferring the env var meant the wrong credential
# won silently. The file is the one that was verified.
KEY = (open(os.path.expanduser("~/.clockchain/orkey")).read().strip()
       if os.path.exists(os.path.expanduser("~/.clockchain/orkey"))
       else os.environ["OPENROUTER_API_KEY"])
MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
CC = os.path.expanduser("~/dev/GitHub/timepointai/clockchain")
BUNDLE = f"{CC}/vendor/tt/taxonomy-v2.1.json"
MIGRATOR = f"{CC}/target/debug/cc-migrator"

b = json.load(open(BUNDLE))
NODES = {n["id"]: n for n in b["nodes"]}
LENSES = b["lenses"]


def price_is_zero():
    d = json.load(urllib.request.urlopen(
        "https://openrouter.ai/api/v1/models", timeout=60))["data"]
    m = [x for x in d if x["id"] == MODEL]
    if not m:
        return False, "not listed"
    p = m[0]["pricing"]
    z = float(p.get("prompt", 1) or 0) == 0 and float(p.get("completion", 1) or 0) == 0
    return z, f"prompt={p.get('prompt')} completion={p.get('completion')}"


# Candidate ids offered to the classifier: a spread across both lenses.
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

If you can read it, put mass only on ids you are actually willing to defend.
JSON only, no prose."""


def classify(title, year, summary):
    p = PROMPT.format(
        la=LENSES["A"]["label"], qa=LENSES["A"]["question"],
        lb=LENSES["B"]["label"], qb=LENSES["B"]["question"],
        ca="\n".join(f"  {i}" for i in CANDIDATES_A),
        cb="\n".join(f"  {i}" for i in CANDIDATES_B),
        title=title, year=year, summary=summary)
    body = json.dumps({"model": MODEL, "temperature": 0.3,
                       "messages": [{"role": "user", "content": p}]}).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions", data=body,
        headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=300) as r:
        j = json.load(r)
    txt = ((j.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    m = re.search(r"\{.*\}", txt, re.S)
    if not m:
        raise ValueError(f"no JSON in response: {txt[:200]}")
    return json.loads(m.group(0))


def validated(profile):
    """Run it through OUR validator — TT's rules — before keeping anything."""
    p = subprocess.run([MIGRATOR, "classify", "-"], input=json.dumps(profile),
                       capture_output=True, text=True, timeout=60)
    return (p.returncode == 0), (p.stdout.strip() or p.stderr.strip())


# REAL stored claims, pulled from production with their summaries VERBATIM.
#
# The first version of this file used four hand-written summaries, two of which
# I had shortened myself ("Artisans produced jade objects."), under a comment
# claiming nothing was engineered to abstain. That comment was false: I wrote
# the thin summaries, so any abstention they produced would have measured my
# prompt rather than the pipeline. Telemetry's probe (a) says "from the chain at
# rest, not a fixture" and that is the whole point of the requirement.
#
# These are loaded from `real_moments.json`, dumped straight out of
# `claim_bodies`. Selected by SHORTEST SUMMARY — the entries where a reading is
# genuinely hardest to defend — plus two of the longest as controls. Selection
# is by length, not by my judgement of which ought to abstain.
MOMENTS = [(m["title"], m["year"], m["summary"])
           for m in json.load(open(os.environ.get("CC_MOMENTS", "real_moments.json")))]


def main():
    ok, detail = price_is_zero()
    print(f"pricing check: {detail} -> {'FREE' if ok else 'NOT FREE'}")
    if not ok:
        print("refusing to spend", file=sys.stderr)
        return 1

    results = []
    for title, year, summary in MOMENTS:
        try:
            prof = classify(title, year, summary)
        except Exception as e:
            print(f"  {title:36s} ERROR {type(e).__name__}: {e}")
            continue
        accepted, out = validated(prof)
        abstained = prof.get("abstain") is True
        state = "ABSTAIN" if abstained else "mass"
        print(f"  {title:36s} {state:8s} {'accepted' if accepted else 'REJECTED'}")
        if not accepted:
            print(f"      {out}")
        else:
            print(f"      {json.dumps(json.loads(out), separators=(',', ':'))}")
        results.append({"title": title, "year": year, "summary": summary,
                        "raw": prof, "accepted": accepted,
                        "normalized": json.loads(out) if accepted else None})

    json.dump(results, open("abstain_results.json", "w"), indent=1, ensure_ascii=False)
    n_ab = sum(1 for r in results if r["accepted"] and r["normalized"]["abstain"])
    print(f"\nput to the classifier: {len(results)}   abstained: {n_ab}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
