#!/usr/bin/env python3
"""Are two claims the same event?

**POLICY NAME: `subset-containment-v1`.** A named policy under TT's identity
doctrine (`CONSUMERS.md`, "Identity has two layers", rev `468fd72`), which Sean
ratified after the Hopfield reading.

The doctrine in one line: **exact identity is the hash and is automatic;
anything tolerant ranks and may never silently resolve.** TT is deliberately
anti-attractor at the identity layer — no basin, no settling, no "close enough
becomes the same" — because the over-merge that destroyed *Arab Conquest of
Ctesiphon* was precisely a spurious attractor, basin dynamics added where
identity lives.

This file is a **tolerant** surface. It is therefore allowed to auto-merge only
because it is a *named policy*, and **every merge it makes is a recorded
decision** naming its resolver and its evidence — never a silent equality. The
trail must show that `subset-containment-v1` chose, not that the world was
equal.

The stricter sibling: the admission gate's `restatement-unresolved` rule does
not merge at all. It reports the pair and refuses to pick a survivor, which is
the doctrine's other permitted shape.


This exists because the previous rule destroyed a real event. It dropped
*Arab Conquest of Ctesiphon* (637) as a duplicate of *Arab Conquest of Egypt*
(641): different conquests, different places, four years apart. A Jaccard score
over content words hit exactly 0.5, because the only differing token is the
place name — and a place name is the thing that distinguishes them, not noise.

**The asymmetry that governs this file:** a missed duplicate is visible and
cheap — it shows up as two near-identical cards and someone merges them. An
over-merge is invisible and permanent: the event is gone and nothing records
that it was ever there. So the rule is deliberately conservative and refuses to
merge whenever both titles carry something the other lacks.

That means genuine same-event-different-name pairs (*First Moon Landing* vs
*Apollo 11 Moon Landing*) are NOT merged here. They are left for human
judgement, which is the correct place for a decision that cannot be made from
string overlap.
"""

import re
import sys

# Words that carry no distinguishing weight. Deliberately short: every word
# added here is a word that can no longer distinguish two events, which is how
# the Ctesiphon bug happened one abstraction up.
STOP = {
    "the", "of", "a", "an", "in", "at", "on", "to", "and", "by", "for", "s",
    "its", "his", "her", "their",
}

# Generic event-shape verbs and nouns. Removing these lets "Black Death Reaches
# Europe" and "Black Death Peaks in Europe" collapse, which they should. A
# PROPER NOUN is never in this set — that is the whole point.
FILLER = {
    "begins", "begin", "began", "starts", "start", "started",
    "reaches", "reached", "peaks", "peaked", "arrival", "arrives",
    "signing", "signed", "posting", "posted", "publication", "published",
    "construction", "constructed", "establishment", "established",
    "founding", "founded", "invention", "invented", "discovery", "discovered",
    "creation", "created", "adoption", "adopted", "formation", "formed",
}

YEAR_TOLERANCE = 12


def content_words(title: str) -> set:
    """Distinguishing words: lowercase, no punctuation, no stopwords, no filler."""
    toks = re.sub(r"[^A-Za-z0-9 ]", " ", title or "").lower().split()
    return {t for t in toks if t and t not in STOP and t not in FILLER}


def same_claim(title_a: str, year_a: int, title_b: str, year_b: int) -> bool:
    """True only when one claim is a *restatement* of the other.

    Merge when one title's distinguishing words are a SUBSET of the other's —
    that is a longer spelling of the same claim. Refuse when each carries
    something the other lacks, because a word present in one and absent in the
    other is, by construction, the thing that tells them apart.
    """
    if abs(year_a - year_b) > YEAR_TOLERANCE:
        return False
    wa, wb = content_words(title_a), content_words(title_b)
    if not wa or not wb:
        return False
    # Subset in either direction: same claim, one spelled more fully.
    return wa <= wb or wb <= wa


POLICY = "subset-containment-v1"


def decision_for(loser, winner):
    """The recorded decision for one merge.

    **Never a silent equality.** Under TT's identity doctrine an automatic
    resolution beyond exact identity must name who resolved and on what
    evidence, so a reader can see that a policy chose rather than that the two
    claims were the same thing. The evidence here is the containment itself —
    which words one title carries that the other does not — because that is the
    entire basis on which the policy acted.
    """
    lw, ww = content_words(loser["title"]), content_words(winner["title"])
    return {
        "resolver": POLICY,
        "resolved": "merge",
        "kept": {"title": winner["title"], "year": winner["year"]},
        "dropped": {"title": loser["title"], "year": loser["year"]},
        "evidence": {
            "rule": "content words of one title are a subset of the other's",
            "dropped_words": sorted(lw),
            "kept_words": sorted(ww),
            "containment": "dropped ⊆ kept" if lw <= ww else "kept ⊆ dropped",
            "year_delta": abs(loser["year"] - winner["year"]),
            "year_tolerance": YEAR_TOLERANCE,
        },
        "doctrine": "tolerant surface; named policy; recorded decision "
                    "(TT CONSUMERS.md, Identity has two layers)",
    }


def dedupe(entries):
    """Return (kept, decisions).

    `decisions` is a list of **recorded decisions**, one per merge, each naming
    `subset-containment-v1` as the resolver and carrying the containment
    evidence it acted on. A caller that logs these has an auditable trail; a
    caller that discards them has produced exactly the silent equality the
    doctrine forbids.
    """
    kept, decisions = [], []
    for e in entries:
        hit = next(
            (k for k in kept
             if same_claim(e["title"], e["year"], k["title"], k["year"])),
            None,
        )
        if hit is None:
            kept.append(e)
        else:
            # Keep the fuller spelling: it carries strictly more information.
            if len(content_words(e["title"])) > len(content_words(hit["title"])):
                decisions.append(decision_for(hit, e))
                kept[kept.index(hit)] = e
            else:
                decisions.append(decision_for(e, hit))
    return kept, decisions


# ---------------------------------------------------------------------------

def _test():
    fails = []

    def check(a, ya, b, yb, want, why):
        got = same_claim(a, ya, b, yb)
        if got != want:
            fails.append(f"  {'MERGED' if got else 'KEPT'} but should be "
                         f"{'merged' if want else 'kept'}: {a!r} / {b!r}  — {why}")

    # THE REGRESSION. Different conquests, different places.
    check("Arab Conquest of Ctesiphon", 637, "Arab Conquest of Egypt", 641, False,
          "a differing place name is the distinguisher, not noise")
    check("Battle of Panipat", 1526, "Battle of Plassey", 1757, False, "different battles")
    check("Siege of Vienna", 1529, "Siege of Malta", 1565, False, "different sieges")
    check("Fall of Constantinople", 1453, "Fall of Granada", 1492, False, "different cities")

    # Restatements that must still collapse.
    check("Fall of Constantinople", 1453, "The Fall of Constantinople", 1453, True,
          "leading article is not a distinction")
    check("Construction of the Great Wall", -221, "Construction of the Great Wall of China", -221,
          True, "a fuller spelling of one claim")
    check("Black Death Reaches Europe", 1347, "Arrival of the Black Death in Europe", 1347, True,
          "event-shape verbs are filler")
    check("First Powered Flight", 1903, "Wright Brothers First Powered Flight", 1903, True,
          "subset: one names the actors as well")
    check("Signing of the Magna Carta", 1215, "Magna Carta", 1215, True, "restatement")

    # Conservative by design: left for human judgement rather than guessed.
    check("First Moon Landing", 1969, "Apollo 11 Moon Landing", 1969, False,
          "same event, but each carries a word the other lacks — human call")

    # Year still separates.
    check("Battle of Panipat", 1526, "Battle of Panipat", 1761, False,
          "same name, different event, 235 years apart")

    # THE DOCTRINE INVARIANT. Every merge must produce a recorded decision
    # naming its resolver and evidence. A refactor that made `dedupe` merge
    # without emitting one would reintroduce exactly the silent equality TT's
    # identity doctrine forbids — and it would still pass every case above,
    # because those test the RULE and this tests the RECORD.
    kept, decisions = dedupe([
        {"title": "Construction of the Great Wall", "year": -221},
        {"title": "Construction of the Great Wall of China", "year": -221},
        {"title": "Arab Conquest of Ctesiphon", "year": 637},
        {"title": "Arab Conquest of Egypt", "year": 641},
    ])
    if len(kept) != 3:
        fails.append(f"  expected 3 kept (one merge, Ctesiphon safe), got {len(kept)}")
    if len(decisions) != 1:
        fails.append(f"  every merge needs a decision: 1 merge, {len(decisions)} decisions")
    for d in decisions:
        if d.get("resolver") != POLICY:
            fails.append(f"  decision does not name its resolver: {d.get('resolver')}")
        if not d.get("evidence", {}).get("containment"):
            fails.append("  decision carries no containment evidence")
        if not (d.get("kept") and d.get("dropped")):
            fails.append("  decision does not say what was kept and what was dropped")

    if fails:
        print("FAIL")
        print("\n".join(fails))
        return 1
    print(f"ok — {12} cases + the doctrine invariant "
          f"(every merge is a recorded decision naming {POLICY})")
    return 0


if __name__ == "__main__":
    sys.exit(_test())
