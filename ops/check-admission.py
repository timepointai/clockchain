#!/usr/bin/env python3
"""Does the LIVE chain still satisfy the strict admission rule?

    python3 ops/check-admission.py            # report; exit 1 if anything fails

The gate in `crates/cc-authoring/src/admission.rs` governs the write path, so
nothing new can enter inadmissible. This checks the other direction — that what
is *already stored* still passes — and it exists because the write-path gate
cannot see two things:

  * `cc_ledger::rebuild()` re-derives the projection from `events` and is
    faithful by design, so it resurrects rows that `ops/drop-inadmissible.sql`
    removed. Nothing warns you. The remedy is to re-run that file.
  * A rule added to the gate later applies to future mints only. Stored claims
    that predate it are invisible to it.

**This is the check running on the side that can actually be wrong.** The write
path validating its own output proves the validator ran, not that the chain is
clean; only reading the chain back proves that. Every recurring defect this
quarter had that shape — validated on the producer and never held by the
consumer, committed and never pushed, delivered to a peer and never read by the
owner.

Read-only. It reports; it never deletes. Dropping on a body-level rule is a
judgement call, and the one time a tool here made that call unasked it destroyed
a real event.
"""

import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ccdb  # noqa: E402

# Repo-relative, derived from this file's own location. The absolute home paths
# that used to sit here made this check runnable on exactly one laptop.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BUNDLE = os.path.join(REPO, "vendor/tt/taxonomy-v2.1.json")

# Mirrors admission.rs. Verified against it at startup by `assert_mirrors_rust()`
# rather than by a comment — the comment that used to sit here claimed a sync
# test existed, no such test existed, and the two drifted the first time the
# Rust gate gained a field (`cross_lens`), which then reported every corrected
# claim as carrying an unknown field. A note asserting a check is not a check.
REQUIRED_PROV_MEASURED = ["text_model", "provider", "method", "run", "generated_at"]
ALLOWED_FIELDS = {
    "title", "year", "claim_type", "claim_type_alternatives", "alternatives_cross_lens",
    "lens", "summary", "date_is_known", "temporal_kind", "observed_count",
    "tt_release", "tt_bundle_sha256", "prov_measured", "prov_asserted", "classification",
    "classification_source",
}

ADMISSION_RS = os.path.join(REPO, "crates/cc-authoring/src/admission.rs")


def parse_rust_fields(src):
    """Extract ALLOWED_FIELDS from admission.rs source. Split out from
    `assert_mirrors_rust` so it can be tested against a known-drifted fixture."""
    block = re.search(r"const ALLOWED_FIELDS: &\[&str\] = &\[(.*?)\];", src, re.S)
    if not block:
        raise SystemExit("cannot find ALLOWED_FIELDS in admission.rs — update this parser")
    # Strip // comments BEFORE extracting: the array carries explanatory comments
    # that quote example values ("derived", "independent"), and reading those as
    # field names made the guard fire on its own parser for the second time.
    # [a-z0-9_] rather than [a-z_] for the same reason the first time — digits.
    body = "\n".join(re.sub(r"//.*$", "", ln) for ln in block.group(1).splitlines())
    return set(re.findall(r'"([a-z0-9_]+)"', body))


def self_test():
    """Prove the guard catches the thing it EXISTS for, not just its own parsing.

    Telemetry's observation, and it was the right one: this guard has fired twice
    and **both times it was catching its own parser** — digits it did not match,
    then quoted words inside a comment. Never once had it been shown to catch the
    guarded thing actually drifting. A check whose only demonstrated behaviour is
    tripping over itself has not been shown to work.

    So: feed it a fixture that IS drifted and require it to notice.
    """
    real = open(ADMISSION_RS).read()

    # 1. A field present in Rust and missing here.
    drifted = real.replace('    "title",',
                           '    "title",\n    "a_new_field_the_mirror_lacks",', 1)
    got = parse_rust_fields(drifted)
    assert "a_new_field_the_mirror_lacks" in got, "guard blind to an ADDED rust field"
    assert got - ALLOWED_FIELDS == {"a_new_field_the_mirror_lacks"}, got - ALLOWED_FIELDS

    # 2. A field removed from Rust but still listed here.
    drifted = real.replace('    "observed_count",\n', "", 1)
    got = parse_rust_fields(drifted)
    assert "observed_count" not in got, "guard blind to a REMOVED rust field"
    assert ALLOWED_FIELDS - got == {"observed_count"}, ALLOWED_FIELDS - got

    # 3. The two parser bugs it actually caught, as regressions.
    assert "tt_bundle_sha256" in parse_rust_fields(real), "digits must parse"
    assert "independent" not in parse_rust_fields(real), "comment values must not parse"

    # 4. And the real file must agree, which is the guard's day job.
    assert parse_rust_fields(real) == ALLOWED_FIELDS, "live drift"
    return True


def assert_mirrors_rust():
    """Fail loudly if this file's field list has drifted from the gate's.

    Deliberately fatal: a mirror that is quietly out of date reports confident
    nonsense about the live chain, which is worse than not running.
    """
    try:
        src = open(ADMISSION_RS).read()
    except OSError:
        print("WARN: cannot read admission.rs; field list unverified", file=sys.stderr)
        return
    rust = parse_rust_fields(src)
    if rust != ALLOWED_FIELDS:
        raise SystemExit(
            "MIRROR DRIFT — this script disagrees with the gate it mirrors.\n"
            f"  only in admission.rs: {sorted(rust - ALLOWED_FIELDS)}\n"
            f"  only in this file:    {sorted(ALLOWED_FIELDS - rust)}\n"
            "Fix ALLOWED_FIELDS here before trusting any result below."
        )

QUERIES = {
    "undated": "select entity_id, canonical_name from entities where start_state <> 0",
    "orphan_moments": (
        "select m.subject from moments m "
        "where not exists (select 1 from entities e where e.entity_id = m.subject) "
        "and m.subject <> 0"
    ),
    "bodyless": (
        "select m.subject, encode(m.body_hash,'hex') from moments m "
        "where not exists (select 1 from claim_bodies b where b.body_hash = m.body_hash) "
        "and m.subject <> 0"
    ),
    "bodies": (
        "select m.subject, encode(convert_to(b.body,'UTF8'),'base64') "
        "from claim_bodies b join moments m on m.body_hash = b.body_hash "
        "where m.subject <> 0"
    ),
    "dangling_edges": (
        "select encode(x.edge_id,'hex') from edges x "
        "where not exists (select 1 from entities e where e.entity_id = x.src_entity) "
        "   or not exists (select 1 from entities e where e.entity_id = x.dst_entity)"
    ),
}


def fetch():
    """One round trip, split on the \\echo markers. Connection from `ccdb`."""
    script = "\n".join(f"\\echo ===={n}\n{q};" for n, q in QUERIES.items())
    out = ccdb.run(script)
    if "====" not in out:
        raise ccdb.Unreachable("no section markers in output — the query did not run")
    blocks, cur = {}, None
    for line in out.splitlines():
        if line.startswith("===="):
            cur = line[4:].strip()
            blocks[cur] = []
        elif cur is not None and line.strip():
            row = line.split(ccdb.SEP)
            # psql wraps base64 at 76 columns; a continuation has no separator.
            if len(row) == 1 and blocks[cur] and cur == "bodies":
                blocks[cur][-1][-1] += row[0]
            else:
                blocks[cur].append(row)
    return blocks


def ancestors(i, parent_of, limit=8):
    """Nearest-first ancestry, bounded like the Rust walk."""
    out, cur = [], parent_of.get(i)
    while cur and len(out) < limit:
        out.append(cur)
        cur = parent_of.get(cur)
    return out


def is_ancestor(maybe, i, parent_of):
    return maybe == i or maybe in ancestors(i, parent_of)


# The scale-mismatch advisory that lived here was ruled DELETED by telemetry on
# 2026-08-17, not patched: it could not be re-expressed from the bundle (the
# branch that motivated it carries no bridge at all), its marker list was 14
# English words, and the mismatch it hunted is an artifact of the single-primary
# projection rather than a defect in the claims. See admission.rs for the full
# reasoning. Nothing replaces it.


def body_failures(body, valid_ids, lens_of, bundle_sha, parent_of):
    """The body-level subset of the gate. Returns a list of rule names."""
    bad = []
    try:
        e = json.loads(body)
    except Exception:
        return ["body-not-json"]

    for k in e:
        if k not in ALLOWED_FIELDS:
            bad.append(f"field-unknown:{k}")

    if e.get("date_is_known") is not True:
        bad.append("date-not-known")

    if not isinstance(e.get("year"), int):
        bad.append("year-missing")

    t = (e.get("title") or "").strip()
    if not t:
        bad.append("title-missing")
    elif any(c.islower() or c.isupper() for c in t) and not any(c.isupper() for c in t):
        bad.append("title-not-capitalised")

    ct = e.get("claim_type")
    if ct not in valid_ids:
        bad.append("claim-type-invalid")
    elif e.get("lens") != lens_of.get(ct):
        bad.append("lens-mismatch")

    alts = e.get("claim_type_alternatives")
    if alts is not None:
        if not isinstance(alts, list):
            bad.append("claim-type-alternative-invalid")
        else:
            for a in alts:
                if not isinstance(a, str) or a not in valid_ids or a == ct \
                        or alts.count(a) > 1:
                    bad.append("claim-type-alternative-invalid")
                # LOCAL PROFILE, not TT policy. TT permits ancestor+descendant
                # mass as specificity uncertainty; we refuse it, which the
                # one-way rule allows (refuse what TT permits, never accept what
                # TT rejects). Mirrors admission.rs.
                elif is_ancestor(a, ct, parent_of):
                    bad.append("claim-type-alternative-is-ancestor")
                elif is_ancestor(ct, a, parent_of):
                    bad.append("claim-type-alternative-is-descendant")
        derived = any(isinstance(a, str) and a in lens_of and lens_of[a] != lens_of.get(ct)
                      for a in (alts if isinstance(alts, list) else []))
        if "alternatives_cross_lens" in e and e["alternatives_cross_lens"] is not derived:
            bad.append("alternatives-cross-lens-mismatch")
    elif e.get("alternatives_cross_lens") is True:
        bad.append("alternatives-cross-lens-mismatch")

    if e.get("tt_bundle_sha256") != bundle_sha:
        bad.append("tt-bundle-mismatch")

    if e.get("temporal_kind") not in ("event", "process"):
        bad.append("temporal-kind-invalid")

    if not isinstance(e.get("observed_count"), int) or e["observed_count"] < 1:
        bad.append("observed-count-invalid")

    if len((e.get("summary") or "").strip()) < 20:
        bad.append("summary-too-short")

    m = e.get("prov_measured")
    if not isinstance(m, dict) or any(not str(m.get(f, "")).strip() for f in REQUIRED_PROV_MEASURED):
        bad.append("prov-measured-incomplete")

    a = e.get("prov_asserted")
    if not isinstance(a, dict) or not str(a.get("historical_claim", "")).strip():
        bad.append("prov-asserted-incomplete")

    return bad


def main():
    import hashlib
    assert_mirrors_rust()
    raw = open(BUNDLE, "rb").read()
    bundle_sha = hashlib.sha256(raw).hexdigest()
    b = json.loads(raw)
    valid_ids = {n["id"] for n in b["nodes"]}
    lens_of = {n["id"]: n.get("lens") for n in b["nodes"]}
    parent_of = {n["id"]: n.get("parent") for n in b["nodes"] if n.get("parent")}

    blocks = fetch()
    problems = []

    if blocks["undated"]:
        problems.append((
            f"{len(blocks['undated'])} entity(ies) have no known window start",
            [f"{r[0]}  {r[1]}" for r in blocks["undated"]],
            "run ops/drop-inadmissible.sql — a rebuild resurrects these",
        ))
    if blocks["orphan_moments"]:
        problems.append((f"{len(blocks['orphan_moments'])} moment(s) reference a missing entity",
                         [r[0] for r in blocks["orphan_moments"][:20]], ""))
    if blocks["bodyless"]:
        problems.append((f"{len(blocks['bodyless'])} moment(s) have no stored claim body",
                         [f"{r[0]} {r[1][:16]}…" for r in blocks["bodyless"][:20]],
                         "a rebuild restores moments but NOT claim_bodies"))
    if blocks["dangling_edges"]:
        problems.append((f"{len(blocks['dangling_edges'])} edge(s) point at a missing entity",
                         [r[0][:16] for r in blocks["dangling_edges"][:20]], ""))

    failures, checked = {}, 0
    for subject, b64 in blocks["bodies"]:
        checked += 1
        raw = base64.b64decode(b64).decode()
        for rule in body_failures(raw, valid_ids, lens_of, bundle_sha, parent_of):
            failures.setdefault(rule, []).append(subject)

    if failures:
        problems.append((
            f"{sum(len(v) for v in failures.values())} body-level rejection(s) across {checked} claims",
            [f"{rule}: {len(subs)}  e.g. {subs[0]}" for rule, subs in sorted(failures.items())],
            "these are reported, never auto-dropped",
        ))

    print(f"checked {checked} stored claims against the strict admission rule")
    print(f"bundle  {bundle_sha[:16]}…  ({len(valid_ids)} nodes)\n")
    if not problems:
        print("PASS — the stored chain satisfies every rule the gate enforces")
        return 0
    print("FAIL")
    for headline, rows, hint in problems:
        print(f"\n  {headline}")
        for r in rows:
            print(f"      {r}")
        if hint:
            print(f"    -> {hint}")
    return 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        self_test()
        print("guard self-test PASS — catches added fields, removed fields, "
              "and both parser bugs it previously tripped over")
        sys.exit(0)
    sys.exit(main())
