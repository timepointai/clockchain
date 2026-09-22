#!/usr/bin/env python3
"""Measure entity duplication, and separate its two causes.

    python3 ops/dup-report.py [postgres-url] [--sample N]

The headline number — entities sharing a canonical name — cannot tell you what
to do, because it mixes two populations that need opposite treatments:

  * the SAME event extracted repeatedly with no resolution step, which should
    merge; and
  * genuinely DIFFERENT events that share a name ("Battle of Ypres", a coronation
    that happened to several monarchs), which must not merge.

So it groups twice. Cut A is name alone. Cut B additionally splits each name
group into temporal clusters, so two entities only stay together if they are
also close in time. **The delta between the cuts is the diagnosis**: if B is
barely smaller than A, the duplicates are near-simultaneous restatements of one
event and a merge is safe; if B is much smaller, the name groups were hiding
distinct events and a name-only merge would destroy history.

Read-only. Touches nothing.
"""

import collections
import os
import re
import subprocess
import sys

DB = next((a for a in sys.argv[1:] if not a.startswith("-")),
          os.environ.get("DATABASE_URL", ""))
SAMPLE = 20
if "--sample" in sys.argv:
    SAMPLE = int(sys.argv[sys.argv.index("--sample") + 1])
if not DB:
    sys.exit("set DATABASE_URL or pass a postgres url")

PSQL = ("/opt/homebrew/opt/postgresql@17/bin/psql"
        if os.path.exists("/opt/homebrew/opt/postgresql@17/bin/psql") else "psql")
SEP = "\x1f"

# Seconds per Julian year, and the offset from Clock Zero (J2000.0) to year 0.
SECONDS_PER_YEAR = 31_557_600
J2000_YEAR = 2000
# Coordinates are stored offset-binary big-endian over 256 bits, with the
# governed split of 64 fractional bits.
SPLIT = 64
PROXIMITY_YEARS = 5


def rows(sql):
    p = subprocess.run([PSQL, DB, "-tA", "-F", SEP, "-c", sql],
                       capture_output=True, text=True, timeout=600)
    if p.returncode:
        raise SystemExit(p.stderr.strip()[:400])
    return [l.split(SEP) for l in p.stdout.split("\n") if l.strip()]


def year_of(hex_coord: str) -> "int | None":
    """Decode a stored b256 coordinate to an approximate calendar year."""
    raw = bytearray.fromhex(hex_coord[2:] if hex_coord.startswith("\\x") else hex_coord)
    raw[0] ^= 0x80                                   # undo offset-binary
    v = int.from_bytes(raw, "big", signed=True)
    if v == (1 << 255) - 1:                          # SENTINEL: no coordinate
        return None
    return J2000_YEAR + (v >> SPLIT) // SECONDS_PER_YEAR


def normalize(name: str) -> str:
    """Fold the differences that are certainly not distinctions."""
    n = name.lower().strip()
    n = re.sub(r"[‘’“”'`]", "", n)   # quotes and apostrophes
    n = re.sub(r"[^a-z0-9]+", " ", n)                    # punctuation -> space
    n = re.sub(r"^(the|a|an)\s+", "", n)
    return re.sub(r"\s+", " ", n).strip()


def cluster(years, gap=PROXIMITY_YEARS):
    """Split sorted years into runs where consecutive members are within `gap`."""
    out, cur = [], []
    for y in sorted(y for y in years if y is not None):
        if cur and y - cur[-1] > gap:
            out.append(cur)
            cur = []
        cur.append(y)
    if cur:
        out.append(cur)
    return out


def main():
    data = rows("""select entity_id, canonical_name, encode(window_start,'hex'),
                          start_state, resolution_key
                   from entities where entity_id <> 0""")
    print(f"entities                     {len(data):>7,}")

    by_name = collections.defaultdict(list)
    for eid, name, coord, ss, key in data:
        y = year_of(coord) if ss == "0" else None
        by_name[normalize(name)].append((eid, name, y, key))

    # ---- Cut A: name alone --------------------------------------------------
    dup_a = {k: v for k, v in by_name.items() if len(v) > 1}
    in_a = sum(len(v) for v in dup_a.values())
    max_a = max((len(v) for v in dup_a.values()), default=0)
    name_a = max(dup_a, key=lambda k: len(dup_a[k]), default="—")

    # ---- Cut B: name + temporal proximity -----------------------------------
    groups_b, in_b, max_b, name_b = 0, 0, 0, "—"
    for k, members in by_name.items():
        for run in cluster([m[2] for m in members]):
            if len(run) > 1:
                groups_b += 1
                in_b += len(run)
                if len(run) > max_b:
                    max_b, name_b = len(run), k
        undated = [m for m in members if m[2] is None]
        if len(undated) > 1:
            groups_b += 1
            in_b += len(undated)

    print(f"distinct normalized names    {len(by_name):>7,}")
    print()
    print(f"CUT A  name only")
    print(f"  groups with duplicates     {len(dup_a):>7,}")
    print(f"  entities inside them       {in_a:>7,}  ({in_a/len(data):.0%})")
    print(f"  largest group              {max_a:>7,}  {name_a!r}")
    print()
    print(f"CUT B  name + within {PROXIMITY_YEARS}y")
    print(f"  groups with duplicates     {groups_b:>7,}")
    print(f"  entities inside them       {in_b:>7,}  ({in_b/len(data):.0%})")
    print(f"  largest group              {max_b:>7,}  {name_b!r}")
    print()
    survives = in_b / in_a if in_a else 0
    print(f"DELTA  {in_a - in_b:,} entities ({1-survives:.0%}) leave the duplicate "
          f"population once time is considered.")
    print("  high survival  -> restatements of one event; name-merge is safe")
    print("  low  survival  -> name groups hide distinct events; merge on name alone loses history")

    print(f"\n--- sample of {SAMPLE} groups (largest first) ---")
    for k in sorted(dup_a, key=lambda x: -len(dup_a[x]))[:SAMPLE]:
        members = dup_a[k]
        ys = [m[2] for m in members if m[2] is not None]
        runs = cluster(ys)
        span = f"{min(ys)}..{max(ys)}" if ys else "undated"
        print(f"  x{len(members):<4} {span:<14} {len(runs)} cluster(s)  {members[0][1][:52]!r}")


if __name__ == "__main__":
    main()
