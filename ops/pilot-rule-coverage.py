"""Exhaustively check the interpretation table for holes and overlaps.

At N=40 the thin rate moves in 2.5pp steps; at N=20 the control rate moves in
5pp steps. So the reachable (T, C) space is small enough to enumerate exactly —
which is the right way to check a rule table, rather than reasoning about it.
"""

THIN_N, CTRL_N = 40, 20


def rows_v1(t, c):
    """The table as committed in b32ebef, evaluated as unordered conditions."""
    hits = []
    if t - c >= 20 and t >= 25:
        hits.append("1 thinness drives")
    if t - c < 10:
        hits.append("2 caution dominates")
    if 10 <= t - c < 20:
        hits.append("3 suggestive")
    if t < 10 and c < 10:
        hits.append("4 unreachable")
    if c > t:
        hits.append("5 instrument broken")
    return hits


def rows_v2(t, c):
    """The amended table: FIRST MATCH in order, plus one standing addition."""
    if c > t:
        primary = "1 instrument broken"
    elif t - c >= 20 and t >= 25:
        primary = "2 thinness drives"
    elif t - c >= 20:
        primary = "3 large gap, low absolute rate"
    elif 10 <= t - c < 20:
        primary = "4 suggestive"
    else:
        primary = "5 caution dominates"
    extra = ["+ unreachable"] if (t < 10 and c < 10) else []
    return [primary] + extra


holes_v1, overlaps_v1, holes_v2, overlaps_v2 = [], [], [], []
for ti in range(THIN_N + 1):
    for ci in range(CTRL_N + 1):
        t = 100.0 * ti / THIN_N
        c = 100.0 * ci / CTRL_N
        h1 = rows_v1(t, c)
        if not h1:
            holes_v1.append((t, c))
        elif len(h1) > 1:
            overlaps_v1.append((t, c, h1))
        h2 = rows_v2(t, c)
        primaries = [x for x in h2 if not x.startswith("+")]
        if len(primaries) != 1:
            (holes_v2 if not primaries else overlaps_v2).append((t, c, h2))

total = (THIN_N + 1) * (CTRL_N + 1)
print(f"reachable (T, C) points: {total}\n")
print("AS COMMITTED (b32ebef):")
print(f"  holes    {len(holes_v1):4d}  e.g. {holes_v1[:3]}")
print(f"  overlaps {len(overlaps_v1):4d}  e.g. {overlaps_v1[0] if overlaps_v1 else None}")
print()
print("AMENDED (first-match + standing rule):")
print(f"  holes    {len(holes_v2):4d}")
print(f"  overlaps {len(overlaps_v2):4d}")
print()
print("telemetry's worked example, T=22.5 C=0:")
print(f"  as committed -> {rows_v1(22.5, 0.0) or 'NO SENTENCE'}")
print(f"  amended      -> {rows_v2(22.5, 0.0)}")
