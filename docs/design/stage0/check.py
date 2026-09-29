"""Run: python docs/design/stage0/check.py --max-events 7 --examples 3000.

Finite exhaustive syntax: one subject, keys 0..2, G/C/D/R/S, exact grant IDs,
all earlier parent choices, every incomparable Resolve parent subset. Invalid
one-step operations are checked but not extended (they have no authority effect).
Distinct correction decisions can share parents. Random DAGs extend to 7 events.
"""
import argparse
from dataclasses import asdict, replace
from itertools import combinations, permutations
import json
from pathlib import Path
import time

from hypothesis import given, settings, strategies as st
from model import Event, fold, ancestry, grant_tree, in_scope

G = Event(0, "G")


def check_invariants(events):
    view = fold(events)
    index = {e.id: e for e in events}
    anc = ancestry(events)
    valid_ids = {i for i, s, _ in view.rows if s not in ("invalid", "pending")}
    valid = tuple(index[i] for i in valid_ids)
    assert {i for i, _, _ in view.rows} == set(index), ("I3", events, view)
    if not valid:
        return view
    grants, _, lineage = grant_tree(valid)
    for i in view.frontier:
        e = index[i]
        if e.kind == "G":
            continue
        assert e.grant in grants, ("I2 grant", events, view)
        holder = grants[e.grant].target if grants[e.grant].kind == "D" else 0
        assert e.key == holder, ("I2 signer", events, view)
        for p in e.parents:
            parent = fold(tuple(index[j] for j in anc[p] if j in index))
            assert e.grant in parent.active, ("I2 parent", events, view)
        for rid in view.effective_revokes:
            r = index[rid]
            if r.target == e.grant:
                # Historical acknowledged acts survive, never late revoked acts.
                assert e.id in anc[r.parents[0]], ("revoked sole/frontier", events, view)
    for rid in view.effective_revokes:
        r = index[rid]
        assert in_scope(grants, lineage, r.grant, r.target), ("scope", events, view)
        for other_id in view.effective_revokes:
            other = index[other_id]
            if other.target == r.grant and rid != other_id:
                assert rid in anc[other.parents[0]] or r.grant == r.target == 0, (
                    "revoked issuer kills survivor", events, view)
    return view


def candidates(prefix):
    """Every operation/author/grant/parent in this bounded event vocabulary."""
    i = len(prefix)
    anc = ancestry(prefix)
    grants = [e.id for e in prefix if e.kind in ("G", "D")]
    for p in prefix:
        for g in grants:
            # Full author mutations are covered on every candidate below.
            holder = prefix[g].target if prefix[g].kind == "D" else 0
            yield Event(i, "C", holder, g, (p.id,))
            for key in range(3):
                yield Event(i, "D", holder, g, (p.id,), key)
            for target in grants:
                yield Event(i, "R", holder, g, (p.id,), target)
    for n in range(2, len(prefix) + 1):
        for parents in combinations(range(len(prefix)), n):
            if any(p != q and p in anc[q] for p in parents for q in parents):
                continue
            for g in grants:
                holder = prefix[g].target if prefix[g].kind == "D" else 0
                yield Event(i, "S", holder, g, parents)


def check_grief(prefix):
    """Exhaust every revoked-grant old-parent correction, including wrong keys."""
    before = fold(prefix)
    for g in before.tombstones:
        for p in prefix:
            for key in range(3):
                attack = Event(len(prefix), "C", key, g, (p.id,))
                after = fold(prefix + (attack,))
                assert after.frontier == before.frontier, ("contest grief", prefix, attack,
                                                          before, after)
                assert after.tombstones == before.tombstones


def canonical_key(events):
    """Alpha-renaming only: erase creation order and swap non-root key names.

    This explores one representative per isomorphic event DAG, not one winner.
    The projection never calls this function or canonicalizes away event IDs.
    """
    def renamed(swap):
        def key(k):
            return 3 - k if swap and k in (1, 2) else k

        def search(done):
            if len(done) == len(events):
                return ()
            ids = {old: new for new, old in enumerate(done)}
            ready = []
            for e in events:
                if e.id in ids or any(p not in ids for p in e.parents):
                    continue
                if e.kind != "G" and e.grant not in ids:
                    continue
                target = key(e.target) if e.kind == "D" else ids.get(e.target, -1)
                sig = (e.kind, key(e.key), ids.get(e.grant, -1),
                       tuple(sorted(ids[p] for p in e.parents)), target)
                ready.append((sig, e.id))
            best = min(sig for sig, _ in ready)
            answers = []
            equivalent = set()
            for sig, i in ready:
                if sig != best:
                    continue
                # Identical leaves/uses are freely interchangeable.
                uses = tuple((e.id, i in e.parents, e.grant == i,
                              e.kind == "R" and e.target == i)
                             for e in events if i in e.parents or
                             (e.id != i and (e.grant == i or
                              (e.kind == "R" and e.target == i))))
                if uses in equivalent:
                    continue
                equivalent.add(uses)
                answers.append((best,) + search(done + (i,)))
            return min(answers)
        return search(())
    return min(renamed(False), renamed(True))


def exhaustive(max_events):
    counts = {"valid_prefixes": 0, "candidate_extensions": 0,
              "invalid_extensions": 0, "author_mutations": 0,
              "symmetry_duplicates": 0}
    seen = set()

    def visit(prefix):
        identity = canonical_key(prefix)
        if identity in seen:
            counts["symmetry_duplicates"] += 1
            return
        seen.add(identity)
        counts["valid_prefixes"] += 1
        before = check_invariants(prefix)
        if counts["valid_prefixes"] % 10000 == 0:
            print(f"Exhaustive states {counts['valid_prefixes']}, extensions {counts['candidate_extensions']}", flush=True)
        if len(prefix) >= max_events:
            return
        check_grief(prefix)
        for e in candidates(prefix):
            proposed = prefix + (e,)
            view = check_invariants(proposed)
            counts["candidate_extensions"] += 1
            assert fold(tuple(reversed(proposed))) == view, "I1 reversed import"
            # Every out-of-cut operation, not only Corrections, is harmless.
            # Root relinquishment is the explicit terminal control exception.
            if e.grant in set(before.tombstones) | set(before.canceled) and not (
                e.kind == "R" and e.grant == e.target == 0
            ):
                assert (view.frontier, view.active, view.effective_revokes) == (
                    before.frontier, before.active, before.effective_revokes
                ), ("revoked operation changes live state", prefix, e, before, view)
            for key in range(3):
                if key != e.key:
                    wrong = fold(prefix + (replace(e, key=key),))
                    row = dict((i, (s, r)) for i, s, r in wrong.rows)[e.id]
                    assert row == ("invalid", "parent_authority")
                    counts["author_mutations"] += 1
            if next(s for i, s, _ in view.rows if i == e.id) == "invalid":
                counts["invalid_extensions"] += 1
                before = fold(prefix)
                assert view.frontier == before.frontier and view.active == before.active
            else:
                visit(proposed)
    visit((G,))
    return counts


def named_cases():
    k = Event(1, "D", 0, 0, (0,), 1)
    c = Event(2, "D", 1, 1, (1,), 2)
    r = Event(3, "R", 0, 0, (2,), 1)
    old_parent_revoke = Event(4, "R", 1, 1, (2,), 2)
    cases = {}

    events = (G, k, Event(2, "R", 0, 0, (1,), 1),
              Event(3, "R", 1, 1, (1,), 0))
    v = check_invariants(events)
    assert v.frontier == (2,) and v.tombstones == (1,)
    assert (3, "invalid", "revocation_scope") in v.rows
    cases["i2_retroactive_revoke_from_old_parent_cannot_freeze"] = events

    events = (G, k, c, r, old_parent_revoke)
    v = check_invariants(events)
    assert v.effective_revokes == (3,) and 2 in v.active
    assert (4, "branch", "revoked_concurrent") in v.rows
    # The owner's literal union-of-branch-valid-Revokes rule would kill C.
    naive_tombstones = {e.target for e in events if e.kind == "R"}
    assert naive_tombstones == {1, 2} and set(v.tombstones) == {1}
    cases["literal_monotone_tombstone_counterexample"] = events

    events = (G, k, c, r, Event(4, "C", 2, 2, (3,)))
    v = check_invariants(events)
    assert 2 in v.active and not v.canceled and v.frontier == (4,)
    cases["i2_revoke_parent_equal_delegate_preserves_grant"] = events

    events = (G, k, c, Event(3, "R", 0, 0, (1,), 1),
              Event(4, "C", 2, 2, (2,)))
    v = check_invariants(events)
    assert v.canceled == (2,) and v.frontier == (3,)
    cases["i2_concurrent_delegate_descendants_do_not_contend"] = events

    events = (G, k, Event(2, "C", 1, 1, (1,)),
              Event(3, "R", 0, 0, (2,), 1),
              Event(4, "R", 0, 0, (1,), 1),
              Event(5, "S", 0, 0, (3, 4)),
              Event(6, "C", 1, 1, (1,)))
    v = check_invariants(events)
    assert (2, "branch", "revoked_concurrent") in v.rows
    assert (6, "branch", "revoked_concurrent") in v.rows
    # Resolve depending on a newly suppressed history cannot launder that branch.
    assert v.frontier == (4,)
    cases["i2_multiple_revokes_intersect_acknowledged_pasts"] = events

    events = (G, k, Event(2, "C", 0, 0, (1,)),
              Event(3, "C", 1, 1, (1,)),
              Event(4, "S", 0, 0, (2, 3)),
              Event(5, "R", 0, 0, (1,), 1),
              Event(6, "C", 0, 0, (5,)))
    v = check_invariants(events)
    assert v.frontier == (2, 6)  # A's real competing body still needs resolution.
    assert (4, "branch", "revoked_ancestor") in v.rows
    cases["i2_revoked_branch_cannot_launder_through_resolution"] = events

    events = (G, Event(1, "C", 0, 0, (0,)), Event(2, "C", 0, 0, (0,)),
              Event(3, "S", 0, 0, (1, 2)), Event(4, "S", 0, 0, (1, 2)),
              Event(5, "S", 0, 0, (3, 4)), Event(6, "C", 0, 0, (5,)))
    assert check_invariants(events).frontier == (6,)
    cases["i1_competing_resolutions_and_join"] = events

    events = (G, k, Event(2, "R", 0, 0, (1,), 0),
              Event(3, "C", 1, 1, (2,)))
    assert check_invariants(events).frontier == (3,)
    cases["i2_root_only_relinquishment_and_prior_delegate"] = events
    return cases


def transport_checks(events):
    expected = check_invariants(events)
    count = 0
    for order in permutations(events):
        assert fold(order) == expected
        count += 1
    # Every subset as the first import partition; independent local fold before union.
    partitions = 0
    for bits in range(1 << len(events)):
        left = tuple(e for i, e in enumerate(events) if bits & (1 << i))
        right = tuple(e for i, e in enumerate(events) if not bits & (1 << i))
        fold(left)
        fold(right)
        assert fold(left + right + left) == expected
        partitions += 1
    return count, partitions


@st.composite
def dags(draw):
    events = [G]
    for i in range(1, draw(st.integers(1, 7))):
        kind = draw(st.sampled_from(("C", "D", "R", "S")))
        parents = tuple(sorted(draw(st.sets(st.integers(0, i - 1), min_size=1,
                                           max_size=min(i, 3)))))
        if kind != "S":
            parents = parents[:1]
        events.append(Event(i, kind, draw(st.integers(0, 2)),
                            draw(st.integers(0, i - 1)), parents,
                            draw(st.integers(0, max(2, i - 1)))))
    return tuple(events)


def randomized(examples):
    @settings(max_examples=examples, derandomize=True, deadline=None, database=None)
    @given(dags(), st.data())
    def property_check(events, data):
        expected = check_invariants(events)
        order = data.draw(st.permutations(events))
        assert fold(order) == expected
        cut = data.draw(st.integers(0, len(events)))
        fold(order[:cut]); fold(order[cut:])
        assert fold(order[:cut] + order[cut:] + order[:cut]) == expected
        if len(events) < 7:
            check_grief(events)
    property_check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-events", type=int, default=7, choices=range(2, 8))
    parser.add_argument("--examples", type=int, default=3000)
    parser.add_argument("--output")
    args = parser.parse_args()
    start = time.monotonic()
    cases = named_cases()
    print("Named traces passed", flush=True)
    orderings = partitions = 0
    for events in cases.values():
        a, b = transport_checks(events)
        orderings += a; partitions += b
    print(f"Trace orderings {orderings}, bipartitions {partitions}", flush=True)
    totals = exhaustive(args.max_events)
    print(totals, flush=True)
    randomized(args.examples)
    report = {"model": "stage0-issuer-stratified-grant-revocation-v1",
              "keys": 3, "exhaustive_max_events": args.max_events,
              "symmetry": "event-ID alpha renaming and exchange of keys 1/2",
              "trace_max_events": 7, "named_cases": list(cases),
              "trace_orderings": orderings, "trace_bipartitions": partitions,
              "hypothesis_examples": args.examples, **totals,
              "seconds": round(time.monotonic() - start, 3), "result": "pass"}
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
