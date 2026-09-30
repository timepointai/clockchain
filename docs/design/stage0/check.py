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
import hashlib
from pathlib import Path
import time

from hypothesis import given, seed, settings, strategies as st
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
    def covered(r, grant):
        return r.target == grant or (r.cascade and r.target in lineage[grant])
    expected_tombstones = {g for g in grants if any(
        covered(index[r], g) for r in view.effective_revokes
    )}
    assert set(view.tombstones) == expected_tombstones, ("cascade coverage", events, view)
    # Check admitted transitions as well as visible heads: a bad Resolve can be
    # hidden by global suppression while still violating admission authority.
    for e in valid:
        if e.kind == "G":
            continue
        cones = [tuple(index[j] for j in anc[p] if j in index) for p in e.parents]
        for cone in cones:
            assert e.grant in fold(cone).active, ("I2 admitted parent", events, e)
        joined = tuple(set().union(*(set(c) for c in cones)))
        assert e.grant in fold(joined).active, ("I2 admitted join", events, e)
    for i, status, reason in view.rows:
        if reason == "revoked_concurrent":
            e = index[i]
            assert any(covered(index[r], e.grant) and i not in anc[index[r].parents[0]]
                       for r in view.effective_revokes), ("reflexive cut", events, i)
        # A valid unsuppressed leaf cannot disappear merely because a sibling
        # sorts before it. This is a completeness check, not just head safety.
        if i in valid_ids and reason not in (
            "revoked_concurrent", "revoked_ancestor", "canceled_grant",
            "canceled_authority", "root_relinquished"
        ) and not any(i != j and i in anc[j] for j in valid_ids):
            assert i in view.frontier, ("I3 eligible leaf lost", events, i)
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
            if covered(r, e.grant):
                # Historical acknowledged acts survive, never late revoked acts.
                assert e.id in anc[r.parents[0]], ("revoked sole/frontier", events, view)
    for rid in view.effective_revokes:
        r = index[rid]
        assert in_scope(grants, lineage, r.grant, r.target), ("scope", events, view)
        for other_id in view.effective_revokes:
            other = index[other_id]
            if covered(other, r.grant) and rid != other_id:
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
                for cascade in (False, True):
                    yield Event(i, "R", holder, g, (p.id,), target, cascade)
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
                       tuple(sorted(ids[p] for p in e.parents)), target, e.cascade)
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
    # Depth three: all grant issuances acknowledged, concurrent issuer cuts.
    chain = (G, Event(1, "D", 0, 0, (0,), 1),
             Event(2, "D", 1, 1, (1,), 2), Event(3, "D", 2, 2, (2,), 3))
    events = chain + (Event(4, "R", 0, 0, (3,), 1),
                      Event(5, "R", 1, 1, (3,), 2),
                      Event(6, "R", 2, 2, (3,), 3))
    v = check_invariants(events)
    assert v.effective_revokes == (4, 6) and v.active == (0, 2)
    assert v.frontier == (4, 6) and v.tombstones == (1, 3)
    assert (5, "branch", "revoked_concurrent") in v.rows
    # K survives because A's concurrent revoke of K is suppressed.
    assert fold(events + (Event(7, "S", 2, 2, (4, 6)),)).frontier == (7,)
    cases["i2_depth_three_concurrent_revocations_alternate"] = events

    # A's revoke of K is now acknowledged by G's revoke of A. Both are effective.
    events = chain + (Event(4, "R", 1, 1, (3,), 2),
                      Event(5, "R", 0, 0, (4,), 1),
                      Event(6, "R", 2, 2, (3,), 3))
    v = check_invariants(events)
    assert v.effective_revokes == (4, 5) and v.active == (0, 3)
    assert v.frontier == (5,) and v.tombstones == (1, 2)
    for grant in (1, 2):
        attempt = events + (Event(7, "S", grant, grant, (5, 6)),)
        assert (7, "invalid", "parent_authority") in fold(attempt).rows
    cases["i2_depth_three_acknowledged_revocation_blocks_counter_revoke"] = events
    compromised = (G, k, c, Event(3, "R", 0, 0, (2,), 1, True),
                   Event(4, "C", 2, 2, (2,)))
    v = check_invariants(compromised)
    assert v.tombstones == (1, 2) and v.active == (0,) and v.frontier == (3,)
    assert (4, "branch", "revoked_concurrent") in v.rows
    cases["i2_cascade_compromise_visible_attacker_delegates"] = compromised

    departure = (G, k, c, Event(3, "R", 0, 0, (2,), 1, False),
                 Event(4, "C", 2, 2, (3,)))
    v = check_invariants(departure)
    assert v.tombstones == (1,) and v.active == (0, 2) and v.frontier == (4,)
    cases["i2_non_cascade_honest_delegator_departure"] = departure

    # A suppressed cascade never kills the acknowledged descendant subtree.
    events = chain + (Event(4, "R", 0, 0, (3,), 1, False),
                      Event(5, "R", 1, 1, (3,), 2, True))
    v = check_invariants(events)
    assert v.effective_revokes == (4,) and v.active == (0, 2, 3)
    cases["i2_suppressed_cascade_has_no_descendant_effect"] = events
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
                            draw(st.integers(0, max(2, i - 1))),
                            draw(st.booleans()) if kind == "R" else False))
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



@st.composite
def depth_dags(draw):
    depth = draw(st.integers(3, 6))
    labels = (0,) + tuple(draw(st.permutations(tuple(range(1, depth + 1)))))
    events = [G]
    for i in range(1, depth + 1):
        events.append(Event(i, "D", labels[i - 1], i - 1, (i - 1,), labels[i]))
    upper = draw(st.integers(1, depth - 2))
    lower = draw(st.integers(upper + 1, depth - 1))
    target = draw(st.integers(lower + 1, depth))
    inner_cut = draw(st.integers(lower, depth))
    outer_cut = draw(st.integers(upper, depth))
    counter_cut = draw(st.integers(target, depth))
    acknowledged = draw(st.booleans())
    cascade = draw(st.booleans())
    inner, outer, counter = depth + 1, depth + 2, depth + 3
    events.extend((Event(inner, "R", labels[upper], upper, (inner_cut,), lower),
                   Event(outer, "R", 0, 0, (inner if acknowledged else outer_cut,), upper, cascade),
                   Event(counter, "R", labels[lower], lower, (counter_cut,), target)))
    return tuple(events), (depth, upper, lower, target, inner_cut, outer_cut, acknowledged, cascade)


def targeted_depth(examples):
    started = time.monotonic()
    seen = {"examples_executed": 0, "max_chain_depth_reached": 0,
            "max_events_reached": 0, "max_keys_reached": 0,
            "acknowledged": 0, "concurrent": 0, "cascade": 0}

    @seed(20260929)
    @settings(max_examples=examples, derandomize=True, deadline=None, database=None)
    @given(depth_dags(), st.data())
    def property_check(case, data):
        events, shape = case
        depth, upper, lower, target, inner_cut, outer_cut, acknowledged, cascade = shape
        view = check_invariants(events)
        inner, outer, counter = depth + 1, depth + 2, depth + 3
        # Independent predictions for these specific three-revoke traces.
        if cascade:
            expected_effective = {inner, outer} if acknowledged else {outer}
            expected_tombstones = set(range(upper, depth + 1))
            assert target not in view.active
        elif acknowledged:
            expected_effective = {inner, outer}
            expected_tombstones = {upper, lower}
            assert (target in view.active) == (inner_cut > lower)
        elif outer_cut == upper:
            expected_effective, expected_tombstones = {outer}, {upper}
            assert lower in view.canceled and target in view.canceled
        else:
            expected_effective, expected_tombstones = {outer, counter}, {upper, target}
            assert lower in view.active
        assert set(view.effective_revokes) == expected_effective, ("depth effects", events, view)
        assert set(view.tombstones) == expected_tombstones, ("depth tombstones", events, view)
        # Every revoked/canceled actor tries an old-parent correction and revoke.
        old_parent = data.draw(st.integers(0, depth))
        for grant in set(view.tombstones) | set(view.canceled):
            holder = events[grant].target
            for kind in ("C", "R"):
                attack = Event(len(events), kind, holder, grant, (old_parent,), target)
                after = check_invariants(events + (attack,))
                assert (after.frontier, after.active, after.effective_revokes) == (
                    view.frontier, view.active, view.effective_revokes
                ), ("depth old-parent grief", events, attack, after)
        order = data.draw(st.permutations(events))
        assert fold(order) == view
        cut = data.draw(st.integers(0, len(order)))
        fold(order[:cut]); fold(order[cut:])
        assert fold(order[:cut] + order[cut:] + order[:cut]) == view
        seen["cascade"] += int(cascade)
        seen["examples_executed"] += 1
        seen["max_chain_depth_reached"] = max(seen["max_chain_depth_reached"], depth)
        seen["max_events_reached"] = max(seen["max_events_reached"], len(events) + 1)
        seen["max_keys_reached"] = max(seen["max_keys_reached"], depth + 1)
        seen["acknowledged" if acknowledged else "concurrent"] += 1
    property_check()
    assert seen["max_chain_depth_reached"] >= 3
    return {**seen, "requested_examples": examples, "seed": 20260929,
            "derandomize": True, "seconds": round(time.monotonic() - started, 3)}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-events", type=int, default=7, choices=range(2, 8))
    parser.add_argument("--examples", type=int, default=3000)
    parser.add_argument("--output")
    parser.add_argument("--mutant", help="Test-only one-rule replacement from mutants.py")
    parser.add_argument("--case", help="JSON event trace, for mutation subprocess checks")
    parser.add_argument("--depth-examples", type=int, default=0)
    args = parser.parse_args()
    if args.mutant:
        from mutants import mutated_fold
        global fold
        fold = mutated_fold(args.mutant)
    if args.case:
        events = tuple(Event(**dict(e, parents=tuple(e["parents"])))
                       for e in json.loads(Path(args.case).read_text()))
        try:
            check_invariants(events)
        except AssertionError as error:
            print(json.dumps({"result": "fail", "assertion": str(error)}))
            raise SystemExit(1)
        print(json.dumps({"result": "pass"}))
        return
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
    depth_report = targeted_depth(args.depth_examples) if args.depth_examples else None
    report = {"model": "stage0-issuer-stratified-cascade-revocation-v1",
              "keys": 3, "exhaustive_max_events": args.max_events,
              "symmetry": "event-ID alpha renaming and exchange of keys 1/2",
              "trace_max_events": 7, "named_cases": list(cases),
              "trace_orderings": orderings, "trace_bipartitions": partitions,
              "hypothesis_examples": args.examples, "depth": depth_report, **totals,
              "source_sha256": {n: hashlib.sha256((Path(__file__).parent / n).read_bytes()).hexdigest()
                                for n in ("model.py", "check.py", "requirements.txt")},
              "seconds": round(time.monotonic() - start, 3), "result": "pass"}
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
