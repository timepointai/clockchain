"""Stage 0 executable specification; no IO, crypto, SQL, or production imports.

IDs are symbols, not priorities. Ancestors are reflexive. Authority is scoped to
an exact grant; two independent grants to one key do not share revocation scope.
"""
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True, order=True)
class Event:
    id: int
    kind: str
    key: int = 0
    grant: int = 0
    parents: tuple[int, ...] = ()
    target: int = -1  # Delegate: key; Revoke: grant.
    cascade: bool = False  # Revoke only; signed, explicit in wire v1.


@dataclass(frozen=True)
class View:
    rows: tuple[tuple[int, str, str], ...]
    frontier: tuple[int, ...]
    active: tuple[int, ...]
    tombstones: tuple[int, ...]
    effective_revokes: tuple[int, ...]
    canceled: tuple[int, ...]

    @property
    def contested(self):
        return len(self.frontier) > 1


def ancestry(events):
    """Reflexive ancestor sets, including missing symbols; cycles rejected."""
    index = {e.id: e for e in events}
    result, visiting = {}, set()

    def visit(i):
        if i in result:
            return result[i]
        if i in visiting:
            raise ValueError("cycle")
        visiting.add(i)
        out = {i}
        if i in index:
            for parent in index[i].parents:
                out.update(visit(parent))
        visiting.remove(i)
        result[i] = frozenset(out)
        return result[i]

    for i in index:
        visit(i)
    return result


def grant_tree(events):
    grants = {e.id: e for e in events if e.kind in ("G", "D")}
    depth, lineage = {}, {}

    def visit(g):
        if g not in depth:
            e = grants[g]
            if e.kind == "G":
                depth[g], lineage[g] = 0, frozenset((g,))
            else:
                visit(e.grant)
                depth[g] = depth[e.grant] + 1
                lineage[g] = lineage[e.grant] | {g}
        return depth[g]

    for g in grants:
        visit(g)
    return grants, depth, lineage


def in_scope(grants, lineage, signer_grant, target):
    return (signer_grant != target and signer_grant in lineage[target]) or (
        signer_grant == target and grants[target].kind == "G"
    )


def project(valid):
    """Project already parent-valid events. Root-to-leaf revoke stratification."""
    if not valid:
        return View((), (), (), (), (), ())
    index = {e.id: e for e in valid}
    anc = ancestry(valid)
    grants, depth, lineage = grant_tree(valid)
    revokes = [e for e in valid if e.kind == "R"]
    effective = []

    def covers(r, grant):
        return r.target == grant or (r.cascade and r.target in lineage[grant])

    def outside_cut(e, r):
        return e.id not in anc[r.parents[0]]

    def cancellations():
        canceled = set()
        for g in sorted(grants, key=lambda x: depth[x]):
            e = grants[g]
            if e.kind == "D" and (
                e.grant in canceled or any(
                    covers(r, e.grant) and outside_cut(e, r) for r in effective
                )
            ):
                canceled.add(g)
        return canceled

    # Scope only points strictly down the grant tree, except root relinquishment.
    # Relinquishments are terminal controls; they do not revoke one another.
    effective.extend(r for r in revokes if r.grant == r.target == 0)
    for level in range(max(depth.values()) + 1):
        canceled = cancellations()
        batch = []
        for r in revokes:
            if depth[r.grant] != level or r.grant == r.target == 0:
                continue
            if r.grant in canceled:
                continue
            if any(covers(q, r.grant) and outside_cut(r, q) for q in effective):
                continue
            batch.append(r)
        effective.extend(batch)
    canceled = cancellations()
    tombstones = {g for g in grants if any(covers(r, g) for r in effective)}
    active = set(grants) - canceled - tombstones
    reasons = {}
    relinquishments = {r.id for r in effective if r.target == r.grant == 0}
    for e in valid:
        if e.id in relinquishments:
            continue  # consumes its parent, but never offers a body head
        if any(covers(r, e.grant) and outside_cut(e, r) for r in effective):
            reasons[e.id] = "revoked_concurrent"
        elif e.kind == "D" and e.id in canceled:
            reasons[e.id] = "canceled_grant"
        elif e.grant in canceled:
            reasons[e.id] = "canceled_authority"
    # A good signer must re-author on a surviving parent, not extend tainted data.
    changed = True
    while changed:
        changed = False
        for e in valid:
            if e.id not in reasons and e.id not in relinquishments and any(
                p in reasons for p in e.parents
            ):
                reasons[e.id] = "revoked_ancestor"
                changed = True
    eligible = set(index) - set(reasons) - relinquishments
    consumed = set()
    for i in eligible | {r.id for r in effective}:
        consumed.update(anc[i] - {i})
    frontier = eligible - consumed
    # Common history is superseded; all other eligible histories remain branches.
    common = set.intersection(*(set(anc[i]) for i in frontier)) if frontier else set()
    rows = []
    for i in sorted(index):
        if i in reasons:
            rows.append((i, "branch", reasons[i]))
        elif i in relinquishments:
            rows.append((i, "superseded", "root_relinquished"))
        elif len(frontier) == 1 and i in frontier:
            rows.append((i, "head", ""))
        elif len(frontier) > 1 and (i in frontier or i not in common):
            rows.append((i, "branch", "contested"))
        else:
            rows.append((i, "superseded", ""))
    return View(tuple(rows), tuple(sorted(frontier)), tuple(sorted(active)),
                tuple(sorted(tombstones)), tuple(sorted(r.id for r in effective)),
                tuple(sorted(canceled)))


@lru_cache(maxsize=50000)
def _fold(events):
    index = {e.id: e for e in events}
    if len(index) != len(events):
        raise ValueError("colliding symbolic IDs")
    try:
        anc = ancestry(events)
    except ValueError:
        return View(tuple((e.id, "invalid", "cycle") for e in events), (), (), (), (), ())
    valid, rejected = {}, {}

    def evaluate(e):
        if e.id in valid or e.id in rejected:
            return
        if type(e.cascade) is not bool or (e.cascade and e.kind != "R"):
            rejected[e.id] = ("invalid", "cascade_kind")
            return
        if e.kind == "G":
            if e != Event(0, "G"):
                rejected[e.id] = ("invalid", "genesis")
            else:
                valid[e.id] = e
            return
        if e.kind not in ("C", "D", "R", "S"):
            rejected[e.id] = ("invalid", "kind")
            return
        if (len(set(e.parents)) != len(e.parents) or not e.parents or
                (e.kind != "S" and len(e.parents) != 1) or
                (e.kind == "S" and len(e.parents) < 2)):
            rejected[e.id] = ("invalid", "parents")
            return
        if any(p not in index for p in e.parents):
            rejected[e.id] = ("pending", "parent_missing")
            return
        for p in e.parents:
            evaluate(index[p])
        if any(p in rejected for p in e.parents):
            why = "invalid" if any(rejected.get(p, (None,))[0] == "invalid"
                                   for p in e.parents) else "pending"
            rejected[e.id] = (why, "ancestor")
            return
        if e.kind == "S" and any(
            p != q and p in anc[q] for p in e.parents for q in e.parents
        ):
            rejected[e.id] = ("invalid", "comparable_parents")
            return
        parent_cones = [tuple(sorted(index[i] for i in anc[p] if i in index))
                        for p in e.parents]
        parent_views = [_fold(cone) for cone in parent_cones]
        joined = tuple(sorted(set().union(*(set(c) for c in parent_cones))))
        joined_view = _fold(joined)
        available = set(joined_view.active)
        for v in parent_views:
            available.intersection_update(v.active)
        grant = index.get(e.grant)
        grant_key = (grant.target if grant.kind == "D" else grant.key) if grant else -1
        if e.grant not in available or e.key != grant_key:
            rejected[e.id] = ("invalid", "parent_authority")
            return
        if e.kind == "D":
            if type(e.target) is not int or e.target < 0:
                rejected[e.id] = ("invalid", "key")
                return
            if any((x.target if x.kind == "D" else x.key) == e.target
                   for x in joined if x.kind in ("G", "D")):
                rejected[e.id] = ("invalid", "key_not_fresh")
                return
        if e.kind == "R":
            parent_valid_ids = {i for i, status, _ in joined_view.rows
                                if status not in ("invalid", "pending")}
            tree = tuple(x for x in joined if x.id in parent_valid_ids)
            grants, _, lineage = grant_tree(tree)
            if (e.target not in available or
                    not in_scope(grants, lineage, e.grant, e.target)):
                rejected[e.id] = ("invalid", "revocation_scope")
                return
        valid[e.id] = e

    for e in events:
        evaluate(e)
    view = project(tuple(valid.values()))
    rows = dict((i, (s, r)) for i, s, r in view.rows)
    rows.update(rejected)
    return View(tuple((i, *rows[i]) for i in sorted(rows)), view.frontier,
                view.active, view.tombstones, view.effective_revokes, view.canceled)


def fold(events):
    """Set-union admission, including duplicates and arbitrary import partitions."""
    return _fold(tuple(sorted(set(events))))
