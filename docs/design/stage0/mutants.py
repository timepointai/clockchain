"""One-rule source mutants, isolated from the checked-in reference model.

Breadth-first search finds a smallest failing event count in the three-key
candidate grammar. Invalid reference extensions are tested but never extended.
A mutant must fail check.py in a subprocess on the reported trace; crashes,
patch mismatches, and surviving mutants fail this runner rather than count kills.
"""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types

import model
import check

NAMES = (
    "monotone_tombstones", "unscoped_revocation", "strict_cut_ancestry",
    "fork_point_resolve", "revoked_frontier", "lowest_id_wins", "ignore_cascade",
)


def replace_once(source, old, new):
    assert source.count(old) == 1, ("mutation anchor drift", old)
    return source.replace(old, new)


def mutated_source(name):
    source = Path(model.__file__).read_text()
    if name == "monotone_tombstones":
        start = source.index("    # Scope only points strictly down")
        end = source.index("    canceled = cancellations()\n    tombstones", start)
        return source[:start] + "    effective = revokes\n" + source[end:]
    if name == "unscoped_revocation":
        return replace_once(source, '''    return (signer_grant != target and signer_grant in lineage[target]) or (
        signer_grant == target and grants[target].kind == "G"
    )''', '    return True')
    if name == "strict_cut_ancestry":
        return replace_once(source, 'return e.id not in anc[r.parents[0]]',
                            'return e.id not in (anc[r.parents[0]] - {r.parents[0]})')
    if name == "fork_point_resolve":
        return replace_once(source, '''        available = set(joined_view.active)
        for v in parent_views:
            available.intersection_update(v.active)''', '''        if e.kind == "S":
            common = set.intersection(*(set(anc[p]) for p in e.parents))
            available = set(_fold(tuple(sorted(index[i] for i in common))).active)
        else:
            available = set(joined_view.active)
            for v in parent_views:
                available.intersection_update(v.active)''')
    if name == "revoked_frontier":
        return replace_once(source, '    eligible = set(index) - set(reasons) - relinquishments',
                            '''    eligible = (set(index) - set(reasons) - relinquishments) | {
        i for i, reason in reasons.items() if reason == "revoked_concurrent"
    }''')
    if name == "ignore_cascade":
        return replace_once(source, "r.target == grant or (r.cascade and r.target in lineage[grant])",
                            "r.target == grant")
    if name == "lowest_id_wins":
        return replace_once(source, '    frontier = eligible - consumed',
                            '''    frontier = eligible - consumed
    if frontier:
        frontier = {min(frontier)}''')
    raise ValueError(name)


def mutated_fold(name):
    module = types.ModuleType("stage0_mutant_" + name)
    sys.modules[module.__name__] = module
    exec(compile(mutated_source(name), module.__name__, "exec"), module.__dict__)
    # Share data types, not rules or caches. Dataclass equality is type-sensitive.
    module.Event, module.View = model.Event, model.View
    return module.fold


def failure(events, candidate_fold):
    original = check.fold
    check.fold = candidate_fold
    try:
        check.check_invariants(events)
    except AssertionError as error:
        label = error.args[0]
        return label[0] if isinstance(label, tuple) else str(label)
    finally:
        check.fold = original
    return None


def minimal_trace(candidate_fold, max_events):
    level = [(check.G,)]
    examined = 0
    for size in range(2, max_events + 1):
        following = []
        for prefix in level:
            for event in check.candidates(prefix):
                events = prefix + (event,)
                examined += 1
                check.check_invariants(events)  # control must pass first
                reason = failure(events, candidate_fold)
                if reason:
                    return events, reason, examined
                view = model.fold(events)
                if next(s for i, s, _ in view.rows if i == event.id) != "invalid":
                    following.append(events)
        level = following
    return None, None, examined


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-events", type=int, default=5)
    parser.add_argument("--output")
    args = parser.parse_args()
    started = time.monotonic()
    rows = []
    for name in NAMES:
        candidate_fold = mutated_fold(name)
        trace, reason, examined = minimal_trace(candidate_fold, args.max_events)
        row = {"mutant": name, "killed": trace is not None,
               "examined_extensions": examined,
               "mutated_source_sha256": hashlib.sha256(mutated_source(name).encode()).hexdigest()}
        if trace is not None:
            row.update(counterexample_size=len(trace), assertion=reason,
                       events=[asdict(e) for e in trace],
                       reference=asdict(model.fold(trace)), mutant_view=asdict(candidate_fold(trace)))
            # Actual check.py CLI must fail for the property, not a load error.
            with tempfile.TemporaryDirectory(prefix="stage0-mutant-") as directory:
                case = Path(directory) / "case.json"
                case.write_text(json.dumps(row["events"]))
                command = [sys.executable, str(Path(check.__file__)), "--case", str(case)]
                control = subprocess.run(command, capture_output=True, text=True)
                assert control.returncode == 0, control.stderr
                result = subprocess.run(command + ["--mutant", name], capture_output=True, text=True)
                assert result.returncode == 1 and json.loads(result.stdout)["result"] == "fail", result.stderr
            print(f"{name}: killed; minimum {len(trace)} events ({reason})", flush=True)
        else:
            print(f"{name}: SURVIVED through {args.max_events} events", flush=True)
        rows.append(row)
        model._fold.cache_clear()
    report = {"keys": 3, "max_events": args.max_events,
              "minimality": "breadth-first candidate grammar; no symmetry reduction",
              "source_sha256": {n: hashlib.sha256((Path(__file__).parent / n).read_bytes()).hexdigest()
                                for n in ("model.py", "check.py", "mutants.py", "requirements.txt")},
              "mutants": rows, "seconds": round(time.monotonic() - started, 3),
              "result": "pass" if all(r["killed"] for r in rows) else "surviving_mutant"}
    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "mutants"}, indent=2))
    if report["result"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
