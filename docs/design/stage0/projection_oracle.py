"""Stage (c) full G/C/D/R/S differential domain; accepted model/checker bytes unchanged.

Stdlib-only: load the checker's pure grammar/trace functions, not its Hypothesis
runner. Compare full fold rows, frontier, authority effects and Resolve admission.
"""
import ast
from dataclasses import asdict, replace
from itertools import combinations
import json
from pathlib import Path
import random
from model import Event, fold, ancestry

source = ast.parse(Path(__file__).with_name('check.py').read_text())
functions = ast.Module(body=[n for n in source.body if isinstance(n, ast.FunctionDef)
                            and n.name in ('named_cases', 'candidates', 'canonical_key')], type_ignores=[])
namespace = dict(Event=Event, G=Event(0, 'G'), fold=fold, check_invariants=fold,
                 ancestry=ancestry, combinations=combinations)
exec(compile(functions, 'check.py:pure-functions', 'exec'), namespace)


def projection(events):
    v = fold(events)
    return dict(rows=v.rows, frontier=v.frontier, active=v.active,
                tombstones=v.tombstones, effective_revokes=v.effective_revokes,
                canceled=v.canceled,
                resolve=[[i, status if status in ('invalid', 'pending') else 'valid',
                          reason if status in ('invalid', 'pending') else '']
                         for i, status, reason in v.rows
                         if next(e for e in events if e.id == i).kind == 'S'])


def cases():
    result, seen, prefixes = [], set(), set()
    named = namespace['named_cases']()
    def add(name, events, exhaustive_subsets=False):
        key = tuple(events)
        if key in seen and name not in named:
            return
        seen.add(key)
        n = len(events)
        # All partitions for small DAGs and named traces; depth gets each cut,
        # singleton loss and a deterministic alternating partition as well.
        masks = set(range(1 << n)) if n <= 4 or exhaustive_subsets else {
            0, (1 << n)-1, sum(1 << i for i in range(0, n, 2))}
        masks.update((1 << i)-1 for i in range(n+1))
        masks.update(((1 << n)-1) ^ (1 << i) for i in range(n))
        masks |= {((1 << n)-1) ^ m for m in list(masks)}
        result.append(dict(name=name, permutations=name in named, events=[asdict(e) for e in events],
                           checks=[dict(mask=m, expected=projection([e for e in events if m & (1 << e.id)]))
                                   for m in sorted(masks)]))
    def visit(prefix):
        key = namespace['canonical_key'](prefix)
        if key in prefixes: return
        prefixes.add(key)
        if len(prefix) == 4: return
        for e in namespace['candidates'](prefix):
            for signer in range(3):
                add('generated-small', prefix+(replace(e, key=signer),))
            candidate = prefix+(e,)
            if all(s not in ('invalid','pending') for _, s, _ in fold(candidate).rows):
                visit(candidate)
    for name, events in named.items():
        add(name, events, True)
    visit((Event(0, 'G'),))
    # Distinct concurrent grants to the same key are independent capabilities.
    add('independent-grants', (Event(0,'G'), Event(1,'D',0,0,(0,),1),
        Event(2,'D',0,0,(0,),1), Event(3,'R',0,0,(1,),1,True),
        Event(4,'C',1,2,(2,))), True)
    # Multiple cuts and suppressed body ancestors without a Resolve.
    add('intersect-cuts', (Event(0,'G'), Event(1,'D',0,0,(0,),1),
        Event(2,'C',1,1,(1,)), Event(3,'R',0,0,(2,),1),
        Event(4,'R',0,0,(1,),1), Event(5,'C',0,0,(2,))), True)
    rng = random.Random(20260930)
    for _ in range(150):
        depth = rng.randrange(3,7)
        events = [Event(0,'G')] + [Event(i,'D',i-1,i-1,(i-1,),i) for i in range(1,depth+1)]
        upper = rng.randrange(1,depth-1); lower = rng.randrange(upper+1,depth)
        inner = Event(depth+1,'R',upper,upper,(rng.randrange(lower,depth+1),),lower)
        outer = Event(depth+2,'R',0,0,(inner.id if rng.choice((True,False)) else rng.randrange(upper,depth+1),),upper,rng.choice((True,False)))
        counter = Event(depth+3,'R',lower,lower,(depth,),depth,rng.choice((True,False)))
        add('generated-depth', tuple(events+[inner,outer,counter]))
    # Explicit admission probes absent from the Stage (b) domain: branch-only
    # grants, comparable parents, partial joins, and crisscross survivor joins.
    base = (Event(0,'G'), Event(1,'C',0,0,(0,)), Event(2,'C',0,0,(0,)), Event(3,'C',0,0,(0,)))
    add('partial-join-late-eligible', base+(Event(4,'S',0,0,(1,2)),), True)
    add('comparable-resolve', base+(Event(4,'S',0,0,(0,1)),), True)
    add('branch-only-resolver', (Event(0,'G'), Event(1,'D',0,0,(0,),1),
        Event(2,'C',0,0,(0,)), Event(3,'S',1,1,(1,2))), True)
    add('crisscross-common-grants', (Event(0,'G'), Event(1,'D',0,0,(0,),1),
        Event(2,'D',0,0,(1,),2), Event(3,'C',1,1,(2,)), Event(4,'C',2,2,(2,)),
        Event(5,'S',1,1,(3,4)), Event(6,'S',2,2,(3,4)), Event(7,'S',1,1,(5,6))), True)
    named = namespace['named_cases']()
    for name, parents in [('i2_depth_three_concurrent_revocations_alternate',(4,6)),
                           ('i2_depth_three_acknowledged_revocation_blocks_counter_revoke',(5,6))]:
        for grant in (0,1,2,3):
            events = named[name]
            add('depth-resolve-'+name+str(grant), events+(Event(len(events),'S',grant,grant,parents),), True)
    # Seeded malformed/valid mixes through seven events (all dependency symbols
    # exist in the full DAG; masks independently test missing deliveries).
    for _ in range(150):
        events = [Event(0,'G')]
        for i in range(1,rng.randrange(3,8)):
            kind = rng.choice(('C','D','R','S'))
            parents = tuple(sorted(rng.sample(range(i), rng.randrange(1,min(i,3)+1)))) if kind == 'S' else (rng.randrange(i),)
            events.append(Event(i,kind,rng.randrange(3),rng.randrange(i),parents,
                                rng.randrange(3) if kind == 'D' else rng.randrange(i) if kind == 'R' else -1,
                                rng.choice((False,True)) if kind == 'R' else False))
        add('generated-mixed',tuple(events),True)
    return result

if __name__ == '__main__':
    print(json.dumps(cases(), separators=(',',':')))
