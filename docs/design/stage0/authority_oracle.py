"""Stage (b) G/C/D/R differential domain; accepted model/checker bytes unchanged.

Stdlib-only: load the checker's pure grammar/trace functions, not its Hypothesis
runner. Compare admission plus authority/suppression; no frontier equivalence.
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


def authority(events):
    v = fold(events)
    reasons = {'revoked_concurrent', 'revoked_ancestor', 'canceled_grant',
               'canceled_authority', 'root_relinquished'}
    return dict(rows=[[i, s if s in ('invalid', 'pending') else 'valid',
                       r if s in ('invalid', 'pending') else '',
                       r if r in reasons else ''] for i, s, r in v.rows],
                active=v.active, tombstones=v.tombstones,
                effective_revokes=v.effective_revokes, canceled=v.canceled)


def cases():
    result, seen, prefixes = [], set(), set()
    def add(name, events, exhaustive_subsets=False):
        key = tuple(events)
        if key in seen:
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
        result.append(dict(name=name, events=[asdict(e) for e in events],
                           checks=[dict(mask=m, expected=authority([e for e in events if m & (1 << e.id)]))
                                   for m in sorted(masks)]))
    def visit(prefix):
        key = namespace['canonical_key'](prefix)
        if key in prefixes: return
        prefixes.add(key)
        if len(prefix) == 4: return
        for e in namespace['candidates'](prefix):
            if e.kind == 'S': continue
            for signer in range(3):
                add('generated-small', prefix+(replace(e, key=signer),))
            candidate = prefix+(e,)
            if all(s not in ('invalid','pending') for _, s, _ in fold(candidate).rows):
                visit(candidate)
    visit((Event(0, 'G'),))
    for name, events in namespace['named_cases']().items():
        if any(e.kind == 'S' for e in events): continue  # (c), explicitly excluded
        add(name, events, True)
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
    return result

if __name__ == '__main__':
    print(json.dumps(cases(), separators=(',',':')))
