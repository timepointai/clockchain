#!/usr/bin/env python3
"""Repeatable, bounded evaluation of the human-selected route; no promotion."""
import argparse
import concurrent.futures
import json
from pathlib import Path
import re

import model_policy as policy
import model_runtime as runtime


def evaluate(registry, suite_path, output, workers=2):
    route,selection=policy.selected(registry)
    suite=policy.read(suite_path)
    policy.exact(suite,'schema id split cases')
    if suite['schema']!='cc.model-suite.v1' or suite['split'] not in ('development','held_out','audit'):
        raise ValueError('invalid evaluation suite')
    if not 1 <= len(suite['cases']) <= 20: raise ValueError('suite size outside bound')
    policy.integer(workers,1,4)
    ids=set(); frozen=[]
    for c in suite['cases']:
        policy.exact(c,'id brief sources expected_status max_edges')
        if not re.fullmatch('[a-z0-9_-]+',c['id']) or c['id'] in ids: raise ValueError('invalid case id')
        ids.add(c['id']);policy.integer(c['max_edges'],0,2)
        if c['expected_status'] not in ('proposal','needs_evidence','conflicting_evidence','abstained'):raise ValueError('invalid expected status')
        brief=policy.read(c['brief']); sources=policy.read(c['sources'])
        runtime.packet(brief,runtime.local.load_sources(sources))
        frozen.append((c,brief,sources))
    out=policy.private(output);out.mkdir(parents=True,mode=0o700,exist_ok=False)
    cases=[]; bindings=[]
    for c,brief,sources in frozen:
        base=out/'fixtures'/c['id']
        policy.save(base/'brief.json',brief); policy.save(base/'sources.json',sources)
        cases.append({**c,'brief':str(base/'brief.json'),'sources':str(base/'sources.json')})
        bindings.append({'id':c['id'],'brief_sha256':policy.digest(policy.canonical(brief)),
                         'sources_sha256':policy.digest(policy.canonical(sources))})
    policy.save(out/'registration.json',{'suite':suite,'frozen_cases':bindings,'suite_sha256':policy.digest(policy.canonical(suite)),
        'selection_sha256':selection,'route_sha256':policy.digest(policy.canonical(route)),'registered_at':policy.utc(),
        'note':'Labels excluded from prompts; repeat use of a held-out suite must be reported as development.'})
    def one(c):
        result=runtime.run(registry,Path(c['brief']),Path(c['sources']),out/c['id'],selection)
        passed=result['status']==c['expected_status'] and result.get('edges',0)<=c['max_edges']
        return {'case':c['id'],'deterministic_pass':passed,'result':result,'semantic_review':'pending'}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool: results=list(pool.map(one,cases))
    report={'schema':'cc.model-evaluation.v1','suite_id':suite['id'],'split':suite['split'],'selection_sha256':selection,
            'cases':results,'deterministic_pass_count':sum(r['deterministic_pass'] for r in results),'total':len(results),
            'semantic_review':'required; not established by deterministic success','promotion':'human decision required','published':False}
    policy.save(out/'evaluation.json',report);return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('registry','suite','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--workers',type=int,default=2);a=p.parse_args()
    result=evaluate(a.registry,a.suite,a.output,a.workers)
    print(json.dumps({'deterministic_pass':result['deterministic_pass_count'],'total':result['total'],'semantic_review':'pending'}))
