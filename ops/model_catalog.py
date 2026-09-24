#!/usr/bin/env python3
"""Daily model discovery and explicit human selection; never auto-promotes."""
import argparse
import html
import json
from pathlib import Path
import sys

import model_policy as policy
from model_transport import public_json


def summarize(catalog):
    result = {}
    for model in catalog['data']:
        ident = model.get('id')
        if not isinstance(ident,str) or ident in result: raise ValueError('invalid model catalog id')
        result[ident] = {k:model.get(k) for k in ('id','name','created','context_length','pricing','supported_parameters','architecture')}
    return result


def refresh(registry):
    registry = policy.private(registry); registry.mkdir(parents=True,exist_ok=True,mode=0o700)
    catalog = public_json('https://openrouter.ai/api/v1/models')
    current = summarize(catalog)
    previous = {}
    last = registry/'catalog-latest.json'
    if last.exists():
        previous = policy.read(registry/'catalogs'/policy.read(last)['snapshot'])['models']
    name = policy.utc().replace(':','-')+'.json'
    candidates = []
    for ident, model in current.items():
        if ident not in previous or model != previous[ident]:
            candidates.append({'model':ident,'change':'new' if ident not in previous else 'changed',
                               'created':model['created'],'pricing':model['pricing'],
                               'rights':'not established by catalog','quality':'not evaluated','action':'human rights review, then bounded evaluation'})
    # Recency is a discovery order, not an intelligence/quality ranking.
    candidates.sort(key=lambda x:(-(x.get('created') or 0),x['model']))
    active = None
    try:
        route,selection = policy.selected(registry)
        active={'route':route['id'],'model':route['model'],'selection_sha256':selection,'available_in_catalog':route['model'] in current}
    except (ValueError,FileNotFoundError): pass
    report={'schema':'cc.model-discovery.v1','observed_at':policy.utc(),'models':current,
            'candidates':candidates,'removed':sorted(set(previous)-set(current)),'active':active,
            'automatic_selection':False,'paid_requests':0,'publication_enabled':False}
    policy.save(registry/'catalogs'/name,report)
    policy.save(last,{'snapshot':name},replace=True)
    e=lambda s:html.escape(str(s))
    rows=''.join('<tr><td>'+e(c['model'])+'</td><td>'+e(c['change'])+'</td><td>'+e(c['pricing'])+'</td><td>Rights review and evaluation required</td></tr>' for c in candidates)
    page='<!doctype html><html><meta charset="utf-8"><title>Clockchain daily model review</title><style>body{font:16px system-ui;max-width:1200px;margin:40px auto;padding:20px;background:#101720;color:#e3eaf2}td,th{padding:12px;border-bottom:1px solid #456;text-align:left}pre{white-space:pre-wrap}</style><h1>Daily model review</h1><p>'+e(report['observed_at'])+'</p><p>Humans choose the active model. Discovery does not establish permissiveness or intelligence, spend inference money, or change generation.</p><h2>Current selection</h2><pre>'+e(json.dumps(active,indent=2))+'</pre><h2>New or changed models</h2><p>Newest first; this is not a quality ranking.</p><table><tr><th>Model</th><th>Change</th><th>Catalog price</th><th>Next step</th></tr>'+rows+'</table><h2>Removed</h2><pre>'+e(json.dumps(report['removed']))+'</pre></html>'
    target=registry/'daily-review.html'; temp=registry/'.daily-review.tmp';temp.write_text(page);temp.chmod(0o600);temp.replace(target)
    return {'snapshot':name,'models':len(current),'new_or_changed':len(candidates),'removed':len(report['removed']),'active':active,'automatic_selection':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--registry',type=Path,required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('refresh');sub.add_parser('status')
    choose=sub.add_parser('select')
    choose.add_argument('--route',type=Path,required=True)
    for name in ('chosen-by','reason','decision-reference'): choose.add_argument('--'+name,required=True)
    a=p.parse_args()
    if a.command=='refresh': result=refresh(a.registry)
    elif a.command=='select':
        route,sha=policy.choose(a.registry,a.route,a.chosen_by,a.reason,a.decision_reference)
        result={'selected_route':route,'selection_sha256':sha,'publication_authorized':False}
    else:
        route,sha=policy.selected(a.registry);budget=policy.Budget(a.registry)
        try: result={'route':route['id'],'model':route['model'],'selection_sha256':sha,'budget':budget.status(),'publication_authorized':False}
        finally: budget.close()
    print(json.dumps(result))


if __name__=='__main__':
    try: main()
    except Exception as error:
        print(json.dumps({'error':type(error).__name__,'detail':str(error)[:200]}),file=sys.stderr);raise SystemExit(1)
