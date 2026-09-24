#!/usr/bin/env python3
"""Configurable source-bound text proposals. No staging, approval or publication."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse
import uuid

import jsonschema
import local_generate as local
import model_policy as policy
from model_transport import public_json

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ('DATABASE_URL','CC_DATABASE_URL','TEST_DATABASE_URL','MIGRATOR_SECRET_KEY',
             'GENESIS_SECRET_KEY','CC_LEDGER_SIGNING_KEY','CC_NODE_API_KEY','CC_NODE_READ_KEY')
INSTRUCTION = local.INSTRUCTION.replace('source_id,excerpt,supports', 'source_id,passage_index,supports').replace(
    'Each excerpt must be a literal substring of a supplied passage.',
    'Use a zero-based passage_index; software attaches the exact captured text. Do not return excerpt strings.') + '''
Return {status,reason,entries,edges}. status is proposal, needs_evidence, conflicting_evidence or abstained.
For proposal, return 1..max_entries entries and 0..max_edges edges, with reason a brief explanation of coverage/omissions. For other statuses return empty entries and edges and a nonempty reason. Bounds are maxima, never quotas. Omit a causal edge when only sequence or an inferred mechanism is supplied; do not label inference as SecondarySource. An empty edge list is valid. Do not fill missing facts using outside knowledge. Missing dates must not be fabricated; abstain if no supported year can be expressed. Every field, including citation/calendar rationales, must be source-supported. Distinguish absence of a report from proof of nonoccurrence. Prefer summaries of 180–260 characters, within 160–320. Return only JSON; entries precede edges. No tools or images.'''


def packet(brief, sources):
    policy.integer(brief['max_entries'], 1, 3); policy.integer(brief['max_edges'], 0, 2)
    labels = [{k:n[k] for k in ('id','lens')} for n in policy.read(ROOT/'vendor/tt/taxonomy-v2.1.json')['nodes'] if n.get('level')=='species']
    allowed = brief.get('allowed_claim_types', [n['id'] for n in labels])
    if not allowed or not set(allowed) <= {n['id'] for n in labels}: raise ValueError('unknown TT label')
    labels = [n for n in labels if n['id'] in allowed]
    schema = local.output_schema(labels, brief)
    schema['properties']['entries']['minItems'] = 0
    schema['properties']['status'] = {'enum':['proposal','needs_evidence','conflicting_evidence','abstained']}
    schema['properties']['reason'] = {'type':'string','minLength':1,'maxLength':2000}
    schema['required'] += ['status','reason']
    schema['properties']['entries']['items']['properties']['summary']['maxLength'] = 320
    for item in (schema['properties']['entries']['items'], schema['properties']['edges']['items']):
        ev = item['properties']['evidence']['items']; ev['required'].remove('excerpt'); ev['required'].append('passage_index')
        del ev['properties']['excerpt']
        ev['properties']['source_id'] = {'enum':list(sources)}
        ev['properties']['passage_index'] = {'type':'integer','minimum':0}
    return {'brief':brief,'sources':[{k:s[k] for k in ('id','publisher','passages')} for s in sources.values()],
            'taxonomy':labels,'output_schema':schema}


def payload(route, messages):
    settings = route['settings']; prices = route['prices']
    return {'model':route['model'],'provider':{'only':[route['provider_slug']],
            'allow_fallbacks':False,'data_collection':'deny','require_parameters':True,
            'quantizations':[route['quantization']],
            'max_price':{'prompt':float(policy.amount(prices['prompt_per_million_usd'])),
                         'completion':float(policy.amount(prices['completion_per_million_usd']))}},
            'temperature':settings['temperature'],'top_p':settings['top_p'],
            'reasoning':settings['reasoning'],'max_tokens':settings['max_tokens'],
            'stream':False,'messages':messages}


def estimate(route, request):
    # UTF-8 bytes overestimate input tokens; include framing overhead. Output
    # ceiling includes reasoning. Unknown non-token surcharges are rejected.
    prices = route['prices']
    usd = ((len(local.wire(request))+4096)*policy.amount(prices['prompt_per_million_usd']) +
           route['settings']['max_tokens']*policy.amount(prices['completion_per_million_usd'])) / 1_000_000
    return policy.micro(usd)


def check_endpoint(route, request, catalog):
    endpoints = catalog['data']['endpoints']
    choices = [e for e in endpoints if e.get('provider_name') == route['provider']]
    if not choices: raise ValueError('selected provider unavailable; human must choose another route')
    if len(choices) != 1:
        raise ValueError('ambiguous provider endpoints; human must review routing')
    required = {'max_tokens','temperature','top_p','reasoning'}
    for endpoint in choices:
        if endpoint.get('name') != route['endpoint_name'] or endpoint.get('quantization') != route['quantization']: continue
        prices = endpoint.get('pricing',{})
        if not {'prompt','completion'} <= set(prices): continue
        if any(policy.amount(v) != 0 for k,v in prices.items() if k not in ('prompt','completion','input_cache_read','input_cache_write','discount') and v is not None): continue
        if policy.amount(prices['prompt'])*1_000_000 > policy.amount(route['prices']['prompt_per_million_usd']): continue
        if policy.amount(prices['completion'])*1_000_000 > policy.amount(route['prices']['completion_per_million_usd']): continue
        if any(policy.amount(prices.get(k) or 0) > policy.amount(prices['prompt']) for k in ('input_cache_read','input_cache_write')): continue
        if not required <= set(endpoint.get('supported_parameters',[])): continue
        maximum = endpoint.get('max_completion_tokens')
        if maximum is not None and maximum < request['max_tokens']: continue
        if endpoint.get('context_length',0) < len(local.wire(request))+4096+request['max_tokens']: continue
        return
    raise ValueError('selected endpoint price, context or parameter capability changed')


def response_output(route, response):
    if response.get('model') != route['model'] or response.get('provider') != route['provider']:
        raise ValueError('returned route mismatch')
    choices = response.get('choices',[])
    if len(choices) != 1 or choices[0].get('finish_reason') != 'stop': raise ValueError('incomplete model response')
    return local.decode_output(choices[0]['message']['content'])


def make_proposal(raw, sources, route, brief, run, request, response, schema):
    jsonschema.validate(raw, schema)
    if raw['status'] != 'proposal':
        if raw['entries'] or raw['edges']: raise ValueError('abstention cannot contain publishable records')
        return None
    if not raw['entries']: raise ValueError('proposal cannot be empty')
    expanded = copy.deepcopy({k:raw[k] for k in ('entries','edges')})
    for item in expanded['entries']+expanded['edges']:
        for ev in item['evidence']:
            idx = ev.pop('passage_index'); s = sources[ev['source_id']]
            if idx >= len(s['passages']): raise ValueError('passage index out of range')
            ev['excerpt'] = s['passages'][idx]
    p = local.proposal(expanded, sources, {'model':route['model'],'model_digest':None}, brief,
                       run, policy.digest(policy.canonical(request)), policy.digest(policy.canonical(response)))
    for entry in p['entries']:
        m = entry['prov_measured']; m.pop('model_digest')
        m.update(provider=route['provider'],router='OpenRouter',hosted_weight_digest=route['hosted_weight_digest'],
                 policy_sha256=policy.digest(policy.canonical(route)),model_route_id=route['id'],
                 reasoning_requested=route['settings']['reasoning'],temperature=route['settings']['temperature'],
                 top_p=route['settings']['top_p'],max_output_tokens_requested=route['settings']['max_tokens'],
                 openrouter_generation_id=response['id'],api_charge_usd=response['usage']['cost'])
    return p


def run(registry, brief_path, sources_path, output, expected_selection=None):
    if any(os.environ.get(k) for k in FORBIDDEN): raise ValueError('remove database/publication credentials from inference environment')
    route, selection = policy.selected(registry, expected_selection)
    brief = policy.read(brief_path); manifest = policy.read(sources_path)
    sources = local.load_sources(manifest); task = packet(brief, sources)
    request = payload(route, [{'role':'system','content':INSTRUCTION},{'role':'user','content':json.dumps(task,ensure_ascii=False)}])
    out = policy.private(output); out.mkdir(parents=True, mode=0o700, exist_ok=False)
    ident = uuid.uuid4().hex; started = time.monotonic()
    result = {'schema':'cc.generation-result.v1','attempt_id':ident,'status':'failed','route_id':route['id'],
              'selection_sha256':selection,'published':False,'human_content_review':'pending','images':'not_requested'}
    for name, data in [('route.json',route),('brief.json',brief),('sources.json',manifest),('request.json',request)]: policy.save(out/name,data)
    budget = policy.Budget(registry)
    try:
        catalog = public_json('https://openrouter.ai/api/v1/models/'+urllib.parse.quote(route['model'],safe='/')+'/endpoints')
        policy.save(out/'endpoint.json',catalog); check_endpoint(route,request,catalog)
        policy.selected(registry,selection)
        if not os.environ.get('OPENROUTER_API_KEY'): raise ValueError('OPENROUTER_API_KEY required')
        upper = estimate(route,request); budget.reserve(ident,upper)
        result['reserved_micro_usd'] = upper
        policy.save(out/'intent.json',{'attempt_id':ident,'started_at':policy.utc(),'reserved_micro_usd':upper,'selection_sha256':selection})
        child_env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG','OPENROUTER_API_KEY')}
        with (out/'transport.json').open('xb') as log:
            process = subprocess.Popen([sys.executable,str(ROOT/'ops/model_transport.py'),'--request',str(out/'request.json'),'--response',str(out/'response-wire.json')],env=child_env,stdout=log,stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic()+route['settings']['deadline_seconds']; progress = time.monotonic()
                while process.poll() is None:
                    if time.monotonic() > deadline: raise TimeoutError('total inference deadline')
                    policy.selected(registry,selection)
                    if time.monotonic()-progress > 45:
                        print('Model request running; reserved budget retained.',flush=True); progress=time.monotonic()
                    time.sleep(1)
                response = policy.read(out/'response-wire.json')
                policy.save(out/'response.json',response)
                if response.get('usage',{}).get('cost') is not None:
                    budget.settle(ident,response['usage']['cost']); result['usage']=response['usage']
                else: raise ValueError('usage unavailable; full reservation retained')
                if process.returncode: raise ValueError('provider HTTP/transport failure')
            finally:
                if process.poll() is None:
                    process.kill(); process.wait()
        policy.selected(registry,selection)
        local.load_sources(manifest)  # detect source replacement during inference
        raw = response_output(route,response); policy.save(out/'model-output.json',raw)
        candidate = make_proposal(raw,sources,route,brief,out.name,request,response,task['output_schema'])
        result.update(status=raw['status'],reason=raw['reason'])
        if candidate is not None:
            for entry in candidate['entries']: entry['prov_measured']['selection_sha256']=selection
            policy.save(out/'proposal.json',candidate)
            env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG')}
            executable = os.environ.get('CC_PUBLISHER_BIN','cc-publisher')
            checked = subprocess.run([executable,'validate','--path',str(out/'proposal.json')],env=env,capture_output=True,text=True,timeout=60)
            policy.save(out/'admission.json',{'exit_code':checked.returncode,'stdout':checked.stdout,'stderr':checked.stderr})
            if checked.returncode: raise ValueError('publisher admission rejected proposal')
            result.update(proposal_sha256=policy.digest((out/'proposal.json').read_bytes()),entries=len(candidate['entries']),edges=len(candidate['edges']),admission='pass')
        policy.selected(registry,selection)
    except Exception as error:
        result.update(status='failed',error=type(error).__name__+': '+str(error)[:300])
    finally:
        result['elapsed_seconds']=round(time.monotonic()-started,3); result['budget']=budget.status(); budget.close()
        policy.save(out/'result.json',result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('registry','brief','sources','output'): p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--expect-selection')
    a=p.parse_args(); result=run(a.registry,a.brief,a.sources,a.output,a.expect_selection)
    print(json.dumps(result)); return int(result['status']=='failed')


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'failed','error':type(error).__name__}),file=sys.stderr)
        raise SystemExit(1)
