#!/usr/bin/env python3
"""Prepare pinned FLUX images for an unpublished candidate. Never sign or submit.

The shared model registry retains the entire GPU timeout reservation until a
provider billing record is reconciled. Completion is not a billing receipt.
"""
import argparse
import base64
import copy
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

import model_policy as policy
import model_runtime

OPS = Path(__file__).resolve().parent
# Executed inside the digest-pinned CUDA image. Code, profile, and prompts are
# separate data; no shell interpolation, repository checkout, or ledger secrets.
BOOTSTRAP = '''import base64,hashlib,json,os,subprocess,sys
from pathlib import Path
root=Path('/tmp/clockchain-images');root.mkdir(mode=0o700)
for key,name in [('CC_GENERATOR','flux_image.py'),('CC_PROFILE','flux_profile.json'),('CC_REQUIREMENTS','requirements.txt')]:
 data=base64.b64decode(os.environ[key],validate=True)
 if hashlib.sha256(data).hexdigest()!=os.environ[key+'_SHA256']:raise ValueError('worker bytes changed')
 (root/name).write_bytes(data)
subprocess.run([sys.executable,'-m','pip','install','-r',str(root/'requirements.txt')],check=True)
for item in json.loads(os.environ['CC_PROMPTS']):
 index=item['entry_index'];prompt=root/('prompt-'+str(index)+'.txt');prompt.write_text(item['prompt'])
 subprocess.run([sys.executable,str(root/'flux_image.py'),'--prompt-file',str(prompt),'--output',str(root/str(index)),
  '--upload-repo',os.environ['CC_OUTPUT_REPO'],'--upload-prefix',os.environ['CC_OUTPUT_PREFIX']+'/'+str(index)],check=True)
'''


def validate_route(route):
    policy.exact(route, 'schema model profile_sha256 generator_sha256 bootstrap_sha256 requirements_sha256 image hardware timeout_seconds max_job_micro_usd output_repo chosen_by decision_reference rights')
    profile = policy.read(OPS/'flux_profile.json')
    if route['schema'] != 'cc.image-route.v1' or route['model'] != profile['model']:
        raise ValueError('unsupported image route')
    for key, raw in [('profile_sha256',(OPS/'flux_profile.json').read_bytes()),
                     ('generator_sha256',(OPS/'flux_image.py').read_bytes()),
                     ('requirements_sha256',(OPS/'requirements-flux-worker.txt').read_bytes()),
                     ('bootstrap_sha256',BOOTSTRAP.encode())]:
        if route[key] != policy.digest(raw): raise ValueError('selected image runtime changed')
    if not re.fullmatch(r'[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}',route['image']):
        raise ValueError('immutable GPU image required')
    policy.integer(route['timeout_seconds'],1,1200)
    policy.integer(route['max_job_micro_usd'],1,2_000_000)
    for key in ('hardware','output_repo','chosen_by','decision_reference'):policy.nonempty(route[key])
    rights = route['rights']
    policy.exact(rights,'commercial_use output_training reviewed_at expires_at evidence conditions')
    if rights['commercial_use'] is not True or rights['output_training'] is not True:
        raise ValueError('image rights not reviewed')
    if not policy.timestamp(rights['reviewed_at']) <= policy.timestamp(policy.utc()) < policy.timestamp(rights['expires_at']):
        raise ValueError('image rights review expired')
    if len(rights['evidence']) < 2:raise ValueError('model and compute terms evidence required')
    for ev in rights['evidence']:policy.evidence(ev)
    policy.nonempty(rights['conditions'])
    return profile


def checked_plan(directory, candidate_bytes, registry):
    plan = policy.read(directory/'media-plan.json')
    result = policy.read(directory/'result.json')
    if result['status'] != 'media_plan' or result['media_plan_sha256'] != policy.digest((directory/'media-plan.json').read_bytes()):
        raise ValueError('media plan receipt mismatch')
    if plan['candidate_sha256'] != policy.digest(candidate_bytes):raise ValueError('media plan is stale')
    route, selection = policy.selected(registry,plan['selection_sha256'])
    sources = model_runtime.local.load_sources(policy.read(directory/'sources.json'))
    request = policy.read(directory/'request.json'); response = policy.read(directory/'response.json')
    raw = model_runtime.response_output(route,response)
    if raw != policy.read(directory/'model-output.json'):raise ValueError('model response changed')
    task = model_runtime.media_packet(policy.read(directory/'brief.json'),sources,json.loads(candidate_bytes))
    expected = model_runtime.media_plan(raw,task,sources,policy.digest(candidate_bytes),selection,request,response)
    if expected != plan:raise ValueError('model-authored media plan changed')
    return plan


def reservation(route, hardware):
    if hardware.name != route['hardware'] or hardware.unit_label not in ('minute','hour','second'):
        raise ValueError('unknown current GPU price')
    unit = {'minute':60,'hour':3600,'second':1}[hardware.unit_label]
    # Include one additional billing unit conservatively for boundary rounding.
    upper = policy.micro((math.ceil(route['timeout_seconds']/unit)+1)*policy.amount(hardware.unit_cost_usd))
    if upper < 1 or upper > route['max_job_micro_usd']:raise ValueError('GPU price exceeds reviewed ceiling')
    return upper


def verify_image(directory, profile, prompt, generator_sha256):
    from PIL import Image
    manifest = policy.read(directory/'manifest.json')
    for field,expected in [('model_requested',profile['model']),('model_revision',profile['model_revision']),
                           ('weights_sha256',profile['weights_sha256']),('generator_sha256',generator_sha256),
                           ('provider','local_inference'),('synthetic',True),('visual_review','pending'),
                           ('historical_verification','not_assessed')]:
        if manifest.get(field) != expected:raise ValueError('image provenance mismatch: '+field)
    for field in ('license_sha256','license_url'):
        if manifest['permission'][field] != profile[field]:raise ValueError('image license mismatch')
    if manifest['parameters']['prompt'] != prompt['prompt'].strip():raise ValueError('image prompt changed')
    image = (directory/manifest['image_file']).resolve()
    if image.parent != directory.resolve():raise ValueError('image path escapes candidate')
    raw = image.read_bytes()
    if len(raw)>8_000_000 or policy.digest(raw)!=manifest['image_sha256']:raise ValueError('image bytes mismatch')
    if policy.digest((directory/'MODEL-LICENSE.txt').read_bytes())!=profile['license_sha256']:
        raise ValueError('downloaded license mismatch')
    with Image.open(image) as png:
        if png.format!='PNG' or png.size!=(1024,1024):raise ValueError('unexpected image dimensions/format')
        png.verify()
    return manifest,image


def run(registry, route_path, candidate_path, plan_dir, output):
    if any(os.environ.get(k) for k in model_runtime.FORBIDDEN):raise ValueError('remove publication credentials')
    from huggingface_hub import HfApi, get_token, hf_hub_download
    route_bytes = route_path.read_bytes(); route = policy.read(route_path); profile=validate_route(route)
    original=candidate_path.read_bytes();candidate=policy.read(candidate_path)
    plan=checked_plan(plan_dir,original,registry)
    env={k:v for k,v in os.environ.items() if k in ('PATH','HOME','TMPDIR','LANG')}
    checked=subprocess.run([os.environ.get('CC_PUBLISHER_BIN','cc-publisher'),'image-bindings','--path',str(candidate_path)],
                           env=env,capture_output=True,text=True,check=True,timeout=60)
    bindings=json.loads(checked.stdout)
    token=get_token()
    if not token:raise ValueError('Hugging Face credential required')
    api=HfApi(token=token)
    owner=api.whoami()['name']
    if route['output_repo'].split('/')[0]!=owner:raise ValueError('output repository must belong to operator account')
    hardware=next((h for h in api.list_jobs_hardware() if h.name==route['hardware']),None)
    if hardware is None:raise ValueError('selected GPU hardware unavailable')
    upper=reservation(route,hardware)
    api.create_repo(repo_id=route['output_repo'],repo_type='dataset',private=True,exist_ok=True)
    if not api.repo_info(route['output_repo'],repo_type='dataset').private:raise ValueError('output repository must be private')
    out=policy.private(output);out.mkdir(mode=0o700,parents=True,exist_ok=False)
    ident=uuid.uuid4().hex
    for name,value in [('route.json',route),('media-plan.json',plan),('bindings.json',bindings)]:policy.save(out/name,value)
    budget=policy.Budget(registry)
    result={'schema':'cc.image-preparation.v1','attempt_id':ident,'status':'failed','published':False,
            'candidate_sha256':policy.digest(original),'visual_review':'pending','billing':'unresolved'}
    try:
        result['phase']='reservation'
        budget.reserve(ident,upper)
        result['reserved_micro_usd']=upper
        policy.save(out/'intent.json',{'attempt_id':ident,'reserved_micro_usd':upper,'created_at':policy.utc(),
                                    'route_sha256':policy.digest(route_bytes),'candidate_sha256':policy.digest(original)})
        worker_env={'CC_PROMPTS':json.dumps([{'entry_index':p['entry_index'],'prompt':p['prompt']} for p in plan['prompts']]),
                    'CC_OUTPUT_REPO':route['output_repo'],'CC_OUTPUT_PREFIX':ident}
        for key,path in [('CC_GENERATOR',OPS/'flux_image.py'),('CC_PROFILE',OPS/'flux_profile.json'),
                         ('CC_REQUIREMENTS',OPS/'requirements-flux-worker.txt')]:
            raw=path.read_bytes();worker_env[key]=base64.b64encode(raw).decode();worker_env[key+'_SHA256']=policy.digest(raw)
        validate_route(route); checked_plan(plan_dir,original,registry)
        if route_path.read_bytes()!=route_bytes or candidate_path.read_bytes()!=original:raise ValueError('inputs changed')
        result['phase']='submit'
        remote=api.run_job(image=route['image'],command=['python','-c',BOOTSTRAP],flavor=route['hardware'],
                           timeout=route['timeout_seconds'],env=worker_env,secrets={'HF_TOKEN':token},
                           labels={'clockchain-preparation':ident})
        namespace=remote.owner.name
        policy.save(out/'remote-job.json',{'id':remote.id,'namespace':namespace,'output_repo':route['output_repo'],
                                         'output_prefix':ident,'timeout_seconds':route['timeout_seconds']})
        deadline=time.monotonic()+route['timeout_seconds']+180
        queue_deadline=time.monotonic()+300
        result['phase']='wait'
        while True:
            info=api.inspect_job(job_id=remote.id,namespace=namespace)
            stage=info.status.stage
            print(json.dumps({'image_job':remote.id,'stage':stage,'reserved_micro_usd':upper}),flush=True)
            if stage=='COMPLETED':break
            if stage in ('ERROR','DELETED','CANCELED','CANCELLED'):raise ValueError('GPU job failed; reservation retained')
            if time.monotonic()>deadline or (stage=='SCHEDULING' and time.monotonic()>queue_deadline):
                api.cancel_job(job_id=remote.id,namespace=namespace)
                raise ValueError('GPU deadline; canceled job and retained reservation')
            if route_path.read_bytes()!=route_bytes or candidate_path.read_bytes()!=original or (registry/'STOP').exists():
                api.cancel_job(job_id=remote.id,namespace=namespace)
                raise ValueError('input or stop condition changed; GPU canceled')
            try:
                validate_route(route);checked_plan(plan_dir,original,registry)
            except Exception:
                api.cancel_job(job_id=remote.id,namespace=namespace)
                raise
            time.sleep(30)
        result['phase']='download_and_verify'
        prepared=copy.deepcopy(candidate)
        for prompt in plan['prompts']:
            index=prompt['entry_index'];directory=out/str(index);directory.mkdir(mode=0o700)
            prefix=ident+'/'+str(index)+'/'
            def download(name):
                if Path(name).name!=name:raise ValueError('invalid output filename')
                cached=hf_hub_download(route['output_repo'],prefix+name,repo_type='dataset',token=token)
                raw=Path(cached).read_bytes()
                fd=os.open(directory/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                with os.fdopen(fd,'wb') as f:f.write(raw)
            download('manifest.json');download('MODEL-LICENSE.txt')
            download(policy.read(directory/'manifest.json')['image_file'])
            manifest,image=verify_image(directory,profile,prompt,route['generator_sha256'])
            policy.save(directory/'generation-manifest.json',manifest)
            manifest['source']=bindings[index]
            manifest['media_plan_sha256']=policy.digest((plan_dir/'media-plan.json').read_bytes())
            manifest['reconstruction_disclosure']=prompt['reconstruction_disclosure']
            policy.save(directory/'manifest.json',manifest,replace=True)
            prepared['images'].append({'path':str(image),'sha256':manifest['image_sha256'],
                                      'manifest':manifest,'entry_index':index})
        validate_route(route);checked_plan(plan_dir,original,registry)
        if candidate_path.read_bytes()!=original or route_path.read_bytes()!=route_bytes:raise ValueError('inputs changed')
        policy.save(out/'proposal.json',prepared)
        result.update(status='prepared',images_generated=len(plan['prompts']),
                      phase='complete',
                      proposal_sha256=policy.digest((out/'proposal.json').read_bytes()))
    except Exception as error:
        # Provider exceptions can contain request/credential details. Preserve only type.
        result['error_type']=type(error).__name__
    finally:
        result['budget']=budget.status();budget.close();policy.save(out/'result.json',result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('registry','route','candidate','plan','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    result=run(args.registry,args.route,args.candidate,args.plan,args.output)
    print(json.dumps(result));return int(result['status']!='prepared')


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status':'failed','error_type':type(error).__name__}),file=sys.stderr)
        raise SystemExit(1)
