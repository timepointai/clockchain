import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import image_prepare as image
import model_policy as policy
import model_runtime
import test_model_runtime as fixtures


class ImagePreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ModelTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        ev={'url':'https://example.org/synthetic-terms','path':str(self.fixture.evidence),
            'sha256':policy.digest(self.fixture.evidence.read_bytes())}
        self.route={'schema':'cc.image-route.v1','model':policy.read(image.OPS/'flux_profile.json')['model'],
            'profile_sha256':policy.digest((image.OPS/'flux_profile.json').read_bytes()),
            'generator_sha256':policy.digest((image.OPS/'flux_image.py').read_bytes()),
            'requirements_sha256':policy.digest((image.OPS/'requirements-flux-worker.txt').read_bytes()),
            'bootstrap_sha256':policy.digest(image.BOOTSTRAP.encode()),'image':'example/fixture@sha256:'+'a'*64,
            'hardware':'synthetic','timeout_seconds':60,'max_job_micro_usd':10000,
            'output_repo':'synthetic/private','chosen_by':'synthetic human','decision_reference':'test only',
            'rights':{'commercial_use':True,'output_training':True,'reviewed_at':'2020-01-01T00:00:00Z',
                      'expires_at':'2100-01-01T00:00:00Z','evidence':[ev,ev],'conditions':'Synthetic test only.'}}

    def test_image_route_detects_changed_runtime_expiry_and_unpinned_image(self):
        image.validate_route(self.route)
        for key,value in [('image','example/latest'),('generator_sha256','a'*64),('model','other/model')]:
            route={**self.route,key:value}
            with self.assertRaises(ValueError):image.validate_route(route)
        route=copy.deepcopy(self.route);route['rights']['expires_at']='2020-01-02T00:00:00Z'
        with self.assertRaisesRegex(ValueError,'expired'):image.validate_route(route)

    def test_gpu_reservation_rounds_up_and_refuses_changed_price(self):
        hardware=SimpleNamespace(name='synthetic',unit_label='minute',unit_cost_usd='0.001')
        self.assertEqual(image.reservation(self.route,hardware),2000)
        hardware.unit_cost_usd='1'
        with self.assertRaisesRegex(ValueError,'ceiling'):image.reservation(self.route,hardware)

    def prepare_plan(self):
        f=self.fixture;candidate=f.convert();path=self.root/'candidate.json';policy.save(path,candidate)
        directory=self.root/'plan';directory.mkdir()
        task=model_runtime.media_packet(f.brief,f.sources,candidate)
        raw={'status':'proposal','reason':'Synthetic illustration.', 'prompts':[{'entry_index':0,
             'prompt':'A synthetic diagram.','reconstruction_disclosure':'All appearance reconstructed.',
             'evidence':[{'source_id':'s','passage_index':0}]}]}
        response=copy.deepcopy(f.response);response['choices'][0]['message']['content']=json.dumps(raw)
        plan=model_runtime.media_plan(raw,task,f.sources,policy.digest(path.read_bytes()),f.selection,{},response)
        for name,value in [('brief.json',f.brief),('sources.json',[f.source]),('request.json',{}),
                           ('response.json',response),('model-output.json',raw),('media-plan.json',plan)]:
            policy.save(directory/name,value)
        policy.save(directory/'result.json',{'status':'media_plan','media_plan_sha256':policy.digest((directory/'media-plan.json').read_bytes())})
        return path,directory,plan

    def test_image_preparation_refuses_edited_prompt_and_stale_body(self):
        candidate,directory,plan=self.prepare_plan()
        self.assertEqual(image.checked_plan(directory,candidate.read_bytes(),self.root),plan)
        with self.assertRaisesRegex(ValueError,'stale'):image.checked_plan(directory,b'{}',self.root)
        plan['prompts'][0]['prompt']='Assistant-authored replacement'
        policy.save(directory/'media-plan.json',plan,replace=True)
        policy.save(directory/'result.json',{'status':'media_plan','media_plan_sha256':policy.digest((directory/'media-plan.json').read_bytes())},replace=True)
        with self.assertRaisesRegex(ValueError,'changed'):image.checked_plan(directory,candidate.read_bytes(),self.root)

    def test_gpu_job_retains_budget_preserves_history_and_binds_returned_images(self):
        candidate,directory,plan=self.prepare_plan();before=candidate.read_bytes()
        route=self.root/'image-route.json';policy.save(route,self.route)
        remote=self.root/'remote';remote.mkdir();(remote/'image.png').write_bytes(b'synthetic image')
        (remote/'MODEL-LICENSE.txt').write_text('synthetic license')
        manifest={'image_file':'image.png','image_sha256':policy.digest(b'synthetic image'),'visual_review':'pending'}
        policy.save(remote/'manifest.json',manifest)
        class Api:
            def __init__(self,**kwargs):pass
            def whoami(self):return {'name':'synthetic'}
            def list_jobs_hardware(self):return [SimpleNamespace(name='synthetic',unit_label='minute',unit_cost_usd='0.001')]
            def create_repo(self,**kwargs):assert kwargs['private'] is True
            def repo_info(self,*a,**kw):return SimpleNamespace(private=True)
            def run_job(self,**kwargs):
                assert kwargs['timeout']==60
                assert kwargs['secrets']=={'HF_TOKEN':'synthetic-token'}
                assert 'HF_TOKEN' not in kwargs['env']
                return SimpleNamespace(id='synthetic-job',owner=SimpleNamespace(name='synthetic'))
            def inspect_job(self,**kwargs):return SimpleNamespace(status=SimpleNamespace(stage='COMPLETED'))
        bindings=[{'entity_id':'123','body_hash':'a'*64}]
        with patch.dict(os.environ,{k:'' for k in model_runtime.FORBIDDEN}), \
             patch('huggingface_hub.HfApi',Api),patch('huggingface_hub.get_token',return_value='synthetic-token'), \
             patch('huggingface_hub.hf_hub_download',side_effect=lambda repo,name,**kw:str(remote/Path(name).name)), \
             patch.object(image.subprocess,'run',return_value=SimpleNamespace(stdout=json.dumps(bindings))), \
             patch.object(image,'verify_image',side_effect=lambda d,*a:(copy.deepcopy(manifest),d/'image.png')):
            result=image.run(self.root,route,candidate,directory,self.root/'output')
        self.assertEqual(result['status'],'prepared');self.assertEqual(result['budget']['held_micro_usd'],2000)
        self.assertEqual(result['budget']['spent_micro_usd'],0)
        self.assertEqual(candidate.read_bytes(),before)
        prepared=policy.read(self.root/'output/proposal.json')
        self.assertEqual(prepared['entries'],json.loads(before)['entries'])
        self.assertEqual(prepared['images'][0]['manifest']['source'],bindings[0])
        self.assertEqual(prepared['images'][0]['manifest']['reconstruction_disclosure'],plan['prompts'][0]['reconstruction_disclosure'])


if __name__=='__main__':unittest.main()
