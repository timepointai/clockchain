import concurrent.futures
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import model_policy as p
import model_runtime as r
import model_catalog as catalog


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.evidence=self.root/'evidence.txt';self.evidence.write_text('Synthetic test rights evidence, not a real license grant.')
        ev={'url':'https://example.org/terms','path':str(self.evidence),'sha256':p.digest(self.evidence.read_bytes())}
        self.route={'schema':'cc.model-route.v1','id':'synthetic','adapter':'openrouter-chat','model':'fixture/model','provider':'Fixture','provider_slug':'fixture','endpoint_name':'Fixture | model-v1','quantization':'bf16','hosted_weight_digest':None,
            'settings':{'reasoning':{'effort':'xhigh'},'temperature':0.6,'top_p':0.95,'max_tokens':20000,'deadline_seconds':900},
            'prices':{'prompt_per_million_usd':'0.2','completion_per_million_usd':'2'},
            'rights':{'license_spdx':'Apache-2.0','commercial_use':True,'output_training':True,'reviewed_by':'synthetic operator','reviewed_at':'2020-01-01T00:00:00Z','expires_at':'2100-01-01T00:00:00Z','model_license':ev,'provider_terms':ev,'router_terms':ev,'conditions':'Synthetic test only'},
            'evaluation':{'path':str(self.evidence),'sha256':ev['sha256'],'scope':'Synthetic tests'}}
        self.route_path=self.root/'route.json';p.save(self.route_path,self.route)
        p.save(self.root/'budget.json',{'schema':'cc.model-budget.v1','total_limit_micro_usd':100000,'daily_limit_micro_usd':100000,'max_daily_calls':10})
        _,self.selection=p.choose(self.root,self.route_path,'human','explicit choice','test decision')
        self.source={'id':'s','url':'https://example.org/source','publisher':'Synthetic fixture','license':'CC0-1.0','locator':'paragraph 1','retrieved_at':'2026-01-01T00:00:00Z','capture_path':str(self.root/'source.txt'),'passages':['A synthetic controlled experiment in 2001 observed a valve opening. No pressure change, cause of the opening, or calendar day is reported.']}
        Path(self.source['capture_path']).write_text(self.source['passages'][0]);self.source['content_sha256']=p.digest(Path(self.source['capture_path']).read_bytes())
        self.sources={'s':self.source};self.brief={'max_entries':3,'max_edges':2,'allowed_claim_types':['scientific-discovery'],'instruction':'Describe supported events. Limits are not quotas.'}
        self.packet=r.packet(self.brief,self.sources)
        summary='A synthetic controlled experiment observed a valve opening in 2001. The supplied account gives no calendar day or cause of the opening, and does not report a pressure change following it.'
        self.raw={'status':'proposal','reason':'One supported event; no supported causal link.','entries':[{'title':'Synthetic experiment observes a valve opening','year':2001,'claim_type':'scientific-discovery','lens':'A','summary':summary,'historical_claim':'A synthetic experiment observed a valve opening in 2001.','date_precision':'year','event_date':None,'source_calendar_basis':'The source gives 2001 only.','evidence':[{'source_id':'s','passage_index':0,'supports':['title','year','summary']}],'source_support':{'claim':'A valve opened in the synthetic experiment.','source_ids':['s'],'support_kind':'observed','rationale':'The source states the observation.'}}],'edges':[]}
        self.response={'id':'fixture-call','model':'fixture/model','provider':'Fixture','choices':[{'finish_reason':'stop','message':{'content':json.dumps(self.raw)}}],'usage':{'cost':0.01}}
        self.endpoint={'data':{'endpoints':[{'provider_name':'Fixture','name':'Fixture | model-v1','quantization':'bf16','context_length':262144,'max_completion_tokens':64000,'supported_parameters':['reasoning','temperature','top_p','max_tokens'],'pricing':{'prompt':'0.0000002','completion':'0.000002','discount':0.25}}]}}
    def convert(self, raw=None):
        return r.make_proposal(raw or self.raw,self.sources,self.route,self.brief,'fixture',{},self.response,self.packet['output_schema'])
    def test_source_ids_attached_without_rewriting_authored_fields(self):
        candidate=self.convert();entry=candidate['entries'][0]
        self.assertEqual(entry['summary'],self.raw['entries'][0]['summary'])
        self.assertEqual(entry['prov_measured']['source_evidence'][0]['excerpt'],self.source['passages'][0])
        self.assertIsNone(entry['prov_measured']['hosted_weight_digest'])
        self.assertEqual(candidate['edges'],[])
        self.assertEqual(entry['prov_measured']['reasoning_requested'],{'effort':'xhigh'})
    def test_invalid_spans_taxonomy_counts_and_dates_fail(self):
        for kind in ('span','source','taxonomy','extra','date'):
            raw=copy.deepcopy(self.raw);entry=raw['entries'][0]
            if kind=='span':entry['evidence'][0]['passage_index']=1
            if kind=='source':entry['evidence'][0]['source_id']='invented'
            if kind=='taxonomy':entry['claim_type']='engineering-and-industry'
            if kind=='extra':raw['entries']*=4
            if kind=='date':entry['date_precision']='year';entry['event_date']='2001-01-01'
            with self.assertRaises((ValueError,r.jsonschema.ValidationError)):self.convert(raw)
    def test_abstention_is_successful_result_but_not_empty_proposal(self):
        for status in ('abstained','needs_evidence','conflicting_evidence'):
            raw={'status':status,'reason':'Evidence does not support a year.','entries':[],'edges':[]}
            self.assertIsNone(self.convert(raw))
            raw['entries']=self.raw['entries']
            with self.assertRaises(ValueError):self.convert(raw)
        with self.assertRaises(ValueError):self.convert({'status':'proposal','reason':'empty','entries':[],'edges':[]})
    def test_human_selection_pins_route_rights_and_evaluation(self):
        self.assertEqual(p.selected(self.root)[1],self.selection)
        changed=copy.deepcopy(self.route);changed['settings']['reasoning']={'effort':'low'}
        p.save(self.route_path,changed,replace=True)
        with self.assertRaisesRegex(ValueError,'route changed'):p.selected(self.root)
    def test_pause_expiry_missing_permissions_and_unknown_fields_fail(self):
        for mutation in ('expired','training','field','adapter'):
            route=copy.deepcopy(self.route)
            if mutation=='expired':route['rights']['expires_at']='2020-01-02T00:00:00Z'
            if mutation=='training':route['rights']['output_training']=False
            if mutation=='field':route['surprise']=True
            if mutation=='adapter':route['adapter']='unreviewed-local'
            with self.assertRaises(ValueError):p.validate_route(route)
        (self.root/'STOP').touch()
        with self.assertRaisesRegex(ValueError,'paused'):p.selected(self.root)
    def test_provider_context_revision_and_price_changes_fail_closed(self):
        request=r.payload(self.route,[]);r.check_endpoint(self.route,request,self.endpoint)
        for k,v in [('provider_name','other'),('name','new-revision'),('quantization','fp8'),('context_length',10),('supported_parameters',[])]:
            catalog=copy.deepcopy(self.endpoint);catalog['data']['endpoints'][0][k]=v
            with self.assertRaises(ValueError):r.check_endpoint(self.route,request,catalog)
        c=copy.deepcopy(self.endpoint);c['data']['endpoints'][0]['pricing']['completion']='0.001'
        with self.assertRaises(ValueError):r.check_endpoint(self.route,request,c)
        self.assertFalse(request['provider']['allow_fallbacks'])
        self.assertTrue(request['provider']['require_parameters'])
    def test_truncation_and_wrong_returned_model_or_host_fail(self):
        for kind in ('provider','model','finish'):
            response=copy.deepcopy(self.response)
            if kind=='finish':response['choices'][0]['finish_reason']='length'
            else:response[kind]='other'
            with self.assertRaises(ValueError):r.response_output(self.route,response)
    def test_concurrent_reservations_unknown_holds_and_exact_settlement(self):
        def reserve(i):
            b=p.Budget(self.root)
            try:
                try:b.reserve(str(i),60000);return True
                except ValueError:return False
            finally:b.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(reserve,range(4)))
        self.assertEqual(sum(results),1)
        b=p.Budget(self.root);self.addCleanup(b.close);self.assertEqual(b.status()['held_micro_usd'],60000)
        ident=b.db.execute('SELECT id FROM attempts').fetchone()[0];b.settle(ident,'0.01')
        self.assertEqual(b.status()['spent_micro_usd'],10000)
        with self.assertRaises(ValueError):b.settle(ident,'0.01')
    def test_unknown_old_hold_counts_against_new_day_and_overrun_freezes(self):
        b=p.Budget(self.root);self.addCleanup(b.close)
        with patch.object(p,'utc',return_value='2000-01-01T00:00:00Z'):b.reserve('old',80000)
        with self.assertRaisesRegex(ValueError,'exhausted'):b.reserve('new',30000)
        with self.assertRaisesRegex(ValueError,'frozen'):b.settle('old','0.09')
        self.assertTrue(b.status()['blocked'])
        with self.assertRaisesRegex(ValueError,'frozen'):b.reserve('next',1)
    def test_catalog_discovery_never_changes_human_selection(self):
        before=(self.root/'active.json').read_bytes()
        with patch.object(catalog,'public_json',return_value={'data':[{'id':'new/unknown','created':1}]}):
            result=catalog.refresh(self.root)
        self.assertFalse(result['automatic_selection']);self.assertEqual((self.root/'active.json').read_bytes(),before)
        self.assertIn('not a quality ranking',(self.root/'daily-review.html').read_text())
    def test_duplicate_json_and_nonfinite_money_rejected(self):
        f=self.root/'invalid.json';f.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError):p.read(f)
        for v in ('NaN','Infinity',-1,True):
            with self.assertRaises(ValueError):p.micro(v)
    def test_runtime_refuses_database_credentials_before_network(self):
        with patch.dict(os.environ,{'DATABASE_URL':'forbidden'}),patch.object(r,'public_json') as network:
            with self.assertRaisesRegex(ValueError,'credentials'):r.run(self.root,Path('none'),Path('none'),self.root/'out')
        network.assert_not_called()

    def test_evaluation_freezes_case_bytes_before_running(self):
        import model_evaluate
        p.save(self.root/'brief.json',self.brief);p.save(self.root/'sources.json',[self.source])
        suite={'schema':'cc.model-suite.v1','id':'frozen-test','split':'development','cases':[{'id':'one','brief':str(self.root/'brief.json'),'sources':str(self.root/'sources.json'),'expected_status':'proposal','max_edges':0}]}
        p.save(self.root/'suite.json',suite)
        def run(registry,brief,sources,output,selection):
            (self.root/'brief.json').write_text('{}')
            self.assertEqual(p.read(brief),self.brief)
            self.assertEqual(p.read(sources),[self.source])
            self.assertEqual(selection,self.selection)
            return {'status':'proposal','edges':0}
        with patch.object(r,'run',side_effect=run):
            report=model_evaluate.evaluate(self.root,self.root/'suite.json',self.root/'evaluation',1)
        self.assertEqual(report['deterministic_pass_count'],1)
        self.assertIn('required',report['semantic_review'])
        registered=p.read(self.root/'evaluation/registration.json')
        self.assertEqual(registered['frozen_cases'][0]['brief_sha256'],p.digest(p.canonical(self.brief)))
    def test_viewer_escapes_content_and_has_no_write_action(self):
        import proposal_view
        candidate=self.convert();candidate['entries'][0]['title']='<script>alert(1)</script>'
        page=proposal_view.render(candidate,{'status':'proposal'}).decode()
        self.assertNotIn('<script>',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn('Unpublished draft',page)
        self.assertNotIn('<form',page)
    def test_daily_job_only_discovers_without_credentials(self):
        import model_daily
        config=model_daily.configuration(self.root,9)
        self.assertEqual(config['ProgramArguments'][-1],'refresh')
        self.assertEqual(config['StartCalendarInterval'],{'Hour':9,'Minute':0})
        self.assertEqual(set(config['EnvironmentVariables']),{'PATH','LANG'})



class RuntimeReceiptTests(unittest.TestCase):
    setUp = ModelTests.setUp
    def test_truncated_paid_response_is_retained_and_charged(self):
        from types import SimpleNamespace
        response=copy.deepcopy(self.response);response['choices'][0]['finish_reason']='length'
        p.save(self.root/'brief.json',self.brief);p.save(self.root/'sources.json',[self.source])
        class Process:
            returncode=0
            def __init__(self,args,**kwargs):
                Path(args[args.index('--response')+1]).write_text(json.dumps(response))
                self.env=kwargs['env']
                assert not any(k in self.env for k in r.FORBIDDEN)
            def poll(self):return 0
        with patch.dict(os.environ,{'PATH':os.environ['PATH'],'OPENROUTER_API_KEY':'synthetic-key'},clear=True), \
                patch.object(r,'public_json',return_value=self.endpoint),patch.object(r.subprocess,'Popen',Process), \
                patch.object(r.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='{}',stderr='')) as admission:
            result=r.run(self.root,self.root/'brief.json',self.root/'sources.json',self.root/'attempt')
        self.assertEqual(result['status'],'failed');self.assertEqual(result['budget']['spent_micro_usd'],10000)
        self.assertTrue((self.root/'attempt/response-wire.json').exists())
        self.assertFalse((self.root/'attempt/proposal.json').exists());admission.assert_not_called()
        self.assertNotIn('synthetic-key',(self.root/'attempt/request.json').read_text())

if __name__=='__main__':unittest.main()
