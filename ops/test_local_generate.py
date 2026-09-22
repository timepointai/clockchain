import copy
import json
from pathlib import Path
import tempfile
import unittest
import local_generate as g


class LocalGenerationTests(unittest.TestCase):
    def fixture(self):
        text='Synthetic valve failure caused a synthetic pressure drop in 2000.'
        source={'id':'s','url':'https://example.org/source','publisher':'Fixture','license':'CC0-1.0','locator':'paragraph 1','retrieved_at':'2026-09-22','content_sha256':'a'*64,'capture_path':'/private/synthetic','passages':[text]}
        item={'source_id':'s','excerpt':text,'supports':['title','year','summary']}
        entry={'title':'Synthetic valve failure','year':2000,'claim_type':'engineering-and-industry','lens':'A','summary':text,'historical_claim':text,'date_precision':'year','source_calendar_basis':'year only','evidence':[item],'source_support':{'claim':text,'source_ids':['s'],'support_kind':'observed','rationale':text}}
        policy={'model':'synthetic-local','model_digest':'b'*64}
        return {'entries':[entry],'edges':[]},{'s':source},policy,{'max_entries':3,'max_edges':2}
    def convert(self,raw,sources,policy,brief):
        return g.proposal(raw,sources,policy,brief,'test','c'*64,'d'*64)
    def test_generated_historical_fields_are_never_rewritten(self):
        raw,sources,policy,brief=self.fixture();out=self.convert(raw,sources,policy,brief)
        for k in ('title','summary','year','claim_type','lens'):
            self.assertEqual(out['entries'][0][k],raw['entries'][0][k])
        self.assertEqual(out['entries'][0]['prov_asserted']['historical_claim'],raw['entries'][0]['historical_claim'])
        self.assertEqual(out['entries'][0]['prov_measured']['model_digest'],'b'*64)
        self.assertEqual(out['images'],[])
    def test_invented_sources_excerpts_and_excess_records_refused(self):
        for mutation in ('source','excerpt','bounds','precision'):
            raw,sources,policy,brief=self.fixture()
            if mutation=='source':raw['entries'][0]['evidence'][0]['source_id']='invented'
            if mutation=='excerpt':raw['entries'][0]['evidence'][0]['excerpt']='invented text'
            if mutation=='bounds':raw['entries']*=4
            if mutation=='precision':raw['entries'][0]['date_precision']='exact instant'
            with self.assertRaises(ValueError):self.convert(raw,sources,policy,brief)
    def test_changed_capture_and_nonliteral_passage_refused(self):
        _,sources,_,_=self.fixture();s=sources['s']
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';p.write_text(s['passages'][0]);s['capture_path']=str(p);s['content_sha256']=g.digest(p.read_bytes())
            self.assertEqual(len(g.load_sources([s])),1)
            s['passages']=['not captured']
            with self.assertRaises(ValueError):g.load_sources([s])
            p.write_text('changed')
            with self.assertRaises(ValueError):g.load_sources([s])
    def test_exact_local_model_and_license_bytes_required(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'LICENSE';p.write_text('synthetic license bytes')
            evidence={'url':'https://example.org/license','path':str(p),'sha256':g.digest(p.read_bytes())}
            policy={'schema':'cc.local-model-policy.v1','reviewed_by':'test','license_spdx':'Apache-2.0','provider':'local-ollama','output_training_allowed':True,'model':'fixture','model_digest':'e'*64,'model_license':evidence,'runtime_license':evidence,'installed_license_sha256':g.digest(b'installed fixture')}
            tags={'models':[{'name':'fixture','digest':'e'*64}]};shown={'license':'installed fixture'}
            g.policy_check(policy,tags,shown)
            for field,value in [('model_digest','f'*64),('provider','hosted'),('output_training_allowed',False),('license_spdx','restricted')]:
                changed=copy.deepcopy(policy);changed[field]=value
                with self.assertRaises(ValueError):g.policy_check(changed,tags,shown)
            p.write_text('changed')
            with self.assertRaises(ValueError):g.policy_check(policy,tags,shown)

    def test_wire_preserves_node_before_edge_schema_order(self):
        value={'format':{'properties':{'entries':{'type':'array'},'edges':{'type':'array'}}}}
        sent=json.loads(g.wire(value))
        self.assertEqual(list(sent['format']['properties']), ['entries','edges'])
        self.assertEqual(g.canonical(sent),g.canonical(value))
