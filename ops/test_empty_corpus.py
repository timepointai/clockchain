import copy
import json
import unittest
from unittest.mock import patch
from deployed_checks import check_empty

class EmptyCorpusTests(unittest.TestCase):
    def call(self,change=None):
        deep={'status':'ok','event_count':3,'ledger':{'entity_count':1,'edge_count':0,'attestation_count':0},'media':{'image_attachment_count':0,'integrity':'pass'}}
        if change:change(deep)
        writes=[]
        def request(base,path,key=None,payload=None):
            if payload is not None:
                writes.append(key);return (403 if key=='read' else 401),b'{}'
            if path=='/health':return 200,json.dumps({'build':'a'*12,'posture':'live'}).encode()
            if key not in ('read','full'):return 401,b'{}'
            if path=='/health/deep':v=deep
            elif path=='/v1/entities/0':return 400,b'{}'
            elif path.startswith('/v1/recents'):v={'entries':[{'subject':0}]}
            elif path.startswith('/v1/images'):v={'images':[]}
            else:v={}
            return 200,json.dumps(v).encode()
        with patch('deployed_checks.request',side_effect=request):
            result=check_empty('http://127.0.0.1:1','a'*40,'full','read')
        self.assertNotIn('full',writes)
        return result
    def test_genesis_passes_without_creating_fixture(self):
        self.assertEqual(self.call()['historical_corpus'],'empty')
    def test_leftover_history_edges_and_media_refused(self):
        changes=[lambda d:d['ledger'].update(entity_count=2),lambda d:d['ledger'].update(edge_count=1),lambda d:d['media'].update(image_attachment_count=1)]
        for change in changes:
            with self.assertRaises(AssertionError):self.call(change)
