import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import graphview

spec = importlib.util.spec_from_file_location('viewer', Path(__file__).with_name('browse-v4.py'))
viewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(viewer)

class ViewerTests(unittest.TestCase):
    def test_same_year_chain_uses_edge_direction_not_title_order(self):
        nodes = {n: {'year':1970,'name':n,'unknown':False} for n in ('a','b','c')}
        svg, order = graphview.svg_component(list(nodes), nodes, [('c','a',2,1),('a','b',2,1)], 0)
        self.assertEqual(order, ['c','a','b'])
        self.assertIn('causation', svg)

    def test_sources_and_prose_are_escaped_without_inventing_source_absence(self):
        body = {'summary':'<script>test</script>','prov_asserted':{'date_precision':'day'},
                'prov_measured':{'text_model':'fixture','source_evidence':[{'excerpt':'a < b'}]}}
        rendered = viewer.prov_line(json.dumps(body))
        self.assertIn('&lt;script&gt;', rendered)
        self.assertIn('a &lt; b', rendered)
        self.assertNotIn('no source consulted', rendered)

    def test_missing_credential_never_discovers_retired_host(self):
        with patch.dict(viewer.os.environ, {}, clear=True), patch.object(viewer.subprocess, 'run') as call:
            self.assertIsNone(viewer.node_key())
            with self.assertRaisesRegex(ValueError, 'CC_DATABASE_URL'):
                viewer.fetch()
            call.assert_not_called()

    def test_connection_credentials_use_environment_not_argv(self):
        with patch.dict(viewer.os.environ, {'CC_DATABASE_URL':'postgres://reader:fake%20value@127.0.0.1:61625/fixture','PGSERVICE':'unrelated'}):
            env = viewer.database_env()
        self.assertEqual(env['PGDATABASE'], 'fixture')
        self.assertEqual(env['PGPASSWORD'], 'fake value')
        self.assertNotIn('PGSERVICE', env)

    def test_nonlocal_viewer_database_is_refused(self):
        with patch.dict(viewer.os.environ, {'CC_DATABASE_URL':'postgres://reader@example.org/fixture'}):
            with self.assertRaisesRegex(ValueError, 'loopback'):
                viewer.database_env()
