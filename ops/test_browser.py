import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

import browse
import browser_service


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root/'read-key'
        self.key.write_text('synthetic-read-credential')
        self.key.chmod(0o600)
        self.raw = browse.PNG + b'synthetic fixture'
        self.sha = browse.digest(self.raw)
        self.eid = '3582419940486658631'
        self.calls = []
        self.responses = {}
        owner = self
        class API(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.calls.append((self.path, self.headers.get('Authorization')))
                path = self.path.split('?')[0]
                override = owner.responses.get(self.path, owner.responses.get(path))
                if override is not None:
                    status, value = override
                    self.send_response(status); self.end_headers()
                    self.wfile.write(json.dumps(value).encode()); return
                if path == '/redirect':
                    self.send_response(302); self.send_header('Location', '/should-not-follow'); self.end_headers(); return
                if path == '/v1/moments':
                    value = {'moments':[{'subject':int(owner.eid)}], 'as_of':'123'}
                elif path == '/v1/entities/'+owner.eid:
                    value = {'entity':{'entity_id':int(owner.eid), 'canonical_name':'Synthetic <script>fixture</script>'}, 'tt':{}, 'edges':[]}
                elif path == '/v2/media':
                    value = {'readings':[{'state':'conflicting_media_records', 'source_binding':'stale_source',
                        'images':[{'manifest':{'image_sha256':owner.sha, 'source_body_hash':'a'*64}}],
                        'absence_decisions':[{'reason':'synthetic retained decision'}]}]}
                elif path == '/v1/images/'+owner.sha:
                    self.send_response(200); self.end_headers(); self.wfile.write(owner.raw); return
                else:
                    self.send_error(404); return
                self.send_response(200); self.end_headers(); self.wfile.write(json.dumps(value).encode())
            def log_message(self, *args): pass
        self.api = ThreadingHTTPServer(('127.0.0.1',0), API)
        threading.Thread(target=self.api.serve_forever, daemon=True).start()
        self.addCleanup(self.api.server_close)
        self.addCleanup(self.api.shutdown)
        self.source = {'id':'node', 'kind':'node', 'label':'Synthetic node', 'url':f'http://127.0.0.1:{self.api.server_port}', 'read_key_file':str(self.key)}
        self.config = {'schema':'cc.browser.v1','port':8766,'sources':[self.source]}

    def browser_url(self):
        server = ThreadingHTTPServer(('127.0.0.1',0),browse.handler(self.config))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def read_browser(self, url):
        try:
            response = urllib.request.urlopen(url, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read().decode()

    def test_empty_window_and_failed_reads_remain_distinct_over_http(self):
        self.responses['/v1/moments'] = (200, {'moments':[], 'as_of':'0'})
        url = self.browser_url()
        for query, status in [('',200), ('&as_of=0',200),
                              ('&entity=garbage',502),
                              ('&entity=9223372036854775807',502),
                              ('&as_of=stale',502)]:
            with self.subTest(query=query):
                actual, body = self.read_browser(url+'/?source=node'+query)
                self.assertEqual(actual,status)
                self.assertEqual('No historical entries in this view' in body,status==200)
                self.assertEqual('0 entries · 0 recorded relationships' in body,status==200)
                self.assertNotIn('deliberately_unillustrated',body)
                if query == '&as_of=0':
                    self.assertIn('name="as_of" value="0"',body)
        self.assertTrue(any(path=='/v1/moments?as_of=0&limit=50' for path,_ in self.calls))
        self.assertFalse(any(path.startswith('/v2/media') for path,_ in self.calls))
        self.responses['/v1/moments'] = (503, {'error':'synthetic unavailable'})
        status, body = self.read_browser(url+'/?source=node&as_of=0')
        self.assertEqual(status,502)
        self.assertIn('Node returned HTTP 503',body)
        self.assertNotIn('No historical entries in this view',body)
        self.assertNotIn('deliberately_unillustrated',body)

    def test_failed_media_and_png_stay_errors_over_http(self):
        url = self.browser_url()
        self.responses['/v2/media'] = (503, {'error':'synthetic unavailable'})
        status, body = self.read_browser(url+'/?source=node&as_of=123')
        self.assertEqual(status,200)  # Entity read succeeded; media failed separately.
        self.assertIn('Media could not be read at this coordinate. No absence is inferred.',body)
        self.assertNotIn('deliberately_unillustrated',body)
        image_url = url+f'/image?source=node&entity={self.eid}&as_of=123&sha={self.sha}'
        for failure in ['media', 'png']:
            if failure == 'png':
                del self.responses['/v2/media']
                self.responses['/v1/images/'+self.sha] = (503, {'error':'synthetic unavailable'})
            with self.subTest(failure=failure):
                status, body = self.read_browser(image_url)
                self.assertEqual(status,400)
                self.assertIn('image unavailable',body)
                self.assertNotIn('deliberately_unillustrated',body)

    def test_image_membership_is_checked_at_exact_entity_and_coordinate(self):
        url = self.browser_url()
        other = '9223372036854775807'
        for eid, at in [(other,'123'),(self.eid,'0')]:
            self.responses[f'/v2/media?entity_id={eid}&as_of={at}'] = (200, {'readings':[]})
            with self.subTest(entity=eid, as_of=at):
                self.calls.clear()
                status, body = self.read_browser(url+f'/image?source=node&entity={eid}&as_of={at}&sha={self.sha}')
                self.assertEqual(status,400)
                self.assertNotIn('deliberately_unillustrated',body)
                self.assertEqual([path for path,_ in self.calls],
                                 [f'/v2/media?entity_id={eid}&as_of={at}'])

    def test_node_reads_and_images_keep_exact_ids_and_media_states(self):
        data = browse.node_data(self.source, '123')
        self.assertEqual(data['entries'][0]['id'], self.eid)
        page = browse.render(self.config, self.source, data, '123').decode()
        self.assertIn('conflicting_media_records',page)
        self.assertIn('stale_source',page)
        self.assertIn('synthetic retained decision',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertNotIn('<script>',page)
        self.assertNotIn('synthetic-read-credential',page)
        raw = browse.image_bytes(self.source, {'sha':self.sha,'entity':self.eid,'as_of':'123'})
        self.assertEqual(raw,self.raw)
        self.assertTrue(all(auth=='Bearer synthetic-read-credential' for _,auth in self.calls))
        self.assertTrue(all('as_of=123' in path for path,_ in self.calls if not path.startswith('/v1/images/')))

    def test_image_unbound_or_corrupt_is_refused(self):
        with self.assertRaisesRegex(ValueError,'not recorded'):
            browse.image_bytes(self.source, {'sha':'f'*64,'entity':self.eid,'as_of':'123'})
        self.raw = browse.PNG+b'changed'
        with self.assertRaisesRegex(ValueError,'integrity'):
            browse.image_bytes(self.source, {'sha':self.sha,'entity':self.eid,'as_of':'123'})

    def test_redirects_cannot_forward_credential(self):
        with self.assertRaisesRegex(ValueError,'redirects'):
            browse.Node(self.source).get('/redirect')
        self.assertEqual(len(self.calls),1)

    def test_localhost_server_refuses_cross_site_hosts_files_and_writes(self):
        server = ThreadingHTTPServer(('127.0.0.1',0),browse.handler(self.config))
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        url=f'http://127.0.0.1:{server.server_port}'
        for req,code in [(urllib.request.Request(url+'/health',headers={'Host':'evil.example'}),403),
                         (urllib.request.Request(url+'/health',headers={'Sec-Fetch-Site':'cross-site'}),403),
                         (urllib.request.Request(url+'/read-key'),404),
                         (urllib.request.Request(url+'/',data=b'write'),501)]:
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(req)
            self.assertEqual(caught.exception.code,code)
        with urllib.request.urlopen(url+'/?source=node&as_of=123') as response:
            self.assertIn("img-src 'self'",response.headers['Content-Security-Policy'])
            self.assertIn('no-store',response.headers['Cache-Control'])
            self.assertNotIn(b'synthetic-read-credential',response.read())

    def test_config_and_service_never_embed_credentials(self):
        path = self.root/'config.json'
        path.write_text(json.dumps(self.config))
        loaded=browse.config_read(path)
        service=browser_service.configuration(path)
        self.assertTrue(service['KeepAlive'])
        self.assertTrue(service['RunAtLoad'])
        self.assertNotIn('synthetic-read-credential',json.dumps(service))
        self.assertEqual(loaded['sources'][0]['id'],'node')
        for url in ['http://example.com','https://user:secret@example.com','https://example.com/other']:
            self.source['url']=url; path.write_text(json.dumps(self.config))
            with self.assertRaises(ValueError): browse.config_read(path)

    def test_read_scope_only_from_env_file(self):
        self.key.write_text('CC_NODE_API_KEY=synthetic-write\nCC_NODE_READ_KEY="synthetic-read"\n')
        self.source['read_key_field']='CC_NODE_READ_KEY'
        self.assertEqual(browse.read_key(self.source),'synthetic-read')
        self.key.chmod(0o644)
        with self.assertRaises(ValueError): browse.read_key(self.source)

    def test_media_error_is_not_absence(self):
        with patch.object(browse.Node,'media',side_effect=ValueError('private error')):
            data=browse.node_data(self.source,'123')
        self.assertIsNone(data['media'])
        self.assertIn('No absence is inferred',data['media_error'])
        self.assertNotIn('private error',browse.render(self.config,self.source,data).decode())

    def test_coordinates_and_ids_do_not_round(self):
        self.assertEqual(browse.entity_id(self.eid),self.eid)
        for value in ['1.5','01','9223372036854775808','/../secret']:
            with self.assertRaises(ValueError): browse.entity_id(value)
        with self.assertRaises(ValueError): browse.coordinate('now')

    def test_no_media_readings_and_unavailable_prose_are_explicit(self):
        self.responses['/v2/media'] = (200, {'readings':[]})
        url = self.browser_url()
        status, page = self.read_browser(url+'/?source=node&as_of=123')
        self.assertEqual(status,200)
        self.assertIn('No media readings at this coordinate.',page)
        self.assertIn('Stored claim prose unavailable',page)
        self.assertNotIn('deliberately_unillustrated',page)
        self.assertNotIn('src="/image',page)

    def test_complete_claim_body_is_only_the_node_response_and_escaped(self):
        raw='{"prov_asserted":{"historical_claim":"Exact node prose <script>inert</script>"}}'
        self.responses['/v1/entities/'+self.eid] = (200, {
            'entity':{'entity_id':int(self.eid),'canonical_name':'Synthetic node'},'tt':{},'edges':[],
            'readings':{'all':[{'body_hash':'b'*64,'body':raw,'body_status':'retained'}]}})
        with patch.object(browse,'local_data',side_effect=AssertionError('local reconstruction attempted')):
            data=browse.node_data(self.source,'123')
            page=browse.render(self.config,self.source,data,'123').decode()
        self.assertIn('Exact stored claim body from node',page)
        self.assertIn('Exact node prose &lt;script&gt;inert&lt;/script&gt;',page)
        self.assertIn('b'*64,page)
        self.assertNotIn('<script>',page)

    def test_malformed_or_inconsistent_media_is_error_not_absence(self):
        url=self.browser_url()
        for value in [{}, {'readings':[{'state':'deliberately_unillustrated','images':[],'absence_decisions':[]}]},
                      {'readings':[{'state':'generated','images':[],'absence_decisions':[]}]}]:
            with self.subTest(value=value):
                self.responses['/v2/media']=(200,value)
                _, page=self.read_browser(url+'/?source=node&as_of=123')
                self.assertIn('Media could not be read',page)
                self.assertNotIn('deliberately_unillustrated',page)
