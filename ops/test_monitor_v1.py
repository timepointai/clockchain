"""monitor_v1.run against an injected proxy and a fake node; nothing leaves the process."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
from fly_proxy import ProxyFailed
import monitor_v1
import owner_jobs
import v1_update
from v1_identity import Expected

CURATORS = ['8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
            '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c',
            'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1']
INSTANCE = '11' * 32
EXPECTED = Expected(INSTANCE, ','.join(CURATORS), '4')
BASE = 'http://cc-node.invalid'
APP = 'cc-sentinel-app'
SECRET = 'SENTINEL-EXTRA-TOKEN-5b1e0c'


def health_doc(**overrides):
    doc = {'ledger': 'v1', 'instance': INSTANCE, 'fold_version': EXPECTED.fold,
           'filter_version': EXPECTED.filter_version, 'curators': list(CURATORS), 'max_hops': 4,
           'build': 'test-build'}
    doc.update(overrides)
    return doc


class Response:
    def __init__(self, status, body):
        self.status, self.body = status, body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeNode:
    """Stands in for urllib.request.urlopen; answers queued per path, last one repeats."""

    def __init__(self, health=None, ready=None):
        self.answers = {'/health': [(200, health or health_doc())],
                        '/ready': ready or [(200, {'serving': True})]}
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append((req.get_method(), req.full_url, dict(req.header_items()), req.data))
        if not req.full_url.startswith(BASE + '/'):
            raise AssertionError('request left the proxied node: ' + req.full_url)
        if isinstance(self.answers.get(req.full_url[len(BASE):]), OSError):
            raise self.answers[req.full_url[len(BASE):]]
        queue = self.answers.get(req.full_url[len(BASE):], [(404, {'error': 'not found'})])
        status, body = queue.pop(0) if len(queue) > 1 else queue[0]
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, 'x', {}, io.BytesIO(raw))
        return Response(status, raw)

    def paths(self):
        return [url[len(BASE):] for _, url, _, _ in self.requests]


class FakeProxy:
    def __init__(self, error=None):
        self.error, self.calls, self.open = error, [], 0

    def __call__(self, app, state, job):
        self.calls.append((app, state, job))
        return self.context()

    @contextlib.contextmanager
    def context(self):
        if self.error:
            raise self.error
        self.open += 1
        try:
            yield BASE
        finally:
            self.open -= 1


class MonitorRunTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.assertFalse(self.dir.is_relative_to(owner_jobs.ROOT))
        self.state = self.dir / 'state'
        self.env = {'CC_FLY_APP': APP, 'CC_OPS_STATE_DIR': str(self.state),
                    'CC_V1_INSTANCE': INSTANCE, 'CC_V1_CURATORS': ','.join(CURATORS),
                    'CC_V1_MAX_HOPS': '4', 'CC_EXTRA_TOKEN': SECRET}
        self.env_path = self.write_env(self.env)
        self.notes = []

    def write_env(self, env, mode=0o600):
        path = self.dir / 'monitor.env'
        path.write_text(''.join(f'{k}={v}\n' for k, v in env.items()))
        path.chmod(mode)
        return path

    def notify(self, title, message):
        self.notes.append((title, message))
        return True

    def run_monitor(self, node, proxy=None):
        self.proxy = proxy or FakeProxy()
        stderr, out, err = io.StringIO(), io.StringIO(), io.StringIO()
        with patch.object(v1_update.urllib.request, 'urlopen', node), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = monitor_v1.run(self.env_path, proxy=self.proxy, notify=self.notify, stderr=stderr)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(err.getvalue(), '')
        self.assertEqual(self.proxy.open, 0)  # the proxy context is always closed
        for method, url, headers, data in node.requests:
            self.assertEqual((method, data), ('GET', None), url)
            self.assertNotIn('Authorization', headers)  # the monitor holds no node credential
        return code, stderr.getvalue()

    def status(self):
        path = self.state / monitor_v1.STATUS
        return json.loads(path.read_text()), path.read_text()

    def assert_alert(self, code, stderr, kind, secrets=(SECRET,)):
        self.assertEqual(code, 1)
        doc, raw = self.status()
        self.assertEqual((doc['schema'], doc['result'], doc['kind']), (monitor_v1.SCHEMA, 'alert', kind))
        self.assertEqual(self.notes, [('Clockchain monitor',
                                       f'{kind.replace("_", " ")}: see {monitor_v1.STATUS}')])
        self.assertTrue(stderr.startswith(f'monitor alert ({kind}): '))
        for secret in secrets:
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(secret, repr(self.notes))
        return doc

    def test_healthy_node_is_quiet_and_writes_ok_status(self):
        node = FakeNode()
        code, stderr = self.run_monitor(node)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(self.notes, [])
        doc, _ = self.status()
        self.assertEqual(doc['result'], 'ok')
        self.assertEqual(doc['schema'], monitor_v1.SCHEMA)
        self.assertEqual(doc['identity'], 'match')
        self.assertEqual(doc['filter_version'], EXPECTED.filter_version)
        self.assertEqual(doc['build'], 'test-build')
        self.assertIs(doc['ready'], True)
        self.assertEqual(node.paths(), ['/health', '/ready'])
        self.assertEqual(self.proxy.calls, [(APP, self.state, 'monitor')])

    def test_identity_drift_alerts(self):
        cases = {'instance': health_doc(instance='22' * 32),
                 'curators': health_doc(curators=CURATORS[1:]),
                 'max_hops': health_doc(max_hops=5),
                 'filter_version': health_doc(filter_version='33' * 32)}
        for field, doc in cases.items():
            with self.subTest(field):
                self.notes = []
                node = FakeNode(health=doc)
                code, stderr = self.run_monitor(node)
                alert = self.assert_alert(code, stderr, 'identity_drift')
                self.assertIn(field, alert['error'])
                self.assertEqual(node.paths(), ['/health'])  # no readiness read after drift

    def test_health_that_is_not_json_is_drift(self):
        code, stderr = self.run_monitor(FakeNode(health=b'<html>proxy page</html>'))
        self.assert_alert(code, stderr, 'identity_drift')

    def test_not_ready(self):
        node = FakeNode(ready=[(503, {'reason': 'store_unavailable'})])
        code, stderr = self.run_monitor(node)
        doc = self.assert_alert(code, stderr, 'not_ready')
        self.assertIn('store_unavailable', doc['error'])
        self.assertEqual(node.paths(), ['/health', '/ready'])  # only busy is retried

    def test_ready_200_but_not_serving_is_not_ready(self):
        code, stderr = self.run_monitor(FakeNode(ready=[(200, {'serving': False})]))
        self.assert_alert(code, stderr, 'not_ready')

    def test_health_non_200_is_not_ready(self):
        node = FakeNode()
        node.answers['/health'] = [(502, b'bad gateway')]
        code, stderr = self.run_monitor(node)
        self.assert_alert(code, stderr, 'not_ready')

    def test_busy_then_ready_is_ok(self):
        node = FakeNode(ready=[(503, {'reason': 'busy'}), (200, {'serving': True})])
        code, stderr = self.run_monitor(node)
        self.assertEqual((code, stderr, self.notes), (0, '', []))
        self.assertEqual(self.status()[0]['result'], 'ok')
        self.assertEqual(node.paths(), ['/health', '/ready', '/ready'])

    def test_proxy_failure_is_unreachable_and_redacted(self):
        error = ProxyFailed(f'fly proxy exited: {SECRET} for {APP}')
        node = FakeNode()
        code, stderr = self.run_monitor(node, FakeProxy(error))
        doc = self.assert_alert(code, stderr, 'unreachable', secrets=(SECRET, APP))
        self.assertIn(owner_jobs.REDACTED, doc['error'])
        self.assertIn(owner_jobs.REDACTED, stderr)
        self.assertEqual(node.requests, [])

    def test_connection_error_is_unreachable(self):
        node = FakeNode()
        node.answers['/health'] = urllib.error.URLError(f'connection refused ({SECRET})')
        code, stderr = self.run_monitor(node)
        self.assert_alert(code, stderr, 'unreachable')

    def test_unexpected_error_echoing_secrets_is_redacted(self):
        error = RuntimeError(f'token={SECRET} instance={INSTANCE} curators={",".join(CURATORS)}')
        code, stderr = self.run_monitor(FakeNode(), FakeProxy(error))
        self.assert_alert(code, stderr, 'error', secrets=(SECRET, INSTANCE, *CURATORS))

    def test_world_readable_env_file_is_a_configuration_failure(self):
        self.env_path.chmod(0o644)
        node = FakeNode()
        code, stderr = self.run_monitor(node)
        self.assertEqual(code, 1)
        self.assertEqual(self.notes, [('Clockchain monitor', f'configuration: see {monitor_v1.STATUS}')])
        self.assertTrue(stderr.startswith('monitor alert (configuration): ConfigError'))
        for value in self.env.values():
            if len(value) >= 4:  # redaction's threshold; '4' (max hops) is not a secret
                self.assertNotIn(value, stderr)
        self.assertEqual(self.proxy.calls, [])
        self.assertEqual(node.requests, [])
        self.assertFalse(self.state.exists())  # no state dir was trusted, so no status written

    def test_missing_names_are_a_configuration_failure(self):
        env = dict(self.env)
        del env['CC_FLY_APP']
        self.write_env(env)
        code, stderr = self.run_monitor(FakeNode())
        self.assertEqual(code, 1)
        self.assertIn('CC_FLY_APP', stderr)
        self.assertNotIn(SECRET, stderr)
        self.assertEqual(self.notes, [('Clockchain monitor', f'configuration: see {monitor_v1.STATUS}')])

    def test_lock_held_returns_quietly_without_the_proxy(self):
        owner_jobs.private_dir(self.state)
        node = FakeNode()
        with owner_jobs.JobLock(self.state, 'monitor') as held:
            self.assertTrue(held)
            code, stderr = self.run_monitor(node)
        self.assertEqual((code, stderr, self.notes), (0, '', []))
        self.assertEqual(self.proxy.calls, [])
        self.assertEqual(node.requests, [])
        self.assertFalse((self.state / monitor_v1.STATUS).exists())

    def test_read_only_client_refuses_writes_before_any_request(self):
        node = FakeNode()
        client = v1_update.ReadOnlyNode(BASE, opener=node)
        for method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            with self.assertRaises(v1_update.ProductionWriteRefused):
                client.request(method, '/health')
        with self.assertRaises(v1_update.ProductionWriteRefused):
            client.request('GET', '/health', body=b'{}')
        self.assertEqual(node.requests, [])


if __name__ == '__main__':
    unittest.main()
