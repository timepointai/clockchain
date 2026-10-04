"""schedule_backups: run() with an injected proxy, capture, machine list and fake node.

No flyctl, pg_dump, PostgreSQL or network: every boundary is a fake, and all
files live in a temporary directory outside the checkout.
"""
import contextlib
import datetime
import io
import json
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import owner_jobs
import schedule_backups
import v1_update
from v1_identity import Expected

CURATORS = ['8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
            '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c',
            'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1']
INSTANCE = '11' * 32
EXPECTED = Expected(INSTANCE, ','.join(CURATORS), '4')
APP = 'cc-test-app'
BASE = 'http://cc-node.invalid'
API_KEY = 'SENTINEL-NODE-API-KEY-c41d9e'
DIGEST = 'sha256:' + 'ab' * 32
# Deliberately not in json.dumps form: the bundle must hold the served bytes verbatim.
EXPORT = b'{ "schema": "cc.v1-export.test",\n  "commitment": "' + b'cd' * 32 + b'",  "events": [] }\n'


def machine(group, state='stopped', digest=DIGEST, id=None):
    """Shaped like test_v1_release.machine()."""
    config = {'image': f'registry.fly.io/{APP}@' + digest,
              'metadata': {'fly_process_group': group} if group else {},
              'mounts': [{'path': '/data/media'}], 'restart': {'policy': 'no'}}
    return dict(id=id or group or 'unnamed', state=state, image_ref={'digest': digest}, config=config)


def health_doc(**overrides):
    doc = {'ledger': 'v1', 'instance': INSTANCE, 'fold_version': EXPECTED.fold,
           'filter_version': EXPECTED.filter_version, 'curators': list(CURATORS), 'max_hops': 4}
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
    """urlopen stand-in: /health, /ready and a key-protected /v1/export."""

    def __init__(self, events):
        self.events = events
        self.answers = {'/health': (200, json.dumps(health_doc()).encode()),
                        '/ready': (200, b'{"serving": true}'),
                        '/v1/export': (200, EXPORT)}
        self.requests = []

    def __call__(self, req, timeout=None):
        path = req.full_url[len(BASE):]
        headers = dict(req.header_items())
        self.requests.append((req.get_method(), path, headers.get('Authorization'), req.data))
        self.events.append('GET ' + path)
        if not req.full_url.startswith(BASE + '/'):
            raise AssertionError('request left the proxied node')
        status, raw = self.answers.get(path, (404, b'{}'))
        if path == '/v1/export' and headers.get('Authorization') != 'Bearer ' + API_KEY:
            status, raw = 401, b'{"error":"unauthorized"}'
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, 'x', {}, io.BytesIO(raw))
        return Response(status, raw)


class BackupRunTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.assertFalse(self.dir.is_relative_to(owner_jobs.ROOT))
        self.backups, self.state = self.dir / 'backups', self.dir / 'state'
        self.env = {'CC_FLY_APP': APP, 'CC_BACKUP_DIR': str(self.backups),
                    'CC_OPS_STATE_DIR': str(self.state), 'CC_BACKUP_DB_APP': 'cc-test-db',
                    'CC_BACKUP_DATABASE': 'clockchain_v1', 'CC_BACKUP_USER': 'cc_operator',
                    'CC_NODE_API_KEY': API_KEY, 'CC_V1_INSTANCE': INSTANCE,
                    'CC_V1_CURATORS': ','.join(CURATORS), 'CC_V1_MAX_HOPS': '4'}
        self.env_path = self.write_env(self.env)
        self.events, self.notes, self.captures = [], [], []
        self.node = FakeNode(self.events)
        self.capture_error = None
        self.report = {'state': 'bound', 'production_export_matched': True,
                       'counts': {'candidates': 3, 'receipts': 3}, 'corpus_digest': 'ee' * 32,
                       'commitment': 'cd' * 32, 'commitment_basis': 'export',
                       'dump_sha256': 'f0' * 32}
        self.machines = [machine('app', 'started'), machine(None, id='db-machine', digest='sha256:' + '00' * 32)]

    def write_env(self, env, mode=0o600):
        path = self.dir / 'backup.env'
        path.write_text(''.join(f'{k}={v}\n' for k, v in env.items()))
        path.chmod(mode)
        return path

    def notify(self, title, message):
        self.notes.append((title, message))
        return True

    @contextlib.contextmanager
    def proxy_context(self):
        self.events.append('proxy open')
        try:
            yield BASE
        finally:
            self.events.append('proxy closed')

    def proxy(self, app, state, job):
        self.events.append(('proxy', app, state, job))
        return self.proxy_context()

    def capture(self, db_app, database, user, bundle, expected, *, export=None, image=None):
        self.events.append('capture')
        self.captures.append(dict(db_app=db_app, database=database, user=user, bundle=bundle,
                                  expected=expected, export=export, image=image))
        bundle.mkdir(mode=0o700, parents=True)
        (bundle / 'manifest.json').write_text(json.dumps({
            'restore_verified': True, 'production_export_matched': True, **self.report}))
        if self.capture_error:
            raise self.capture_error
        return dict(self.report)

    def run_backup(self, **overrides):
        kwargs = dict(proxy=self.proxy, capture=self.capture, machines=self.machines,
                      auth=lambda: self.events.append('auth'))
        kwargs.update(overrides)
        stderr, out, err = io.StringIO(), io.StringIO(), io.StringIO()
        with patch.object(v1_update.urllib.request, 'urlopen', self.node), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = schedule_backups.run(self.env_path, notify=self.notify, stderr=stderr, **kwargs)
        self.assertEqual((out.getvalue(), err.getvalue()), ('', ''))
        for method, path, auth, data in self.node.requests:
            self.assertEqual((method, data), ('GET', None), path)
            if path != '/v1/export':
                self.assertIsNone(auth, path)  # the full key goes to the export read only
        return code, stderr.getvalue()

    def status(self):
        raw = (self.state / schedule_backups.STATUS).read_text()
        return json.loads(raw), raw

    def assert_failed(self, code, stderr, secrets=(API_KEY,)):
        self.assertEqual(code, 1)
        doc, raw = self.status()
        self.assertEqual((doc['schema'], doc['result']), (schedule_backups.SCHEMA, 'failed'))
        self.assertEqual(self.notes, [('Clockchain backup', f'backup failed: see {schedule_backups.STATUS}')])
        self.assertTrue(stderr.startswith('backup failed: '))
        for secret in secrets:
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(secret, repr(self.notes))
        return doc

    def bundles(self, suffix=''):
        return sorted(p.name for p in self.backups.iterdir()
                      if p.is_dir() and p.name.endswith(suffix) and p.name.startswith('cc_v1-'))

    # --- success ---------------------------------------------------------------

    def test_success_keeps_served_export_and_writes_ok_status(self):
        code, stderr = self.run_backup()
        self.assertEqual((code, stderr, self.notes), (0, '', []))
        (call,) = self.captures
        bundle = call['bundle']
        self.assertRegex(bundle.name, r'^cc_v1-\d{8}T\d{6}Z$')
        self.assertEqual(bundle.parent, self.backups)
        self.assertEqual((call['db_app'], call['database'], call['user']),
                         ('cc-test-db', 'clockchain_v1', 'cc_operator'))
        self.assertEqual(call['expected'].filter_version, EXPECTED.filter_version)
        self.assertEqual(call['export'], json.loads(EXPORT))
        self.assertEqual(call['image'], f'registry.fly.io/{APP}@{DIGEST}')
        export = bundle / 'export.json'
        self.assertEqual(export.read_bytes(), EXPORT)
        self.assertEqual(stat.S_IMODE(export.stat().st_mode), 0o600)
        doc, raw = self.status()
        self.assertEqual(doc['result'], 'ok')
        self.assertEqual(doc['backup'], bundle.name)
        self.assertEqual(doc['image'], call['image'])
        self.assertEqual((doc['state'], doc['commitment'], doc['dump_sha256'], doc['counts']),
                         ('bound', self.report['commitment'], self.report['dump_sha256'],
                          self.report['counts']))
        self.assertIs(doc['restore_verified'], True)
        self.assertEqual((doc['kept'], doc['removed']), (1, []))
        self.assertNotIn(API_KEY, raw)
        self.assertEqual(stat.S_IMODE((self.state / schedule_backups.STATUS).stat().st_mode), 0o600)
        # The image is pinned and docker auth done before the proxy; capture runs after it closes.
        self.assertEqual(self.events, ['auth', ('proxy', APP, self.state, 'backup'), 'proxy open',
                                       'GET /health', 'GET /ready', 'GET /v1/export',
                                       'proxy closed', 'capture'])
        export_req = [r for r in self.node.requests if r[1] == '/v1/export']
        self.assertEqual(export_req[0][2], 'Bearer ' + API_KEY)

    def test_retention_keeps_newest_30_verified_and_5_failed_only(self):
        self.backups.mkdir(mode=0o700)
        base = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        old = [f'cc_v1-{owner_jobs.stamp(base + datetime.timedelta(hours=i))}' for i in range(32)]
        manifest = json.dumps({'restore_verified': True, 'production_export_matched': True})
        for name in old:
            (self.backups / name).mkdir()
            (self.backups / name / 'manifest.json').write_text(manifest)
        failed = [f'cc_v1-{owner_jobs.stamp(base - datetime.timedelta(days=i))}.failed' for i in range(7)]
        for name in failed:
            (self.backups / name).mkdir()
        # Older than every verified bundle, so counting or pruning them would be visible.
        unverified = {'cc_v1-20000101T000000Z': {'restore_verified': False, 'production_export_matched': True},
                      'cc_v1-20000102T000000Z': {'restore_verified': True, 'production_export_matched': False},
                      'cc_v1-20000103T000000Z': {'restore_verified': 'true', 'production_export_matched': True}}
        for name, doc in unverified.items():
            (self.backups / name).mkdir()
            (self.backups / name / 'manifest.json').write_text(json.dumps(doc))
        (self.backups / 'cc_v1-20000104T000000Z').mkdir()                     # no manifest at all
        (self.backups / 'cc_v1-20000105T000000Z' / 'manifest.json').parent.mkdir()
        (self.backups / 'cc_v1-20000105T000000Z' / 'manifest.json').write_text('not json')
        (self.backups / 'notes').mkdir()
        (self.backups / 'cc_v1-latest').mkdir()
        (self.backups / 'cc_v1-20000101T000000Z.tar').write_text('archive')
        (self.backups / 'cc_v1-19990101T000000Z').write_text('a file, not a bundle')
        (self.backups / 'README').write_text('owner notes')
        outside = self.dir / 'elsewhere'
        outside.mkdir()
        (outside / 'manifest.json').write_text(manifest)
        (self.backups / 'cc_v1-19980101T000000Z').symlink_to(outside)
        untouched_before = sorted(p.name for p in self.backups.iterdir()
                                  if p.name not in old and p.name not in failed)

        code, stderr = self.run_backup()
        self.assertEqual((code, stderr), (0, ''))
        new = self.captures[0]['bundle'].name
        verified = [p.name for p in sorted(self.backups.iterdir())
                    if p.is_dir() and not p.is_symlink() and schedule_backups.BUNDLE.fullmatch(p.name)
                    and schedule_backups.verified(p)]
        self.assertEqual(verified, old[3:] + [new])  # the three oldest of 33 are gone
        self.assertEqual(len(verified), 30)
        self.assertEqual(self.bundles('.failed'), sorted(failed)[2:])
        untouched_after = sorted(p.name for p in self.backups.iterdir()
                                 if p.name not in old and p.name not in failed and p.name != new)
        self.assertEqual(untouched_after, untouched_before)
        self.assertTrue((outside / 'manifest.json').exists())
        doc, _ = self.status()
        self.assertEqual(doc['kept'], 30)
        self.assertEqual(sorted(doc['removed']), sorted(old[:3] + sorted(failed)[:2]))

    def test_prune_without_an_excess_removes_nothing(self):
        self.backups.mkdir(mode=0o700)
        for i in range(3):
            (self.backups / f'cc_v1-2025010{i + 1}T000000Z.failed').mkdir()
        self.assertEqual(schedule_backups.prune(self.backups), {'kept': 0, 'removed': []})
        self.assertEqual(len(self.bundles('.failed')), 3)

    # --- failures --------------------------------------------------------------

    def test_capture_failure_marks_bundle_failed_and_redacts(self):
        self.capture_error = RuntimeError(f'pg_dump: auth failed for key {API_KEY} on cc-test-db')
        code, stderr = self.run_backup()
        doc = self.assert_failed(code, stderr, secrets=(API_KEY, 'cc-test-db'))
        bundle = self.captures[0]['bundle']
        self.assertFalse(bundle.exists())
        self.assertTrue(bundle.with_name(bundle.name + '.failed').is_dir())
        self.assertEqual(self.bundles(), [bundle.name + '.failed'])
        self.assertIn('RuntimeError', doc['error'])
        self.assertIn(owner_jobs.REDACTED, doc['error'])

    def test_unbound_report_is_a_failure(self):
        self.report['state'] = 'unbound'
        code, stderr = self.run_backup()
        self.assert_failed(code, stderr)
        self.assertEqual(len(self.bundles('.failed')), 1)
        self.assertFalse((self.captures[0]['bundle'].with_name(
            self.captures[0]['bundle'].name + '.failed') / 'export.json').exists())

    def test_unmatched_export_is_a_failure(self):
        self.report['production_export_matched'] = False
        code, stderr = self.run_backup()
        self.assert_failed(code, stderr)
        self.assertEqual(len(self.bundles('.failed')), 1)

    def test_identity_drift_skips_capture(self):
        for name, doc in {'instance': health_doc(instance='22' * 32),
                          'max_hops': health_doc(max_hops=5),
                          'curators': health_doc(curators=CURATORS[:2])}.items():
            with self.subTest(name):
                self.notes, self.captures = [], []
                self.node.answers['/health'] = (200, json.dumps(doc).encode())
                code, stderr = self.run_backup()
                status = self.assert_failed(code, stderr)
                self.assertIn('IdentityDrift', status['error'])
                self.assertEqual(self.captures, [])
                self.assertFalse(any(r[1] == '/v1/export' for r in self.node.requests))
                self.assertEqual(self.bundles(), [])

    def test_not_ready_skips_export_and_capture(self):
        self.node.answers['/ready'] = (503, b'{"reason":"store_unavailable"}')
        code, stderr = self.run_backup()
        self.assertIn('NotReady', self.assert_failed(code, stderr)['error'])
        self.assertEqual(self.captures, [])
        self.assertFalse(any(r[1] == '/v1/export' for r in self.node.requests))

    def test_export_non_200_is_a_failure(self):
        for status in (401, 500):
            with self.subTest(status=status):
                self.notes = []
                self.node.answers['/v1/export'] = (status, b'{"error":"x"}')
                code, stderr = self.run_backup()
                self.assertIn(f'/v1/export: HTTP {status}', self.assert_failed(code, stderr)['error'])
                self.assertEqual(self.captures, [])

    def test_unpinned_app_image_fails_before_auth_and_proxy(self):
        unpinned = machine('app', 'started')
        unpinned['image_ref'] = {}
        unpinned['config']['image'] = f'registry.fly.io/{APP}:latest'
        for machines in ([unpinned], [], [machine('app', 'started'), machine('app', 'started', id='b')]):
            with self.subTest(n=len(machines)):
                self.notes, self.events[:] = [], []
                code, stderr = self.run_backup(machines=machines)
                self.assert_failed(code, stderr)
                self.assertEqual(self.events, [])

    def test_required_names_missing_is_a_failure(self):
        env = dict(self.env)
        del env['CC_NODE_API_KEY']
        env['CC_BACKUP_USER'] = ''
        self.write_env(env)
        code, stderr = self.run_backup()
        self.assertEqual(code, 1)
        self.assertEqual(stderr, 'backup failed: ConfigError: env file needs: CC_BACKUP_USER, CC_NODE_API_KEY\n')
        self.assertEqual(self.notes, [('Clockchain backup', f'backup failed: see {schedule_backups.STATUS}')])
        self.assertEqual(self.events, [])
        self.assertFalse(self.state.exists())

    def test_world_readable_env_file_is_refused(self):
        self.env_path.chmod(0o644)
        code, stderr = self.run_backup()
        self.assertEqual(code, 1)
        self.assertIn('chmod 600', stderr)
        self.assertNotIn(API_KEY, stderr)
        self.assertEqual(self.events, [])

    def test_lock_held_is_a_failure_without_touching_the_node(self):
        owner_jobs.private_dir(self.state)
        with owner_jobs.JobLock(self.state, 'backup') as held:
            self.assertTrue(held)
            code, stderr = self.run_backup()
        self.assertIn('holds the lock', self.assert_failed(code, stderr)['error'])
        self.assertEqual(self.events, [])


class GenerateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        env = {'CC_FLY_APP': APP, 'CC_BACKUP_DIR': str(self.dir / 'backups'),
               'CC_OPS_STATE_DIR': str(self.dir / 'state'), 'CC_BACKUP_DB_APP': 'cc-test-db',
               'CC_BACKUP_DATABASE': 'clockchain_v1', 'CC_BACKUP_USER': 'cc_operator',
               'CC_NODE_API_KEY': API_KEY, 'CC_V1_INSTANCE': INSTANCE,
               'CC_V1_CURATORS': ','.join(CURATORS), 'CC_V1_MAX_HOPS': '4'}
        self.env_path = self.dir / 'backup.env'
        self.env_path.write_text(''.join(f'{k}={v}\n' for k, v in env.items()))
        self.env_path.chmod(0o600)

    def generate(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(schedule_backups.main(['generate', '--env-file', str(self.env_path), *extra]), 0)
        data = out.getvalue()
        for secret in (API_KEY, INSTANCE, 'cc-test-db', 'clockchain_v1', 'cc_operator', APP, *CURATORS):
            self.assertNotIn(secret, data)
        return plistlib.loads(data.encode())

    def test_time_option_sets_the_calendar(self):
        doc = self.generate('--time', '07:30')
        self.assertEqual(doc['StartCalendarInterval'], {'Hour': 7, 'Minute': 30})
        self.assertNotIn('StartInterval', doc)
        self.assertEqual(doc['Label'], schedule_backups.LABEL)
        self.assertEqual(doc['ProgramArguments'][-3:], ['run', '--env-file', str(self.env_path)])

    def test_default_is_nine_am(self):
        self.assertEqual(self.generate()['StartCalendarInterval'], {'Hour': 9, 'Minute': 0})

    def test_invalid_time_exits(self):
        for value in ('24:00', '9', '09:60', 'ab'):
            with self.subTest(value=value):
                err = io.StringIO()
                with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
                    schedule_backups.main(['generate', '--env-file', str(self.env_path), '--time', value])
                self.assertEqual(caught.exception.code, 2)
                self.assertIn('HH:MM', err.getvalue())
                self.assertFalse((self.dir / 'state').exists())


if __name__ == '__main__':
    unittest.main()
