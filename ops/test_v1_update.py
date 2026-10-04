"""v1 update release: read-only client, identity gate, readiness, commitments, store
fingerprint, the update promotion and the owner release wrapper.

Everything is synthetic: made-up hex identities and commitments, `.invalid`
hosts, and fakes for Fly, SSH and HTTP. The store fingerprint runs against a
throwaway database on the TEST_DATABASE_URL server (skipped without it).
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import deploy_digest
import release
import test_v1_release as base
from test_v1_backup import DATABASE_URL, Database, PgCase
from test_v1_checks import CURATORS
import v1_update
from v1_backup import fingerprint_v1
from v1_identity import TABLES, Expected, corpus_digest, view_commitment
from v1_update import (CommitmentChanged, IdentityDrift, NotReady, ProductionWriteRefused,
                       ReadOnlyNode, expected_identity, identity_of, observe, require_identity,
                       require_ready, require_unchanged)

EXPECTED = Expected('11' * 32, ','.join(CURATORS), '4')
OTHER = Expected('11' * 32, ','.join(CURATORS), '5')
SHA = base.SHA
NEW = base.NEW
NEW_DIGEST = base.NEW_DIGEST
OLD = base.OLD
OLD_BUILD = 'a' * 12
BASE_URL = 'https://node.invalid'
FULL, READ = 'synthetic-full-key', 'synthetic-read-key'
sha = lambda data: hashlib.sha256(data).digest()

EVENTS = [sha(b'synthetic event one'), sha(b'synthetic event two')]
CORPUS = corpus_digest(EVENTS).hex()
COMMITMENT = view_commitment(bytes.fromhex(EXPECTED.filter_version), corpus_digest(EVENTS),
                             b'synthetic populated rows').hex()
OTHER_COMMITMENT = view_commitment(bytes.fromhex(EXPECTED.filter_version), corpus_digest(EVENTS),
                                   b'synthetic changed rows').hex()
OTHER_CORPUS = corpus_digest(EVENTS[:1]).hex()
COUNTS = {'bodies': 1, 'candidates': 2, 'identity': 1, 'receipts': 2, 'rejections': 0,
          'rule_identity': 1}
STORED = {'state': 'bound', 'instance': EXPECTED.instance, 'filter_version': EXPECTED.filter_version,
          'counts': COUNTS}
FINGERPRINT = {t: {'rows': COUNTS[t], 'sha256': hashlib.sha256(t.encode()).hexdigest()} for t in TABLES}
BACKUP = {'state': 'bound', 'counts': COUNTS, 'commitment': COMMITMENT,
          'commitment_basis': 'synthetic restored copy', 'dump_sha256': 'd' * 64}
DATABASE = ('synthetic-db-app', 'synthetic-database', 'synthetic-operator')
ENV = dict(base.ENV, CC_NODE_URL=BASE_URL, CC_NODE_API_KEY=FULL, CC_NODE_READ_KEY=READ,
           CC_BACKUP_DB_APP=DATABASE[0], CC_BACKUP_DATABASE=DATABASE[1], CC_BACKUP_USER=DATABASE[2])
SECRET_NAMES = ('CC_NODE_API_KEY', 'CC_NODE_READ_KEY', 'CC_V1_CURATORS', 'CC_V1_INSTANCE', 'DATABASE_URL')
SECRETS = [{'name': n, 'digest': 'e' * 16} for n in SECRET_NAMES]
SEED = [{'name': 'CC_V1_NODE_SEED', 'digest': 'f' * 16}]


def health_of(expected=EXPECTED, **kw):
    """A `/health` document serving exactly `expected`."""
    doc = {'ledger': 'v1', 'build': OLD_BUILD, 'posture': 'live', 'instance': expected.instance,
           'fold_version': dict(expected.fold), 'filter_version': expected.filter_version,
           'curators': list(expected.curators), 'max_hops': expected.max_hops, 'semantic': 'ready'}
    doc.update(kw)
    return doc


def export_bytes(corpus=CORPUS, commitment=COMMITMENT, **kw):
    doc = {'corpus_digest': corpus, 'commitment': commitment,
           'envelopes': [e.hex() + '00' * 64 for e in EVENTS],
           'rule': {'fold_version': 1, 'fold_manifest': EXPECTED.fold['manifest'],
                    'filter_version': EXPECTED.filter_version}}
    doc.update(kw)
    return json.dumps(doc, separators=(',', ':')).encode()


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
    """A synthetic v1 node behind `urlopen`. Records every request it receives.

    State in `after` replaces the matching attribute once `deployed` is set
    (the promotion's fake `flyctl deploy` sets it and switches the build).
    """

    def __init__(self, events=None):
        self.health = health_of()
        self.ready = [(200, {'serving': True, 'posture': 'live'})]
        self.snapshot = {'corpus_digest': CORPUS, 'commitment': COMMITMENT, 'rows': []}
        self.export = export_bytes()
        self.after, self.deployed, self.seen = {}, False, []
        self.events = [] if events is None else events

    def state(self, name):
        return self.after[name] if self.deployed and name in self.after else getattr(self, name)

    def __call__(self, req, timeout=None):
        url = urlsplit(req.full_url)
        method, auth = req.get_method(), req.get_header('Authorization')
        self.seen.append((method, url.netloc, url.path, auth, req.data))
        self.events.append(url.path)
        status, body = self.route(url.path, auth)
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, 'synthetic', {}, io.BytesIO(body))
        return Response(status, body)

    def route(self, path, auth):
        if path == '/health':
            return 200, json.dumps(self.state('health')).encode()
        if path == '/ready':
            queue = self.state('ready')
            status, body = queue.pop(0) if len(queue) > 1 else queue[0]
            return status, json.dumps(body).encode()
        if path == '/v1/snapshot':
            if auth not in ('Bearer ' + READ, 'Bearer ' + FULL):
                return 401, b'{}'
            return 200, json.dumps(self.state('snapshot')).encode()
        if path == '/v1/export':
            if auth != 'Bearer ' + FULL:
                return 403, b'{}'
            return 200, self.state('export')
        return 404, b'{}'


class ReadOnlyNodeTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

    def opener(self, req, timeout=None):
        self.calls.append((req.get_method(), req.full_url, req.get_header('Authorization'), timeout))
        if req.full_url.endswith('/missing'):
            raise urllib.error.HTTPError(req.full_url, 404, 'synthetic', {}, io.BytesIO(b'gone'))
        return Response(200, b'{"ok":true}')

    def test_get_goes_through_the_injected_opener(self):
        node = ReadOnlyNode(BASE_URL + '/', self.opener)
        self.assertEqual(node.get('/health'), (200, b'{"ok":true}'))
        self.assertEqual(node.json('/v1/snapshot', READ), {'ok': True})
        self.assertEqual(node.get('/missing'), (404, b'gone'))
        self.assertEqual([c[:3] for c in self.calls],
                         [('GET', BASE_URL + '/health', None),
                          ('GET', BASE_URL + '/v1/snapshot', 'Bearer ' + READ),
                          ('GET', BASE_URL + '/missing', None)])
        self.assertEqual(node.requests, [('GET', '/health'), ('GET', '/v1/snapshot'), ('GET', '/missing')])
        with self.assertRaisesRegex(ValueError, '/missing: HTTP 404'):
            node.json('/missing')

    def test_writes_are_refused_before_the_opener_is_called(self):
        node = ReadOnlyNode(BASE_URL, self.opener)
        for method in ('PUT', 'POST', 'DELETE', 'PATCH', 'HEAD', 'get', 'OPTIONS'):
            for body in (None, b'synthetic'):
                with self.subTest(method=method, body=body), \
                        self.assertRaisesRegex(ProductionWriteRefused, method):
                    node.request(method, '/v1/candidates', FULL, body)
        self.assertEqual(self.calls, [])
        self.assertEqual(node.requests, [])

    def test_get_with_a_body_is_refused_before_the_opener_is_called(self):
        node = ReadOnlyNode(BASE_URL, self.opener)
        for body in (b'synthetic', b'', {}):
            with self.subTest(body=body), self.assertRaises(ProductionWriteRefused):
                node.request('GET', '/v1/export', FULL, body)
        self.assertEqual(self.calls, [])
        self.assertEqual(node.requests, [])


class IdentityTests(unittest.TestCase):
    def test_exact_match_passes_and_normalizes(self):
        self.assertEqual(require_identity(health_of(), EXPECTED), expected_identity(EXPECTED))
        self.assertEqual(require_identity(health_of(), EXPECTED, STORED), expected_identity(EXPECTED))
        # The node may serve hashes as 32-byte arrays; they normalize to the same identity.
        arrays = health_of(instance=list(bytes.fromhex(EXPECTED.instance)),
                           filter_version=list(bytes.fromhex(EXPECTED.filter_version)))
        self.assertEqual(identity_of(arrays), expected_identity(EXPECTED))

    def test_each_single_field_drift_is_named(self):
        other_manifest = '0f' * 32
        cases = (('instance', {'instance': '22' * 32}),
                 ('curators', {'curators': CURATORS[1:]}),
                 ('curators', {'curators': CURATORS + ['ff' * 32]}),
                 ('max_hops', {'max_hops': 5}),
                 ('max_hops', {'max_hops': True}),
                 ('max_hops', {'max_hops': '4'}),
                 ('fold_version', {'fold_version': {'version': 1, 'manifest': other_manifest}}),
                 ('fold_version', {'fold_version': {'version': 2, 'manifest': EXPECTED.fold['manifest']}}),
                 ('fold_version', {'fold_version': {'version': True, 'manifest': EXPECTED.fold['manifest']}}),
                 ('filter_version', {'filter_version': OTHER.filter_version}),
                 ('ledger', {'ledger': 'v0'}),
                 ('ledger', {'ledger': None}))
        for field, change in cases:
            with self.subTest(change=change):
                with self.assertRaisesRegex(IdentityDrift, f'expected identity: {field}$'):
                    require_identity(health_of(**change), EXPECTED)

    def test_malformed_health_is_drift(self):
        cases = ([], 'v1', None,
                 health_of(instance='xyz'), health_of(instance=None), health_of(curators='a' * 64),
                 health_of(curators=['nothex']), health_of(fold_version='v1'),
                 health_of(fold_version={'version': 1, 'manifest': 'short'}),
                 health_of(filter_version=list(range(31))))
        for health in cases:
            with self.subTest(health=health), self.assertRaises(IdentityDrift):
                require_identity(health, EXPECTED)

    def test_stored_identity_must_be_bound_to_the_expected_identity(self):
        for stored in (dict(STORED, state='provisioned_unbound'), dict(STORED, state='uninitialized'),
                       {'counts': COUNTS}, dict(STORED, instance='22' * 32),
                       dict(STORED, filter_version=OTHER.filter_version)):
            with self.subTest(stored=stored), self.assertRaisesRegex(IdentityDrift, 'stored rule identity'):
                require_identity(health_of(), EXPECTED, stored)


class ScriptedNode:
    def __init__(self, *replies):
        self.replies, self.paths = list(replies), []

    def get(self, path, key=None):
        self.paths.append(path)
        status, body = self.replies.pop(0)
        return status, body if isinstance(body, bytes) else json.dumps(body).encode()


SERVING = (200, {'serving': True, 'posture': 'live'})
BUSY = (503, {'serving': False, 'posture': 'live', 'reason': 'busy'})


class ReadyTests(unittest.TestCase):
    def ready(self, *replies):
        self.node, self.sleeps = ScriptedNode(*replies), []
        return require_ready(self.node, sleep=self.sleeps.append)

    def test_serving_passes_without_retry(self):
        self.assertEqual(self.ready(SERVING), SERVING[1])
        self.assertEqual((self.node.paths, self.sleeps), (['/ready'], []))

    def test_busy_is_retried_then_serving_passes(self):
        self.assertEqual(self.ready(BUSY, BUSY, SERVING), SERVING[1])
        self.assertEqual((len(self.node.paths), self.sleeps), (3, [1, 1]))

    def test_busy_on_every_attempt_fails(self):
        with self.assertRaisesRegex(NotReady, 'HTTP 503 .busy.'):
            self.ready(*[BUSY] * v1_update.READY_ATTEMPTS)
        self.assertEqual(len(self.node.paths), v1_update.READY_ATTEMPTS)
        self.assertEqual(len(self.sleeps), v1_update.READY_ATTEMPTS - 1)

    def test_other_unavailability_fails_at_once(self):
        for reply, message in (((503, {'serving': False, 'reason': 'store_unavailable'}), 'store_unavailable'),
                               ((503, b'not json'), 'HTTP 503$'),
                               ((500, {'reason': 'busy'}), 'HTTP 500'),
                               ((200, {'serving': False}), 'HTTP 200'),
                               ((200, {'serving': 'true'}), 'HTTP 200'),
                               ((200, b'[true]'), 'HTTP 200')):
            with self.subTest(reply=reply):
                with self.assertRaisesRegex(NotReady, message):
                    self.ready(reply, SERVING)
                self.assertEqual((self.node.paths, self.sleeps), (['/ready'], []))


class CommitmentTests(unittest.TestCase):
    def observe(self, **state):
        node = FakeNode()
        for name, value in state.items():
            setattr(node, name, value)
        self.node = node
        return observe(ReadOnlyNode(BASE_URL, node), FULL, READ)

    def test_observe_reads_snapshot_with_read_key_and_export_with_full_key(self):
        seen = self.observe()
        self.assertEqual((seen['corpus_digest'], seen['commitment']), (CORPUS, COMMITMENT))
        self.assertEqual(seen['export'], export_bytes())
        self.assertEqual(seen['export_sha256'], hashlib.sha256(export_bytes()).hexdigest())
        self.assertEqual([(m, p, a, d) for m, _, p, a, d in self.node.seen],
                         [('GET', '/v1/snapshot', 'Bearer ' + READ, None),
                          ('GET', '/v1/export', 'Bearer ' + FULL, None)])

    def test_export_naming_another_view_than_the_snapshot_is_refused(self):
        for export in (export_bytes(commitment=OTHER_COMMITMENT), export_bytes(corpus=OTHER_CORPUS)):
            with self.subTest(export=export), self.assertRaisesRegex(CommitmentChanged, 'different views'):
                self.observe(export=export)

    def test_unavailable_export_is_refused(self):
        node = FakeNode()
        with self.assertRaisesRegex(ValueError, '/v1/export: HTTP 403'):
            observe(ReadOnlyNode(BASE_URL, node), READ, READ)

    def test_identical_observations_pass(self):
        before, after = self.observe(), self.observe()
        self.assertEqual(require_unchanged(before, after),
                         {'corpus_digest': CORPUS, 'commitment': COMMITMENT,
                          'export_sha256': hashlib.sha256(export_bytes()).hexdigest()})

    def test_each_change_is_refused_and_named(self):
        before = self.observe()
        reordered = json.dumps(dict(reversed(list(json.loads(export_bytes()).items()))),
                               separators=(',', ':')).encode()
        cases = (('commitment, export', {'snapshot': {'corpus_digest': CORPUS, 'commitment': OTHER_COMMITMENT},
                                 'export': export_bytes(commitment=OTHER_COMMITMENT)}),
                 ('corpus_digest, export', {'snapshot': {'corpus_digest': OTHER_CORPUS, 'commitment': COMMITMENT},
                                            'export': export_bytes(corpus=OTHER_CORPUS)}),
                 ('export', {'export': export_bytes() + b' '}),
                 ('export', {'export': export_bytes() + b'\n'}),
                 ('export', {'export': reordered}),
                 ('export', {'export': json.dumps(json.loads(export_bytes())).encode()}))
        for named, state in cases:
            with self.subTest(named=named, state=state):
                after = self.observe(**state)
                self.assertNotEqual(after, before)
                with self.assertRaisesRegex(CommitmentChanged, f'no-write step: {named}$'):
                    require_unchanged(before, after)
        # A changed digest alone (export bytes held equal) is still named.
        for field, value in (('corpus_digest', OTHER_CORPUS), ('commitment', OTHER_COMMITMENT)):
            with self.assertRaisesRegex(CommitmentChanged, f'no-write step: {field}$'):
                require_unchanged(before, dict(before, **{field: value}))


def read_only_sql(db):
    """`sql` over a second connection whose transactions are read-only by default."""
    import psycopg
    conn = psycopg.connect(urlsplit(DATABASE_URL)._replace(path='/' + db.name).geturl(), autocommit=True)
    conn.execute('SET default_transaction_read_only = on')
    shim = SimpleNamespace(conn=conn)
    return conn, lambda query: Database.sql(shim, query)


@unittest.skipUnless(DATABASE_URL, 'TEST_DATABASE_URL required for real Postgres')
class FingerprintTests(PgCase):
    def read_only(self, db):
        conn, sql = read_only_sql(db)
        self.addCleanup(conn.close)
        return conn, sql

    def test_bound_store_has_one_entry_per_table(self):
        db = self.store()
        conn, sql = self.read_only(db)
        prints = fingerprint_v1(sql)
        self.assertEqual(tuple(prints), TABLES)
        self.assertEqual({t: p['rows'] for t, p in prints.items()},
                         {'bodies': 0, 'candidates': 0, 'identity': 1, 'receipts': 0, 'rejections': 0,
                          'rule_identity': 1})
        empty = hashlib.sha256(b'').hexdigest()
        for table, entry in prints.items():
            self.assertRegex(entry['sha256'], '^[0-9a-f]{64}$')
            self.assertEqual(entry['sha256'] == empty, entry['rows'] == 0, table)
        self.assertNotEqual(prints['identity']['sha256'], prints['rule_identity']['sha256'])

    def test_session_is_read_only_and_repeated_calls_are_equal(self):
        db = self.store(candidates=(b'synthetic one',), bodies=(b'synthetic body',))
        conn, sql = self.read_only(db)
        self.assertEqual(sql('SHOW default_transaction_read_only'), 'on')
        import psycopg
        with self.assertRaises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute('CREATE TABLE public.synthetic_write (x int)')
        self.assertEqual(fingerprint_v1(sql), fingerprint_v1(sql))
        self.assertEqual(fingerprint_v1(sql), fingerprint_v1(db.sql))

    def test_adding_a_row_changes_exactly_that_table(self):
        db = self.store(candidates=(b'synthetic one',))
        conn, sql = self.read_only(db)
        before = fingerprint_v1(sql)
        for table, add in (('candidates', lambda: db.candidate(b'synthetic two')),
                           ('bodies', lambda: db.body(b'synthetic body')),
                           ('rejections', lambda: db.rejection(b'synthetic'))):
            with self.subTest(table):
                add()
                after = fingerprint_v1(sql)
                self.assertEqual([t for t in TABLES if after[t] != before[t]], [table])
                self.assertEqual(after[table]['rows'], before[table]['rows'] + 1)
                before = after

    def test_same_count_different_rows_differ(self):
        one, two = self.store(candidates=(b'synthetic one',)), self.store(candidates=(b'synthetic two',))
        a, b = fingerprint_v1(self.read_only(one)[1]), fingerprint_v1(self.read_only(two)[1])
        self.assertEqual(a['candidates']['rows'], b['candidates']['rows'])
        self.assertNotEqual(a['candidates']['sha256'], b['candidates']['sha256'])
        self.assertEqual({t: a[t] for t in TABLES if t != 'candidates'},
                         {t: b[t] for t in TABLES if t != 'candidates'})


class ConfigAndSecretTests(unittest.TestCase):
    def test_node_seed_in_checked_in_config_is_refused(self):
        text = Path(base.FLY).read_text()
        hops = 'CC_V1_MAX_HOPS = "4"\n'
        self.assertIn(hops, text)
        with tempfile.TemporaryDirectory() as tmp:
            for seed in ('CC_V1_NODE_SEED = "' + '5a' * 32 + '"\n', 'CC_V1_NODE_SEED = ""\n'):
                with self.subTest(seed=seed), self.assertRaisesRegex(ValueError, 'CC_V1_NODE_SEED is a secret'):
                    deploy_digest.check_config(base.write(tmp, text.replace(hops, hops + '  ' + seed)), True)
            # The unmodified config still passes.
            deploy_digest.check_config(base.write(tmp, text), True)

    def test_secret_names_pass_with_or_without_node_seed(self):
        for listed in (SECRETS, SECRETS + SEED):
            with self.subTest(len(listed)), patch.object(deploy_digest, 'fly',
                                                         return_value=json.dumps(listed)) as fly:
                names = deploy_digest.check_secret_names('synthetic-app')
                self.assertEqual(names, sorted(e['name'] for e in listed))
                fly.assert_called_once_with('secrets', 'list', '--app', 'synthetic-app', '--json')


class UpdateFlyTests(unittest.TestCase):
    def test_commands_outside_the_allow_list_are_refused_without_calling_fly(self):
        refused = (('ssh', 'console', '--app', 'x', '-C', 'cc-publisher pause'),
                   ('secrets', 'set', 'A=b'), ('secrets', 'unset', 'A'),
                   ('machine', 'update', 'id', '--image', NEW), ('machines', 'destroy', 'id'),
                   ('machines',), ('scale', 'count', '2'), ('scale', 'count', '0'), ('scale', 'count'),
                   ('scale', 'vm', 'shared-cpu-1x'), ('postgres', 'connect'), ())
        with patch.object(deploy_digest, 'fly') as fly:
            for args in refused:
                with self.subTest(args), self.assertRaisesRegex(RuntimeError, 'v1-update refuses flyctl'):
                    deploy_digest.update_fly(*args)
            fly.assert_not_called()

    def test_allowed_commands_call_through(self):
        allowed = (('machines', 'list', '--app', 'x', '--json'), ('secrets', 'list', '--app', 'x', '--json'),
                   ('deploy', '--app', 'x', '--image', NEW),
                   ('scale', 'count', '1', '--process-group', 'app', '--app', 'x', '--yes'))
        with patch.object(deploy_digest, 'fly', return_value='synthetic output') as fly:
            for args in allowed:
                self.assertEqual(deploy_digest.update_fly(*args), 'synthetic output')
            self.assertEqual([c.args for c in fly.call_args_list], list(allowed))

    def test_rollout_waits_for_the_new_build_only(self):
        node = FakeNode()
        listings = iter([[base.app()], [base.app(digest=NEW_DIGEST)], [base.app(digest=NEW_DIGEST)]])

        def fly(*args):
            if args[:2] == ('machines', 'list'):
                listing = next(listings)
                if listing[0]['image_ref']['digest'] == NEW_DIGEST and len(sleeps) == 2:
                    node.health = health_of(build=SHA[:12])
                return json.dumps(listing)
            raise AssertionError(args)

        sleeps = []
        with patch.object(deploy_digest, 'fly', side_effect=fly):
            fleet, health = deploy_digest.wait_for_rollout('x', ReadOnlyNode(BASE_URL, node), SHA,
                                                           NEW_DIGEST, sleep=sleeps.append)
        self.assertEqual((fleet['app_digest'], health['build'], sleeps), (NEW_DIGEST, SHA[:12], [5, 5]))
        stuck = FakeNode()
        with patch.object(deploy_digest, 'fly', return_value=json.dumps([base.app(digest=NEW_DIGEST)])):
            with self.assertRaisesRegex(AssertionError, 'new build'):
                deploy_digest.wait_for_rollout('x', ReadOnlyNode(BASE_URL, stuck), SHA, NEW_DIGEST,
                                               attempts=3, sleep=sleeps.append)


class PromoteV1UpdateTests(unittest.TestCase):
    """`deploy_digest.py --v1-update` with Fly, SSH, backups and HTTP all faked."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp, self.runs = Path(tmp.name), 0

    def promote(self, raises=None, *, after=None, health=None, stored=(STORED, STORED),
                prints=(FINGERPRINT, FINGERPRINT), backups=(BACKUP, BACKUP), secrets=SECRETS, extra=(),
                env=None):
        self.runs += 1
        self.evidence = self.tmp / f'evidence-{self.runs}'
        self.events, self.fly_calls = [], []
        node = self.node = FakeNode(self.events)
        if health:
            node.health.update(health)
        node.after.update(after or {})
        sql = object()
        stored, prints, backups = list(stored), list(prints), list(backups)

        def fly(*args):
            self.fly_calls.append(args)
            self.events.append(args[0])
            if args[:2] == ('machines', 'list'):
                return json.dumps([base.app(digest=NEW_DIGEST if node.deployed else OLD)])
            if args[:2] == ('secrets', 'list'):
                return json.dumps(secrets)
            if args[0] == 'deploy':
                node.deployed = True
                node.health = dict(node.health, build=SHA[:12])
            return ''

        def remote_sql(*database):
            self.assertEqual(database, DATABASE)
            return sql

        def inspect(got, expected):
            self.assertIs(got, sql)
            self.assertEqual(expected.summary(), EXPECTED.summary())
            self.events.append('inspect')
            reply = stored.pop(0)
            if isinstance(reply, Exception):
                raise reply
            return reply

        def fingerprint(got):
            self.assertIs(got, sql)
            self.events.append('fingerprint')
            return prints.pop(0)

        def capture(*args, **kw):
            self.assertEqual(args[:3], DATABASE)
            self.events.append(Path(args[3]).name)
            return backups.pop(0)

        argv = ['deploy_digest.py', '--app', 'production', '--image', NEW, '--sha', SHA,
                '--evidence', str(self.evidence), '--v1-update', '--config', base.FLY, *extra]
        m, self.stderr = SimpleNamespace(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, dict(ENV, **(env or {}))))
            stack.enter_context(patch('sys.argv', argv))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            stack.enter_context(patch.object(v1_update.urllib.request, 'urlopen', new=node))
            for name, effect in (('fly', fly), ('remote_sql', remote_sql), ('inspect_v1', inspect),
                                 ('fingerprint_v1', fingerprint), ('capture_v1', capture),
                                 ('check_v1_zero', AssertionError), ('http', AssertionError),
                                 ('request', AssertionError), ('wake', AssertionError),
                                 ('capture', AssertionError), ('seed', AssertionError)):
                setattr(m, name, stack.enter_context(patch.object(deploy_digest, name, side_effect=effect)))
            if raises:
                with self.assertRaises(raises) as self.error:
                    deploy_digest.main()
            else:
                deploy_digest.main()
        return m

    def evidence_json(self, name):
        return json.loads((self.evidence / name).read_text())

    def deploys(self):
        return [args for args in self.fly_calls if args[0] == 'deploy']

    def assert_read_only(self):
        """Every request is a body-less GET to the node; every flyctl call is allow-listed."""
        for method, host, path, auth, data in self.node.seen:
            self.assertEqual((method, host, data), ('GET', 'node.invalid', None), path)
        for args in self.fly_calls:
            self.assertTrue(any(args[:len(a)] == a for a in deploy_digest.UPDATE_FLY), args)
            self.assertFalse(any('cc-publisher' in str(a) for a in args), args)
            self.assertNotIn('--skip-release-command', args)
        self.assertLessEqual(len(self.deploys()), 1)

    def assert_failed(self, when, captures, deployed):
        self.assertIn(f'v1 update failed {when} the deploy', (self.evidence / 'FAILED').read_text())
        self.assertFalse((self.evidence / 'acceptance.json').exists())
        recovery = self.evidence_json('recovery.json')
        self.assertEqual((recovery['status'], recovery['deployed']), ('NOT RUN', deployed))
        self.assertEqual(recovery['previous_image'], 'registry.fly.io/timepoint-clockchain-prod@' + OLD)
        self.assertEqual([e for e in self.events if e.startswith('backup-')], captures)
        self.assertEqual(len(self.deploys()), int(deployed))
        self.assert_read_only()

    def test_success_order_and_evidence(self):
        m = self.promote()
        self.assertEqual(self.events, [
            'machines', 'secrets',
            'inspect', '/health', '/ready', '/v1/snapshot', '/v1/export', 'fingerprint', 'backup-before',
            'deploy', 'scale',
            'machines', '/health',
            '/ready', '/v1/snapshot', '/v1/export', 'fingerprint', 'inspect', 'backup-after'])
        result = self.evidence_json('acceptance.json')
        self.assertEqual(result['unchanged'], {'corpus_digest': CORPUS, 'commitment': COMMITMENT,
                                               'export_sha256': hashlib.sha256(export_bytes()).hexdigest()})
        self.assertEqual(result['http_methods'], ['GET'])
        self.assertEqual((result['node_seed'], result['store_fingerprint']), ('absent', 'unchanged'))
        self.assertEqual((result['previous_build'], result['build']), (OLD_BUILD, SHA[:12]))
        self.assertEqual(result['identity'], expected_identity(EXPECTED))
        self.assertEqual(result['machines']['app_digest'], NEW_DIGEST)
        self.assertEqual(result['backup_after']['commitment'], COMMITMENT)
        self.assertEqual(self.evidence_json('rollback.json')['node_seed'], 'absent')
        before = self.evidence_json('before.json')
        self.assertEqual((before['commitment'], before['corpus_digest'], before['fingerprint']),
                         (COMMITMENT, CORPUS, FINGERPRINT))
        self.assertNotIn('export', before)
        exported = self.evidence / 'export-before.json'
        self.assertEqual(exported.read_bytes(), export_bytes())
        self.assertEqual(stat.S_IMODE(exported.stat().st_mode), 0o600)
        self.assertFalse((self.evidence / 'FAILED').exists())
        # Both backups re-serve the exact image and compare against the observed export.
        for call in m.capture_v1.call_args_list:
            self.assertEqual(call.kwargs['export'], json.loads(export_bytes()))
            self.assertEqual(call.kwargs['image'], NEW)
            self.assertNotIn('fresh', call.kwargs)
        deploy, = self.deploys()
        self.assertEqual((deploy[deploy.index('--image') + 1], deploy[deploy.index('--config') + 1]),
                         (NEW, base.FLY))
        self.assertIn(('scale', 'count', '1', '--process-group', 'app', '--app', 'production', '--yes'),
                      self.fly_calls)
        # Snapshot with the read key, export with the full key; health and ready unauthenticated.
        auth = {(path, a) for _, _, path, a, _ in self.node.seen}
        self.assertEqual(auth, {('/health', None), ('/ready', None), ('/v1/snapshot', 'Bearer ' + READ),
                                ('/v1/export', 'Bearer ' + FULL)})
        self.assertEqual(len(self.node.seen), 8)
        self.assert_read_only()

    def test_node_seed_secret_is_recorded_present(self):
        self.promote(secrets=SECRETS + SEED)
        self.assertEqual(self.evidence_json('acceptance.json')['node_seed'], 'present')
        self.assertEqual(self.evidence_json('rollback.json')['node_seed'], 'present')
        self.assertNotIn('f' * 16, (self.evidence / 'rollback.json').read_text())

    def test_identity_drift_refused_before_backup_or_deploy(self):
        cases = (('instance', {'health': {'instance': '22' * 32}}, IdentityDrift),
                 ('curators', {'health': {'curators': CURATORS[1:]}}, IdentityDrift),
                 ('filter_version', {'health': {'filter_version': OTHER.filter_version}}, IdentityDrift),
                 ('stored unbound', {'stored': (dict(STORED, state='provisioned_unbound'),) * 2},
                  IdentityDrift),
                 ('stored refused', {'stored': (ValueError('stored rule identity differs from '
                                                           'CC_V1_CURATORS/CC_V1_MAX_HOPS'),) * 2}, ValueError))
        for name, kw, error in cases:
            with self.subTest(name):
                m = self.promote(error, **kw)
                m.capture_v1.assert_not_called()
                self.assertEqual(self.deploys(), [])
                self.assertNotIn('/v1/export', self.events)
                self.assert_failed('before', [], False)

    def test_commitment_change_after_deploy_is_refused(self):
        m = self.promote(CommitmentChanged, after={
            'snapshot': {'corpus_digest': CORPUS, 'commitment': OTHER_COMMITMENT},
            'export': export_bytes(commitment=OTHER_COMMITMENT)})
        self.assertRegex(str(self.error.exception), 'no-write step: commitment, export$')
        self.assertEqual(m.capture_v1.call_count, 1)
        self.assert_failed('after', ['backup-before'], True)

    def test_export_bytes_change_after_deploy_is_refused(self):
        for export in (export_bytes() + b'\n',
                       json.dumps(json.loads(export_bytes()), sort_keys=True).encode(),
                       export_bytes(envelopes=[])):
            with self.subTest(export=export):
                self.promote(CommitmentChanged, after={'export': export})
                self.assertRegex(str(self.error.exception), 'no-write step: export$')
                self.assert_failed('after', ['backup-before'], True)

    def test_store_fingerprint_change_after_deploy_is_refused(self):
        written = dict(FINGERPRINT, rule_identity={'rows': 1, 'sha256': 'ab' * 32})
        self.promote(CommitmentChanged, prints=(FINGERPRINT, written))
        self.assertRegex(str(self.error.exception), 'store changed across the update')
        self.assert_failed('after', ['backup-before'], True)

    def test_stored_identity_or_counts_change_after_deploy_is_refused(self):
        self.promote(CommitmentChanged, stored=(STORED, dict(STORED, counts=dict(COUNTS, rejections=1))))
        self.assertRegex(str(self.error.exception), 'stored identity or counts changed')
        self.assert_failed('after', ['backup-before'], True)

    def test_identity_drift_after_deploy_is_refused(self):
        self.promote(IdentityDrift, after={'health': health_of(build=SHA[:12], max_hops=5)})
        self.assertRegex(str(self.error.exception), 'max_hops$')
        self.assert_failed('after', ['backup-before'], True)

    def test_unavailable_store_after_deploy_fails_without_retry(self):
        self.promote(NotReady, after={'ready': [(503, {'serving': False, 'reason': 'store_unavailable'})]})
        self.assertRegex(str(self.error.exception), 'store_unavailable')
        post = self.events[self.events.index('deploy'):]
        self.assertEqual(post.count('/ready'), 1)
        self.assertNotIn('/v1/snapshot', post)
        self.assert_failed('after', ['backup-before'], True)

    def test_busy_readiness_after_deploy_is_retried(self):
        # require_ready binds time.sleep as a default at definition; inject a no-op instead.
        with patch.object(deploy_digest, 'require_ready',
                          side_effect=lambda node: require_ready(node, sleep=lambda s: None)):
            self.promote(after={'ready': [BUSY, BUSY, SERVING]})
        post = self.events[self.events.index('deploy'):]
        self.assertEqual(post.count('/ready'), 3)
        self.assertTrue((self.evidence / 'acceptance.json').exists())

    def test_pre_deploy_backup_must_hold_observed_commitment(self):
        for backup in (dict(BACKUP, commitment=OTHER_COMMITMENT), dict(BACKUP, state='provisioned_unbound'),
                       dict(BACKUP, commitment=None)):
            with self.subTest(backup=backup):
                self.promote(CommitmentChanged, backups=(backup, BACKUP))
                self.assertRegex(str(self.error.exception), 'pre-deploy backup')
                self.assert_failed('before', ['backup-before'], False)

    def test_post_deploy_backup_must_match_pre_deploy_backup(self):
        for backup in (dict(BACKUP, commitment=OTHER_COMMITMENT), dict(BACKUP, counts=dict(COUNTS, bodies=2)),
                       dict(BACKUP, state='provisioned_unbound')):
            with self.subTest(backup=backup):
                self.promote(CommitmentChanged, backups=(BACKUP, backup))
                self.assertRegex(str(self.error.exception), 'post-deploy backup')
                self.assert_failed('after', ['backup-before', 'backup-after'], True)

    def test_every_request_is_get_and_every_fly_call_allow_listed_across_outcomes(self):
        for kw in ({}, {'after': {'export': export_bytes() + b' '}},
                   {'health': {'instance': '22' * 32}}, {'prints': (FINGERPRINT, {})}):
            with self.subTest(kw=kw):
                self.promote(None if not kw else Exception, **kw)
                self.assert_read_only()

    def test_update_is_production_only_and_exclusive(self):
        for flag, message in (('--acceptance', 'production only'), ('--v1-fresh', 'not allowed with'),
                              ('--zero-events', 'not allowed with')):
            with self.subTest(flag):
                m = self.promote(SystemExit, extra=[flag])
                self.assertIn(message, self.stderr.getvalue())
                m.fly.assert_not_called()
                self.assertEqual(self.node.seen, [])

    def test_missing_or_shared_credentials_refused_before_any_production_read(self):
        for env in ({'CC_NODE_READ_KEY': FULL}, {'CC_V1_MAX_HOPS': '5'}, {'CC_V1_INSTANCE': 'nothex'}):
            with self.subTest(env):
                m = self.promote(ValueError, env=env)
                m.fly.assert_not_called()
                m.remote_sql.assert_not_called()
                self.assertEqual(self.node.seen, [])


class ReleaseUpdateTests(unittest.TestCase):
    """`release.py --v1-update`, mirroring test_v1_release.ReleaseTests."""

    CURRENT = {'id': 'app', 'state': 'started',
               'image_ref': {'digest': OLD, 'tag': 'git-' + 'c' * 40},
               'config': {'image': 'registry.fly.io/timepoint-clockchain-prod:git-' + 'c' * 40 + '@' + OLD,
                          'metadata': {'fly_process_group': 'app'}}}

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.evidence = self.tmp / 'evidence'

    def output(self, *args):
        self.commands.append(args)
        self.events.append(args[:2])
        if args[:3] == ('flyctl', 'machines', 'list'):
            return json.dumps([self.CURRENT])
        return base.ReleaseTests.output(self, *args)

    def release(self, *flags, raises=None, env=None, drop=(), secrets=SECRETS):
        self.commands, self.events, self.stderr = [], [], io.StringIO()
        argv = ['release.py', '--app', 'timepoint-clockchain-prod', '--image', NEW, '--config', base.FLY,
                '--evidence', str(self.evidence), *flags]
        m = SimpleNamespace()

        def fly(*args):
            self.events.append(('fly',) + args[:2])
            if args[:2] == ('secrets', 'list'):
                return json.dumps(secrets)
            raise AssertionError(f'unexpected flyctl {args}')

        def accepted(name):
            return lambda *a, **kw: self.events.append(name)

        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, dict(base.ENV, HOME=str(self.tmp / 'home'), **(env or {}))))
            for name in drop:
                del os.environ[name]
            stack.enter_context(patch('sys.argv', argv))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            stack.enter_context(patch.object(release, 'output', side_effect=self.output))
            m.fly = stack.enter_context(patch.object(deploy_digest, 'fly', side_effect=fly))
            m.chdir = stack.enter_context(patch.object(release.os, 'chdir'))
            m.accept = stack.enter_context(patch.object(release, 'accept', side_effect=accepted('accept')))
            m.accept_v1 = stack.enter_context(patch.object(release, 'accept_v1', side_effect=accepted('accept_v1')))
            m.accept_v1_update = stack.enter_context(patch.object(
                release, 'accept_v1_update', side_effect=accepted('accept_v1_update')))
            m.run = stack.enter_context(patch.object(release.subprocess, 'run',
                                                     side_effect=lambda *a, **k: self.events.append('deploy')))
            m.popen = stack.enter_context(patch.object(release.subprocess, 'Popen'))
            m.popen.return_value.poll.return_value = None
            stack.enter_context(patch.object(release, 'request', return_value=(200, b'{}')))
            m.stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if raises:
                with self.assertRaises(raises):
                    release.main()
            else:
                release.main()
        return m

    def assert_refused(self, m, message):
        self.assertIn(message, self.stderr.getvalue())
        for mock in (m.accept, m.accept_v1, m.accept_v1_update, m.run, m.fly):
            mock.assert_not_called()
        self.assertFalse(any(c[0] == 'flyctl' for c in self.commands))
        self.assertFalse(self.evidence.exists())

    def test_mode_flag(self):
        modes = dict(v1_fresh=False, v1_update=False, empty_corpus=False, zero_events=False)
        self.assertEqual(release.mode_flag(argparse.Namespace(**modes)), [])
        self.assertEqual(release.mode_flag(argparse.Namespace(**dict(modes, v1_update=True))), ['--v1-update'])

    def test_update_runs_both_acceptances_then_promotes_with_update_flag(self):
        m = self.release('--v1-update')
        evidence = self.evidence.resolve()
        m.accept_v1.assert_called_once_with(NEW, SHA, evidence / 'acceptance')
        m.accept_v1_update.assert_called_once_with(
            'registry.fly.io/timepoint-clockchain-prod@' + OLD, NEW, SHA, evidence / 'acceptance-update',
            node_seed=False)
        m.accept.assert_not_called()
        order = [e for e in self.events if e in ('accept_v1', 'accept_v1_update', 'deploy')]
        self.assertEqual(order, ['accept_v1', 'accept_v1_update', 'deploy'])
        (command,), kw = m.run.call_args
        self.assertEqual(command[1:2] + command[-1:], ['ops/deploy_digest.py', '--v1-update'])
        self.assertNotIn('--v1-fresh', command)
        self.assertTrue(kw['env']['CC_NODE_URL'].startswith('http://127.0.0.1:'))
        # The only production reads before the deploy are the machine and secret-name census.
        self.assertEqual([c for c in m.fly.call_args_list],
                         [unittest.mock.call('secrets', 'list', '--app', 'timepoint-clockchain-prod', '--json')])
        self.assertIn('identity, commitments and export unchanged', m.stdout.getvalue())

    def test_update_acceptance_mirrors_node_seed(self):
        m = self.release('--v1-update', secrets=SECRETS + SEED)
        self.assertIs(m.accept_v1_update.call_args.kwargs['node_seed'], True)

    def test_update_refuses_an_unpinned_current_image(self):
        current = self.CURRENT
        self.CURRENT = dict(current, config=dict(current['config'],
                                                 image='registry.fly.io/another-app:git-x@' + OLD))
        m = self.release('--v1-update', raises=ValueError)
        m.accept_v1.assert_called_once()
        m.accept_v1_update.assert_not_called()
        m.run.assert_not_called()

    def test_update_and_fresh_are_exclusive(self):
        for flags in (('--v1-update', '--v1-fresh'), ('--v1-fresh', '--v1-update'),
                      ('--v1-update', '--zero-events')):
            with self.subTest(flags):
                m = self.release(*flags, raises=SystemExit)
                self.assert_refused(m, 'not allowed with argument')
                self.assertEqual(self.commands, [])

    def test_update_identity_refused_before_acceptance(self):
        for kw, message in (({'drop': ('CC_V1_CURATORS',)}, 'CC_V1_CURATORS'),
                            ({'drop': ('CC_V1_INSTANCE',)}, 'CC_V1_INSTANCE'),
                            ({'env': {'CC_V1_MAX_HOPS': '3'}}, 'CC_V1_MAX_HOPS must be 4'),
                            ({'env': {'CC_V1_CURATORS': ','.join(reversed(CURATORS))}}, 'strictly sorted'),
                            ({'env': {'CC_NODE_READ_KEY': base.ENV['CC_NODE_API_KEY']}},
                             'distinct full and read-only')):
            with self.subTest(message):
                self.assert_refused(self.release('--v1-update', raises=SystemExit, **kw), message)


if __name__ == '__main__':
    unittest.main()
