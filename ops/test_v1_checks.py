import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
from v1_checks import check_v1_populated, check_v1_zero, load_entry
from v1_identity import Expected, corpus_digest, view_commitment

CURATORS = ['8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
            '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c',
            'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1']
EXPECTED = Expected('11' * 32, ','.join(CURATORS), '4')
OTHER = Expected('11' * 32, ','.join(CURATORS), '5')
REV, WRITE, READ = 'c' * 40, 'full-key', 'read-key'
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
h = lambda s: hashlib.sha256(s.encode()).hexdigest()
BODY = 'Synthetic genesis prose, Zürich.\n'.encode()
ENVELOPE = b'\x01synthetic signed genesis envelope'
PREVIEW = {'event': h('event'), 'subject': h('subject'), 'revision': h('revision'),
           'body_hash': hashlib.sha256(BODY).hexdigest(), 'author': CURATORS[2],
           'instance': EXPECTED.instance}


class Node:
    """Honest fake of the v1 node HTTP contract; records every request."""

    def __init__(self, entry=None):
        e = EXPECTED
        self.calls, self.retained, self.force = [], [], {}
        self.patch = {'pinned': {}, 'export': {}, 'subject': {}}
        self.ready, self.foreign_fold = (200, {'serving': True, 'posture': 'live'}), 409
        self.health = {'ledger': 'v1', 'build': REV[:12], 'posture': 'live', 'instance': e.instance,
                       'fold_version': dict(e.fold), 'filter_version': e.filter_version,
                       'curators': list(e.curators), 'max_hops': 4, 'semantic': 'ready'}
        fv = bytes.fromhex(e.filter_version)
        self.view = {'rule': {'fold_version': 1, 'fold_manifest': list(bytes.fromhex(e.fold['manifest'])),
                              'filter_version': list(fv)},
                     'rows': [], 'subjects': [], 'revisions': [], 'edges': [], 'media': [],
                     'authority': {'grants': [], 'active': [], 'tombstones': []},
                     'corpus_digest': corpus_digest([]).hex(), 'commitment': e.empty_commitment}
        self.envelopes, self.subjects, self.prose = [], {}, {}
        if entry:
            event = bytes.fromhex(entry['event'])
            self.view.update(
                rows=[{'event': list(event), 'state': 'head', 'frontier': True,
                       'revision': list(bytes.fromhex(entry['revision']))}],
                subjects=[{'subject': entry['subject'], 'state': 'resolved'}],
                revisions=[{'id': list(bytes.fromhex(entry['revision'])), 'body': entry['body_hash']}],
                corpus_digest=corpus_digest([event]).hex(),
                commitment=view_commitment(fv, corpus_digest([event]), b'synthetic populated rows').hex())
            self.envelopes = [entry['envelope'].hex()]
            self.subjects[entry['subject']] = {'state': 'resolved', 'revision': {'id': entry['revision']}}
            self.prose[entry['revision']] = {'availability': 'available', 'prose': entry['body'].decode()}

    def digests(self):
        return {'corpus_digest': self.view['corpus_digest'], 'commitment': self.view['commitment']}

    def __call__(self, base, method, path, key=None, body=None):
        self.calls.append((method, path, key, body))
        status, value = self.route(method, path, key, body)
        status = self.force.get((method, urlsplit(path).path, key), status)
        return status, json.dumps(value).encode()

    def route(self, method, path, key, body):
        route, query = urlsplit(path).path, parse_qs(urlsplit(path).query)
        authed = key in (READ, WRITE)
        if (method, route) == ('GET', '/health'):
            return 200, self.health
        if (method, route) == ('GET', '/ready'):
            return self.ready
        if (method, route) == ('GET', '/v1/snapshot'):
            if not authed:
                return 401, {}
            if query and (query.get('fold_version') != ['1']
                          or query.get('fold_manifest') != [EXPECTED.fold['manifest']]):
                return self.foreign_fold, self.view
            return 200, {**self.view, **self.patch['pinned']} if query else self.view
        if (method, route) == ('GET', '/v1/export'):
            if key != WRITE:
                return (403 if key == READ else 401), {}
            return 200, {**self.digests(), 'envelopes': self.envelopes, **self.patch['export']}
        if method == 'PUT' and route.startswith('/v1/bodies/'):
            if key != WRITE:
                return (403 if key == READ else 401), {}
            if hashlib.sha256(body).hexdigest() != route.rsplit('/', 1)[1]:
                return 400, {}
            self.retained.append(body)
            return 201, {}
        if (method, route) == ('POST', '/v1/candidates'):
            if key != WRITE:
                return (403 if key == READ else 401), {}
            self.retained.append(body)
            return 202, {}
        if method == 'GET' and route.startswith('/v1/subjects/'):
            subject = self.subjects.get(route.rsplit('/', 1)[1])
            return (401, {}) if not authed else (404, {}) if not subject else (200, {**subject, **self.digests(), **self.patch['subject']})
        if method == 'GET' and route.startswith('/v1/revisions/') and route.endswith('/prose'):
            prose = self.prose.get(route.split('/')[3])
            return (401, {}) if not authed else (404, {}) if not prose else (200, prose)
        return 404, {}


def zero(node, **kw):
    with patch('v1_checks.http', side_effect=node):
        return check_v1_zero('http://node.invalid/', REV, kw.pop('key', WRITE), kw.pop('read_key', READ),
                             EXPECTED, **kw)


def populated(node, entry, **kw):
    with patch('v1_checks.http', side_effect=node):
        return check_v1_populated('http://node.invalid', REV, WRITE, READ, EXPECTED, entry, **kw)


def write_entry(directory, preview=PREVIEW, body=BODY):
    d = Path(directory)
    (d / 'preview.json').write_text(json.dumps(preview))
    (d / 'envelope.bin').write_bytes(ENVELOPE)
    (d / 'body.bin').write_bytes(body)
    return d


# Mutations of the honest node: each returns a function applied to a fresh Node.
def health(**kw):
    return lambda n: n.health.update(kw)


def view(**kw):
    return lambda n: n.view.update(kw)


def answer(part, **kw):
    return lambda n: n.patch[part].update(kw)


def force(method, path, key, status):
    return lambda n: n.force.__setitem__((method, path, key), status)


def attr(name, value):
    return lambda n: setattr(n, name, value)


def drift(n):
    """The view changes once the full export has been served."""
    route = n.route
    def changed(method, path, key, body):
        result = route(method, path, key, body)
        if (path, key) == ('/v1/export', WRITE):
            n.view = dict(n.view, commitment=OTHER.empty_commitment)
        return result
    n.route = changed


class ZeroTests(unittest.TestCase):
    def test_honest_empty_node_passes_without_initialization(self):
        result = zero(Node())
        self.assertFalse(result['initialization_performed'])
        self.assertFalse(result['probe_candidates'])
        self.assertEqual((result['corpus_digest'], result['commitment']),
                         (corpus_digest([]).hex(), EXPECTED.empty_commitment))
        self.assertEqual(result['passed'], len(result['checks']))
        self.assertIn('foreign fold refused', result['checks'])

    def test_distinct_credentials_required(self):
        for key, read_key in ((WRITE, WRITE), ('', READ), (WRITE, ''), (None, READ)):
            node = Node()
            with self.assertRaises(ValueError):
                zero(node, key=key, read_key=read_key)
            self.assertEqual(node.calls, [])

    def test_populated_node_is_not_zero(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(AssertionError, 'corpus is not empty'):
                zero(Node(load_entry(write_entry(d))))

    def test_dishonest_node_refused(self):
        row = {'event': [7] * 32, 'state': 'head', 'frontier': True, 'revision': [8] * 32}
        manifest = EXPECTED.fold['manifest']
        mutations = [
            ('instance mismatch', health(instance='22' * 32)),
            ('filter_version mismatch', health(filter_version=OTHER.filter_version)),
            ('curator set mismatch', health(curators=CURATORS[1:])),
            ('curator set mismatch', health(curators=[CURATORS[1], CURATORS[0]] + CURATORS[2:])),
            ('max_hops mismatch', health(max_hops=5)),
            ('not serving the v1 ledger', health(ledger='v0')),
            ('semantic readiness', health(semantic='incompatible_rule_identity')),
            ('wrong deployed revision', health(build='d' * 12)),
            ('unexpected posture', health(posture='frozen')),
            ('fold version mismatch', health(fold_version={'version': 2, 'manifest': manifest})),
            ('fold manifest mismatch', health(fold_version={'version': 1, 'manifest': '00' * 32})),
            ('ready: HTTP 503', attr('ready', (503, {'serving': False, 'posture': 'live'}))),
            ('node not serving', attr('ready', (200, {'serving': False, 'posture': 'live'}))),
            ('snapshot anonymous denied: HTTP 200', force('GET', '/v1/snapshot', None, 200)),
            ('wrong credential denied: HTTP 200', force('GET', '/v1/snapshot', 'invalid-credential', 200)),
            ('export anonymous denied: HTTP 200', force('GET', '/v1/export', None, 200)),
            ('read key cannot export: HTTP 200', force('GET', '/v1/export', READ, 200)),
            ('read key cannot write: HTTP 201', force('PUT', '/v1/bodies/' + EMPTY_SHA256, READ, 201)),
            # A 401 would mean the read key is not recognized at all: a misconfiguration.
            ('read key cannot write: HTTP 401', force('PUT', '/v1/bodies/' + EMPTY_SHA256, READ, 401)),
            ('read key cannot export: HTTP 401', force('GET', '/v1/export', READ, 401)),
            ('empty commitment differs', view(commitment=OTHER.empty_commitment)),
            ('corpus is not empty', view(corpus_digest=corpus_digest([bytes(32)]).hex())),
            ('empty snapshot has rows', view(rows=[row])),
            ('empty snapshot has edges', view(edges=[{}])),
            ('authority state', view(authority={'grants': [row]})),
            ('snapshot filter mismatch', lambda n: n.view['rule'].update(filter_version=OTHER.filter_version)),
            ('snapshot fold mismatch', lambda n: n.view['rule'].update(fold_version=2)),
            ('snapshot fold mismatch', lambda n: n.view['rule'].update(fold_manifest=[0] * 32)),
            ('foreign fold refused: HTTP 200', attr('foreign_fold', 200)),
            ('pinned fold snapshot differs', answer('pinned', commitment=OTHER.empty_commitment)),
            ('export: HTTP 403', force('GET', '/v1/export', WRITE, 403)),
            ('empty node exported envelopes', attr('envelopes', [ENVELOPE.hex()])),
            ('export commitment differs', answer('export', commitment=OTHER.empty_commitment)),
            ('snapshot changed during checks', drift),
        ]
        for message, mutate in mutations:
            node = Node()
            mutate(node)
            with self.assertRaisesRegex(AssertionError, message):
                zero(node)


class SafetyTests(unittest.TestCase):
    """No probe can retain a write on production, even against a broken node."""

    def calls(self, probe_candidates):
        node, broken = Node(), Node()
        # A node whose write authorization is broken treats any caller as the full key.
        broken.route = lambda m, p, k, b, route=broken.route: route(m, p, WRITE if m != 'GET' else k, b)
        with tempfile.TemporaryDirectory() as d:
            entry = load_entry(write_entry(d))
        zero(node, probe_candidates=probe_candidates)
        full = Node(entry)
        populated(full, entry, probe_candidates=probe_candidates)
        with self.assertRaisesRegex(AssertionError, 'write without token denied: HTTP 400'):
            zero(broken, probe_candidates=probe_candidates)
        self.assertIn('PUT', {c[0] for c in broken.calls})
        self.assertEqual(node.retained + full.retained + broken.retained, [])
        return node.calls + full.calls + broken.calls

    def test_production_default_never_writes(self):
        calls = self.calls(False)
        self.assertNotIn('POST', {c[0] for c in calls})
        self.assertEqual({c[0] for c in calls}, {'GET', 'PUT'})
        puts = [c for c in calls if c[0] == 'PUT']
        self.assertTrue(puts)
        for method, path, key, body in puts:
            self.assertEqual(path, '/v1/bodies/' + EMPTY_SHA256)
            self.assertIsNotNone(body)
            self.assertNotEqual(hashlib.sha256(body).hexdigest(), path.rsplit('/', 1)[1])
        self.assertTrue([c for c in calls if c[2] == WRITE])
        self.assertEqual({c[0] for c in calls if c[2] == WRITE}, {'GET'})

    def test_candidate_probe_only_in_acceptance_and_never_with_write_key(self):
        calls = self.calls(True)
        posts = [c for c in calls if c[0] == 'POST']
        self.assertEqual({(c[1], c[2]) for c in posts}, {('/v1/candidates', None), ('/v1/candidates', READ)})
        self.assertEqual({c[0] for c in calls if c[2] == WRITE}, {'GET'})
        self.assertTrue(zero(Node(), probe_candidates=True)['probe_candidates'])


class PopulatedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.entry = load_entry(write_entry(self.tmp.name))

    def test_honest_populated_node_passes(self):
        result = populated(Node(self.entry), self.entry)
        self.assertEqual(result['corpus_digest'], corpus_digest([bytes.fromhex(PREVIEW['event'])]).hex())
        self.assertNotEqual(result['commitment'], EXPECTED.empty_commitment)
        self.assertEqual((result['event'], result['subject'], result['revision']),
                         (PREVIEW['event'], PREVIEW['subject'], PREVIEW['revision']))
        self.assertIn('prose readable', result['checks'])

    def test_empty_node_is_not_populated(self):
        with self.assertRaisesRegex(AssertionError, 'corpus is not exactly the entry'):
            populated(Node(), self.entry)

    def test_mismatched_node_refused(self):
        flipped = bytes([ENVELOPE[0] ^ 1]) + ENVELOPE[1:]
        other = corpus_digest([bytes.fromhex(h('other event'))]).hex()
        subject, revision = PREVIEW['subject'], PREVIEW['revision']
        extra = {'event': list(bytes.fromhex(h('extra'))), 'state': 'head', 'frontier': True,
                 'revision': list(bytes.fromhex(h('extra revision')))}
        mutations = [
            ('exported envelope differs', attr('envelopes', [flipped.hex()])),
            ('exported envelope differs', attr('envelopes', [ENVELOPE.hex()] * 2)),
            ('served prose differs', lambda n: n.prose[revision].update(prose=BODY.decode() + '!')),
            ('body is not retained', lambda n: n.prose[revision].update(availability='missing')),
            ('unexpected rows', lambda n: n.view['rows'].append(extra)),
            ('entry is not the head', lambda n: n.view['rows'][0].update(state='superseded')),
            ('entry is not the head', lambda n: n.view['rows'][0].update(state='valid')),
            ('entry is not the head', lambda n: n.view['rows'][0].update(frontier=False)),
            ('head row names another revision', lambda n: n.view['rows'][0].update(revision=[9] * 32)),
            ('corpus is not exactly the entry', view(corpus_digest=other)),
            ('still names the empty view', view(commitment=EXPECTED.empty_commitment)),
            ('unexpected subjects', lambda n: n.view['subjects'].append({'subject': h('s2'), 'state': 'resolved'})),
            ('subject is not resolved', lambda n: n.view['subjects'][0].update(state='conflicted')),
            ('unexpected revisions', lambda n: n.view['revisions'].append({'id': h('r2'), 'body': h('b2')})),
            ('revision body differs', lambda n: n.view['revisions'][0].update(body=h('other body'))),
            ('edges or media', view(media=[{}])),
            ('snapshot filter mismatch', lambda n: n.view['rule'].update(filter_version=OTHER.filter_version)),
            ('pinned fold snapshot differs', answer('pinned', corpus_digest=other)),
            ('subject anonymous denied: HTTP 200', force('GET', '/v1/subjects/' + subject, None, 200)),
            ('subject read is not resolved', lambda n: n.subjects[subject].update(state='conflicted')),
            ('subject read revision differs', lambda n: n.subjects[subject].update(revision={'id': h('r2')})),
            ('subject read names another view', answer('subject', commitment=OTHER.empty_commitment)),
            ('export commitment differs', answer('export', commitment=OTHER.empty_commitment)),
            ('snapshot changed during checks', drift),
        ]
        for message, mutate in mutations:
            node = Node(self.entry)
            mutate(node)
            with self.assertRaisesRegex(AssertionError, message):
                populated(node, self.entry)

    def test_entry_must_match_expected_identity_before_any_request(self):
        for field, value, message in (('author', '33' * 32, 'not a configured curator'),
                                      ('instance', '22' * 32, 'another instance')):
            node = Node(self.entry)
            with self.assertRaisesRegex(ValueError, message):
                populated(node, dict(self.entry, **{field: value}))
            self.assertEqual(node.calls, [])

    def test_load_entry_checks_body_and_accepts_alternative_names(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, 'body.bin'):
                load_entry(write_entry(d, body=BODY + b'!'))
        alternative = {'event_id': list(bytes.fromhex(PREVIEW['event'])), 'subject_id': PREVIEW['subject'],
                       'revision_id': PREVIEW['revision'], 'body_sha256': PREVIEW['body_hash'],
                       'author': PREVIEW['author'], 'instance': PREVIEW['instance']}
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_entry(write_entry(d, alternative)), self.entry)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ValueError, 'lacks event/event_id'):
                load_entry(write_entry(d, {k: v for k, v in PREVIEW.items() if k != 'event'}))
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                load_entry(write_entry(d, dict(PREVIEW, author=PREVIEW['author'].upper())))


if __name__ == '__main__':
    unittest.main()
