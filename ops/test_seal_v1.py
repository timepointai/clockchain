"""seal_v1 against an injected proxy and a fake node; nothing leaves the process.

The node key below is derived from a visibly patterned synthetic seed (the
bytes 0x00..0x1f), the same one the Rust tests use. It is not a real node key.
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
from fly_proxy import ProxyFailed
import owner_jobs
import seal_v1
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
READ_KEY = 'SENTINEL-READ-KEY-7f3a2c9d1e0b4a5f6c7d8e9f'
SECRET = 'SENTINEL-EXTRA-TOKEN-5b1e0c'
SEED = bytes(range(32))
KEY = ed25519.Ed25519PrivateKey.from_private_bytes(SEED)
NODE_KEY = KEY.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw).hex()
OTHER_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([9] * 32))

# The vector `crates/cc-core/tests/v1_seal.rs` pins, and the Rust signature over it.
VECTOR_SEAL = {'instance': INSTANCE, 'node_key': NODE_KEY,
               'fold_version': {'version': 1, 'manifest': '22' * 32},
               'filter_version': '33' * 32, 'corpus_digest': '44' * 32, 'commitment': '55' * 32,
               'counts': {'candidates': 7}, 'build': 'abc123def456',
               'sealed_at_us': 1_700_000_000_000_000}
VECTOR = ('0000000a63632e7365616c2e7631' + '11' * 32 + NODE_KEY + '0001' + '22' * 32 + '33' * 32
          + '44' * 32 + '55' * 32 + '0000000000000007' + '0000000c616263313233646566343536'
          + '00060a24181e4000')
RUST_SIGNATURE = ('e219ff478eb38268b8f54be28d3acad26f51ceedc90a30554705d1a7c990dabb'
                  '1f6814915780265bd2be4d468d4cfc298e0d7980d7ff4b35ada944b67a20710c')


def seal_fields(**overrides):
    doc = {'instance': INSTANCE, 'node_key': NODE_KEY, 'fold_version': dict(EXPECTED.fold),
           'filter_version': EXPECTED.filter_version, 'corpus_digest': 'aa' * 32,
           'commitment': 'bb' * 32, 'counts': {'candidates': 3}, 'build': 'test-build',
           'sealed_at_us': 1_800_000_000_000_000}
    doc.update(overrides)
    return doc


def signed(seal=None, key=KEY, **overrides):
    """A `/v1/seal` answer signed by `key` over the canonical bytes of the seal."""
    seal = dict(seal or seal_fields(**overrides))
    node_key = key.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw).hex()
    seal['node_key'] = node_key
    return {'seal': seal, 'signature': key.sign(seal_v1.encode_seal(seal)).hex(),
            'node_key': node_key}


def successor(doc, **overrides):
    """A seal one hour later with the same state unless overridden."""
    fields = dict(doc['seal'])
    fields['sealed_at_us'] += 3_600_000_000
    fields.update(overrides)
    return signed(fields)


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

    def __init__(self, seal=None, answers=None):
        self.answers = {'/v1/seal': answers or [(200, seal if seal is not None else signed())]}
        self.requests = []

    def __call__(self, req, timeout=None):
        self.requests.append((req.get_method(), req.full_url, dict(req.header_items()), req.data))
        if not req.full_url.startswith(BASE + '/'):
            raise AssertionError('request left the proxied node: ' + req.full_url)
        path = req.full_url[len(BASE):]
        if isinstance(self.answers.get(path), OSError):
            raise self.answers[path]
        queue = self.answers.get(path, [(404, {'error': 'no_such_route'})])
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


class EncodingTests(unittest.TestCase):
    def test_canonical_bytes_match_the_rust_vector(self):
        self.assertEqual(seal_v1.encode_seal(VECTOR_SEAL).hex(), VECTOR)
        self.assertEqual(KEY.sign(seal_v1.encode_seal(VECTOR_SEAL)).hex(), RUST_SIGNATURE)
        doc = {'seal': VECTOR_SEAL, 'signature': RUST_SIGNATURE, 'node_key': NODE_KEY}
        self.assertEqual(seal_v1.verify_signed(doc, NODE_KEY), VECTOR_SEAL)

    def test_every_field_is_covered_by_the_signature(self):
        doc = signed()
        seal_v1.verify_signed(doc, NODE_KEY)
        changes = {'instance': '12' * 32, 'fold_version': {'version': 2, 'manifest': EXPECTED.fold['manifest']},
                   'filter_version': '34' * 32, 'corpus_digest': 'ab' * 32, 'commitment': 'bc' * 32,
                   'counts': {'candidates': 4}, 'build': 'test-build-2',
                   'sealed_at_us': doc['seal']['sealed_at_us'] + 1}
        self.assertEqual(set(changes) | {'node_key'}, seal_v1.SEAL_KEYS)
        for field, value in changes.items():
            with self.subTest(field):
                bad = {**doc, 'seal': {**doc['seal'], field: value}}
                with self.assertRaises(seal_v1.SealInvalid):
                    seal_v1.verify_signed(bad, NODE_KEY)
        flipped = doc['signature'][:-1] + ('0' if doc['signature'][-1] != '0' else '1')
        with self.assertRaises(seal_v1.SealInvalid):
            seal_v1.verify_signed({**doc, 'signature': flipped}, NODE_KEY)

    def test_malformed_documents_are_invalid_not_errors(self):
        doc = signed()
        cases = {'extra top-level key': {**doc, 'extra': 1},
                 'missing signature': {k: v for k, v in doc.items() if k != 'signature'},
                 'uppercase hex': {**doc, 'seal': {**doc['seal'], 'commitment': 'BB' * 32}},
                 'byte-list hash': {**doc, 'seal': {**doc['seal'], 'instance': [17] * 32}},
                 'extra seal key': {**doc, 'seal': {**doc['seal'], 'rule': {}}},
                 'float count': {**doc, 'seal': {**doc['seal'], 'counts': {'candidates': 3.0}}},
                 'bool count': {**doc, 'seal': {**doc['seal'], 'counts': {'candidates': True}}},
                 'negative time': {**doc, 'seal': {**doc['seal'], 'sealed_at_us': -1}},
                 'empty build': {**doc, 'seal': {**doc['seal'], 'build': ''}},
                 'spaced build': {**doc, 'seal': {**doc['seal'], 'build': 'a b'}},
                 'short signature': {**doc, 'signature': doc['signature'][:-2]},
                 'not an object': [doc]}
        for name, bad in cases.items():
            with self.subTest(name):
                with self.assertRaises(seal_v1.SealInvalid):
                    seal_v1.verify_signed(bad, NODE_KEY)

    def test_another_signer_is_a_key_mismatch_before_any_signature_check(self):
        other = signed(key=OTHER_KEY)
        with self.assertRaises(seal_v1.NodeKeyMismatch):
            seal_v1.verify_signed(other, NODE_KEY)
        # A document that merely claims the expected key, signed by another, is a bad signature.
        forged = {**other, 'node_key': NODE_KEY, 'seal': {**other['seal'], 'node_key': NODE_KEY}}
        with self.assertRaises(seal_v1.SealInvalid):
            seal_v1.verify_signed(forged, NODE_KEY)

    def test_succession_rules(self):
        a = seal_v1.verify_signed(signed(), NODE_KEY)
        later = successor(signed())['seal']
        self.assertEqual(seal_v1.require_succession(a, later), later)
        grown = successor(signed(), corpus_digest='ac' * 32, commitment='bd' * 32,
                          counts={'candidates': 4})['seal']
        seal_v1.require_succession(a, grown)
        cases = {
            'time_regression': successor(signed(), sealed_at_us=a['sealed_at_us'])['seal'],
            'count_decrease': successor(signed(), counts={'candidates': 2})['seal'],
            'commitment_changed': successor(signed(), commitment='bd' * 32)['seal'],
        }
        cases['commitment_changed (corpus)'] = successor(signed(), corpus_digest='ac' * 32)['seal']
        cases['commitment_changed (count without corpus)'] = successor(
            signed(), counts={'candidates': 4})['seal']
        cases['commitment_changed (count and commitment, same corpus)'] = successor(
            signed(), counts={'candidates': 4}, commitment='bd' * 32)['seal']
        cases['commitment_changed (count and corpus, same commitment)'] = successor(
            signed(), counts={'candidates': 4}, corpus_digest='ac' * 32)['seal']
        for name, bad in cases.items():
            with self.subTest(name):
                with self.assertRaises(seal_v1.Regression) as caught:
                    seal_v1.require_succession(a, bad)
                self.assertEqual(caught.exception.kind, name.split(' ')[0])


class SealRunTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        self.assertFalse(self.dir.is_relative_to(owner_jobs.ROOT))
        self.state = self.dir / 'state'
        self.log = self.dir / 'seals.ndjson'
        self.env = {'CC_FLY_APP': APP, 'CC_OPS_STATE_DIR': str(self.state),
                    'CC_SEAL_LOG': str(self.log), 'CC_SEAL_NODE_KEY': NODE_KEY,
                    'CC_NODE_READ_KEY': READ_KEY, 'CC_V1_INSTANCE': INSTANCE,
                    'CC_V1_CURATORS': ','.join(CURATORS), 'CC_V1_MAX_HOPS': '4',
                    'CC_EXTRA_TOKEN': SECRET}
        self.env_path = self.write_env(self.env)
        self.notes = []

    def write_env(self, env, mode=0o600):
        path = self.dir / 'seal.env'
        path.write_text(''.join(f'{k}={v}\n' for k, v in env.items()))
        path.chmod(mode)
        return path

    def notify(self, title, message):
        self.notes.append((title, message))
        return True

    def run_seal(self, node, proxy=None):
        self.proxy = proxy or FakeProxy()
        stderr, out, err = io.StringIO(), io.StringIO(), io.StringIO()
        with patch.object(v1_update.urllib.request, 'urlopen', node), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = seal_v1.run(self.env_path, proxy=self.proxy, notify=self.notify, stderr=stderr)
        self.assertEqual(out.getvalue(), '')
        self.assertEqual(err.getvalue(), '')
        self.assertEqual(self.proxy.open, 0)  # the proxy context is always closed
        for method, url, headers, data in node.requests:
            self.assertEqual((method, data), ('GET', None), url)
            self.assertEqual(headers.get('Authorization'), 'Bearer ' + READ_KEY)
            self.assertEqual(url, BASE + '/v1/seal')
        return code, stderr.getvalue()

    def verify(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        code = seal_v1.verify(self.env_path, stdout=stdout, stderr=stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def status(self):
        path = self.state / seal_v1.STATUS
        return json.loads(path.read_text()), path.read_text()

    def lines(self):
        return self.log.read_bytes().split(b'\n')[:-1] if self.log.exists() else []

    def assert_alert(self, code, stderr, kind, secrets=(SECRET, READ_KEY)):
        self.assertEqual(code, 1)
        doc, raw = self.status()
        self.assertEqual((doc['schema'], doc['result'], doc['kind']), (seal_v1.SCHEMA, 'alert', kind))
        self.assertEqual(self.notes, [('Clockchain seal', f'{kind.replace("_", " ")}: see {seal_v1.STATUS}')])
        self.assertTrue(stderr.startswith(f'seal alert ({kind}): '), stderr)
        for secret in secrets:
            self.assertNotIn(secret, raw)
            self.assertNotIn(secret, stderr)
            self.assertNotIn(secret, repr(self.notes))
        return doc

    def test_first_seal_starts_the_chain_and_later_seals_extend_it(self):
        first = signed()
        code, stderr = self.run_seal(FakeNode(first))
        self.assertEqual((code, stderr, self.notes), (0, '', []))
        self.assertEqual(self.log.stat().st_mode & 0o777, 0o600)
        lines = self.lines()
        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(set(entry), seal_v1.ENTRY_KEYS)
        self.assertEqual(entry['prev_sha256'], '0' * 64)
        self.assertEqual(entry['seal'], first)
        self.assertIn('T', entry['fetched_at'])
        doc, _ = self.status()
        self.assertEqual(doc['result'], 'ok')
        self.assertEqual((doc['entries'], doc['head_sha256']), (1, seal_v1.line_digest(lines[0])))
        self.assertEqual(doc['candidates'], 3)
        self.assertEqual(doc['commitment'], 'bb' * 32)
        self.assertEqual(self.proxy.calls, [(APP, self.state, 'seal')])

        second = successor(first)
        third = successor(second, corpus_digest='ac' * 32, commitment='bd' * 32,
                          counts={'candidates': 4}, build='next-build')
        for doc_n, n in ((second, 2), (third, 3)):
            self.notes = []
            code, stderr = self.run_seal(FakeNode(doc_n))
            self.assertEqual((code, stderr, self.notes), (0, '', []))
            lines = self.lines()
            self.assertEqual(len(lines), n)
            entry = json.loads(lines[-1])
            self.assertEqual(entry['prev_sha256'], seal_v1.line_digest(lines[-2]))
            self.assertEqual(entry['seal'], doc_n)
        self.assertEqual(self.status()[0]['candidates'], 4)

        code, out, err = self.verify()
        self.assertEqual((code, err), (0, ''))
        report = json.loads(out)
        self.assertEqual((report['result'], report['entries']), ('ok', 3))
        self.assertEqual(report['head_sha256'], seal_v1.line_digest(lines[-1]))
        self.assertEqual(report['head']['build'], 'next-build')
        self.assertNotIn(READ_KEY, out)

    def test_given_node_url_skips_the_proxy(self):
        env = dict(self.env)
        del env['CC_FLY_APP']
        env['CC_NODE_URL'] = BASE + '/'
        self.write_env(env)
        node = FakeNode()
        code, stderr = self.run_seal(node)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(self.proxy.calls, [])
        self.assertEqual(node.paths(), ['/v1/seal'])
        self.assertEqual(len(self.lines()), 1)

    def test_prev_hash_tamper_is_refused_by_verify_and_by_the_next_run(self):
        first = signed()
        self.run_seal(FakeNode(first))
        self.run_seal(FakeNode(successor(first)))
        lines = self.lines()
        entry = json.loads(lines[1])
        entry['prev_sha256'] = 'f' * 64
        tampered = seal_v1.encode_entry(entry)
        self.log.write_bytes(lines[0] + b'\n' + tampered + b'\n')
        code, out, err = self.verify()
        self.assertEqual((code, out), (1, ''))
        self.assertTrue(err.startswith('seal log refused (log_broken): '), err)
        self.assertIn('line 2', err)
        self.notes = []
        code, stderr = self.run_seal(FakeNode(successor(successor(first))))
        self.assert_alert(code, stderr, 'log_broken')
        self.assertEqual(self.lines(), [lines[0], tampered])  # nothing was appended

    def test_rewritten_seal_in_the_log_is_refused(self):
        first = signed()
        self.run_seal(FakeNode(first))
        self.run_seal(FakeNode(successor(first)))
        lines = self.lines()
        entry = json.loads(lines[0])
        entry['seal']['seal']['commitment'] = 'cc' * 32  # the chain still holds; the signature does not
        self.log.write_bytes(seal_v1.encode_entry(entry) + b'\n' + lines[1] + b'\n')
        code, out, err = self.verify()
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith('seal log refused (log_broken): '), err)  # line 2's prev no longer matches
        entry2 = json.loads(lines[1])
        entry2['prev_sha256'] = seal_v1.line_digest(seal_v1.encode_entry(entry))
        self.log.write_bytes(seal_v1.encode_entry(entry) + b'\n' + seal_v1.encode_entry(entry2) + b'\n')
        code, out, err = self.verify()
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith('seal log refused (bad_signature): SealInvalid: log line 1'), err)

    def test_bad_signature_is_refused_and_not_logged(self):
        doc = signed()
        doc['signature'] = doc['signature'][:-2] + ('00' if doc['signature'][-2:] != '00' else '01')
        code, stderr = self.run_seal(FakeNode(doc))
        self.assert_alert(code, stderr, 'bad_signature')
        self.assertFalse(self.log.exists())

    def test_another_node_key_is_refused(self):
        code, stderr = self.run_seal(FakeNode(signed(key=OTHER_KEY)))
        self.assert_alert(code, stderr, 'node_key_mismatch')
        self.assertFalse(self.log.exists())

    def test_identity_drift_is_refused(self):
        cases = {'instance': signed(instance='22' * 32),
                 'fold_version': signed(fold_version={'version': 1, 'manifest': '33' * 32}),
                 'filter_version': signed(filter_version='44' * 32)}
        for field, doc in cases.items():
            with self.subTest(field):
                self.notes = []
                code, stderr = self.run_seal(FakeNode(doc))
                alert = self.assert_alert(code, stderr, 'identity_drift')
                self.assertIn(field, alert['error'])
        self.assertFalse(self.log.exists())

    def test_count_decrease_is_refused(self):
        first = signed()
        self.run_seal(FakeNode(first))
        code, stderr = self.run_seal(FakeNode(successor(first, counts={'candidates': 2})))
        self.assert_alert(code, stderr, 'count_decrease')
        self.assertEqual(len(self.lines()), 1)

    def test_commitment_change_without_new_candidates_is_refused(self):
        first = signed()
        self.run_seal(FakeNode(first))
        for change in ({'commitment': 'bd' * 32}, {'corpus_digest': 'ac' * 32},
                       {'commitment': 'bd' * 32, 'corpus_digest': 'ac' * 32}):
            with self.subTest(sorted(change)):
                self.notes = []
                code, stderr = self.run_seal(FakeNode(successor(first, **change)))
                self.assert_alert(code, stderr, 'commitment_changed')
        self.assertEqual(len(self.lines()), 1)
        # Growth is the one allowed change.
        self.notes = []
        grown = successor(first, commitment='bd' * 32, corpus_digest='ac' * 32, counts={'candidates': 4})
        self.assertEqual(self.run_seal(FakeNode(grown))[0], 0)
        self.assertEqual(len(self.lines()), 2)

    def test_growth_without_a_new_corpus_digest_is_refused(self):
        first = signed()
        self.run_seal(FakeNode(first))
        for change in ({}, {'commitment': 'bd' * 32}, {'corpus_digest': 'ac' * 32}):
            with self.subTest(sorted(change) or 'neither'):
                self.notes = []
                grown = successor(first, counts={'candidates': 4}, **change)
                code, stderr = self.run_seal(FakeNode(grown))
                alert = self.assert_alert(code, stderr, 'commitment_changed')
                self.assertIn('grew', alert['error'])
        self.assertEqual(len(self.lines()), 1)
        # Both digests moving with the count is growth; verify agrees.
        self.notes = []
        grown = successor(first, counts={'candidates': 4}, commitment='bd' * 32, corpus_digest='ac' * 32)
        self.assertEqual(self.run_seal(FakeNode(grown))[0], 0)
        self.assertEqual(len(self.lines()), 2)
        self.assertEqual(self.verify()[0], 0)
        # A log holding a growth step with an unchanged digest is refused by verify.
        lines = self.lines()
        bad = successor(first, counts={'candidates': 4}, commitment='bd' * 32)
        entry = {'prev_sha256': seal_v1.line_digest(lines[0]), 'seal': bad, 'fetched_at': 'x'}
        self.log.write_bytes(lines[0] + b'\n' + seal_v1.encode_entry(entry) + b'\n')
        code, out, err = self.verify()
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith('seal log refused (commitment_changed): Regression: log line 2'), err)

    def test_non_monotonic_time_is_refused(self):
        first = signed()
        self.run_seal(FakeNode(first))
        for when in (first['seal']['sealed_at_us'], first['seal']['sealed_at_us'] - 1):
            with self.subTest(when):
                self.notes = []
                code, stderr = self.run_seal(FakeNode(successor(first, sealed_at_us=when)))
                self.assert_alert(code, stderr, 'time_regression')
        self.assertEqual(len(self.lines()), 1)

    def test_no_seal_key_is_a_named_failure(self):
        node = FakeNode(answers=[(503, {'error': 'no_seal_key'})])
        code, stderr = self.run_seal(node)
        doc = self.assert_alert(code, stderr, 'no_seal_key')
        self.assertIn('CC_V1_NODE_SEED', doc['error'])
        self.assertEqual(node.paths(), ['/v1/seal'])
        self.assertFalse(self.log.exists())

    def test_busy_is_retried_then_other_refusals_are_named(self):
        node = FakeNode(answers=[(503, {'error': 'busy'}), (200, signed())])
        with patch.object(seal_v1.time, 'sleep', lambda s: None):
            code, stderr = self.run_seal(node)
        self.assertEqual((code, stderr), (0, ''))
        self.assertEqual(node.paths(), ['/v1/seal', '/v1/seal'])
        for status, kind in ((401, 'unauthorized'), (403, 'unauthorized'), (500, 'node_error'),
                             (503, 'node_error')):
            with self.subTest(status):
                self.notes = []
                node = FakeNode(answers=[(status, {'error': 'store_unavailable'})])
                code, stderr = self.run_seal(node)
                self.assert_alert(code, stderr, kind)
        self.notes = []
        code, stderr = self.run_seal(FakeNode(answers=[(200, b'<html>proxy page</html>')]))
        self.assert_alert(code, stderr, 'bad_signature')

    def test_proxy_failure_is_unreachable_and_redacted(self):
        error = ProxyFailed(f'fly proxy exited: {SECRET} {READ_KEY} for {APP}')
        node = FakeNode()
        code, stderr = self.run_seal(node, FakeProxy(error))
        doc = self.assert_alert(code, stderr, 'unreachable', secrets=(SECRET, READ_KEY, APP))
        self.assertIn(owner_jobs.REDACTED, doc['error'])
        self.assertEqual(node.requests, [])

    def test_connection_error_is_unreachable(self):
        node = FakeNode()
        node.answers['/v1/seal'] = urllib.error.URLError(f'connection refused ({READ_KEY})')
        code, stderr = self.run_seal(node)
        self.assert_alert(code, stderr, 'unreachable')

    def test_unsafe_env_file_or_log_is_a_configuration_failure(self):
        self.env_path.chmod(0o644)
        node = FakeNode()
        code, stderr = self.run_seal(node)
        self.assertEqual(code, 1)
        self.assertEqual(self.notes, [('Clockchain seal', f'configuration: see {seal_v1.STATUS}')])
        self.assertTrue(stderr.startswith('seal alert (configuration): ConfigError'))
        self.assertNotIn(READ_KEY, stderr)
        self.assertEqual((self.proxy.calls, node.requests), ([], []))
        self.assertFalse(self.state.exists())
        self.env_path.chmod(0o600)
        self.notes = []
        self.log.write_bytes(b'')
        self.log.chmod(0o644)
        code, stderr = self.run_seal(node)
        self.assert_alert(code, stderr, 'configuration')
        self.assertIn('CC_SEAL_LOG', stderr)
        self.assertEqual(node.requests, [])
        self.log.chmod(0o600)
        self.notes = []
        env = dict(self.env)
        del env['CC_SEAL_NODE_KEY']
        self.write_env(env)
        code, stderr = self.run_seal(node)
        self.assert_alert(code, stderr, 'configuration')
        self.assertIn('CC_SEAL_NODE_KEY', stderr)
        self.assertEqual(node.requests, [])

    def test_log_inside_the_checkout_is_refused(self):
        env = dict(self.env)
        env['CC_SEAL_LOG'] = str(owner_jobs.ROOT / 'ops' / 'seals.ndjson')
        self.write_env(env)
        node = FakeNode()
        code, stderr = self.run_seal(node)
        self.assert_alert(code, stderr, 'configuration')
        self.assertEqual(node.requests, [])
        self.assertFalse((owner_jobs.ROOT / 'ops' / 'seals.ndjson').exists())

    def test_lock_held_returns_quietly(self):
        owner_jobs.private_dir(self.state)
        node = FakeNode()
        with owner_jobs.JobLock(self.state, 'seal') as held:
            self.assertTrue(held)
            code, stderr = self.run_seal(node)
        self.assertEqual((code, stderr, self.notes), (0, '', []))
        self.assertEqual((self.proxy.calls, node.requests), ([], []))
        self.assertFalse(self.log.exists())

    def test_install_only_prints(self):
        out, checks = io.StringIO(), []
        with patch.object(owner_jobs, 'install', side_effect=AssertionError('installed')), \
                patch.object(owner_jobs.subprocess, 'run', side_effect=AssertionError('ran a command')), \
                patch.object(owner_jobs, 'check_interpreter',
                             side_effect=lambda python, modules: checks.append((python, modules)) or python), \
                contextlib.redirect_stdout(out):
            code = seal_v1.main(['install', '--env-file', str(self.env_path)])
        self.assertEqual(code, 0)
        self.assertEqual(checks, [(sys.executable, owner_jobs.JOB_IMPORTS + ('seal_v1',))])
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)  # the one thing install creates
        text = out.getvalue()
        self.assertIn('# Not installed.', text)
        self.assertIn('launchctl bootstrap gui/', text)
        self.assertIn(f'<string>{seal_v1.LABEL}</string>', text)
        self.assertIn('<key>StartInterval</key>', text)
        self.assertIn('<integer>3600</integer>', text)
        self.assertIn('seal_v1.py', text)
        for secret in (READ_KEY, SECRET, NODE_KEY):
            self.assertNotIn(secret, text)
        self.assertFalse(self.log.exists())

    def test_install_refuses_an_interpreter_that_cannot_run_the_job(self):
        out, err = io.StringIO(), io.StringIO()
        refusal = owner_jobs.ConfigError(f'python cannot run this job (No module named cryptography) {READ_KEY}')
        with patch.object(owner_jobs, 'install', side_effect=AssertionError('installed')), \
                patch.object(owner_jobs, 'check_interpreter', side_effect=refusal), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = seal_v1.main(['install', '--env-file', str(self.env_path)])
        self.assertEqual((code, out.getvalue()), (1, ''))
        self.assertTrue(err.getvalue().startswith('seal install refused (configuration): '), err.getvalue())
        self.assertIn('cryptography', err.getvalue())
        self.assertNotIn(READ_KEY, err.getvalue())
        # A missing name is refused the same way, before any interpreter check.
        env = dict(self.env)
        del env['CC_SEAL_LOG']
        self.write_env(env)
        err = io.StringIO()
        with patch.object(owner_jobs, 'check_interpreter', side_effect=AssertionError('checked')), \
                contextlib.redirect_stderr(err):
            code = seal_v1.main(['install', '--env-file', str(self.env_path)])
        self.assertEqual(code, 1)
        self.assertIn('CC_SEAL_LOG', err.getvalue())

    def test_verify_of_an_empty_or_missing_log_is_ok_with_no_entries(self):
        code, out, err = self.verify()
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(out), {'result': 'ok', 'entries': 0, 'head_sha256': None, 'head': None})


if __name__ == '__main__':
    unittest.main()
