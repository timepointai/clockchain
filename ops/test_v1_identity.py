import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import v1_identity as v
from v1_identity import Expected, hexbytes

ROOT = v.ROOT
# Synthetic testkit curators: Ed25519 public keys of seeds 0x01*32..0x04*32 (cc_testkit::v1::filter).
CURATORS = ['8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
            '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c',
            'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1']
INSTANCE = '11' * 32


def vectors(path):
    return dict(line.split(' ', 1) for line in (ROOT / path).read_text().splitlines())


def expected(curators=CURATORS, hops='4', instance=INSTANCE):
    return Expected(instance, ','.join(curators), hops)


class PinnedVectorTests(unittest.TestCase):
    def test_rule_vectors(self):
        want = vectors('crates/cc-core/tests/vectors/v1-rule.txt')
        keys = [bytes.fromhex(k) for k in CURATORS[:2]]
        canonical = v.filter_canonical(keys, 4)
        corpus = v.corpus_digest([bytes([n]) * 32 for n in (3, 1, 2, 1)])
        self.assertEqual(v.fold_manifest().hex(), want['fold_manifest'])
        self.assertEqual(v.ontology().hex(), want['ontology'])
        self.assertEqual(canonical.hex(), want['filter_canonical'])
        self.assertEqual(v.sha(canonical).hex(), want['filter_version'])
        self.assertEqual(expected(CURATORS[:2]).filter_version, want['filter_version'])
        self.assertEqual(corpus.hex(), want['corpus_digest'])
        self.assertEqual(v.corpus_digest([]).hex(), want['corpus_digest_empty'])
        self.assertEqual(v.view_commitment(v.sha(canonical), corpus, b'synthetic rows').hex(),
                         want['view_commitment'])

    def test_view_vectors(self):
        want = vectors('crates/cc-ledger/tests/vectors/v1-view.txt')
        rows = (ROOT / 'crates/cc-ledger/tests/vectors/v1-view-rows.json').read_bytes()
        ids = [bytes(r['event']) for r in json.loads(rows)['rows']]
        e = expected()
        self.assertEqual(v.sha(rows).hex(), want['rows_sha256'])
        self.assertEqual(e.filter_version, want['filter_version'])
        self.assertEqual(v.corpus_digest(ids).hex(), want['corpus_digest'])
        self.assertEqual(v.view_commitment(bytes.fromhex(e.filter_version), v.corpus_digest(ids),
                                           rows).hex(), want['view_commitment'])

    def test_empty_view_matches_rust_snapshot(self):
        # Cross-language vector produced by Rust
        # `Snapshot::of(&cc_testkit::v1::filter(), &BTreeMap::new())` (the 4 testkit
        # curators, max_hops 4) in the v1 release-ops session; not recomputed by cargo here.
        self.assertEqual(expected().empty_commitment,
                         '5f57b5f03b940d42ef92df4802a750c63adf4a7a871c8a4eac4559fe29cdbcb1')
        self.assertEqual(v.EMPTY_ROWS, b'{"schema":"cc.view-rows.json.v1","rows":[],"revisions":[],'
                         b'"subjects":[],"grants":[],"active":[],"tombstones":[],"effective_revokes":[],'
                         b'"canceled":[],"effects":[],"edges":[],"media":[]}')

    def test_schema_hash_is_sql_bytes(self):
        sql = (ROOT / 'crates/cc-ledger/src/v1.sql').read_bytes()
        self.assertEqual(v.schema_hash(), hashlib.sha256(sql).digest())
        self.assertEqual(expected().summary()['schema_hash'], hashlib.sha256(sql).hexdigest())


class ExpectedTests(unittest.TestCase):
    def test_rejects_malformed_identity(self):
        c = ','.join(CURATORS)
        bad = [('AB' * 32, c, '4'), ('ab' * 31, c, '4'), (None, c, '4'),
               (INSTANCE, '', '4'), (INSTANCE, ','.join(reversed(CURATORS)), '4'),
               (INSTANCE, CURATORS[0] + ',' + CURATORS[0], '4'),
               (INSTANCE, 'zz' * 32, '4'), (INSTANCE, CURATORS[0].upper(), '4'),
               (INSTANCE, c + ',', '4'), (INSTANCE, CURATORS, '4')]
        bad += [(INSTANCE, c, h) for h in ('0', 0, '04', 'abc', '70000', 70000, 4, '', '-4')]
        for args in bad:
            with self.assertRaises(ValueError, msg=repr(args)):
                Expected(*args)
        self.assertEqual(expected(hops='65535').max_hops, 65535)

    def test_from_env_names_missing(self):
        with self.assertRaises(ValueError) as error:
            Expected.from_env({})
        for name in ('CC_V1_INSTANCE', 'CC_V1_CURATORS', 'CC_V1_MAX_HOPS'):
            self.assertIn(name, str(error.exception))
        with self.assertRaises(ValueError) as error:
            Expected.from_env({'CC_V1_INSTANCE': INSTANCE, 'CC_V1_MAX_HOPS': ''})
        self.assertNotIn('CC_V1_INSTANCE', str(error.exception))
        self.assertIn('CC_V1_CURATORS, CC_V1_MAX_HOPS', str(error.exception))

    def test_production_pins_max_hops(self):
        env = {'CC_V1_INSTANCE': INSTANCE, 'CC_V1_CURATORS': ','.join(CURATORS), 'CC_V1_MAX_HOPS': '5'}
        self.assertEqual(Expected.from_env(env).max_hops, 5)
        with self.assertRaises(ValueError):
            Expected.from_env(env, production=True)
        env['CC_V1_MAX_HOPS'] = '4'
        e = Expected.from_env(env, production=True)
        self.assertEqual((e.instance, e.curators, e.max_hops), (INSTANCE, CURATORS, 4))

    def test_identity_inputs_change_rule(self):
        base = expected()
        for other in (expected(CURATORS[1:]), expected(hops='5'), expected(CURATORS[:3])):
            self.assertNotEqual(other.filter_version, base.filter_version)
            self.assertNotEqual(other.empty_commitment, base.empty_commitment)
        same = expected(instance='22' * 32)
        self.assertEqual((same.filter_version, same.empty_commitment),
                         (base.filter_version, base.empty_commitment))


class HexbytesTests(unittest.TestCase):
    def test_accepts_hex_and_byte_arrays(self):
        self.assertEqual(hexbytes('ab' * 32), 'ab' * 32)
        self.assertEqual(hexbytes(list(range(32))), bytes(range(32)).hex())
        self.assertEqual(hexbytes([255] * 32), 'ff' * 32)

    def test_rejects_other_shapes(self):
        for value in ('ab' * 31, 'ab' * 33, [1] * 31, [1] * 33, [True] * 32, [0] * 31 + [False],
                      'AB' * 32, 'Ab' * 32, [256] * 32, [0] * 31 + [-1], [1.0] * 32, ['ab'] * 32,
                      bytes(32), None, 7, ' ' + 'ab' * 32):
            with self.assertRaises(ValueError, msg=repr(value)):
                hexbytes(value)


if __name__ == '__main__':
    unittest.main()
