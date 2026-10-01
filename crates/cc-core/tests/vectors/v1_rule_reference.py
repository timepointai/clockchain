"""Independent stdlib computation of the Stage (e) rule-identity vectors.

Curator keys are synthetic Ed25519 public keys of seeds 0x01*32..0x04*32. The
view vector recomputes the corpus digest and view commitment from the pinned
canonical rows of the testkit's fixed synthetic projection. No production key,
corpus or body is used.
"""
import hashlib
import json
from pathlib import Path
import struct

here = Path(__file__).resolve().parent
root = here.parents[3]
sha = lambda b: hashlib.sha256(b).digest()
u16 = lambda n: struct.pack('>H', n)
u32 = lambda n: struct.pack('>I', n)
u64 = lambda n: struct.pack('>Q', n)
frame = lambda s: u32(len(s.encode())) + s.encode()
h = lambda n: bytes([n]) * 32

manifest = sha((root / 'crates/cc-core/src/v1/fold-manifest-v1.txt').read_bytes())
ontology = sha((root / 'vendor/tt/taxonomy-v2.1.json').read_bytes())
curators = sorted(bytes.fromhex(k) for k in (
    '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
    '8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394'))
policy = 'cc.trust.curator-genesis-creator.v1'.encode()
def filter_identity(keys, hops):
    return (frame('cc.filter.v1') + u16(1) + manifest + u16(1) + u16(0)
            + ontology + u32(len(keys)) + b''.join(keys)
            + u32(len(policy)) + policy + u16(hops))
filter_canonical = filter_identity(curators, 4)
filter_version = sha(filter_canonical)
corpus = sha(frame('cc.corpus.v1') + u32(3) + h(1) + h(2) + h(3))
empty = sha(frame('cc.corpus.v1') + u32(0))
rows = b'synthetic rows'
view = sha(frame('cc.view.v1') + u16(1) + u16(1) + manifest + filter_version
           + corpus + u64(len(rows)) + rows)
query = b'synthetic query'
cache = sha(frame('cc.cache.v1') + filter_version + corpus + u64(len(query)) + query)
vectors = [('fold_manifest', manifest), ('ontology', ontology),
           ('filter_canonical', filter_canonical), ('filter_version', filter_version),
           ('corpus_digest', corpus), ('corpus_digest_empty', empty),
           ('view_commitment', view), ('cache_key', cache)]
(here / 'v1-rule.txt').write_text(''.join(f'{n} {v.hex()}\n' for n, v in vectors))

# Canonical rows of cc_testkit::v1::view_fixture() under cc_testkit::v1::filter().
ledger = root / 'crates/cc-ledger/tests/vectors'
rows = (ledger / 'v1-view-rows.json').read_bytes()
ids = sorted(bytes(r['event']) for r in json.loads(rows)['rows'])
corpus = sha(frame('cc.corpus.v1') + u32(len(ids)) + b''.join(ids))
testkit = sorted(curators + [bytes.fromhex(k) for k in (
    'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1',
    'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c')])
version = sha(filter_identity(testkit, 4))
view = sha(frame('cc.view.v1') + u16(1) + u16(1) + manifest + version + corpus
           + u64(len(rows)) + rows)
vectors = [('rows_sha256', sha(rows)), ('filter_version', version),
           ('corpus_digest', corpus), ('view_commitment', view)]
(ledger / 'v1-view.txt').write_text(''.join(f'{n} {v.hex()}\n' for n, v in vectors))
