"""Independent stdlib computation of the Stage (e) rule-identity vectors.

Curator keys are the synthetic Ed25519 public keys of seeds 0x02*32 and 0x01*32,
sorted. No production key, corpus or body is used.
"""
import hashlib
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
filter_canonical = (frame('cc.filter.v1') + u16(1) + manifest + u16(1) + u16(0)
                    + ontology + u32(len(curators)) + b''.join(curators)
                    + u32(len(policy)) + policy + u16(4))
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
