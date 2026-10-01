#!/usr/bin/env python3
"""Expected v1 identity, recomputed from this checkout without the node.

The release tooling must not take the node's word for which instance, rule and
curators it serves. These stdlib computations mirror the pinned Rust encodings
(`FilterIdentity::canonical`, `corpus_digest`, `view_commitment`, the
`cc_v1.identity` schema hash) and are tested against the committed vectors.
Configuration values come from the operator environment, never argv.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
FOLD_MANIFEST_FILE = ROOT / 'crates/cc-core/src/v1/fold-manifest-v1.txt'
TAXONOMY_FILE = ROOT / 'vendor/tt/taxonomy-v2.1.json'
SCHEMA_FILE = ROOT / 'crates/cc-ledger/src/v1.sql'

FOLD_VERSION = 1
CANON_VERSION = 1
CONSTANTS_VERSION = 0
TRUST_POLICY = 'cc.trust.curator-genesis-creator.v1'
# HOLD.md, owner launch decisions: production max_hops = 4.
PRODUCTION_MAX_HOPS = 4
TABLES = ('bodies', 'candidates', 'identity', 'receipts', 'rejections', 'rule_identity')
APPEND_ONLY_ERROR = 'v1 append-only evidence'

HEX64 = re.compile(r'[0-9a-f]{64}')


def sha(data):
    return hashlib.sha256(data).digest()


def u16(n):
    return struct.pack('>H', n)


def u32(n):
    return struct.pack('>I', n)


def u64(n):
    return struct.pack('>Q', n)


def frame(domain):
    return u32(len(domain.encode())) + domain.encode()


def fold_manifest():
    return sha(FOLD_MANIFEST_FILE.read_bytes())


def ontology():
    return sha(TAXONOMY_FILE.read_bytes())


def schema_hash():
    return sha(SCHEMA_FILE.read_bytes())


def filter_canonical(curators, max_hops):
    policy = TRUST_POLICY.encode()
    return (frame('cc.filter.v1') + u16(FOLD_VERSION) + fold_manifest() + u16(CANON_VERSION)
            + u16(CONSTANTS_VERSION) + ontology() + u32(len(curators)) + b''.join(curators)
            + u32(len(policy)) + policy + u16(max_hops))


def corpus_digest(event_ids):
    ids = sorted(set(event_ids))
    return sha(frame('cc.corpus.v1') + u32(len(ids)) + b''.join(ids))


# Canonical rows of an empty projection, as `canonical_rows` serializes them.
EMPTY_ROWS = json.dumps({
    'schema': 'cc.view-rows.json.v1', 'rows': [], 'revisions': [], 'subjects': [],
    'grants': [], 'active': [], 'tombstones': [], 'effective_revokes': [], 'canceled': [],
    'effects': [], 'edges': [], 'media': []}, separators=(',', ':')).encode()


def view_commitment(filter_version, corpus, rows):
    return sha(frame('cc.view.v1') + u16(CANON_VERSION) + u16(FOLD_VERSION) + fold_manifest()
               + filter_version + corpus + u64(len(rows)) + rows)


def hexbytes(value, name='hash'):
    """Accept a 64-hex string or a 32-byte JSON array; return lowercase hex."""
    if isinstance(value, list) and len(value) == 32 and all(
            isinstance(b, int) and not isinstance(b, bool) and 0 <= b < 256 for b in value):
        return bytes(value).hex()
    if isinstance(value, str) and HEX64.fullmatch(value):
        return value
    raise ValueError(f'{name} is not a 32-byte hash')


class Expected:
    """The identity the owner intends production to hold."""

    def __init__(self, instance, curators, max_hops):
        if not isinstance(instance, str) or not HEX64.fullmatch(instance):
            raise ValueError('CC_V1_INSTANCE must be 64 lowercase hex characters')
        if not isinstance(curators, str) or not curators:
            raise ValueError('CC_V1_CURATORS must name at least one curator key')
        keys = curators.split(',')
        if any(not HEX64.fullmatch(k) for k in keys):
            raise ValueError('CC_V1_CURATORS must be comma-separated 64-hex Ed25519 keys')
        if any(a >= b for a, b in zip(keys, keys[1:])):
            raise ValueError('CC_V1_CURATORS must be strictly sorted without duplicates')
        if not isinstance(max_hops, str) or not re.fullmatch(r'[1-9][0-9]{0,4}', max_hops) \
                or int(max_hops) > 0xFFFF:
            raise ValueError('CC_V1_MAX_HOPS must be a positive 16-bit integer')
        self.instance = instance
        self.curators = keys
        self.max_hops = int(max_hops)

    @classmethod
    def from_env(cls, env=None, *, production=False):
        env = os.environ if env is None else env
        missing = [n for n in ('CC_V1_INSTANCE', 'CC_V1_CURATORS', 'CC_V1_MAX_HOPS') if not env.get(n)]
        if missing:
            raise ValueError('operator environment needs: ' + ', '.join(missing))
        expected = cls(env['CC_V1_INSTANCE'], env['CC_V1_CURATORS'], env['CC_V1_MAX_HOPS'])
        if production and expected.max_hops != PRODUCTION_MAX_HOPS:
            raise ValueError(f'production CC_V1_MAX_HOPS must be {PRODUCTION_MAX_HOPS} (HOLD.md)')
        return expected

    @property
    def filter_canonical(self):
        return filter_canonical([bytes.fromhex(k) for k in self.curators], self.max_hops)

    @property
    def filter_version(self):
        return sha(self.filter_canonical).hex()

    @property
    def fold(self):
        return {'version': FOLD_VERSION, 'manifest': fold_manifest().hex()}

    @property
    def empty_commitment(self):
        return view_commitment(bytes.fromhex(self.filter_version), corpus_digest([]),
                               EMPTY_ROWS).hex()

    def summary(self):
        """Public, non-secret description for evidence files."""
        return {'instance': self.instance, 'curators': self.curators, 'max_hops': self.max_hops,
                'fold_version': self.fold, 'filter_version': self.filter_version,
                'empty_commitment': self.empty_commitment,
                'empty_corpus_digest': corpus_digest([]).hex(), 'schema_hash': schema_hash().hex()}


if __name__ == '__main__':
    print(json.dumps(Expected.from_env().summary(), indent=2))
