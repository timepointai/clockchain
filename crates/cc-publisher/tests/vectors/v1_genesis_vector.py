"""Independent derivation of `v1-genesis.txt`, read by tests/v1_offline.rs.

Python stdlib framing and SHA-256, and the Ed25519 signature from the
`cryptography` package (ops/requirements.txt), outside the Rust encoder.
Synthetic inputs only: seed 0x01 * 32, whose public key is pinned by
crates/cc-core/tests/vectors/v1_reference.py, and instance 0x09 * 32.
Run it and `git diff --exit-code` the vector.
"""
import datetime
import hashlib
from pathlib import Path
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

u16 = lambda n: struct.pack('>H', n)
u32 = lambda n: struct.pack('>I', n)
frame = lambda s: u32(len(s.encode())) + s.encode()
sha = lambda b: hashlib.sha256(b).digest()

key = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32)
author = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
assert author.hex() == '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c'

days = (datetime.date(1901, 2, 3) - datetime.date(1970, 1, 1)).days
assert days == -25169
seconds = days * 86400 - 946_728_000  # since J2000.0, 2000-01-01T12:00:00 UTC
coordinate = bytearray(((seconds << 64) % (1 << 256)).to_bytes(32, 'big'))
coordinate[0] ^= 0x80  # offset binary
coordinate = bytes(coordinate)

body = b'Synthetic v1 Genesis body for publisher vector-1.\n'
preimage = (frame('cc.event.v1') + u16(1) + u16(0) + bytes([9]) * 32 + u16(1) + author
            + b'\x00'
            + b'\x01' + frame('scientific-discovery') + frame('synthetic.publisher')
            + frame('vector-1')
            + b'\x00' + u32(0)
            + b'\x01' + coordinate + frame('day')
            + bytes([0x5a]) * 32 + sha(body) + u32(2) + bytes([0xaa]) * 32 + bytes([0xbb]) * 32)
envelope = preimage + key.sign(preimage)
event = sha(preimage)

header = """\
# Synthetic cc-publisher v1 Genesis vector, checked by tests/v1_offline.rs.
# No real key, body or subject. Ed25519 seed 0x01*32 (public key pinned in
# crates/cc-core/tests/vectors/v1_reference.py), instance 0x09*32, kind
# scientific-discovery, namespace synthetic.publisher, value vector-1,
# asserted time 1901-02-03 (precision day), nonce 0x5a*32, evidence
# {0xaa*32, 0xbb*32} (passed to the builder unsorted), body below.
# Derived outside Rust: Python stdlib framing and SHA-256, Ed25519 signature
# from the `cryptography` package. One `name hex` pair per line.
"""
rows = [
    ('body', body.hex()),
    ('body_sha256', sha(body).hex()),
    ('coordinate', coordinate.hex()),
    ('event', event.hex()),
    ('revision', sha(u32(14) + b'cc.revision.v1' + event + event).hex()),
    ('root_grant', sha(u32(16) + b'cc.root-grant.v1' + event).hex()),
    ('envelope_sha256', sha(envelope).hex()),
    ('envelope', envelope.hex()),
]
with open(Path(__file__).with_name('v1-genesis.txt'), 'w', newline='\n') as f:
    f.write(header + ''.join(f'{k} {v}\n' for k, v in rows))
