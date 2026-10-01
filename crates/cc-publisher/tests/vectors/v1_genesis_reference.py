"""Independent stdlib derivation of the cc-publisher v1 Genesis vector.

Frames the canonical cc.event.v1 preimage for fixed synthetic inputs without
the Rust encoder, derives the asserted-time coordinate with `datetime`, and
writes the identifiers `crates/cc-publisher/tests/v1_vector.rs` compares with
`cc_publisher::v1::genesis::build`. The Ed25519 public key of seed 0x01 * 32
is the one pinned by crates/cc-core/tests/vectors/v1_reference.py. Synthetic
inputs only; no production key, instance or body.
"""
import datetime
import hashlib
from pathlib import Path
import struct

u16 = lambda n: struct.pack('>H', n)
u32 = lambda n: struct.pack('>I', n)
frame = lambda s: u32(len(s.encode())) + s.encode()
sha = lambda b: hashlib.sha256(b).digest()

AUTHOR = bytes.fromhex('8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')
INSTANCE = bytes([9]) * 32
NONCE = bytes([0x5a]) * 32
KIND, NAMESPACE, VALUE = 'scientific-discovery', 'synthetic.publisher', 'reference-1'
BODY = b'Synthetic publisher reference body.\nIt names no historical claim.\n'
DATE, PRECISION = datetime.date(1901, 2, 3), 'day'
EVIDENCE = sorted([bytes([0xbb]) * 32, bytes([0xaa]) * 32])
J2000_UNIX_SECONDS = 946_728_000  # 2000-01-01T12:00:00 UTC


def coordinate(date):
    """Tick canon bytes of 00:00:00 UTC on `date`: offset-binary big-endian
    256-bit two's complement of (seconds since J2000.0) << 64."""
    seconds = (date - datetime.date(1970, 1, 1)).days * 86400 - J2000_UNIX_SECONDS
    raw = ((seconds << 64) % (1 << 256)).to_bytes(32, 'big')
    return bytes([raw[0] ^ 0x80]) + raw[1:]


def domain(name, *ids):
    return sha(u32(len(name)) + name.encode() + b''.join(ids))


preimage = (frame('cc.event.v1') + u16(1) + u16(0) + INSTANCE + u16(1) + AUTHOR
            + b'\x00'                                          # subject: none
            + b'\x01' + frame(KIND) + frame(NAMESPACE) + frame(VALUE)
            + b'\x00'                                          # grant: none
            + u32(0)                                           # parents: empty
            + b'\x01' + coordinate(DATE) + frame(PRECISION)    # asserted time
            + NONCE + sha(BODY) + u32(len(EVIDENCE)) + b''.join(EVIDENCE))
event = sha(preimage)
values = {
    'preimage': preimage.hex(),
    'event': event.hex(),
    'subject': event.hex(),
    'revision': domain('cc.revision.v1', event, event).hex(),
    'root_grant': domain('cc.root-grant.v1', event).hex(),
    'body_sha256': sha(BODY).hex(),
    'coordinate': coordinate(DATE).hex(),
}
Path(__file__).with_name('v1-genesis-reference.txt').write_text(
    ''.join(f'{k} {v}\n' for k, v in values.items()))
