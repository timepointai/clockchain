"""Independent stdlib framing of the eight synthetic Rust wire test vectors.

The fixed public key is Ed25519 seed 0x01 * 32. These are encoding vectors,
not semantically admissible proposals. No production key or body is used.
"""
import hashlib
from pathlib import Path
import struct

u16 = lambda n: struct.pack('>H', n)
u32 = lambda n: struct.pack('>I', n)
h = lambda n: bytes([n]) * 32
frame = lambda s: u32(len(s.encode())) + s.encode()
key = bytes.fromhex('8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c')


def header(kind):
    return (frame('cc.event.v1') + u16(1) + u16(0) + h(9) + u16(kind) + key
            + b'\x00\x01' + frame('test') + frame('synthetic') + frame('subject')
            + b'\x00' + u32(0) + b'\x00')


def decision(kind):
    return u16(kind) + frame('synthetic') + u32(1) + h(7) + u32(0) + u16(0) + u16(0)


pin = h(1) + h(2) + h(3) + h(4)
pins = pin + pin
payloads = [
    h(2) + h(3) + u32(1) + h(4),
    h(5) + decision(2),
    h(5) + h(6) + decision(3),
    h(5) + b'\x01' + decision(4),
    u16(1) + h(5) + u32(1) + h(6) + u16(2) + frame('synthetic') + decision(5),
    frame('disputes') + pins + decision(6),
    h(5) + u32(1) + h(6) + pins + pins + decision(7),
    u16(2) + h(5) + frame('source') + h(6),
]
vectors = [header(i) + payload for i, payload in enumerate(payloads, 1)]
Path(__file__).with_name('v1-preimages.txt').write_text(''.join(
    f'{wire.hex()} {hashlib.sha256(wire).hexdigest()}\n' for wire in vectors))
