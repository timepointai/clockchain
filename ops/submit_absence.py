#!/usr/bin/env python3
"""Sign one explicit media absence decision; optionally submit after review.

Requires the same jcs/cryptography dependencies as submit_image.py. Signing is
local by default. --submit sends the signed decision, never a historical event.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import urllib.request

DOMAIN = b"cc.media-absence.v1\0"


def sign_manifest(manifest, seed):
    import jcs
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    key = Ed25519PrivateKey.from_private_bytes(seed)
    author = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    manifest = dict(manifest, writer=author)
    digest = hashlib.sha256(DOMAIN + jcs.canonicalize(manifest)).digest()
    return dict(manifest=manifest, author=author, signature=key.sign(digest).hex()), digest.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entity-id", required=True, type=int)
    parser.add_argument("--body-hash", required=True)
    parser.add_argument("--reason-file", required=True, type=Path)
    parser.add_argument("--decided-at-ticks", required=True, type=int,
                        help="Writer-declared whole ticks since J2000")
    parser.add_argument("--writer-key", required=True, type=Path,
                        help="Existing private 32-byte Ed25519 seed (mode 600)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--submit", action="store_true")
    args = parser.parse_args()
    if args.writer_key.stat().st_mode & 0o077:
        parser.error("Writer key must be private (mode 600)")
    if not -(2**63) <= args.entity_id < 2**63 or not -(2**63) <= args.decided_at_ticks < 2**63:
        parser.error("Entity ID and decision time must fit signed 64-bit integers")
    try:
        source = bytes.fromhex(args.body_hash)
    except ValueError:
        parser.error("Invalid body hash")
    if len(source) != 32 or source.hex() != args.body_hash:
        parser.error("Body hash must be lowercase 32-byte hex")
    reason = args.reason_file.read_text()
    if not reason.strip() or len(reason.encode()) > 4096:
        parser.error("Reason must be nonblank and at most 4096 UTF-8 bytes")
    payload, decision_id = sign_manifest(dict(
        schema="cc.media-absence.v1", kind="deliberately_unillustrated",
        source_entity_id=str(args.entity_id), source_body_hash=args.body_hash,
        reason=reason, decided_at_ticks=str(args.decided_at_ticks)), args.writer_key.read_bytes())
    # Exclusive creation protects a previously reviewed artifact; save before send.
    with args.output.open("x") as output:
        json.dump(payload, output, indent=2, ensure_ascii=False)
        output.write("\n")
    if not args.submit:
        print(json.dumps(dict(decision_id=decision_id, submitted=False)))
        return
    token = os.environ["CC_NODE_API_KEY"]
    request = urllib.request.Request(
        "http://127.0.0.1:18080/v2/media/absence-decisions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        receipt = json.load(response)
    if receipt.get("decision_id") != decision_id:
        raise ValueError("Returned decision ID mismatch; signed payload retained")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
