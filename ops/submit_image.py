#!/usr/bin/env python3
"""Sign and submit one generated image attachment; never mint a claim event.

Requires cryptography and jcs. API credential comes only from CC_NODE_API_KEY.
The writer seed lives in a private local file, separate from historical writers.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.request
import urllib.error


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate',type=Path,required=True)
    parser.add_argument('--writer-key',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--node',default='http://127.0.0.1:18080')
    args=parser.parse_args()
    if args.node!='http://127.0.0.1:18080':
        parser.error('This contribution tool sends credentials only to the local private-instance proxy')
    if args.receipt.exists(): parser.error('Receipt already exists')
    import jcs
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    candidate=json.loads((args.candidate/'manifest.json').read_text())
    image_path=args.candidate/candidate['image_file']
    if image_path.resolve().parent!=args.candidate.resolve(): parser.error('Invalid image path')
    raw=image_path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=candidate['image_sha256']: parser.error('Image digest mismatch')
    if candidate['visual_review']!='accepted_as_illustration': parser.error('Image needs visual review')
    permission = candidate['permission']
    profile = permission.get('profile', 'sdxl-openrail++-m-local-v1')
    if profile == 'flux-klein-4b-apache-local-v1':
        if permission['status'] != 'permissive_model_license': parser.error('Wrong Apache permission route')
    elif profile != 'sdxl-openrail++-m-local-v1' or permission['status'] != 'conditional_model_license':
        parser.error('Wrong permission route')
    if not args.writer_key.exists():
        args.writer_key.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        fd=os.open(args.writer_key,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as f: f.write(os.urandom(32))
    if args.writer_key.stat().st_mode & 0o077: parser.error('Writer key must be private (mode 600)')
    key=Ed25519PrivateKey.from_private_bytes(args.writer_key.read_bytes())
    author=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    manifest=dict(schema='cc.image-attachment.v1',kind='generated_interpretation_of_claim',
        historical_verification='not_assessed',provider=candidate['provider'],
        source_entity_id=str(candidate['source']['entity_id']),source_body_hash=candidate['source']['body_hash'],
        model=candidate['model_requested'],model_revision=candidate['model_revision'],
        weights_sha256=candidate['weights_sha256'],permission_profile=profile,
        license_sha256=candidate['permission']['license_sha256'],
        license_url=candidate['permission']['license_url'],license_conditions=candidate['permission']['conditions'],
        prompt=candidate['parameters']['prompt'],prompt_in_training=False,seed=candidate['parameters']['seed'],
        parameters=candidate['parameters'],generated_at=candidate['generated_at'],
        image_sha256=candidate['image_sha256'],byte_count=len(raw),writer=author)
    for field in ('generator_sha256', 'execution_platform'):
        if field in candidate: manifest[field] = candidate[field]
    digest=hashlib.sha256(b'cc.image-attachment.v1\0'+jcs.canonicalize(manifest)).digest()
    signature=key.sign(digest).hex()
    payload=dict(manifest=manifest,author=author,signature=signature,image_base64=base64.b64encode(raw).decode())
    token=os.environ['CC_NODE_API_KEY']
    request=urllib.request.Request(args.node+'/v1/images',data=json.dumps(payload).encode(),
        headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=120) as response: receipt=json.load(response)
    except urllib.error.HTTPError as exc:
        print(json.dumps({'status':'FAILED','http_status':exc.code,'detail':exc.read(1000).decode(errors='replace').replace(token,'[REDACTED]')}))
        raise SystemExit(1)
    if receipt.get('attachment_id')!=digest.hex(): raise ValueError('Returned attachment id mismatch')
    args.receipt.write_text(json.dumps({'receipt':receipt,'manifest':manifest,'author':author,'signature':signature},indent=2)+'\n')
    print(json.dumps(receipt))


if __name__=='__main__': main()
