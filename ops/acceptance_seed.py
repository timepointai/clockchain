#!/usr/bin/env python3
"""Prepare the isolated acceptance app with its own synthetic creation.

The deployed checks replay a genuine media attachment, which a freshly
migrated acceptance database does not have and must never borrow from
production. This drives the real operator path on the deployed app —
brief, approval, candidate, approval, publication — and attaches one
synthetic image to the moment that path published.

Synthetic content is confined to acceptance. Production publishes only
what a human approved, so this tool refuses to run against it.
"""
import argparse
import base64
import hashlib
import json
import random
import tempfile
from pathlib import Path
from urllib.parse import urlparse
import struct
import subprocess
import urllib.error
import urllib.request
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REMOTE = '/tmp/cc-acceptance'
TT_BUNDLE = '31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113'
LICENSE = '19b6998b569b53ac1fc2158a8a3202c8699a9a4605b47075715d9c96be7fb6d0'
WEIGHTS = {
    'text_encoder/model.fp16.safetensors':
        '660c6f5b1abae9dc498ac2d21e1347d2abdb0cf6c0c0c8576cd796491d9a6cdd',
    'text_encoder_2/model.fp16.safetensors':
        'ec310df2af79c318e24d20511b601a591ca8cd4f1fce1d8dff822a356bcdb1f4',
    'unet/diffusion_pytorch_model.fp16.safetensors':
        '83e012a805b84c7ca28e5646747c90a243c65c8ba4f070e2d7ddc9d74661e139',
    'vae/diffusion_pytorch_model.fp16.safetensors':
        'bcb60880a46b63dea58e9bc591abe15f8350bde47b405f9c38f4be70c6161e68',
}
SOURCE = (b'Egyptian and Hittite forces fought at Kadesh in 1274 BCE. This '
          b'acceptance fixture records the battle and does not establish causal '
          b'relationships.')


def canonical(value):
    """RFC 8785 for the shapes used here: sorted keys, no insignificant space."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False).encode()


def png(rgb=None):
    """Deterministic 768x768 RGB noise PNG, about 1.7 MiB like production media."""
    def chunk(tag, payload):
        body = tag + payload
        return struct.pack('>I', len(payload)) + body + struct.pack('>I', zlib.crc32(body))
    width = height = 768
    pixels = random.Random(20260922).randbytes(width * height * 3)
    raw = b''.join(b'\0' + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    header = struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header)
            + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


def local_container(app):
    if not app.startswith('docker:'):
        return None
    name = app.removeprefix('docker:')
    data = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True))[0]
    if data.get('Config', {}).get('Labels', {}).get('cc.acceptance') != 'true':
        raise ValueError('container is not labelled as temporary Clockchain acceptance')
    return name


def ssh(app, command):
    name = local_container(app)
    args = ['docker', 'exec', name, 'sh', '-lc', command] if name else ['flyctl', 'ssh', 'console', '--app', app, '-C', command]
    out = subprocess.check_output(args, text=True)
    # flyctl prefixes connection chatter; the command's own output is what counts.
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith('{'):
            return json.loads(line)
    raise ValueError(f'no JSON from remote command: {out.strip()[:200]}')


def put(app, name, data):
    container = local_container(app)
    if container:
        subprocess.check_call(['docker', 'exec', container, 'mkdir', '-p', REMOTE])
        with tempfile.TemporaryDirectory(prefix='cc-fixture-') as temporary:
            path = Path(temporary) / name
            path.write_bytes(data)
            destination = REMOTE + '/' + name
            subprocess.check_call(['docker', 'cp', str(path), container + ':' + destination])
            # docker cp creates root-owned files; owner umask 077 must work.
            subprocess.check_call(['docker', 'exec', '--user', 'root', container,
                                   'chown', 'clockchain:clockchain', destination])
            subprocess.check_call(['docker', 'exec', '--user', 'root', container,
                                   'chmod', '600', destination])
        return
    encoded = base64.b64encode(data).decode()
    subprocess.check_call([
        'flyctl', 'ssh', 'console', '--app', app, '-C',
        f"sh -c 'mkdir -p {REMOTE} && echo {encoded} | base64 -d > {REMOTE}/{name}'"])


def entry(capture_path):
    text = SOURCE.decode()
    source = {
        'url': 'https://example.org/acceptance-source',
        'retrieved_at': '2026-09-15T00:00:00Z',
        'content_sha256': hashlib.sha256(SOURCE).hexdigest(),
        'capture_path': capture_path,
        'excerpt': text,
        'license': 'CC0-1.0',
        'publisher': 'Acceptance fixture',
        'locator': 'paragraph 1',
        'supports': ['title', 'year', 'summary'],
    }
    return {
        'title': 'Battle of Kadesh', 'year': -1274,
        'claim_type': 'conflict-and-warfare', 'lens': 'A', 'summary': text,
        'date_is_known': True, 'temporal_kind': 'event', 'observed_count': 1,
        'tt_release': 'tt-ontology/2.1.0', 'tt_bundle_sha256': TT_BUNDLE,
        'prov_measured': {
            'text_model': 'fixture', 'provider': 'fixture', 'method': 'acceptance',
            'run': 'frozen-acceptance', 'generated_at': '2026-09-15T00:00:00Z',
            'source_evidence_schema': 'cc.source-evidence.v1',
            'source_evidence': [source],
        },
        'prov_asserted': {
            'historical_claim': 'fixture',
            'source_support': {
                'schema': 'cc.source-support.v1', 'claim': 'battle occurrence',
                'source_urls': [source['url']], 'support_kind': 'observed',
                'rationale': 'explicit statement in the retained capture',
            },
        },
    }


def request(base, path, key, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        base + path, data=body,
        headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()[:300]


def seed(app, url, key, ident='acceptance-canary'):
    """Drive the operator path on `app` and return the published entity id."""
    if app.startswith('docker:') and urlparse(url).hostname not in ('127.0.0.1', 'localhost'):
        raise ValueError('local acceptance may only attach media through loopback')
    if app == 'timepoint-clockchain-prod':
        raise ValueError('acceptance seeding never targets production')

    # Re-running must not mint a second creation: a finished candidate already
    # has a receipt, and returning it is the same replay the checks rely on.
    existing = _published(app, ident)
    if existing:
        return existing['moments'][0]['entity_id']

    put(app, 'source.txt', SOURCE)
    brief = {'text': 'Acceptance fixture: one observed event, no causal claim.',
             'max_entries': 1}
    candidate = {'entries': [entry(f'{REMOTE}/source.txt')], 'edges': [], 'images': []}
    put(app, 'brief.json', canonical(brief))
    put(app, 'candidate.json', canonical(candidate))

    staged = ssh(app, f'cc-publisher brief-stage --id {ident} --path {REMOTE}/brief.json')
    ssh(app, f'cc-publisher approve-brief --id {ident} '
             f'--digest {staged["digest"]} --reviewer acceptance-operator')
    proposal = ssh(app, f'cc-publisher candidate-stage --id {ident} '
                        f'--brief {ident} --path {REMOTE}/candidate.json')
    ssh(app, f'cc-publisher approve-candidate --id {ident} '
             f'--digest {proposal["digest"]} --reviewer acceptance-operator')
    ssh(app, 'cc-publisher resume --reason acceptance-seed')
    receipt = ssh(app, f'cc-publisher publish --id {ident} --digest {proposal["digest"]}')
    _attach(url, key, receipt)
    return receipt['moments'][0]['entity_id']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', required=True)
    p.add_argument('--url', required=True)
    p.add_argument('--key', required=True)
    p.add_argument('--id', default='acceptance-canary')
    args = p.parse_args()
    try:
        entity = seed(args.app, args.url, args.key, args.id)
    except ValueError as exc:
        p.error(str(exc))
    print(json.dumps({'entity': entity}, indent=2))
    return 0


def _published(app, ident):
    """The existing receipt for this candidate, or None if it never published."""
    try:
        return ssh(app, f'cc-publisher receipt --id {ident}')
    except (subprocess.CalledProcessError, ValueError):
        return None


def _attach(url, key, receipt):
    """Attach one synthetic illustration to the moment just published."""
    moment = receipt['moments'][0]
    raw = png()
    signing = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b'cc-acceptance-writer').digest())
    writer = signing.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    manifest = {
        'schema': 'cc.image-attachment.v1', 'kind': 'generated_interpretation_of_claim',
        'historical_verification': 'not_assessed', 'provider': 'local_inference',
        'model': 'stabilityai/stable-diffusion-xl-base-1.0',
        'model_revision': '462165984030d82259a11f4367a4eed129e94a7b',
        'permission_profile': 'sdxl-openrail++-m-local-v1', 'license_sha256': LICENSE,
        'source_entity_id': moment['entity_id'], 'source_body_hash': moment['body_hash'],
        'writer': writer, 'prompt_in_training': False,
        'prompt': 'acceptance fixture illustration', 'generated_at': '2026-09-15T00:00:00Z',
        'seed': 1, 'image_sha256': hashlib.sha256(raw).hexdigest(), 'byte_count': len(raw),
        'weights_sha256': WEIGHTS,
    }
    digest = hashlib.sha256(b'cc.image-attachment.v1\x00' + canonical(manifest)).digest()
    payload = {'manifest': manifest, 'author': writer,
               'signature': signing.sign(digest).hex(),
               'image_base64': base64.b64encode(raw).decode()}
    status, body = request(url.rstrip('/'), '/v1/images', key, payload)
    if status != 201:
        raise SystemExit(f'acceptance attachment refused: HTTP {status}: {body}')
    return body['attachment_id']


if __name__ == '__main__':
    raise SystemExit(main())
