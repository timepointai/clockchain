#!/usr/bin/env python3
"""One off-ledger Stability image; fail closed before credentials or network.

Approval is a human-reviewed grant, not a machine determination of legal rights.
Only original PNG bytes are stored; no ledger writes, retries, or publication.
"""
import argparse
from datetime import date, datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request
import uuid

ENDPOINT = 'https://api.stability.ai/v2beta/stable-image/generate/sd3'
MODEL = 'sd3.5-large'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def approval(path):
    record = json.loads(path.read_text())
    if record.get('status') != 'approved':
        raise ValueError('downstream-training permission is not approved')
    if record.get('provider') != 'stability.ai' or record.get('model') != MODEL:
        raise ValueError('permission does not cover this provider/model')
    for field in ('training_including_competing_models', 'dataset_redistribution'):
        if record.get(field) is not True:
            raise ValueError('permission missing: ' + field)
    if not record.get('reviewer') or not record.get('grant_reference'):
        raise ValueError('reviewer and provider grant reference are required')
    if not date.fromisoformat(record['reviewed_at']) <= date.today() <= date.fromisoformat(record['valid_through']):
        raise ValueError('permission review is not currently valid')
    grant = (path.parent / record['grant_file']).read_bytes()
    if not grant or sha(grant) != record['grant_sha256']:
        raise ValueError('provider grant missing or hash mismatch')
    return record


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('redirect refused; credential stays on Stability API')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--approval', type=Path)
    parser.add_argument('--preview-only', action='store_true',
                        help='generate a display preview permanently excluded from training by this tool')
    parser.add_argument('--prompt-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='new private staging directory')
    args = parser.parse_args(argv)
    try:
        if args.preview_only:
            grant = {'status': 'not_approved', 'scope': 'display_preview_only'}
        elif args.approval:
            grant = approval(args.approval)  # Must precede key access and paid request.
        else:
            raise ValueError('training candidate requires --approval; display preview requires --preview-only')
        prompt = args.prompt_file.read_text().strip()
        if not 1 <= len(prompt) <= 10000:
            raise ValueError('prompt must contain 1–10000 characters')
        key = os.environ.get('STABILITY_API_KEY')
        if not key:
            raise ValueError('STABILITY_API_KEY is required in the environment')
        args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
        fields = dict(prompt=prompt, model=MODEL, mode='text-to-image',
                      aspect_ratio='16:9', output_format='png', seed='742091')
        boundary = uuid.uuid4().hex
        body = b''.join((f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n').encode()
                        for k, v in fields.items()) + f'--{boundary}--\r\n'.encode()
        request = urllib.request.Request(ENDPOINT, data=body, headers={
            'Authorization': 'Bearer ' + key, 'Accept': 'image/*',
            'User-Agent': 'clockchain-image-preview/1.0',
            'Content-Type': 'multipart/form-data; boundary=' + boundary})
        # Exactly one attempt. A timeout can still incur a charge; no auto-retry.
        with urllib.request.build_opener(NoRedirect).open(request, timeout=120) as response:
            raw = response.read(32 * 1024 * 1024 + 1)
            if response.headers.get('finish-reason', '').upper() == 'CONTENT_FILTERED':
                raise ValueError('provider filtered the result')
            if len(raw) > 32 * 1024 * 1024 or not raw.startswith(b'\x89PNG\r\n\x1a\n'):
                raise ValueError('response is not a supported PNG image')
            headers = {k: response.headers.get(k) for k in ('seed', 'finish-reason', 'x-request-id')}
        image_hash = sha(raw)
        image_path = args.output / (image_hash + '.png')
        image_path.write_bytes(raw)  # Preserve content credentials/watermarks in original bytes.
        manifest = dict(schema='cc.image-candidate.v1', provider='stability.ai',
                        endpoint=ENDPOINT, model_requested=MODEL,
                        model_revision='not_exposed_by_provider', parameters=fields,
                        generated_at=datetime.now(timezone.utc).isoformat(),
                        image_sha256=image_hash, image_file=image_path.name,
                        byte_count=len(raw), mime_type='image/png', response=headers,
                        permission=grant,
                        permission_manifest_sha256=None if args.preview_only else sha(args.approval.read_bytes()),
                        synthetic=True, historical_verification='not_assessed',
                        visual_review='pending',
                        training_admission='excluded' if args.preview_only else 'pending_review',
                        prompt_and_manifest_in_training=False, ledger_write=False)
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
        print(json.dumps({'status': 'GENERATED_CANDIDATE', 'image': str(image_path),
                          'sha256': image_hash, 'ledger_write': False}))
        return 0
    except urllib.error.HTTPError as exc:
        # Restrict diagnostics to provider error fields and redact the credential.
        try:
            error = json.loads(exc.read(8192))
            detail = {k: error[k] for k in ('name', 'errors', 'message') if k in error}
        except (ValueError, OSError):
            detail = {'message': 'non-JSON provider error'}
        safe = json.dumps(detail).replace(os.environ.get('STABILITY_API_KEY', '') or '__NO_KEY__', '[REDACTED]')
        print(json.dumps({'status': 'FAILED', 'http_status': exc.code, 'detail': safe[:1000]}), file=sys.stderr)
    except (OSError, ValueError, KeyError) as exc:
        # Avoid raw provider responses, prompts, and credentials in diagnostics.
        reason = str(exc) if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__
        print(json.dumps({'status': 'NOT_RUN_OR_FAILED', 'reason': reason}), file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
