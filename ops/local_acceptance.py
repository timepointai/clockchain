#!/usr/bin/env python3
"""Exercise an immutable release image in temporary Docker + PG18 containers.

No Fly resources, production credentials, or production data are used. All test
containers, networks and volumes are removed on success or failure.
"""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time
import uuid

from acceptance_seed import seed
from deployed_checks import check, check_empty, check_zero, request


def docker(*args):
    return subprocess.check_output(['docker', *map(str, args)], text=True).strip()


def accept(image, sha, evidence):
    if not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', image):
        raise ValueError('acceptance requires an immutable image digest')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('acceptance requires the full source SHA')
    evidence = Path(evidence)
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    ident = 'cc-accept-' + uuid.uuid4().hex[:12]
    app, db, volume = ident + '-app', ident + '-db', ident + '-media'
    key, read_key, password = [secrets.token_hex(32) for _ in range(3)]
    owned = []
    try:
        docker('pull', '--platform', 'linux/amd64', image)
        resolved = json.loads(docker('image', 'inspect', image))[0]
        if image not in resolved.get('RepoDigests', []):
            raise ValueError('pulled image digest differs from requested image')
        docker('network', 'create', '--label', 'cc.acceptance=true', ident)
        owned.append(('network', ident))
        docker('volume', 'create', '--label', 'cc.acceptance=true', volume)
        owned.append(('volume', volume))
        with tempfile.TemporaryDirectory(prefix='cc-acceptance-env-') as temporary:
            envfile = Path(temporary) / 'env'
            values = {'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'clockchain',
                      'DATABASE_URL': f'postgres://postgres:{password}@{db}:5432/clockchain',
                      'CC_NODE_API_KEY': key, 'CC_NODE_READ_KEY': read_key,
                      'CC_NODE_POSTURE': 'live', 'PORT': '8080',
                      'CC_MEDIA_DIR': '/data/media/objects',
                      'CC_MEDIA_FREE_RESERVE_PERCENT': '0',
                      'MIGRATOR_SECRET_KEY': secrets.token_hex(32)}
            fd = os.open(envfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
            owned.append(('container', db))
            docker('run', '-d', '--name', db, '--network', ident,
                   '--label', 'cc.acceptance=true', '--env-file', envfile, 'postgres:18')
            for attempt in range(60):
                result = subprocess.run(['docker', 'exec', db, 'pg_isready', '-U', 'postgres'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    break
                if attempt == 59:
                    raise RuntimeError('temporary Postgres did not become ready')
                time.sleep(1)
            docker('run', '--rm', '--platform', 'linux/amd64', '--network', ident,
                   '--env-file', envfile, image, 'cc-node', 'migrate')
            docker('run', '--rm', '--platform', 'linux/amd64', '--user', 'root',
                   '-v', volume + ':/data/media', image, 'sh', '-c',
                   'mkdir -p /data/media/objects && chown -R clockchain:clockchain /data/media')
            owned.append(('container', app))
            docker('run', '-d', '--platform', 'linux/amd64', '--name', app,
                   '--label', 'cc.acceptance=true', '--network', ident,
                   '-p', '127.0.0.1::8080', '--env-file', envfile,
                   '-v', volume + ':/data/media', image)
        address = docker('port', app, '8080/tcp').splitlines()[0]
        if not address.startswith('127.0.0.1:'):
            raise RuntimeError('acceptance port must be loopback only')
        url = 'http://' + address
        for attempt in range(90):
            try:
                status, _ = request(url, '/health')
                if status == 200:
                    break
            except OSError:
                pass
            if attempt == 89:
                raise RuntimeError('temporary node did not become ready')
            time.sleep(1)
        zero_result = check_zero(url, sha, key, read_key)
        (evidence / 'zero-events.json').write_text(json.dumps(zero_result, indent=2) + '\n')
        docker('exec', app, 'python3', '/app/ops/model_catalog.py', '--help')
        docker('exec', app, 'python3', '/app/ops/model_runtime.py', '--help')
        docker('exec', app, 'cc-migrator', 'genesis')
        empty_result = check_empty(url, sha, key, read_key)
        (evidence / 'empty-corpus.json').write_text(json.dumps(empty_result, indent=2) + '\n')
        entity = seed('docker:' + app, url, key)
        result = check(url, sha, entity, key, read_key)
        result.update({'schema': 'cc.local-acceptance.v1', 'image': image,
                       'isolation': 'temporary Docker network/PG18/media, loopback HTTP',
                       'synthetic_fixture': True})
        (evidence / 'acceptance.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except BaseException as error:
        for container in (app, db):
            logs = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
            (evidence / (container + '.log')).write_text(logs.stdout + logs.stderr)
        (evidence / 'FAILED').write_text(type(error).__name__ + '\n')
        raise
    finally:
        failures = []
        for kind, name in reversed(owned):
            command = ['docker', 'rm', '-f', '-v', name] if kind == 'container' else ['docker', kind, 'rm', name]
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                failures.append(name)
        (evidence / 'cleanup.json').write_text(json.dumps({'removed': not failures, 'remaining': failures}) + '\n')
        if failures:
            raise RuntimeError('temporary acceptance cleanup failed: ' + ', '.join(failures))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    result = accept(args.image, args.sha, args.evidence)
    print(json.dumps({'result': result['result'], 'checks': len(result['checks'])}))
