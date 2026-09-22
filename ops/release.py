#!/usr/bin/env python3
"""Owner-operated promotion of an already-built immutable image.

Public GitHub CI holds no production credentials and never deploys. The owner
runs this from a clean exact-main checkout with local Fly/GitHub authentication.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time

from local_acceptance import accept
from deployed_checks import request


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='registry.fly.io/<app>@sha256:<digest>')
    parser.add_argument('--app', required=True)
    parser.add_argument('--config', default='fly.toml')
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'registry\.fly\.io/' + re.escape(args.app) + r'@sha256:[0-9a-f]{64}', args.image):
        parser.error('image must be pinned to the target app registry digest')
    root = Path(output('git', 'rev-parse', '--show-toplevel'))
    os.chdir(root)
    if output('git', 'status', '--porcelain'):
        parser.error('checkout must be clean')
    sha = output('git', 'rev-parse', 'HEAD')
    if output('git', 'ls-remote', 'origin', 'refs/heads/main').split()[0] != sha:
        parser.error('checkout must equal current origin/main')
    runs = json.loads(output('gh', 'run', 'list', '--workflow', 'ci.yml', '--commit', sha,
                             '--json', 'status,conclusion,headSha', '--limit', '10'))
    if not any(r['headSha'] == sha and r['status'] == 'completed' and r['conclusion'] == 'success' for r in runs):
        parser.error('a successful exact-SHA CI run is required')
    required = ('CC_NODE_API_KEY', 'CC_NODE_READ_KEY', 'CC_SMOKE_ENTITY',
                'CC_BACKUP_DB_APP', 'CC_BACKUP_DATABASE', 'CC_BACKUP_USER')
    if any(not os.environ.get(name) for name in required):
        parser.error('operator environment needs: ' + ', '.join(required))
    args.evidence = args.evidence.resolve()
    if args.evidence.is_relative_to(root):
        parser.error('private release evidence must be outside the public checkout')
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    # One local owner at a time; GitHub never holds deploy credentials.
    lockpath = Path.home() / '.clockchain' / 'release.lock'
    lockpath.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import fcntl
    with lockpath.open('a') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        output('flyctl', 'auth', 'docker')
        accept(args.image, sha, args.evidence / 'acceptance')
        if output('git', 'ls-remote', 'origin', 'refs/heads/main').split()[0] != sha:
            raise RuntimeError('main advanced during acceptance; no promotion performed')
        # A private service must not regain public ingress during deployment.
        def private_ips():
            ips = json.loads(output('flyctl', 'ips', 'list', '-a', args.app, '--json'))
            if any(i.get('Type') in ('v4', 'v6', 'shared_v4') for i in ips):
                raise RuntimeError('production has public ingress; hold for operator review')
        private_ips()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        proxylog = (args.evidence / 'proxy.log').open('w')
        proxy = subprocess.Popen(['flyctl', 'proxy', f'{port}:80', args.app + '.flycast', '-a', args.app,
                                  '--bind-addr', '127.0.0.1'], stdout=proxylog, stderr=proxylog)
        try:
            url = f'http://127.0.0.1:{port}'
            for attempt in range(30):
                if proxy.poll() is not None:
                    raise RuntimeError('Fly proxy exited before readiness')
                try:
                    if request(url, '/health')[0] == 200:
                        break
                except OSError:
                    pass
                if attempt == 29:
                    raise RuntimeError('private Fly proxy did not become ready')
                time.sleep(1)
            env = {**os.environ, 'CC_NODE_URL': url}
            subprocess.run([sys.executable, 'ops/deploy_digest.py', '--app', args.app,
                            '--config', args.config, '--sha', sha, '--image', args.image,
                            '--evidence', str(args.evidence / 'production')], env=env, check=True)
            private_ips()
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill(); proxy.wait()
            proxylog.close()
    print('Owner release verified:', sha)


if __name__ == '__main__':
    main()
