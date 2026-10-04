#!/usr/bin/env python3
"""Owner-operated promotion of an already-built immutable image.

Public GitHub CI holds no production credentials and never deploys. The owner
runs this from a clean exact-main checkout with local Fly/GitHub authentication.

`--v1-fresh` releases the v1 ledger onto a fresh database. The expected
identity (`CC_V1_INSTANCE`, `CC_V1_CURATORS`, `CC_V1_MAX_HOPS`) comes from the
operator environment; acceptance runs the exact image against synthetic v1
data locally; production only receives the deploy and read-only checks.

`--v1-update` releases a new image over the bound, populated v1 store. The
expected identity is checked the same way; acceptance runs the W3 sequence on
the new image and then an update scenario (the current production image
populates a synthetic store, the new image takes it over, and every
commitment and the export must stay byte-identical). Production then gets the
identity-gated, backed-up, read-only-checked deploy in `deploy_digest.py`.
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
from deploy_digest import NODE_SEED, check_config, check_secret_names, previous_image
from v1_acceptance import accept_v1, accept_v1_update, pinned_image
from v1_identity import Expected
from verify_fly_machines import group


def output(*args):
    return subprocess.check_output(args, text=True).strip()


def mode_flag(args):
    for flag in ('v1_fresh', 'v1_update', 'empty_corpus', 'zero_events'):
        if getattr(args, flag, False):
            return ['--' + flag.replace('_', '-')]
    return []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='registry.fly.io/<app>@sha256:<digest>')
    parser.add_argument('--app', required=True)
    parser.add_argument('--config', default='fly.toml')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--zero-events', action='store_true', help='verify a completely empty uninitialized production ledger')
    modes.add_argument('--empty-corpus', action='store_true', help='verify genesis-only production without media fixtures')
    modes.add_argument('--v1-fresh', action='store_true', help='release v1 onto a fresh database; the entry stays with the owner')
    modes.add_argument('--v1-update', action='store_true',
                       help='release a new image over the bound, populated v1 store; never writes')
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
    required = ('CC_NODE_API_KEY', 'CC_NODE_READ_KEY',
                'CC_BACKUP_DB_APP', 'CC_BACKUP_DATABASE', 'CC_BACKUP_USER')
    v1 = args.v1_fresh or args.v1_update
    if not (args.empty_corpus or args.zero_events or v1):
        required += ('CC_SMOKE_ENTITY',)
    if any(not os.environ.get(name) for name in required):
        parser.error('operator environment needs: ' + ', '.join(required))
    if os.environ['CC_NODE_API_KEY'] == os.environ['CC_NODE_READ_KEY']:
        parser.error('distinct full and read-only credentials required')
    try:
        if v1:
            # Values stay in the environment; only their validity is checked here.
            Expected.from_env(production=True)
        check_config(args.config, v1)
    except ValueError as error:
        parser.error(str(error))
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
        (accept_v1 if v1 else accept)(args.image, sha, args.evidence / 'acceptance')
        if args.v1_update:
            # Read-only: the image production runs now, and whether the optional
            # node seed secret is set (names only), so acceptance mirrors both.
            machines = json.loads(output('flyctl', 'machines', 'list', '--app', args.app, '--json'))
            current = pinned_image(previous_image(group(machines, 'app')), args.app)
            accept_v1_update(current, args.image, sha, args.evidence / 'acceptance-update',
                             node_seed=NODE_SEED in check_secret_names(args.app))
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
                            '--evidence', str(args.evidence / 'production')] + mode_flag(args), env=env, check=True)
            private_ips()
        finally:
            proxy.terminate()
            try:
                proxy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proxy.kill(); proxy.wait()
            proxylog.close()
    print('Owner release verified:', sha)
    if args.v1_fresh:
        print('v1 store bound and empty. The inaugural entry remains the owner\'s step.')
    if args.v1_update:
        print('v1 store updated; identity, commitments and export unchanged.')


if __name__ == '__main__':
    main()
