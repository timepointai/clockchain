#!/usr/bin/env python3
"""Monitor the live v1 node from the owner's workstation (launchd, every 15 minutes).

Each run opens a short-lived localhost `flyctl proxy` (see `fly_proxy.py`),
reads `/health` and `/ready` with GET only, and compares the served identity
with the expected one (`CC_V1_INSTANCE`, `CC_V1_CURATORS`, `CC_V1_MAX_HOPS`
and the fold recomputed from this checkout). It needs no node credential.

Success is quiet: nothing is printed, only the status JSON is refreshed.
Identity drift, a non-200 `/ready` (503 `busy` is retried) or an unreachable
node writes an alert status, raises a macOS notification and exits 1.

    monitor_v1.py run --env-file PATH       one check (what launchd runs)
    monitor_v1.py generate --env-file PATH  print the LaunchAgent plist
    monitor_v1.py install --env-file PATH   install and load it
    monitor_v1.py remove                    unload and delete it

The env file (mode 0600, outside the checkout) holds CC_FLY_APP,
CC_OPS_STATE_DIR and the three CC_V1_* values.
"""
import argparse
import json
from pathlib import Path
import sys

from fly_proxy import FlyProxy, ProxyFailed
import owner_jobs
from v1_identity import Expected
from v1_update import IdentityDrift, NotReady, ReadOnlyNode, require_identity, require_ready

LABEL = owner_jobs.LABEL_PREFIX + 'monitor'
INTERVAL = 15 * 60
STATUS = 'monitor-status.json'
SCHEMA = 'cc.v1-monitor-status.v1'


def classify(error):
    if isinstance(error, IdentityDrift):
        return 'identity_drift'
    if isinstance(error, NotReady):
        return 'not_ready'
    if isinstance(error, (ProxyFailed, OSError)):
        return 'unreachable'
    if isinstance(error, owner_jobs.ConfigError):
        return 'configuration'
    return 'error'


def check(url, expected):
    node = ReadOnlyNode(url)
    status, raw = node.get('/health')
    if status != 200:
        raise NotReady(f'/health: HTTP {status}')
    try:
        health = json.loads(raw)
    except ValueError:
        raise IdentityDrift('/health is not JSON') from None
    identity = require_identity(health, expected)
    require_ready(node)
    return {'identity': 'match', 'filter_version': identity['filter_version'],
            'build': health.get('build'), 'ready': True}


def run(env_file, *, proxy=FlyProxy, notify=owner_jobs.notify, stderr=sys.stderr):
    env, state = {}, None
    started = owner_jobs.now()
    try:
        env = owner_jobs.load_env_file(env_file)
        app, state_dir = owner_jobs.require(env, 'CC_FLY_APP', 'CC_OPS_STATE_DIR')
        state = owner_jobs.private_dir(state_dir)
        expected = Expected.from_env(env, production=True)
        with owner_jobs.JobLock(state, 'monitor') as locked:
            if not locked:
                return 0  # the previous check is still running; it will report
            with proxy(app, state, 'monitor') as url:
                result = check(url, expected)
        owner_jobs.write_status(state / STATUS, {
            'schema': SCHEMA, 'result': 'ok', 'checked_at': started.isoformat(), **result})
        return 0
    except Exception as error:
        kind = classify(error)
        message = owner_jobs.redact(f'{type(error).__name__}: {error}', env)
        if state is not None:
            owner_jobs.write_status(state / STATUS, {
                'schema': SCHEMA, 'result': 'alert', 'kind': kind,
                'checked_at': started.isoformat(), 'error': message})
        notify('Clockchain monitor', f'{kind.replace("_", " ")}: see {STATUS}')
        print(f'monitor alert ({kind}): {message}', file=stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('run', 'generate', 'install', 'remove'))
    parser.add_argument('--env-file', type=Path)
    args = parser.parse_args(argv)
    if args.command == 'remove':
        owner_jobs.remove(LABEL)
        print('removed', LABEL)
        return 0
    if not args.env_file:
        parser.error('--env-file is required')
    if args.command == 'run':
        return run(args.env_file)
    env = owner_jobs.load_env_file(args.env_file)
    Expected.from_env(env, production=True)
    owner_jobs.require(env, 'CC_FLY_APP')
    state = owner_jobs.private_dir(owner_jobs.require(env, 'CC_OPS_STATE_DIR')[0])
    data = owner_jobs.plist(LABEL, __file__, args.env_file, state, interval=INTERVAL)
    if args.command == 'generate':
        sys.stdout.write(data.decode())
    else:
        print('installed', owner_jobs.install(LABEL, data))
    return 0


if __name__ == '__main__':
    sys.exit(main())
