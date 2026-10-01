#!/usr/bin/env python3
"""Promote one immutable image; preserve additive DB changes on rollback.

The owner release wrapper owns exact-main checks and its local concurrency lock.
Failure never resumes publication. No source build occurs in this command.

`--v1-fresh` promotes onto a fresh v1 database instead. It checks the database
is empty or holds only the expected identity, backs it up, deploys the digest
(release command `cc-node provision-v1`), then only reads: machine census with
no tick, /health identity, /ready, the read-only `check_v1_zero` and a second
verified backup. It never pauses or resumes v0 publication, never touches a
tick, never writes an entry, and never rolls back automatically.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

from acceptance_seed import seed
from deployed_checks import check, check_empty, check_zero, request
from backup_fly import capture, capture_v1, wake
from v1_checks import check_v1_zero, http
from v1_identity import PRODUCTION_MAX_HOPS, Expected
from verify_fly_machines import digest, group, verify, verify_v1

V1_RELEASE_COMMAND = 'cc-node provision-v1'


def fly(*args):
    return subprocess.check_output(['flyctl', *args], text=True)


def machines(app):
    return json.loads(fly('machines', 'list', '--app', app, '--json'))


def deploy(app, config, image, *, rollback=False):
    # An older sqlx migrator refuses applied versions absent from its binary.
    # serve does not migrate. Preserve the schema and skip ONLY on recovery.
    extra = ('--skip-release-command',) if rollback else ()
    fly('deploy', '--app', app, '--config', config, '--ha=false', '--no-public-ips', '--image', image, *extra)


def machine_image(image, tag):
    """Keep the digest authoritative, adding the tag machine update requires."""
    name, pinned = image.split('@', 1)
    if ':' not in name.rsplit('/', 1)[-1]:
        name += ':' + tag
    return name + '@' + pinned


def previous_image(machine):
    name = machine['config']['image'].split('@', 1)[0]
    image = name + '@' + digest(machine)
    tag = machine.get('image_ref', {}).get('tag')
    return machine_image(image, tag) if tag else image


def recover(args, before, rollback):
    """Attempt every recovery step; never let a failed pause prevent rollback.

    This supports backward-compatible additive migrations, not destructive
    schema changes. It never restores a database or resumes publication.
    """
    evidence = {'status': 'NOT RUN', 'steps': {}, 'release_command': 'SKIPPED'}
    if not rollback['image']:
        evidence['reason'] = 'acceptance bootstrap has no previous image'
        return evidence

    def attempt(name, action):
        try:
            action()
            evidence['steps'][name] = 'PASS'
        except Exception as error:
            # Subprocess output/arguments may include credentials; keep them out.
            evidence['steps'][name] = 'FAIL: ' + type(error).__name__

    def pause():
        fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher pause --reason deployment-failed')

    if not args.acceptance:
        attempt('pause_before', pause)
    attempt('app', lambda: deploy(args.app, args.config, rollback['image'], rollback=True))
    if not args.acceptance:
        attempt('tick', lambda: fly('machine', 'update', group(before, 'tick')['id'],
                '--app', args.app, '--image', rollback['previous_tick_image'], '--yes', '--skip-start'))
        attempt('pause_after', pause)

    def verify_recovery():
        for retry in range(12):
            try:
                if args.acceptance:
                    wake(args.app)
                after = machines(args.app)
                app = group(after, 'app')
                assert app['state'] == 'started' and digest(app) == digest(group(before, 'app'))
                if not args.acceptance:
                    verify(after)
                    assert digest(group(after, 'tick')) == digest(group(before, 'tick'))
                    status = json.loads(fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher status'))
                    assert status['paused'] is True
                url = os.environ['CC_NODE_URL'].rstrip('/')
                code, raw = request(url, '/health')
                assert code == 200 and json.loads(raw)['build'] == rollback['previous_build']
                code, _ = request(url, '/health/deep', os.environ['CC_NODE_READ_KEY'])
                assert code == 200, 'restored app cannot read the retained schema'
                return
            except (AssertionError, ValueError, OSError, subprocess.CalledProcessError):
                if retry == 11:
                    raise
                time.sleep(5)

    attempt('verify', verify_recovery)
    evidence['status'] = 'PASS' if all(v == 'PASS' for v in evidence['steps'].values()) else 'FAIL'
    return evidence


def check_config(path, v1):
    """The Fly config must match the release mode before anything is deployed."""
    with open(path, 'rb') as f:
        config = tomllib.load(f)
    env = config.get('env', {})
    command = config.get('deploy', {}).get('release_command')
    checks = [c.get('path') for c in config.get('http_service', {}).get('checks', [])]
    if v1:
        if env.get('CC_NODE_LEDGER') != 'v1' or command != V1_RELEASE_COMMAND:
            raise ValueError(f'v1 release needs CC_NODE_LEDGER=v1 and release_command "{V1_RELEASE_COMMAND}"')
        if '/health' not in checks:
            raise ValueError('v1 release needs an HTTP health check on /health')
        if env.get('CC_V1_MAX_HOPS') != str(PRODUCTION_MAX_HOPS):
            raise ValueError(f'v1 release config must pin CC_V1_MAX_HOPS = "{PRODUCTION_MAX_HOPS}"')
    elif env.get('CC_NODE_LEDGER') == 'v1' or command == V1_RELEASE_COMMAND:
        raise ValueError('a v0 release mode cannot deploy a v1 configuration')
    return config


def promote_v1(args):
    """Fresh v1 promotion. Checks and the owner-approved deploy only; no entry."""
    expected = Expected.from_env(production=True)
    check_config(args.config, True)
    url = os.environ['CC_NODE_URL'].rstrip('/')
    key, read_key = os.environ['CC_NODE_API_KEY'], os.environ['CC_NODE_READ_KEY']
    if not key or not read_key or key == read_key:
        # Checked before production is touched, not first by the post-deploy checks.
        raise ValueError('Distinct full and read-only credentials required')
    database = (os.environ['CC_BACKUP_DB_APP'], os.environ['CC_BACKUP_DATABASE'],
                os.environ['CC_BACKUP_USER'])
    (args.evidence / 'expected.json').write_text(json.dumps(expected.summary(), indent=2))
    before = machines(args.app)
    # The tick must already be gone: it writes v0 events.
    verify_v1(before)
    previous = previous_image(group(before, 'app'))
    (args.evidence / 'rollback.json').write_text(json.dumps(
        {'app': args.app, 'mode': 'v1-fresh', 'previous_image': previous, 'sha': args.sha,
         'automatic_rollback': False}, indent=2))
    try:
        # Empty, or only the expected identity with no evidence rows, else refuse.
        capture_v1(*database, args.evidence / 'backup-before', expected, fresh=True, image=args.image)
        deploy(args.app, args.config, args.image)
        fly('scale', 'count', '1', '--process-group', 'app', '--app', args.app, '--yes')
        expected_digest = args.image.split('@')[1]
        for attempt in range(12):
            try:
                fleet = verify_v1(machines(args.app), expected_digest)
                result = check_v1_zero(url, args.sha, key, read_key, expected)
                break
            except (AssertionError, ValueError, OSError):
                if attempt == 11:
                    raise
                time.sleep(5)
        code, raw = http(url, 'GET', '/v1/export', key)
        if code != 200:
            raise ValueError('production export unavailable after deploy')
        after = capture_v1(*database, args.evidence / 'backup-after', expected, fresh=True,
                           export=json.loads(raw), image=args.image)
        if after['state'] != 'bound' or after['commitment'] != result['commitment']:
            raise ValueError('post-deploy backup does not hold the bound empty store')
        result.update({'image': args.image, 'app': args.app, 'machines': fleet,
                       'backup_after': {k: after[k] for k in ('state', 'counts', 'commitment',
                                                             'commitment_basis', 'dump_sha256')},
                       'tick': 'none_running_or_scheduled', 'entry': 'left_to_owner'})
        (args.evidence / 'acceptance.json').write_text(json.dumps(result, indent=2))
        return result
    except Exception as error:
        (args.evidence / 'FAILED').write_text(
            'v1 promotion failed. No automatic rollback: see docs/FIRST-ENTRY.md abort points.\n')
        (args.evidence / 'recovery.json').write_text(json.dumps(
            {'status': 'NOT RUN', 'error': type(error).__name__, 'previous_image': previous,
             'reason': 'v1-fresh never redeploys v0 automatically; the owner decides'}, indent=2))
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--config', default='fly.toml')
    p.add_argument('--acceptance', action='store_true')
    modes=p.add_mutually_exclusive_group()
    modes.add_argument('--empty-corpus', action='store_true')
    modes.add_argument('--zero-events', action='store_true')
    modes.add_argument('--v1-fresh', action='store_true')
    p.add_argument('--evidence', type=Path, required=True)
    args = p.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.sha):
        p.error('full source SHA required')
    if not re.fullmatch(r'registry\.fly\.io/[a-z0-9-]+@sha256:[0-9a-f]{64}', args.image):
        p.error('immutable Fly registry image required')
    if args.acceptance and args.app == 'timepoint-clockchain-prod':
        p.error('acceptance cannot target production')
    if args.v1_fresh and args.acceptance:
        p.error('v1 acceptance runs locally in Docker; --v1-fresh is production only')
    args.evidence.mkdir(parents=True, exist_ok=True)
    if any(args.evidence.iterdir()):
        p.error('evidence directory must be empty; use a fresh path for each attempt')
    if args.v1_fresh:
        promote_v1(args)
        return
    check_config(args.config, False)
    # The initial rollout predates cc-publisher. Only that explicitly marked
    # bootstrap may omit the old binary; migration0014 starts publication paused.
    was_paused = True
    if not args.acceptance:
        try:
            control = json.loads(fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher status'))
            was_paused = control['paused']
            fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher pause --reason deployment')
        except (subprocess.CalledProcessError, ValueError, KeyError):
            if os.environ.get('CC_PUBLICATION_BOOTSTRAP') != '1':
                raise
    if not args.acceptance:
        capture(args.app, os.environ['CC_BACKUP_DB_APP'], os.environ['CC_BACKUP_DATABASE'],
                os.environ['CC_BACKUP_USER'], args.evidence / 'backup', allow_zero=args.zero_events)
    before = machines(args.app)
    # A freshly created acceptance app has no machines, so there is no previous
    # release to name and nothing to roll back to. Only the acceptance lane may
    # bootstrap: production always has a running release to return to, and an
    # empty production machine list means something is wrong, not new.
    bootstrap = args.acceptance and not before
    previous = None if bootstrap else group(before, 'app')
    old_image = None if bootstrap else previous_image(previous)
    previous_build = None
    if previous:
        if args.acceptance:
            wake(args.app)
        code, raw = request(os.environ['CC_NODE_URL'].rstrip('/'), '/health')
        if code != 200:
            raise ValueError('cannot record previous build for rollback verification')
        previous_build = json.loads(raw)['build']
    if not args.acceptance:
        verify(before)
    # Machine metadata can contain environment secrets: retain only needed fields.
    rollback = {'app': args.app, 'image': old_image, 'sha': args.sha,
                'bootstrap': bootstrap, 'previous_build': previous_build,
                'previous_tick_image': None if args.acceptance else previous_image(group(before, 'tick'))}
    (args.evidence / 'rollback.json').write_text(json.dumps(rollback, indent=2))
    try:
        deploy(args.app, args.config, args.image)
        fly('scale', 'count', '1', '--process-group', 'app', '--app', args.app, '--yes')
        if not args.acceptance:
            tick = group(before, 'tick')
            fly('machine', 'update', tick['id'], '--app', args.app,
                '--image', machine_image(args.image, 'git-' + args.sha), '--yes', '--skip-start')
        expected = args.image.split('@')[1]
        for attempt in range(12):
            try:
                if args.acceptance:
                    # Acceptance scales to zero, so an idle machine is stopped
                    # rather than broken. Start it before asserting on it; the
                    # checks that follow need it awake regardless.
                    wake(args.app)
                after = machines(args.app)
                if args.acceptance:
                    app = group(after, 'app')
                    assert app['state'] == 'started' and digest(app) == expected
                else:
                    verify(after, expected)
                url = os.environ['CC_NODE_URL'].rstrip('/')
                # Acceptance replays its own synthetic creation. Production
                # names a real approved entity and mints nothing.
                if args.zero_events:
                    result = check_zero(url, args.sha, os.environ['CC_NODE_API_KEY'], os.environ['CC_NODE_READ_KEY'])
                elif args.empty_corpus:
                    result = check_empty(url, args.sha, os.environ['CC_NODE_API_KEY'], os.environ['CC_NODE_READ_KEY'])
                else:
                    entity = (seed(args.app, url, os.environ['CC_NODE_API_KEY'])
                              if args.acceptance else os.environ['CC_SMOKE_ENTITY'])
                    result = check(url, args.sha, entity, os.environ['CC_NODE_API_KEY'],
                                   os.environ['CC_NODE_READ_KEY'])
                break
            except (AssertionError, ValueError, OSError):
                if attempt == 11:
                    raise
                time.sleep(5)
        result['publication_was_paused'] = was_paused
        result['image'] = args.image
        result['app'] = args.app
        if not args.acceptance and not (args.empty_corpus or args.zero_events) and not was_paused:
            fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher resume --reason deployment-accepted')
        (args.evidence / 'acceptance.json').write_text(json.dumps(result, indent=2))
    except Exception:
        (args.evidence / 'FAILED').write_text('Promotion failed. See recovery.json for recovery and publication state.\n')
        recovery = recover(args, before, rollback)
        (args.evidence / 'recovery.json').write_text(json.dumps(recovery, indent=2))
        raise


if __name__ == '__main__':
    main()
