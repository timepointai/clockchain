#!/usr/bin/env python3
"""Promote one immutable image; preserve additive DB changes on rollback.

The owner release wrapper owns exact-main checks and its local concurrency lock.
Failure never resumes publication. No source build occurs in this command.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time

from acceptance_seed import seed
from deployed_checks import check, request
from backup_fly import capture, wake
from verify_fly_machines import digest, group, verify


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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--app', required=True)
    p.add_argument('--image', required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--config', default='fly.toml')
    p.add_argument('--acceptance', action='store_true')
    p.add_argument('--evidence', type=Path, required=True)
    args = p.parse_args()
    if not re.fullmatch(r'[0-9a-f]{40}', args.sha):
        p.error('full source SHA required')
    if not re.fullmatch(r'registry\.fly\.io/[a-z0-9-]+@sha256:[0-9a-f]{64}', args.image):
        p.error('immutable Fly registry image required')
    if args.acceptance and args.app == 'timepoint-clockchain-prod':
        p.error('acceptance cannot target production')
    args.evidence.mkdir(parents=True, exist_ok=True)
    if any(args.evidence.iterdir()):
        p.error('evidence directory must be empty; use a fresh path for each attempt')
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
                os.environ['CC_BACKUP_USER'], args.evidence / 'backup')
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
        if not args.acceptance and not was_paused:
            fly('ssh', 'console', '--app', args.app, '-C', 'cc-publisher resume --reason deployment-accepted')
        (args.evidence / 'acceptance.json').write_text(json.dumps(result, indent=2))
    except Exception:
        (args.evidence / 'FAILED').write_text('Promotion failed. See recovery.json for recovery and publication state.\n')
        recovery = recover(args, before, rollback)
        (args.evidence / 'recovery.json').write_text(json.dumps(recovery, indent=2))
        raise


if __name__ == '__main__':
    main()
