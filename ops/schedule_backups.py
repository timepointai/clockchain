#!/usr/bin/env python3
"""Scheduled, restore-verified v1 backups from the owner's workstation (launchd).

    schedule_backups.py run --env-file PATH                 one backup (what launchd runs)
    schedule_backups.py generate --env-file PATH [--time HH:MM]   print the plist
    schedule_backups.py install --env-file PATH [--time HH:MM]    install and load it
    schedule_backups.py remove                              unload and delete it

The job runs daily at 09:00 local time unless `--time` says otherwise. Each run:

1. reads the deployed app machine's exact image digest (`flyctl machines list`);
2. opens a short-lived localhost `flyctl proxy` it alone owns and stops;
3. requires `/health` to name the expected identity and `/ready` to be 200,
   then reads `/v1/export` (GET only);
4. takes a `cc_v1` backup with `backup_fly.capture_v1`: a read-only source
   inspection, `pg_dump` on the database machine, and a restore into a
   throwaway local PostgreSQL 18 that the exact image re-serves; the restored
   commitment must equal production's export;
5. keeps the newest 30 verified backups in `CC_BACKUP_DIR` (and the newest 5
   failed attempts), deleting only directories this job named.

Every run rewrites `backup-status.json` in `CC_OPS_STATE_DIR`. A failure also
raises a macOS notification. Secret values (the node key, and any env-file
value in an error message) never reach argv, the plist, stdout or the status
file; the app, database and user names do appear in flyctl argv.

The env file (mode 0600, outside the checkout) holds CC_FLY_APP,
CC_BACKUP_DIR, CC_OPS_STATE_DIR, CC_BACKUP_DB_APP, CC_BACKUP_DATABASE,
CC_BACKUP_USER, CC_NODE_API_KEY (export is a full-key read) and the three
CC_V1_* values.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from backup_fly import capture_v1
from fly_proxy import FlyProxy
import owner_jobs
from v1_identity import Expected
from v1_update import NotReady, ReadOnlyNode, require_identity, require_ready
from verify_fly_machines import digest, group

LABEL = owner_jobs.LABEL_PREFIX + 'backup'
DEFAULT_TIME = '09:00'
KEEP, KEEP_FAILED = 30, 5
STATUS = 'backup-status.json'
SCHEMA = 'cc.v1-backup-status.v1'
BUNDLE = re.compile(r'cc_v1-\d{8}T\d{6}Z')
FAILED = re.compile(r'cc_v1-\d{8}T\d{6}Z\.failed')
REQUIRED = ('CC_FLY_APP', 'CC_BACKUP_DIR', 'CC_OPS_STATE_DIR', 'CC_BACKUP_DB_APP',
            'CC_BACKUP_DATABASE', 'CC_BACKUP_USER', 'CC_NODE_API_KEY')


def fly_json(*args):
    return json.loads(subprocess.check_output(['flyctl', *args], text=True))


def deployed_image(app, machines=None):
    """The exact digest the single app machine runs, as a pullable reference."""
    machines = fly_json('machines', 'list', '--app', app, '--json') if machines is None else machines
    image = f'registry.fly.io/{app}@{digest(group(machines, "app"))}'
    if not re.fullmatch(r'registry\.fly\.io/[a-z0-9-]+@sha256:[0-9a-f]{64}', image):
        raise ValueError('app machine does not run a pinned image digest')
    return image


def verified(bundle):
    try:
        manifest = json.loads((bundle / 'manifest.json').read_text())
    except (OSError, ValueError):
        return False
    return manifest.get('restore_verified') is True and manifest.get('production_export_matched') is True


def prune(directory, keep=KEEP, keep_failed=KEEP_FAILED):
    """Delete the oldest verified backups beyond `keep` and failed ones beyond `keep_failed`.

    Only directories whose names this job generates are considered; anything
    else in the directory is never touched.
    """
    entries = sorted(p for p in Path(directory).iterdir() if p.is_dir() and not p.is_symlink())
    good = [p for p in entries if BUNDLE.fullmatch(p.name) and verified(p)]
    failed = [p for p in entries if FAILED.fullmatch(p.name)]
    removed = good[:max(len(good) - keep, 0)] + failed[:max(len(failed) - keep_failed, 0)]
    for path in removed:
        shutil.rmtree(path)
    return {'kept': min(len(good), keep), 'removed': [p.name for p in removed]}


def backup(env, backup_dir, state, *, proxy=FlyProxy, capture=capture_v1, machines=None,
           auth=lambda: subprocess.run(['flyctl', 'auth', 'docker'], check=True,
                                       capture_output=True)):
    expected = Expected.from_env(env, production=True)
    app = env['CC_FLY_APP']
    image = deployed_image(app, machines)
    auth()
    with proxy(app, state, 'backup') as url:
        node = ReadOnlyNode(url)
        status, raw = node.get('/health')
        if status != 200:
            raise NotReady(f'/health: HTTP {status}')
        require_identity(json.loads(raw), expected)
        require_ready(node)
        status, export = node.get('/v1/export', env['CC_NODE_API_KEY'])
        if status != 200:
            raise ValueError(f'/v1/export: HTTP {status}')
    bundle = backup_dir / ('cc_v1-' + owner_jobs.stamp())
    try:
        report = capture(env['CC_BACKUP_DB_APP'], env['CC_BACKUP_DATABASE'], env['CC_BACKUP_USER'],
                         bundle, expected, export=json.loads(export), image=image)
        if report.get('state') != 'bound' or report.get('production_export_matched') is not True:
            raise ValueError('backup did not verify against the production export')
        fd = os.open(bundle / 'export.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(export)
    except BaseException:
        try:
            if bundle.exists():
                bundle.rename(bundle.with_name(bundle.name + '.failed'))
        except OSError:
            pass  # the original error matters more than the rename
        raise
    return bundle, report, image


def run(env_file, *, notify=owner_jobs.notify, stderr=sys.stderr, **kwargs):
    env, state = {}, None
    started = owner_jobs.now()
    try:
        env = owner_jobs.load_env_file(env_file)
        owner_jobs.require(env, *REQUIRED)
        state = owner_jobs.private_dir(env['CC_OPS_STATE_DIR'])
        backup_dir = owner_jobs.private_dir(env['CC_BACKUP_DIR'])
        with owner_jobs.JobLock(state, 'backup') as locked:
            if not locked:
                raise RuntimeError('another backup run holds the lock')
            bundle, report, image = backup(env, backup_dir, state, **kwargs)
            retention = prune(backup_dir)
        owner_jobs.write_status(state / STATUS, {
            'schema': SCHEMA, 'result': 'ok', 'started_at': started.isoformat(),
            'finished_at': owner_jobs.now().isoformat(), 'backup': bundle.name, 'image': image,
            'state': report['state'], 'counts': report['counts'],
            'corpus_digest': report.get('corpus_digest'), 'commitment': report['commitment'],
            'commitment_basis': report.get('commitment_basis'),
            'dump_sha256': report['dump_sha256'], 'restore_verified': True, **retention})
        return 0
    except Exception as error:
        message = owner_jobs.redact(f'{type(error).__name__}: {error}', env)
        if state is not None:
            owner_jobs.write_status(state / STATUS, {
                'schema': SCHEMA, 'result': 'failed', 'started_at': started.isoformat(),
                'finished_at': owner_jobs.now().isoformat(), 'error': message})
        notify('Clockchain backup', f'backup failed: see {STATUS}')
        print('backup failed: ' + message, file=stderr)
        return 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('run', 'generate', 'install', 'remove'))
    parser.add_argument('--env-file', type=Path)
    parser.add_argument('--time', default=DEFAULT_TIME, help='daily local time, HH:MM (default 09:00)')
    args = parser.parse_args(argv)
    if args.command == 'remove':
        owner_jobs.remove(LABEL)
        print('removed', LABEL)
        return 0
    if not args.env_file:
        parser.error('--env-file is required')
    if args.command == 'run':
        return run(args.env_file)
    try:
        when = owner_jobs.parse_time(args.time)
    except ValueError as error:
        parser.error(str(error))
    env = owner_jobs.load_env_file(args.env_file)
    owner_jobs.require(env, *REQUIRED)
    Expected.from_env(env, production=True)
    owner_jobs.private_dir(env['CC_BACKUP_DIR'])
    state = owner_jobs.private_dir(env['CC_OPS_STATE_DIR'])
    data = owner_jobs.plist(LABEL, __file__, args.env_file, state, calendar=when)
    if args.command == 'generate':
        sys.stdout.write(data.decode())
    else:
        print('installed', owner_jobs.install(LABEL, data))
    return 0


if __name__ == '__main__':
    sys.exit(main())
