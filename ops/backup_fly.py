#!/usr/bin/env python3
"""Capture production DB/media and prove the exact artifacts restore in PG18.

Run with publication paused. DB machine must provide pg_dump 18. Retained files
are private release artifacts; only the checksum report is printed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tarfile
import time
import uuid

from verify_fly_machines import group


def run(*args, **kwargs):
    return subprocess.check_output(list(args), text=True, **kwargs)


def file_sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_archive(archive, rows):
    expected = dict(rows)
    checked = {}
    with tarfile.open(archive) as tar:
        for member in tar:
            name = member.name.removeprefix('./')
            if not name.endswith('.png'):
                continue
            digest = name[:-4]
            if digest not in expected:
                continue
            if not member.isfile() or member.size != int(expected[digest]):
                raise ValueError('media archive contains invalid object ' + digest)
            stream = tar.extractfile(member)
            if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                raise ValueError('corrupt archived PNG ' + digest)
            checked[digest] = member.size
    if set(checked) != set(expected):
        raise ValueError('media archive is missing restored catalog objects')
    return checked


def restore_verify(bundle):
    name = 'cc-restore-' + uuid.uuid4().hex[:12]
    def db(query):
        return run('docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore',
                   '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', query).strip()
    try:
        run('docker', 'run', '-d', '--name', name, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_DB=restore', '-v', str(bundle.resolve()) + ':/backup:ro', 'postgres:18')
        for _ in range(30):
            try:
                run('docker', 'exec', name, 'pg_isready', '-U', 'postgres', stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
        run('docker', 'exec', name, 'pg_restore', '-U', 'postgres', '-d', 'restore',
            '--exit-on-error', '--no-owner', '--no-privileges', '/backup/database.dump')
        rows = [line.split('|') for line in db(
            "SELECT image_sha256, manifest::jsonb->>'byte_count' FROM image_attachments").splitlines()]
        objects = verify_archive(bundle / 'media.tar', rows)
        counts = {table: int(db('SELECT count(*) FROM ' + table))
                  for table in ('events', 'exhibits', 'image_attachments')}
        # A restored ledger with no events is not a restore worth claiming.
        # Other guarded tables may be legitimately empty — an acceptance chain
        # has no frozen corpus — so their guards are recorded as NOT RUN rather
        # than silently skipped or reported as proven.
        if not counts['events']:
            raise ValueError('restored ledger has no events')
        guards = {}
        for table, expected_error, assignment in [('events', 'events is append-only', 'payload=payload'),
                                                  ('exhibits', 'exhibits are immutable', 'byte_len=byte_len')]:
            if not counts[table]:
                guards[table] = 'not_run_no_rows'
                continue
            for query in ('DELETE FROM ' + table, 'UPDATE ' + table + ' SET ' + assignment):
                result = subprocess.run(['docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore',
                    '-X', '-v', 'ON_ERROR_STOP=1', '-c', 'BEGIN; ' + query + '; ROLLBACK;'],
                    capture_output=True, text=True)
                if result.returncode == 0 or expected_error not in result.stderr:
                    raise ValueError('restored guard did not produce expected refusal: ' + table)
            guards[table] = 'proven'
        report = {'schema': 'cc.backup-restore.v1', 'restore_verified': True, 'counts': counts,
                  'guards': guards,
                  'objects': objects, 'dump_sha256': file_sha(bundle / 'database.dump'),
                  'media_sha256': file_sha(bundle / 'media.tar'), 'projection_replay_verified': False}
        (bundle / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        return report
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)


def wake(app):
    """Wake the single app holding media; never start the scheduled tick."""
    def app_machine():
        machines = json.loads(run('flyctl', 'machines', 'list', '--app', app, '--json'))
        # Missing/duplicate app machines are a contract failure, not an empty
        # all() success. A stopped hourly tick is healthy between invocations.
        return group(machines, 'app')

    machine = app_machine()
    if machine.get('state') != 'started':
        run('flyctl', 'machine', 'start', machine['id'], '--app', app)
    for _ in range(30):
        if app_machine().get('state') == 'started':
            return
        time.sleep(2)
    raise ValueError('app machine did not start for backup: ' + app)


def capture(app, db_app, database, user, bundle):
    bundle.mkdir(mode=0o700, parents=True)
    remote = '/tmp/cc-backup-' + uuid.uuid4().hex
    def ssh(target, command):
        return run('flyctl', 'ssh', 'console', '--app', target, '-C', 'sh -lc ' + shlex.quote(command))
    try:
        version = ssh(db_app, 'pg_dump --version')
        if ' 18.' not in version:
            raise ValueError('remote pg_dump must be version 18')
        # postgres-flex publishes no local unix socket, so the default
        # connection fails on every Fly cluster. Connect over TCP with the
        # operator password the machine already holds; it never crosses the
        # wire to us and never lands in argv.
        ssh(db_app, 'PGPASSWORD="$OPERATOR_PASSWORD" pg_dump --host 127.0.0.1 '
            '--format=custom --no-owner --no-privileges --username ' +
            shlex.quote(user) + ' --file ' + shlex.quote(remote + '.dump') + ' ' + shlex.quote(database))
        run('flyctl', 'ssh', 'sftp', 'get', '--app', db_app, remote + '.dump', str(bundle / 'database.dump'))
        wake(app)
        ssh(app, 'tar -C /data/media/objects -cf ' + shlex.quote(remote + '.tar') + ' .')
        run('flyctl', 'ssh', 'sftp', 'get', '--app', app, remote + '.tar', str(bundle / 'media.tar'))
    finally:
        for target, suffix in ((db_app, '.dump'), (app, '.tar')):
            try:
                ssh(target, 'rm -f ' + shlex.quote(remote + suffix))
            except subprocess.CalledProcessError:
                pass
    return restore_verify(bundle)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = capture('timepoint-clockchain-prod', os.environ['CC_BACKUP_DB_APP'],
                     os.environ['CC_BACKUP_DATABASE'], os.environ['CC_BACKUP_USER'], args.output)
    print(json.dumps({'restore_verified': report['restore_verified'], 'counts': report['counts']}))
