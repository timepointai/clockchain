#!/usr/bin/env python3
"""Capture production DB/media and prove the exact artifacts restore in PG18.

Run with publication paused. DB machine must provide pg_dump 18. Retained files
are private release artifacts; only the checksum report is printed.

`--v1` captures a v1 database instead: no media, no publication pause (v1 has
none, and pausing would write to the archived v0 database). The source is first
inspected read-only; the restored copy must hold only `cc_v1`, the expected
instance and rule identity, intact append-only triggers, candidates that hash
to their ids, and an export commitment equal to production's.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import tarfile
import tempfile
import time
import uuid

from v1_backup import compare_export, inspect_v1, prove_guards, require_fresh, verify_contents
from v1_identity import Expected
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


def restore_verify(bundle, *, allow_zero=False):
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
        # Zero-event restores require an explicit release mode.
        # Other guarded tables may be legitimately empty — an acceptance chain
        # has no frozen corpus — so their guards are recorded as NOT RUN rather
        # than silently skipped or reported as proven.
        if not counts['events'] and not allow_zero:
            raise ValueError('restored ledger has no events; explicit zero-event release required')
        migrations = db("SELECT version || ':' || encode(checksum,'hex') FROM _sqlx_migrations WHERE success ORDER BY version")
        if not migrations or int(db('SELECT count(*) FROM _sqlx_migrations WHERE NOT success')):
            raise ValueError('restored migration history incomplete')
        truncate = subprocess.run(['docker','exec',name,'psql','-U','postgres','-d','restore',
            '-X','-v','ON_ERROR_STOP=1','-c','BEGIN; TRUNCATE events CASCADE; ROLLBACK;'],capture_output=True,text=True)
        if truncate.returncode == 0 or 'events is append-only' not in truncate.stderr:
            raise ValueError('restored event truncate guard missing')
        zero_counts = {}
        if not counts['events']:
            tables = db("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").splitlines()
            for table in tables:
                if not table.replace('_','').isalnum(): raise ValueError('unexpected table name')
                zero_counts[table] = int(db('SELECT count(*) FROM "' + table + '"'))
            allowed = {'_sqlx_migrations','event_digest','publication_control'}
            if any(n for table,n in zero_counts.items() if table not in allowed):
                raise ValueError('zero-event restore contains leftover projections or operational content')
            if db("SELECT n || ':' || encode(acc,'hex') FROM event_digest") != '0:'+'0'*64:
                raise ValueError('zero-event commitment mismatch')
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
                  'guards': guards, 'event_truncate_guard':'proven', 'zero_event_restore':not counts['events'],
                  'migration_checksums':migrations.splitlines(), 'zero_table_counts':zero_counts,
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


def ssh(target, command):
    return run('flyctl', 'ssh', 'console', '--app', target, '-C', 'sh -lc ' + shlex.quote(command))


def capture(app, db_app, database, user, bundle, *, allow_zero=False):
    bundle.mkdir(mode=0o700, parents=True)
    remote = '/tmp/cc-backup-' + uuid.uuid4().hex
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
    return restore_verify(bundle, allow_zero=allow_zero)


def remote_sql(db_app, database, user):
    """Read-only psql on the Fly database machine; the query travels base64-encoded.

    The session is read-only too, so even a mistaken query cannot write.
    """
    def sql(query):
        encoded = base64.b64encode(query.encode()).decode()
        return ssh(db_app, f'echo {encoded} | base64 -d | PGOPTIONS="-c default_transaction_read_only=on" '
                   'PGPASSWORD="$OPERATOR_PASSWORD" psql '
                   f'--host 127.0.0.1 --username {shlex.quote(user)} -X -At -v ON_ERROR_STOP=1 '
                   f'-f - {shlex.quote(database)}').strip()
    return sql


def serve_restored(image, network, database_url, expected):
    """Re-serve a restored v1 copy with the exact image; return its export.

    `provision-v1` against the copy is the identity check: on a bound store it
    only verifies. Credentials here are random and local to this run.
    """
    from v1_acceptance import check_provision, docker, envfile, provision, serve
    from v1_checks import http
    key, read_key = secrets.token_hex(32), secrets.token_hex(32)
    workdir = tempfile.TemporaryDirectory(prefix='cc-restore-v1-env-')
    env = envfile(workdir.name, 'node.env', {
        'DATABASE_URL': database_url, 'CC_NODE_API_KEY': key, 'CC_NODE_READ_KEY': read_key,
        'CC_NODE_POSTURE': 'live', 'PORT': '8080', 'CC_NODE_LEDGER': 'v1',
        'CC_V1_INSTANCE': expected.instance, 'CC_V1_CURATORS': ','.join(expected.curators),
        'CC_V1_MAX_HOPS': str(expected.max_hops)})
    owned = []
    try:
        check_provision(provision(image, network, env), expected)
        url = serve(image, network + '-node', network, env, owned)
        code, raw = http(url, 'GET', '/v1/export', key)
        if code != 200:
            raise ValueError('restored copy cannot export')
        return json.loads(raw)
    finally:
        for _, name in owned:
            docker('rm', '-f', '-v', name, check=False)
        workdir.cleanup()


def restore_verify_v1(bundle, expected, *, allow_uninitialized=False, export=None, image=None):
    """Restore `bundle/database.dump` into a throwaway PG18 and verify it as a v1 store."""
    name = 'cc-restore-v1-' + uuid.uuid4().hex[:12]
    def db(query):
        return run('docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore',
                   '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', query).strip()
    def attempt(query):
        return subprocess.run(['docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore',
                               '-X', '-v', 'ON_ERROR_STOP=1', '-c', query],
                              capture_output=True, text=True)
    network = False
    try:
        if image:
            run('docker', 'network', 'create', '--label', 'cc.acceptance=true', name)
            network = True
        run('docker', 'run', '-d', '--name', name, '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_DB=restore', *(('--network', name) if image else ()),
            '-v', str(bundle.resolve()) + ':/backup:ro', 'postgres:18')
        for _ in range(30):
            try:
                run('docker', 'exec', name, 'psql', '-U', 'postgres', '-d', 'restore', '-Atc',
                    'SELECT 1', stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError:
                time.sleep(1)
        run('docker', 'exec', name, 'pg_restore', '-U', 'postgres', '-d', 'restore',
            '--exit-on-error', '--no-owner', '--no-privileges', '/backup/database.dump')
        state = inspect_v1(db, expected)
        report = {'schema': 'cc.backup-restore-v1.v1', 'restore_verified': True, 'state': state['state'],
                  'counts': state['counts'], 'dump_sha256': file_sha(bundle / 'database.dump'),
                  'expected': expected.summary()}
        if state['state'] == 'uninitialized':
            if not allow_uninitialized:
                raise ValueError('restored v1 database is uninitialized; only a fresh release may back that up')
            report.update(guards='not_run_uninitialized', commitment=None,
                          commitment_basis='not_applicable_uninitialized')
        else:
            report['guards'] = prove_guards(attempt, db)
            contents = verify_contents(db)
            report.update(corpus_digest=contents['corpus_digest'], events=contents['events'])
            if image:
                restored = serve_restored(image, name, f'postgres://postgres@{name}:5432/restore',
                                          expected)
                compare_export(restored, contents, expected, restored['commitment'])
                commitment, basis = restored['commitment'], 'exact_image_reserved_restored_copy'
                if not contents['events'] and commitment != expected.empty_commitment:
                    raise ValueError('empty restored copy does not commit to the recomputed empty view')
            elif not contents['events']:
                commitment, basis = expected.empty_commitment, 'recomputed_empty_corpus'
            else:
                raise ValueError('a populated v1 backup needs the exact image to verify its commitment')
            if export is not None:
                compare_export(export, contents, expected, commitment)
                report['production_export_matched'] = True
            report.update(commitment=commitment, commitment_basis=basis)
        (bundle / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
        return report
    finally:
        subprocess.run(['docker', 'rm', '-f', '-v', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, check=False)
        if network:
            subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)


def capture_v1(db_app, database, user, bundle, expected, *, fresh=False, export=None, image=None):
    """Inspect, dump and restore-verify the v1 database. Never touches media or v0."""
    bundle.mkdir(mode=0o700, parents=True)
    remote = '/tmp/cc-backup-v1-' + uuid.uuid4().hex + '.dump'
    if ' 18.' not in ssh(db_app, 'pg_dump --version'):
        raise ValueError('remote pg_dump must be version 18')
    source = inspect_v1(remote_sql(db_app, database, user), expected)
    if fresh:
        require_fresh(source)
    try:
        ssh(db_app, 'PGPASSWORD="$OPERATOR_PASSWORD" pg_dump --host 127.0.0.1 '
            '--format=custom --no-owner --no-privileges --username ' + shlex.quote(user) +
            ' --file ' + shlex.quote(remote) + ' ' + shlex.quote(database))
        run('flyctl', 'ssh', 'sftp', 'get', '--app', db_app, remote, str(bundle / 'database.dump'))
    finally:
        try:
            ssh(db_app, 'rm -f ' + shlex.quote(remote))
        except subprocess.CalledProcessError:
            pass
    report = restore_verify_v1(bundle, expected, allow_uninitialized=fresh, export=export, image=image)
    if report['counts'] != source['counts'] or report['state'] != source['state']:
        raise ValueError('restored v1 backup differs from the inspected source')
    report['source'] = source
    (bundle / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--v1', action='store_true', help='back up the v1 database (CC_V1_* expected identity)')
    parser.add_argument('--image', help='exact deployed image digest; required for a populated v1 backup')
    parser.add_argument('--export', type=Path, help='production /v1/export JSON to match')
    args = parser.parse_args()
    if args.v1:
        report = capture_v1(os.environ['CC_BACKUP_DB_APP'], os.environ['CC_BACKUP_DATABASE'],
                            os.environ['CC_BACKUP_USER'], args.output,
                            Expected.from_env(production=True), image=args.image,
                            export=json.loads(args.export.read_text()) if args.export else None)
        print(json.dumps({'restore_verified': report['restore_verified'], 'state': report['state'],
                          'counts': report['counts'], 'commitment': report['commitment']}))
    else:
        report = capture('timepoint-clockchain-prod', os.environ['CC_BACKUP_DB_APP'],
                         os.environ['CC_BACKUP_DATABASE'], os.environ['CC_BACKUP_USER'], args.output)
        print(json.dumps({'restore_verified': report['restore_verified'], 'counts': report['counts']}))
