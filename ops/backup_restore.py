#!/usr/bin/env python3
"""Back up DB + media, restore to an already-created ISOLATED empty PG18 DB.

Connection parameters use CC_SOURCE_PG* / CC_RESTORE_PG* environment variables
(e.g. PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE), never secret argv.
The media input must be a local copy of the production media volume. Stop media
publication while obtaining that copy and dumping. No source mutation occurs.

`--v1` backs up a v1 database instead (no media). Both sides are inspected for
the expected `CC_V1_*` identity; the isolated restore must keep every
append-only trigger, candidates must hash to their ids, and the commitment is
recomputed for an empty corpus or read from `--node-bin` re-serving the
restored copy. `--export` must then match it exactly.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
from urllib.parse import quote

from v1_backup import compare_export, inspect_v1, prove_guards, verify_contents
from v1_identity import Expected


def connection(prefix):
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    for key in ('PGHOST', 'PGPORT', 'PGUSER', 'PGPASSWORD', 'PGDATABASE', 'PGSSLMODE', 'PGPASSFILE'):
        if prefix + key in os.environ:
            env[key] = os.environ[prefix + key]
    for key in ('PGHOST', 'PGUSER', 'PGDATABASE'):
        if not env.get(key):
            raise ValueError(prefix + key + ' required')
    return env


def sql(env, query):
    return subprocess.check_output(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', query],
                                   env=env, text=True, stderr=subprocess.DEVNULL).strip()


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def verify_objects(rows, directory):
    checked = {}
    for digest, size in rows:
        if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid image digest in catalog')
        path = directory / (digest + '.png')
        if path.is_symlink() or not path.is_file() or path.stat().st_size != int(size) or sha(path) != digest:
            raise ValueError('missing/corrupt media object: ' + digest)
        checked[digest] = int(size)
    return checked


def attempt(env, query):
    return subprocess.run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-c', query], env=env,
                          capture_output=True, text=True)


def database_url(env):
    user = quote(env['PGUSER'], safe='')
    password = ':' + quote(env['PGPASSWORD'], safe='') if env.get('PGPASSWORD') else ''
    host = env['PGHOST']
    if host.startswith('/'):
        return f'postgres://{user}{password}@/{quote(env["PGDATABASE"], safe="")}?host={quote(host, safe="")}'
    port = ':' + env['PGPORT'] if env.get('PGPORT') else ''
    return f'postgres://{user}{password}@{host}{port}/{quote(env["PGDATABASE"], safe="")}'


def reserve(node_bin, restore, expected):
    """Serve the isolated restored copy with a local cc-node; return its export."""
    from v1_checks import http
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    key, read_key = secrets.token_hex(32), secrets.token_hex(32)
    env = {k: v for k, v in os.environ.items() if not k.startswith(('PG', 'CC_', 'DATABASE_URL'))}
    env.update({'DATABASE_URL': database_url(restore), 'CC_NODE_API_KEY': key,
                'CC_NODE_READ_KEY': read_key, 'CC_NODE_POSTURE': 'live', 'PORT': str(port),
                'CC_NODE_LEDGER': 'v1', 'CC_V1_INSTANCE': expected.instance,
                'CC_V1_CURATORS': ','.join(expected.curators),
                'CC_V1_MAX_HOPS': str(expected.max_hops)})
    provisioned = subprocess.run([str(node_bin), 'provision-v1'], env=env, capture_output=True, text=True)
    if provisioned.returncode:
        raise ValueError('restored copy failed the provision-v1 identity check')
    from v1_acceptance import check_provision
    check_provision(json.loads(provisioned.stdout), expected)
    node = subprocess.Popen([str(node_bin), 'serve'], env=env, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        url = f'http://127.0.0.1:{port}'
        for _ in range(60):
            try:
                if http(url, 'GET', '/health')[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.5)
        code, raw = http(url, 'GET', '/v1/export', key)
        if code != 200:
            raise ValueError('restored copy cannot export')
        return json.loads(raw)
    finally:
        node.terminate()
        node.wait(timeout=10)


def main_v1(args, source, restore):
    expected = Expected.from_env()
    source_state = inspect_v1(lambda q: sql(source, q), expected)
    args.output.mkdir(mode=0o700, parents=True)
    dump = args.output / 'database.dump'
    subprocess.run(['pg_dump', '--format=custom', '--no-owner', '--no-privileges', '--file', str(dump)],
                   env=source, check=True, stderr=subprocess.DEVNULL)
    subprocess.run(['pg_restore', '--exit-on-error', '--no-owner', '--no-privileges',
                    '--dbname', restore['PGDATABASE'], str(dump)], env=restore, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    state = inspect_v1(lambda q: sql(restore, q), expected)
    if state != source_state:
        raise ValueError('restored v1 copy differs from the source')
    if state['state'] == 'uninitialized':
        raise ValueError('source holds no v1 store; nothing to verify')
    # Guards are exercised on the isolated restored copy, never on the source.
    guards = prove_guards(lambda q: attempt(restore, q))
    contents = verify_contents(lambda q: sql(restore, q))
    if args.node_bin:
        reserved = reserve(args.node_bin, restore, expected)
        compare_export(reserved, contents, expected, reserved['commitment'])
        commitment, basis = reserved['commitment'], 'node_reserved_restored_copy'
        if not contents['events'] and commitment != expected.empty_commitment:
            raise ValueError('empty restored copy does not commit to the recomputed empty view')
    elif not contents['events']:
        commitment, basis = expected.empty_commitment, 'recomputed_empty_corpus'
    else:
        raise ValueError('a populated v1 backup needs --node-bin to verify its commitment')
    if args.export:
        compare_export(json.loads(args.export.read_text()), contents, expected, commitment)
    report = {'schema': 'cc.backup-restore-v1.v1', 'dump_sha256': sha(dump), 'state': state['state'],
              'counts': state['counts'], 'guards': guards, 'corpus_digest': contents['corpus_digest'],
              'events': contents['events'], 'commitment': commitment, 'commitment_basis': basis,
              'production_export_matched': bool(args.export), 'restore_verified': True,
              'expected': expected.summary()}
    (args.output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'restore_verified': True, 'state': state['state'], 'counts': state['counts'],
                      'commitment': commitment}))
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--media', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--v1', action='store_true', help='back up a v1 database (no media)')
    p.add_argument('--export', type=Path, help='v1: production /v1/export JSON that must match')
    p.add_argument('--node-bin', type=Path, help='v1: cc-node binary to re-serve the restored copy')
    args = p.parse_args()
    if args.v1 == bool(args.media):
        p.error('exactly one of --media (v0) or --v1 is required')
    source, restore = connection('CC_SOURCE_'), connection('CC_RESTORE_')
    identity = lambda env: tuple(env.get(k, '') for k in ('PGHOST', 'PGPORT', 'PGDATABASE'))
    if identity(source) == identity(restore):
        p.error('restore destination must differ from source')
    if args.output.exists():
        p.error('output already exists')
    for env in (source, restore):
        if int(sql(env, 'SHOW server_version_num')) // 10000 != 18:
            p.error('source and restore must be Postgres 18')
    for tool in ('pg_dump', 'pg_restore'):
        version = subprocess.check_output([tool, '--version'], text=True)
        if ' 18.' not in version:
            p.error(tool + ' must be version 18')
    if sql(restore, "SELECT count(*) FROM information_schema.tables WHERE table_schema NOT IN "
                    "('pg_catalog','information_schema')") != '0':
        p.error('restore database must be empty; nothing is dropped automatically')
    if args.v1:
        return main_v1(args, source, restore)
    args.output.mkdir(mode=0o700, parents=True)
    dump = args.output / 'database.dump'
    subprocess.run(['pg_dump', '--format=custom', '--no-owner', '--no-privileges', '--file', str(dump)],
                   env=source, check=True, stderr=subprocess.DEVNULL)
    subprocess.run(['pg_restore', '--exit-on-error', '--no-owner', '--no-privileges',
                    '--dbname', restore['PGDATABASE'], str(dump)], env=restore, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = [line.split('|') for line in sql(restore,
        "SELECT image_sha256, (manifest::jsonb->>'byte_count') FROM image_attachments ORDER BY image_sha256").splitlines()]
    objects = verify_objects(rows, args.media)
    media = args.output / 'objects'
    media.mkdir(mode=0o700)
    for digest in objects:
        shutil.copyfile(args.media / (digest + '.png'), media / (digest + '.png'))
    verify_objects(rows, media)
    # Check the guards on isolated restored rows, never against production.
    events = int(sql(restore, 'SELECT count(*) FROM events'))
    if not events:
        raise ValueError('empty ledger cannot demonstrate append-only guard')
    for table in ('events', 'exhibits'):
        if not int(sql(restore, f'SELECT count(*) FROM {table}')):
            raise ValueError(f'no {table} rows to test restored guard')
        for command in (f'DELETE FROM {table}', f'UPDATE {table} SET ' +
                        ('payload=payload' if table == 'events' else 'byte_len=byte_len')):
            try:
                sql(restore, 'BEGIN; ' + command + '; ROLLBACK;')
            except subprocess.CalledProcessError:
                pass
            else:
                raise ValueError('restored guard permitted ' + command)
    report = {'schema': 'cc.backup-restore.v1', 'dump_sha256': sha(dump),
              'restored_events': events, 'objects': objects, 'restore_verified': True,
              'projection_replay_verified': False}
    (args.output / 'manifest.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'restore_verified': True, 'objects': len(objects), 'events': events}))


if __name__ == '__main__':
    main()
