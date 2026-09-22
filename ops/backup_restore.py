#!/usr/bin/env python3
"""Back up DB + media, restore to an already-created ISOLATED empty PG18 DB.

Connection parameters use CC_SOURCE_PG* / CC_RESTORE_PG* environment variables
(e.g. PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE), never secret argv.
The media input must be a local copy of the production media volume. Stop media
publication while obtaining that copy and dumping. No source mutation occurs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--media', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
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
    if sql(restore, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'") != '0':
        p.error('restore database must be empty; nothing is dropped automatically')
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
