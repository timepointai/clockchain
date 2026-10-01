#!/usr/bin/env python3
"""Accept an immutable image against the v1 ledger in temporary Docker + PG18.

Everything is synthetic and local: a fresh curator key made by the image's own
`cc-publisher v1 keygen` in a temporary directory, a random instance, random
node credentials and a synthetic Genesis submitted only to the throwaway node
on its private Docker network. No Fly resource, production credential or
production data is used, and every container, network and directory created
here is removed on success or failure.

Sequence: empty database; `migrate` refused in v1 mode; `provision-v1`
(idempotent, wrong identity refused); serve; `check_v1_zero`; synthetic
Genesis + `submit`; `check_v1_populated`; `pg_dump -n cc_v1` restored into a
fresh empty database; `provision-v1` identity check; equal snapshot commitment
and byte-equal export from the restored node.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

from v1_checks import check_v1_populated, check_v1_zero, http, load_entry
from v1_backup import RELATIONS, prove_guards
from v1_identity import TABLES, Expected, hexbytes

PREFIX = 'cc-accept-v1-'
MIGRATE_REFUSED = 78
PG_IMAGE = 'postgres:18'
SYNTHETIC_BODY = (b'Synthetic acceptance subject. It names no historical claim and '
                  b'never leaves the temporary acceptance network.\n')
# Synthetic Genesis parameters: a valid TT kind, an acceptance-only namespace.
SYNTHETIC_KIND = 'invention-and-technology'
SYNTHETIC_NAMESPACE = 'cc.acceptance'
SYNTHETIC_TIME = '2000-01-01'


def docker(*args, check=True):
    """Run docker; return stdout. With check=False return the CompletedProcess."""
    result = subprocess.run(['docker', *map(str, args)], capture_output=True, text=True)
    if not check:
        return result
    if result.returncode:
        # Docker stderr can echo argv; it never contains env-file values.
        raise subprocess.CalledProcessError(result.returncode, ['docker', str(args[0])])
    return result.stdout.strip()


def envfile(directory, name, values):
    path = Path(directory) / name
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
    return path


def synthetic_node(app):
    """The only node a synthetic write may target: this run's own container."""
    if not re.fullmatch(re.escape(PREFIX) + r'[0-9a-f]{12}-(app|restored)', app):
        raise ValueError('synthetic writes only target a temporary acceptance node')
    return f'http://{app}:8080'


def single_key(text):
    keys = set(re.findall(r'\b[0-9a-f]{64}\b', text))
    if len(keys) != 1:
        raise ValueError('expected exactly one public key in publisher output')
    return keys.pop()


def wait_http(url, path='/health', attempts=90):
    for attempt in range(attempts):
        try:
            if http(url, 'GET', path)[0] == 200:
                return
        except OSError:
            pass
        if attempt == attempts - 1:
            raise RuntimeError('temporary node did not become ready')
        time.sleep(1)


def wait_pg(container, attempts=60):
    for attempt in range(attempts):
        if not docker('exec', container, 'pg_isready', '-U', 'postgres', check=False).returncode:
            # The image restarts once after initdb; require a real query.
            if not docker('exec', container, 'psql', '-U', 'postgres', '-Atc', 'SELECT 1',
                          check=False).returncode:
                return
        if attempt == attempts - 1:
            raise RuntimeError('temporary Postgres did not become ready')
        time.sleep(1)


def psql(container, database, query, check=True):
    return docker('exec', container, 'psql', '-U', 'postgres', '-d', database, '-X',
                  '-v', 'ON_ERROR_STOP=1', '-At', '-c', query, check=check)


def relation_count(container, database):
    return int(psql(container, database, RELATIONS))


def counts(container, database):
    return {t: int(psql(container, database, f'SELECT count(*) FROM cc_v1.{t}')) for t in TABLES}


def provision(image, network, env, *, expect_ok=True):
    result = docker('run', '--rm', '--platform', 'linux/amd64', '--network', network,
                    '--env-file', env, image, 'cc-node', 'provision-v1', check=False)
    if expect_ok:
        if result.returncode:
            raise RuntimeError('provision-v1 failed on the synthetic database')
        return json.loads(result.stdout)
    if result.returncode == 0:
        raise AssertionError('provision-v1 accepted a mismatched identity')
    return result.returncode


def check_provision(report, expected):
    """`provision-v1` must report exactly the expected identity, ready."""
    assert report.get('semantic') == 'ready', 'provision-v1 did not reach ready'
    assert hexbytes(report.get('instance')) == expected.instance, 'provisioned instance differs'
    assert hexbytes(report.get('filter_version')) == expected.filter_version, 'provisioned filter differs'
    fold = report.get('fold_version') or {}
    assert fold.get('version') == expected.fold['version'] and \
        hexbytes(fold.get('manifest')) == expected.fold['manifest'], 'provisioned fold differs'
    return report


def serve(image, name, network, env, owned):
    owned.append(('container', name))
    docker('run', '-d', '--platform', 'linux/amd64', '--name', name, '--label',
           'cc.acceptance=true', '--network', network, '-p', '127.0.0.1::8080',
           '--env-file', env, image)
    address = docker('port', name, '8080/tcp').splitlines()[0]
    if not address.startswith('127.0.0.1:'):
        raise RuntimeError('acceptance port must be loopback only')
    url = 'http://' + address
    wait_http(url)
    return url


def accept_v1(image, sha, evidence):
    if not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', image):
        raise ValueError('acceptance requires an immutable image digest')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('acceptance requires the full source SHA')
    evidence = Path(evidence)
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    ident = PREFIX + uuid.uuid4().hex[:12]
    db, app, restored = ident + '-db', ident + '-app', ident + '-restored'
    key, read_key, password, instance = [secrets.token_hex(32) for _ in range(4)]
    owned = []
    # Keys and Genesis files are mounted into publisher containers; node
    # credentials live in a separate directory that is never mounted.
    work = Path(tempfile.mkdtemp(prefix='cc-accept-v1-'))
    private = Path(tempfile.mkdtemp(prefix='cc-accept-v1-env-'))
    user = f'{os.getuid()}:{os.getgid()}'
    try:
        docker('pull', '--platform', 'linux/amd64', image)
        resolved = json.loads(docker('image', 'inspect', image))[0]
        if image not in resolved.get('RepoDigests', []):
            raise ValueError('pulled image digest differs from requested image')
        docker('network', 'create', '--label', 'cc.acceptance=true', ident)
        owned.append(('network', ident))

        # 1. Synthetic curator key, made by the image's own publisher.
        def publisher(*args, network='none', env=None):
            extra = ('--env-file', env) if env else ()
            return docker('run', '--rm', '--platform', 'linux/amd64', '--network', network,
                          '--user', user, '-v', f'{work}:/work', *extra, image,
                          'cc-publisher', 'v1', *args)
        curator = single_key(publisher('keygen', '--out', '/work/curator.seed'))
        if (work / 'curator.seed').stat().st_mode & 0o777 != 0o600:
            raise AssertionError('keygen did not write the seed with mode 0600')
        if single_key(publisher('pubkey', '--key', '/work/curator.seed')) != curator:
            raise AssertionError('pubkey disagrees with keygen')
        expected = Expected(instance, curator, '4')

        base = {'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'clockchain',
                'CC_NODE_API_KEY': key, 'CC_NODE_READ_KEY': read_key,
                'CC_NODE_POSTURE': 'live', 'PORT': '8080', 'CC_NODE_LEDGER': 'v1',
                'CC_V1_INSTANCE': instance, 'CC_V1_CURATORS': curator, 'CC_V1_MAX_HOPS': '4'}
        url_for = lambda database: f'postgres://postgres:{password}@{db}:5432/{database}'
        env = envfile(private, 'node.env', {**base, 'DATABASE_URL': url_for('clockchain')})
        restored_env = envfile(private, 'restored.env', {**base, 'DATABASE_URL': url_for('restored')})
        wrong_instance = envfile(private, 'wrong-instance.env', {
            **base, 'DATABASE_URL': url_for('restored'), 'CC_V1_INSTANCE': secrets.token_hex(32)})
        wrong_curators = envfile(private, 'wrong-curators.env', {
            **base, 'DATABASE_URL': url_for('restored'),
            'CC_V1_CURATORS': ','.join(sorted([curator, single_key(
                publisher('keygen', '--out', '/work/other.seed'))]))})
        submit_env = envfile(private, 'submit.env', {'CC_NODE_API_KEY': key})
        read_env = envfile(private, 'read.env', {'CC_NODE_READ_KEY': read_key})

        # 2. Empty PG18 database; v0 migration must refuse in v1 mode.
        owned.append(('container', db))
        docker('run', '-d', '--name', db, '--network', ident, '--label', 'cc.acceptance=true',
               '--env-file', env, PG_IMAGE)
        wait_pg(db)
        if relation_count(db, 'clockchain'):
            raise AssertionError('temporary database is not empty')
        refused = docker('run', '--rm', '--platform', 'linux/amd64', '--network', ident,
                         '--env-file', env, image, 'cc-node', 'migrate', check=False).returncode
        if refused != MIGRATE_REFUSED or relation_count(db, 'clockchain'):
            raise AssertionError('cc-node migrate must refuse with 78 in v1 mode and write nothing')

        # 3. Provision twice (idempotent), then serve.
        first = check_provision(provision(image, ident, env), expected)
        if provision(image, ident, env) != first:
            raise AssertionError('provision-v1 is not idempotent')
        (evidence / 'provision.json').write_text(json.dumps(first, indent=2) + '\n')
        url = serve(image, app, ident, env, owned)

        # 4. Zero check, including the candidate-route probes production skips.
        zero = check_v1_zero(url, sha, key, read_key, expected, probe_candidates=True)
        if any(counts(db, 'clockchain')[t] for t in ('bodies', 'candidates', 'rejections', 'receipts')):
            raise AssertionError('denial probes left rows in the store')
        (evidence / 'v1-zero.json').write_text(json.dumps(zero, indent=2) + '\n')

        # 5. Synthetic Genesis, signed offline and submitted to this run's node only.
        (work / 'body.txt').write_bytes(SYNTHETIC_BODY)
        node = synthetic_node(app)
        info = json.loads(publisher('node-info', '--node', node, network=ident))
        if not (info.get('fold_matches_build') is True and info.get('filter_version_consistent') is True
                and info.get('health', {}).get('instance') == instance
                and info.get('health', {}).get('filter_version') == expected.filter_version):
            raise AssertionError('node-info does not match the provisioned identity')
        publisher('genesis', '--key', '/work/curator.seed', '--instance', instance,
                  '--kind', SYNTHETIC_KIND, '--namespace', SYNTHETIC_NAMESPACE,
                  '--value', ident, '--body', '/work/body.txt', '--asserted-time', SYNTHETIC_TIME,
                  '--evidence', hashlib.sha256(b'synthetic acceptance evidence').hexdigest(),
                  '--out', '/work/genesis')
        entry = load_entry(work / 'genesis')
        if entry['body'] != SYNTHETIC_BODY or entry['author'] != curator:
            raise AssertionError('genesis output does not match its inputs')
        publisher('submit', '--node', node, '--dir', '/work/genesis', network=ident, env=submit_env)
        if not (work / 'genesis' / 'receipt.json').is_file():
            raise AssertionError('submit wrote no receipt')
        publisher('verify', '--node', node, '--subject', entry['subject'], '--dir',
                  '/work/genesis', network=ident, env=read_env)

        # 6. Populated check.
        populated = check_v1_populated(url, sha, key, read_key, expected, entry,
                                       probe_candidates=True)
        stored = counts(db, 'clockchain')
        if stored != {'bodies': 1, 'candidates': 1, 'identity': 1, 'receipts': 0,
                      'rejections': 0, 'rule_identity': 1}:
            raise AssertionError('unexpected stored rows after the synthetic Genesis')
        (evidence / 'v1-populated.json').write_text(json.dumps(populated, indent=2) + '\n')
        original_export = json.loads(http(url, 'GET', '/v1/export', key)[1])

        # 7. pg_dump -n cc_v1, restore into a fresh empty database, re-check.
        psql(db, 'postgres', 'CREATE DATABASE restored')
        if relation_count(db, 'restored'):
            raise AssertionError('restore target is not empty')
        docker('exec', db, 'pg_dump', '-U', 'postgres', '-n', 'cc_v1', '--format=custom',
               '--no-owner', '--no-privileges', '-f', '/tmp/cc_v1.dump', 'clockchain')
        dump_sha = docker('exec', db, 'sha256sum', '/tmp/cc_v1.dump').split()[0]
        docker('exec', db, 'pg_restore', '-U', 'postgres', '-d', 'restored', '--exit-on-error',
               '--no-owner', '--no-privileges', '/tmp/cc_v1.dump')
        if counts(db, 'restored') != stored:
            raise AssertionError('restored row counts differ')
        guards = prove_guards(lambda q: psql(db, 'restored', q, check=False))
        if check_provision(provision(image, ident, restored_env), expected) != first:
            raise AssertionError('restored identity differs from the original provision')
        refusals = {'wrong_instance': provision(image, ident, wrong_instance, expect_ok=False),
                    'wrong_curators': provision(image, ident, wrong_curators, expect_ok=False)}
        restored_url = serve(image, restored, ident, restored_env, owned)
        again = check_v1_populated(restored_url, sha, key, read_key, expected, entry)
        if (again['corpus_digest'], again['commitment']) != (populated['corpus_digest'],
                                                            populated['commitment']):
            raise AssertionError('restored snapshot commitment differs')
        restored_export = json.loads(http(restored_url, 'GET', '/v1/export', key)[1])
        if restored_export != original_export:
            raise AssertionError('restored export differs from the original export')
        restore = {'dump_sha256': dump_sha, 'counts': stored, 'guards': guards,
                   'identity': 'provision-v1 matched', 'mismatch_refusals': refusals,
                   'commitment': again['commitment'], 'export_equal': True}
        (evidence / 'v1-restore.json').write_text(json.dumps(restore, indent=2) + '\n')
        result = {'schema': 'cc.local-acceptance-v1.v1', 'image': image, 'sha': sha,
                  'result': 'pass', 'checks': zero['checks'] + populated['checks'] + again['checks'],
                  'empty_commitment': zero['commitment'], 'commitment': populated['commitment'],
                  'isolation': 'temporary Docker network/PG18, loopback HTTP',
                  'synthetic_fixture': True}
        (evidence / 'acceptance.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except BaseException as error:
        for container in (app, restored, db):
            logs = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
            (evidence / (container + '.log')).write_text(logs.stdout + logs.stderr)
        (evidence / 'FAILED').write_text(type(error).__name__ + '\n')
        raise
    finally:
        failures = []
        for kind, name in reversed(owned):
            command = ['docker', 'rm', '-f', '-v', name] if kind == 'container' else ['docker', kind, 'rm', name]
            if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                failures.append(name)
        for directory in (work, private):
            shutil.rmtree(directory, ignore_errors=True)
            if directory.exists():
                failures.append('temporary directory')
        (evidence / 'cleanup.json').write_text(json.dumps({'removed': not failures, 'remaining': failures}) + '\n')
        if failures:
            raise RuntimeError('temporary acceptance cleanup failed: ' + ', '.join(failures))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    result = accept_v1(args.image, args.sha, args.evidence)
    print(json.dumps({'result': result['result'], 'checks': len(result['checks'])}))
