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

`accept_v1_update` is the update scenario: the image production runs now
provisions and serves a synthetic store holding one synthetic Genesis; then
the new image's `provision-v1` must leave every row untouched (a no-op), a
mismatched identity must still be refused, and the new image must serve the
same identity, corpus digest, view commitment and byte-identical export.
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
from v1_backup import RELATIONS, fingerprint_v1, prove_guards
from v1_identity import TABLES, Expected, hexbytes
from v1_update import ReadOnlyNode, observe, require_identity, require_unchanged, summary

PREFIX = 'cc-accept-v1-'
MIGRATE_REFUSED = 78
# `provision-v1` exit status for a stored identity that differs from the configuration.
IDENTITY_MISMATCH = 65
PG_IMAGE = 'postgres:18'
SYNTHETIC_BODY = (b'Synthetic acceptance subject. It names no historical claim and '
                  b'never leaves the temporary acceptance network.\n')
# Synthetic Genesis parameters: a valid TT kind, an acceptance-only namespace.
SYNTHETIC_KIND = 'invention-and-technology'
SYNTHETIC_NAMESPACE = 'cc.acceptance'
SYNTHETIC_TIME = '2000-01-01'


def docker(*args, check=True, text=True):
    """Run docker; return stdout. With check=False return the CompletedProcess."""
    result = subprocess.run(['docker', *map(str, args)], capture_output=True, text=text)
    if not check:
        return result
    if result.returncode:
        # Name the step, not its arguments; stderr is kept for synthetic evidence.
        step = [str(a) for a in args if str(a) in ('cc-node', 'cc-publisher')][:1]
        tail = [str(args[-1])] if step else []
        raise subprocess.CalledProcessError(result.returncode, ['docker', str(args[0]), *step, *tail],
                                            stderr=result.stderr)
    return result.stdout.strip()


def envfile(directory, name, values):
    path = Path(directory) / name
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(''.join(f'{k}={v}\n' for k, v in values.items()))
    return path


def synthetic_node(app):
    """The only node a synthetic write may target: this run's own container."""
    if not re.fullmatch(re.escape(PREFIX) + r'[0-9a-f]{12}-(app|restored|previous)', app):
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


def provision(image, network, env, *, expect_ok=True, evidence=None):
    result = docker('run', '--rm', '--platform', 'linux/amd64', '--network', network,
                    '--env-file', env, image, 'cc-node', 'provision-v1', check=False, text=False)
    if evidence is not None:
        # The --rm container is already gone. Save each attempt before checking
        # its status or decoding stdout, including expected identity refusals.
        attempts = Path(evidence) / 'provision-attempts'
        attempts.mkdir(mode=0o700, exist_ok=True)
        attempt = Path(tempfile.mkdtemp(prefix=Path(env).stem + '-', dir=attempts))
        report = {'image': image, 'env_file': Path(env).name, 'returncode': result.returncode}
        for name, raw in [('stdout', result.stdout), ('stderr', result.stderr),
                          ('result.json', (json.dumps(report, indent=2) + '\n').encode())]:
            fd = os.open(attempt / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
    if expect_ok:
        if result.returncode:
            raise RuntimeError(f'provision-v1 failed on the synthetic database (exit {result.returncode})')
        return json.loads(result.stdout.decode('utf-8'))
    if result.returncode != IDENTITY_MISMATCH:
        raise AssertionError(f'provision-v1 must refuse a mismatched identity with {IDENTITY_MISMATCH}, '
                             f'not {result.returncode}')
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
        first = check_provision(provision(image, ident, env, evidence=evidence), expected)
        if provision(image, ident, env, evidence=evidence) != first:
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
        reported = info.get('health') or {}
        if not (info.get('fold_matches_build') is True and info.get('filter_version_consistent') is True
                and reported.get('instance') == instance
                and reported.get('filter_version') == expected.filter_version):
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
        guards = prove_guards(lambda q: psql(db, 'restored', q, check=False),
                              lambda q: psql(db, 'restored', q))
        if check_provision(provision(image, ident, restored_env, evidence=evidence), expected) != first:
            raise AssertionError('restored identity differs from the original provision')
        refusals = {'wrong_instance': provision(image, ident, wrong_instance, expect_ok=False,
                                                evidence=evidence),
                    'wrong_curators': provision(image, ident, wrong_curators, expect_ok=False,
                                                evidence=evidence)}
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
        detail = getattr(error, 'stderr', None) or ''
        # Everything in this run is synthetic, so the failing step's stderr is kept.
        (evidence / 'FAILED').write_text(type(error).__name__ + ': ' + str(error) + '\n'
                                         + detail[-4000:])
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
            # A pass result next to leftover resources is not a pass.
            with open(evidence / 'FAILED', 'a') as marker:
                marker.write('cleanup failed: ' + ', '.join(failures) + '\n')
            raise RuntimeError('temporary acceptance cleanup failed: ' + ', '.join(failures))



def pinned_image(image, app):
    """`registry.fly.io/<app>[:tag]@sha256:<hex>` as the tagless digest reference."""
    name, _, digest = image.partition('@')
    repo, _, tag = name.rpartition(':') if ':' in name.rsplit('/', 1)[-1] else (name, '', '')
    pinned = f'{repo}@{digest}'
    if not re.fullmatch(r'registry\.fly\.io/' + re.escape(app) + r'@sha256:[0-9a-f]{64}', pinned):
        raise ValueError('current production image is not a pinned digest of the target app')
    return pinned


def accept_v1_update(previous, image, sha, evidence, *, node_seed=False):
    """An image upgrade over a populated synthetic store keeps every commitment.

    `previous` (the image production runs now) provisions, serves and admits one
    synthetic Genesis; `image` then takes the same database over. Its
    `provision-v1` must be a no-op (every table's rows identical), it must
    still refuse a mismatched identity, and it must serve the same identity,
    corpus digest, view commitment and byte-identical export. With
    `node_seed`, the new node runs with a random synthetic CC_V1_NODE_SEED, as
    production would. Everything is local, synthetic and removed afterwards.
    """
    for ref in (previous, image):
        if not re.fullmatch(r'.+@sha256:[0-9a-f]{64}', ref):
            raise ValueError('update acceptance requires immutable image digests')
    if not re.fullmatch(r'[0-9a-f]{40}', sha):
        raise ValueError('acceptance requires the full source SHA')
    evidence = Path(evidence)
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    ident = PREFIX + uuid.uuid4().hex[:12]
    db, old, app = ident + '-db', ident + '-previous', ident + '-app'
    key, read_key, password, instance = [secrets.token_hex(32) for _ in range(4)]
    owned = []
    work = Path(tempfile.mkdtemp(prefix='cc-accept-v1-'))
    private = Path(tempfile.mkdtemp(prefix='cc-accept-v1-env-'))
    user = f'{os.getuid()}:{os.getgid()}'
    try:
        for ref in dict.fromkeys((previous, image)):
            docker('pull', '--platform', 'linux/amd64', ref)
            if ref not in json.loads(docker('image', 'inspect', ref))[0].get('RepoDigests', []):
                raise ValueError('pulled image digest differs from requested image')
        docker('network', 'create', '--label', 'cc.acceptance=true', ident)
        owned.append(('network', ident))

        def publisher(*args, network='none', env=None):
            extra = ('--env-file', env) if env else ()
            return docker('run', '--rm', '--platform', 'linux/amd64', '--network', network,
                          '--user', user, '-v', f'{work}:/work', *extra, image,
                          'cc-publisher', 'v1', *args)
        curator = single_key(publisher('keygen', '--out', '/work/curator.seed'))
        expected = Expected(instance, curator, '4')
        base = {'POSTGRES_PASSWORD': password, 'POSTGRES_DB': 'clockchain',
                'CC_NODE_API_KEY': key, 'CC_NODE_READ_KEY': read_key,
                'CC_NODE_POSTURE': 'live', 'PORT': '8080', 'CC_NODE_LEDGER': 'v1',
                'CC_V1_INSTANCE': instance, 'CC_V1_CURATORS': curator, 'CC_V1_MAX_HOPS': '4',
                'DATABASE_URL': f'postgres://postgres:{password}@{db}:5432/clockchain'}
        env = envfile(private, 'node.env', base)
        new_env = envfile(private, 'update.env', {
            **base, **({'CC_V1_NODE_SEED': secrets.token_hex(32)} if node_seed else {})})
        wrong_instance = envfile(private, 'wrong-instance.env', {
            **base, 'CC_V1_INSTANCE': secrets.token_hex(32)})
        submit_env = envfile(private, 'submit.env', {'CC_NODE_API_KEY': key})

        owned.append(('container', db))
        docker('run', '-d', '--name', db, '--network', ident, '--label', 'cc.acceptance=true',
               '--env-file', env, PG_IMAGE)
        wait_pg(db)
        if relation_count(db, 'clockchain'):
            raise AssertionError('temporary database is not empty')
        fingerprint = lambda: fingerprint_v1(lambda q: psql(db, 'clockchain', q))

        # 1. The current image provisions, serves and admits one synthetic Genesis.
        first = check_provision(provision(previous, ident, env, evidence=evidence), expected)
        old_url = serve(previous, old, ident, env, owned)
        (work / 'body.txt').write_bytes(SYNTHETIC_BODY)
        publisher('genesis', '--key', '/work/curator.seed', '--instance', instance,
                  '--kind', SYNTHETIC_KIND, '--namespace', SYNTHETIC_NAMESPACE,
                  '--value', ident, '--body', '/work/body.txt', '--asserted-time', SYNTHETIC_TIME,
                  '--evidence', hashlib.sha256(b'synthetic acceptance evidence').hexdigest(),
                  '--out', '/work/genesis')
        entry = load_entry(work / 'genesis')
        publisher('submit', '--node', synthetic_node(old), '--dir', '/work/genesis',
                  network=ident, env=submit_env)
        old_node = ReadOnlyNode(old_url)
        identity = require_identity(old_node.json('/health'), expected)
        before = observe(old_node, key, read_key)
        stored = counts(db, 'clockchain')
        if stored['candidates'] != 1:
            raise AssertionError('the synthetic Genesis was not admitted')
        rows = fingerprint()
        docker('rm', '-f', '-v', old)
        owned.remove(('container', old))

        # 2. The new image's release command is a no-op on the matching store.
        if check_provision(provision(image, ident, new_env, evidence=evidence), expected) != first:
            raise AssertionError('new image provisions a different identity')
        if fingerprint() != rows:
            raise AssertionError('new image provision-v1 wrote to a matching store')
        refused = provision(image, ident, wrong_instance, expect_ok=False, evidence=evidence)
        if fingerprint() != rows:
            raise AssertionError('refused provision-v1 wrote to the store')

        # 3. The new image serves the same identity, commitments and export bytes.
        url = serve(image, app, ident, new_env, owned)
        populated = check_v1_populated(url, sha, key, read_key, expected, entry)
        node = ReadOnlyNode(url)
        if require_identity(node.json('/health'), expected) != identity:
            raise AssertionError('identity changed across the upgrade')
        after = observe(node, key, read_key)
        unchanged = require_unchanged(before, after)
        if (populated['corpus_digest'], populated['commitment']) != (before['corpus_digest'],
                                                                    before['commitment']):
            raise AssertionError('populated check names another view')
        if fingerprint() != rows:
            raise AssertionError('serving the new image wrote to the store')
        result = {'schema': 'cc.local-acceptance-v1-update.v1', 'previous_image': previous,
                  'image': image, 'sha': sha, 'result': 'pass', 'counts': stored,
                  'provision_v1': 'no-op (store fingerprint identical)',
                  'mismatch_refusal': refused, 'unchanged': unchanged,
                  'before': summary(before), 'after': summary(after),
                  'checks': populated['checks'], 'node_seed': bool(node_seed),
                  'isolation': 'temporary Docker network/PG18, loopback HTTP',
                  'synthetic_fixture': True}
        (evidence / 'v1-update.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except BaseException as error:
        for container in (old, app, db):
            logs = subprocess.run(['docker', 'logs', container], capture_output=True, text=True)
            (evidence / (container + '.log')).write_text(logs.stdout + logs.stderr)
        detail = getattr(error, 'stderr', None) or ''
        (evidence / 'FAILED').write_text(type(error).__name__ + ': ' + str(error) + '\n'
                                         + detail[-4000:])
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
            with open(evidence / 'FAILED', 'a') as marker:
                marker.write('cleanup failed: ' + ', '.join(failures) + '\n')
            raise RuntimeError('temporary acceptance cleanup failed: ' + ', '.join(failures))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--sha', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    result = accept_v1(args.image, args.sha, args.evidence)
    print(json.dumps({'result': result['result'], 'checks': len(result['checks'])}))
