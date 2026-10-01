#!/usr/bin/env python3
"""HTTP checks for a node serving the v1 ledger (`CC_NODE_LEDGER=v1`).

`check_v1_zero` and `check_v1_populated` compare what the node reports with the
identity and digests recomputed from this checkout by `v1_identity`. Against
production they are read-only: every probe that uses a mutating method carries
a body whose hash does not match its route, so even a node whose authorization
were broken could only refuse it. The candidate-route probe, which a broken
node could record as a rejection, runs only in isolated acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

from v1_identity import Expected, corpus_digest, hexbytes

TIMEOUT = int(os.environ.get('CC_CHECK_TIMEOUT', '120'))
EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()
# Deliberately not the preimage of EMPTY_SHA256: a body route must refuse it
# with or without credentials, so the probe can never retain anything.
DENIAL_BODY = b'cc-v1-denial-probe'
ANONYMOUS = 401
READ_KEY_ON_WRITE = (401, 403)


def http(base, method, path, key=None, body=None):
    headers = {'Authorization': 'Bearer ' + key} if key else {}
    if body is not None:
        headers['Content-Type'] = 'application/octet-stream'
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class Probe:
    """Records each named HTTP expectation; any mismatch raises."""

    def __init__(self, base):
        self.base = base.rstrip('/')
        self.checks = []

    def expect(self, name, method, path, key, status, body=None):
        actual, raw = http(self.base, method, path, key, body)
        allowed = status if isinstance(status, tuple) else (status,)
        if actual not in allowed:
            raise AssertionError(f'{name}: HTTP {actual}, expected {status}')
        self.checks.append(name)
        return raw

    def json(self, name, path, key, status=200):
        return json.loads(self.expect(name, 'GET', path, key, status))


def check_v1_health(health, expected, revision, posture='live'):
    """Assert /health names exactly the expected v1 identity and build."""
    assert health.get('ledger') == 'v1', 'node is not serving the v1 ledger'
    assert health.get('build') == revision[:12], 'wrong deployed revision'
    assert health.get('posture') == posture, 'unexpected posture'
    assert hexbytes(health.get('instance'), 'instance') == expected.instance, 'instance mismatch'
    fold = health.get('fold_version') or {}
    assert integer(fold.get('version')) == expected.fold['version'], 'fold version mismatch'
    assert hexbytes(fold.get('manifest'), 'fold manifest') == expected.fold['manifest'], \
        'fold manifest mismatch'
    assert hexbytes(health.get('filter_version'), 'filter_version') == expected.filter_version, \
        'filter_version mismatch'
    curators = health.get('curators')
    assert isinstance(curators, list) and [hexbytes(k, 'curator') for k in curators] == \
        expected.curators, 'curator set mismatch'
    assert integer(health.get('max_hops')) == expected.max_hops, 'max_hops mismatch'
    assert health.get('semantic') == 'ready', 'semantic readiness is not ready'
    return health


def integer(value):
    """JSON integers only: `true` must not pass for 1."""
    return value if type(value) is int else None


def check_rule(snapshot, expected):
    rule = snapshot.get('rule')
    assert isinstance(rule, dict), 'snapshot does not name its rule'
    assert integer(rule.get('fold_version')) == expected.fold['version'], 'snapshot fold mismatch'
    assert hexbytes(rule.get('fold_manifest')) == expected.fold['manifest'], 'snapshot fold mismatch'
    assert hexbytes(rule.get('filter_version')) == expected.filter_version, 'snapshot filter mismatch'


def common(p, revision, key, read_key, expected, posture, probe_candidates):
    if not key or not read_key or key == read_key:
        raise ValueError('Distinct full and read-only credentials required')
    health = check_v1_health(p.json('health', '/health', None), expected, revision, posture)
    ready = p.json('ready', '/ready', None)
    assert ready.get('serving') is True and ready.get('posture') == posture, 'node not serving'
    p.expect('snapshot anonymous denied', 'GET', '/v1/snapshot', None, ANONYMOUS)
    p.expect('snapshot wrong credential denied', 'GET', '/v1/snapshot', 'invalid-credential', ANONYMOUS)
    p.expect('export anonymous denied', 'GET', '/v1/export', None, ANONYMOUS)
    p.expect('read key cannot export', 'GET', '/v1/export', read_key, READ_KEY_ON_WRITE)
    body_path = '/v1/bodies/' + EMPTY_SHA256
    p.expect('write without token denied', 'PUT', body_path, None, ANONYMOUS, DENIAL_BODY)
    p.expect('read key cannot write', 'PUT', body_path, read_key, READ_KEY_ON_WRITE, DENIAL_BODY)
    if probe_candidates:
        p.expect('candidate without token denied', 'POST', '/v1/candidates', None, ANONYMOUS, b'')
        p.expect('read key cannot submit', 'POST', '/v1/candidates', read_key,
                 READ_KEY_ON_WRITE, b'')
    pinned = f'/v1/snapshot?fold_version={expected.fold["version"]}&fold_manifest={expected.fold["manifest"]}'
    p.expect('foreign fold refused', 'GET', f'/v1/snapshot?fold_version={expected.fold["version"]}'
             '&fold_manifest=' + '00' * 32, read_key, 409)
    return health, pinned


def snapshot_digests(snapshot):
    return hexbytes(snapshot.get('corpus_digest'), 'corpus_digest'), \
        hexbytes(snapshot.get('commitment'), 'commitment')


def check_v1_zero(base, revision, key, read_key, expected, *, posture='live', probe_candidates=False):
    """Verify a provisioned, bound and still empty v1 node. Never writes."""
    p = Probe(base)
    health, pinned = common(p, revision, key, read_key, expected, posture, probe_candidates)
    snapshot = p.json('empty snapshot', '/v1/snapshot', read_key)
    corpus, commitment = snapshot_digests(snapshot)
    assert corpus == corpus_digest([]).hex(), 'corpus is not empty'
    assert commitment == expected.empty_commitment, 'empty commitment differs from recomputation'
    for field in ('rows', 'subjects', 'revisions', 'edges', 'media'):
        assert snapshot.get(field) == [], f'empty snapshot has {field}'
    authority = snapshot.get('authority') or {}
    assert all(not v for v in authority.values()), 'empty snapshot has authority state'
    check_rule(snapshot, expected)
    assert snapshot_digests(p.json('pinned fold snapshot', pinned, read_key)) == (corpus, commitment), \
        'pinned fold snapshot differs'
    export = p.json('export', '/v1/export', key)
    assert export.get('envelopes') == [], 'empty node exported envelopes'
    assert snapshot_digests(export) == (corpus, commitment), 'export commitment differs'
    after = p.json('no probe writes', '/v1/snapshot', read_key)
    assert snapshot_digests(after) == (corpus, commitment), 'snapshot changed during checks'
    return {'schema': 'cc.v1-zero-check.v1', 'checks': p.checks, 'passed': len(p.checks),
            'ledger': 'v1', 'instance': expected.instance, 'filter_version': expected.filter_version,
            'corpus_digest': corpus, 'commitment': commitment, 'build': health['build'],
            'initialization_performed': False, 'probe_candidates': probe_candidates}


def load_entry(directory):
    """Read a `cc-publisher v1 genesis` output directory and cross-check it."""
    directory = Path(directory)
    preview = json.loads((directory / 'preview.json').read_text())
    envelope = (directory / 'envelope.bin').read_bytes()
    body = (directory / 'body.bin').read_bytes()

    def field(*names):
        for name in names:
            if name in preview:
                value = preview[name]
                # `cc-publisher v1 genesis` writes body as {sha256, bytes}.
                if isinstance(value, dict):
                    value = value.get('sha256')
                return hexbytes(value, name)
        raise ValueError('preview.json lacks ' + '/'.join(names))
    entry = {'event': field('event', 'event_id'), 'subject': field('subject', 'subject_id'),
             'revision': field('revision', 'revision_id'),
             'body_hash': field('body', 'body_hash', 'body_sha256'),
             'author': field('author'), 'instance': field('instance'),
             'envelope': envelope, 'body': body}
    if hashlib.sha256(body).hexdigest() != entry['body_hash']:
        raise ValueError('body.bin does not match the previewed body hash')
    return entry


def check_v1_populated(base, revision, key, read_key, expected, entry, *, posture='live',
                       probe_candidates=False):
    """Verify exactly one admitted Genesis matches its signed files. Never writes."""
    if entry['instance'] != expected.instance:
        raise ValueError('entry was signed for another instance')
    if entry['author'] not in expected.curators:
        raise ValueError('entry author is not a configured curator')
    p = Probe(base)
    health, pinned = common(p, revision, key, read_key, expected, posture, probe_candidates)
    snapshot = p.json('snapshot', '/v1/snapshot', read_key)
    corpus, commitment = snapshot_digests(snapshot)
    assert corpus == corpus_digest([bytes.fromhex(entry['event'])]).hex(), \
        'corpus is not exactly the entry'
    assert commitment != expected.empty_commitment, 'commitment still names the empty view'
    check_rule(snapshot, expected)
    rows = snapshot.get('rows') or []
    assert [hexbytes(r.get('event')) for r in rows] == [entry['event']], 'unexpected rows'
    assert rows[0].get('state') == 'valid' and rows[0].get('frontier') is True, 'entry not a valid head'
    subjects = snapshot.get('subjects') or []
    assert [hexbytes(s.get('subject')) for s in subjects] == [entry['subject']], 'unexpected subjects'
    assert subjects[0].get('state') == 'resolved', 'subject is not resolved'
    revisions = snapshot.get('revisions') or []
    assert [hexbytes(r.get('id')) for r in revisions] == [entry['revision']], 'unexpected revisions'
    assert hexbytes(revisions[0].get('body')) == entry['body_hash'], 'revision body differs'
    assert snapshot.get('edges') == [] and snapshot.get('media') == [], 'entry carries edges or media'
    assert snapshot_digests(p.json('pinned fold snapshot', pinned, read_key)) == (corpus, commitment), \
        'pinned fold snapshot differs'
    p.expect('subject anonymous denied', 'GET', '/v1/subjects/' + entry['subject'], None, ANONYMOUS)
    subject = p.json('subject readable', '/v1/subjects/' + entry['subject'], read_key)
    assert subject.get('state') == 'resolved', 'subject read is not resolved'
    assert isinstance(subject.get('revision'), dict) and \
        hexbytes(subject['revision'].get('id')) == entry['revision'], 'subject read revision differs'
    assert snapshot_digests(subject) == (corpus, commitment), 'subject read names another view'
    prose = p.json('prose readable', f'/v1/revisions/{entry["revision"]}/prose', read_key)
    assert prose.get('availability') == 'available', 'body is not retained'
    assert prose.get('prose', '').encode() == entry['body'], 'served prose differs from body.bin'
    export = p.json('export', '/v1/export', key)
    envelopes = export.get('envelopes') or []
    assert len(envelopes) == 1 and bytes.fromhex(envelopes[0]) == entry['envelope'], \
        'exported envelope differs from envelope.bin'
    assert snapshot_digests(export) == (corpus, commitment), 'export commitment differs'
    after = p.json('no probe writes', '/v1/snapshot', read_key)
    assert snapshot_digests(after) == (corpus, commitment), 'snapshot changed during checks'
    return {'schema': 'cc.v1-populated-check.v1', 'checks': p.checks, 'passed': len(p.checks),
            'ledger': 'v1', 'instance': expected.instance, 'event': entry['event'],
            'subject': entry['subject'], 'revision': entry['revision'],
            'corpus_digest': corpus, 'commitment': commitment, 'build': health['build']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('zero', 'populated', 'export'))
    parser.add_argument('--sha', help='full source SHA the node must report')
    parser.add_argument('--entry', type=Path, help='genesis output directory (populated mode)')
    parser.add_argument('--posture', default='live', choices=('live', 'frozen'))
    parser.add_argument('--out', type=Path, help='export mode: new file for the /v1/export JSON')
    args = parser.parse_args()
    # URL and credentials come from the operator environment, never argv.
    base = os.environ['CC_NODE_URL'].rstrip('/')
    key, read_key = os.environ['CC_NODE_API_KEY'], os.environ['CC_NODE_READ_KEY']
    if args.mode == 'export':
        if not args.out:
            parser.error('--out is required in export mode')
        status, raw = http(base, 'GET', '/v1/export', key)
        if status != 200:
            raise SystemExit(f'export failed: HTTP {status}')
        json.loads(raw)
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(raw)
        print(json.dumps({'export': str(args.out), 'sha256': hashlib.sha256(raw).hexdigest()}))
        return
    if not args.sha:
        parser.error('--sha is required')
    expected = Expected.from_env()
    if args.mode == 'zero':
        result = check_v1_zero(base, args.sha, key, read_key, expected, posture=args.posture)
    else:
        if not args.entry:
            parser.error('--entry is required in populated mode')
        result = check_v1_populated(base, args.sha, key, read_key, expected,
                                    load_entry(args.entry), posture=args.posture)
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == '__main__':
    main()
