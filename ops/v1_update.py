"""Read-only primitives for updating, backing up and monitoring a live v1 node.

An update release (`deploy-fly.sh --v1-update`) runs over a bound, populated
production store, so nothing in it may write. Every production HTTP request
here goes through `ReadOnlyNode`, which refuses any method but GET before a
socket is opened; the store is read through a read-only SQL session.

- `identity_of` / `require_identity`: `/health` and the stored rule identity
  must both equal the identity recomputed from this checkout and the operator
  environment (`CC_V1_INSTANCE`, `CC_V1_CURATORS`, `CC_V1_MAX_HOPS`, fold).
- `require_ready`: `/ready` must answer 200; only the node's 503 `busy` (one
  readiness query at a time) is retried.
- `observe` / `require_unchanged`: the corpus digest, view commitment and
  `/v1/export` bytes before and after a step must be byte-identical.
"""
import hashlib
import json
import os
import time
import urllib.error
import urllib.request

from v1_identity import hexbytes

TIMEOUT = int(os.environ.get('CC_CHECK_TIMEOUT', '120'))
READ_METHODS = frozenset({'GET'})
READY_ATTEMPTS = 5
IDENTITY_FIELDS = ('ledger', 'instance', 'fold_version', 'filter_version', 'curators', 'max_hops')


class ProductionWriteRefused(RuntimeError):
    """A write was attempted through the read-only production client."""


class IdentityDrift(ValueError):
    """The served or stored identity differs from the expected identity."""


class NotReady(RuntimeError):
    """`/ready` did not answer 200."""


class CommitmentChanged(ValueError):
    """The corpus, view commitment or export changed across a no-write step."""


class ReadOnlyNode:
    """HTTP client for a production node that can only read.

    Any method outside READ_METHODS, or any request body, is refused before a
    request is built, so a coding mistake cannot turn into a production write.
    """

    def __init__(self, base, opener=None):
        self.base = base.rstrip('/')
        self.opener = opener or urllib.request.urlopen
        self.requests = []

    def request(self, method, path, key=None, body=None):
        if method not in READ_METHODS or body is not None:
            raise ProductionWriteRefused(f'read-only production client refuses {method} {path}')
        self.requests.append((method, path))
        headers = {'Authorization': 'Bearer ' + key} if key else {}
        req = urllib.request.Request(self.base + path, headers=headers, method=method)
        try:
            with self.opener(req, timeout=TIMEOUT) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def get(self, path, key=None):
        return self.request('GET', path, key)

    def json(self, path, key=None):
        status, raw = self.get(path, key)
        if status != 200:
            raise ValueError(f'{path}: HTTP {status}')
        return json.loads(raw)


def _integer(value):
    return value if type(value) is int else None


def expected_identity(expected):
    return {'ledger': 'v1', 'instance': expected.instance, 'fold_version': dict(expected.fold),
            'filter_version': expected.filter_version, 'curators': list(expected.curators),
            'max_hops': expected.max_hops}


def identity_of(health):
    """The identity fields of a `/health` document, normalized; malformed is drift."""
    if not isinstance(health, dict):
        raise IdentityDrift('/health is not a JSON object')
    try:
        fold = health.get('fold_version') or {}
        curators = health.get('curators')
        if not isinstance(curators, list):
            raise ValueError('curators is not a list')
        return {'ledger': health.get('ledger'),
                'instance': hexbytes(health.get('instance'), 'instance'),
                'fold_version': {'version': _integer(fold.get('version')),
                                 'manifest': hexbytes(fold.get('manifest'), 'fold manifest')},
                'filter_version': hexbytes(health.get('filter_version'), 'filter_version'),
                'curators': [hexbytes(k, 'curator') for k in curators],
                'max_hops': _integer(health.get('max_hops'))}
    except (AttributeError, ValueError) as error:
        raise IdentityDrift('/health identity is malformed: ' + str(error)) from None


def drift(actual, expected):
    """Names of identity fields that differ; values are not repeated."""
    return [f for f in IDENTITY_FIELDS if actual.get(f) != expected.get(f)]


def require_identity(health, expected, stored=None):
    """`/health` (and, when given, the inspected store) must hold exactly `expected`.

    `stored` is an `inspect_v1` report: it already refuses another instance,
    schema, fold or rule identity, and here it must also be bound.
    """
    want = expected_identity(expected)
    actual = identity_of(health)
    fields = drift(actual, want)
    if fields:
        raise IdentityDrift('/health identity differs from the expected identity: ' + ', '.join(fields))
    if stored is not None:
        if stored.get('state') != 'bound':
            raise IdentityDrift('stored rule identity is not bound: ' + str(stored.get('state')))
        if stored.get('instance') != expected.instance or \
                stored.get('filter_version') != expected.filter_version:
            raise IdentityDrift('stored rule identity differs from the expected identity')
    return actual


def require_ready(node, attempts=READY_ATTEMPTS, sleep=None):
    """`/ready` must be 200 and serving. Only 503 `busy` is retried."""
    for attempt in range(attempts):
        status, raw = node.get('/ready')
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        if status == 503 and body.get('reason') == 'busy' and attempt < attempts - 1:
            (sleep or time.sleep)(1)
            continue
        if status != 200 or body.get('serving') is not True:
            raise NotReady(f'/ready: HTTP {status}' + (f' ({body["reason"]})' if
                                                       isinstance(body.get('reason'), str) else ''))
        return body
    raise NotReady('/ready stayed busy')  # unreachable: the last attempt never retries


def observe(node, key, read_key):
    """Corpus digest, view commitment and export bytes of the served store.

    The snapshot is read with the read key, the export with the full key; both
    are GETs. The export must name the snapshot's corpus and commitment.
    """
    snapshot = node.json('/v1/snapshot', read_key)
    status, export = node.get('/v1/export', key)
    if status != 200:
        raise ValueError(f'/v1/export: HTTP {status}')
    manifest = json.loads(export)
    corpus = hexbytes(snapshot.get('corpus_digest'), 'corpus_digest')
    commitment = hexbytes(snapshot.get('commitment'), 'commitment')
    if (hexbytes(manifest.get('corpus_digest'), 'corpus_digest'),
            hexbytes(manifest.get('commitment'), 'commitment')) != (corpus, commitment):
        raise CommitmentChanged('export and snapshot name different views')
    return {'corpus_digest': corpus, 'commitment': commitment,
            'export_sha256': hashlib.sha256(export).hexdigest(), 'export': export}


def require_unchanged(before, after):
    """Corpus digest, commitment and export bytes must be identical."""
    changed = [f for f in ('corpus_digest', 'commitment') if before[f] != after[f]]
    if before['export'] != after['export']:
        changed.append('export')
    if changed:
        raise CommitmentChanged('changed across a no-write step: ' + ', '.join(changed))
    return {f: before[f] for f in ('corpus_digest', 'commitment', 'export_sha256')}


def summary(observed):
    """`observe` output without the export bytes, for evidence files."""
    return {k: v for k, v in observed.items() if k != 'export'}
