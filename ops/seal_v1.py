#!/usr/bin/env python3
"""Keep an operator-held, hash-chained log of node seals (launchd, hourly).

The node signs stateless seals (`GET /v1/seal`: instance, fold, filter_version,
corpus_digest, commitment, candidate count, build, node clock) and keeps none
of them. This tool is the log. Each run fetches one seal through a short-lived
localhost `flyctl proxy` (see `fly_proxy.py`), or from `CC_NODE_URL` when the
env file names one, with GET only and the read key in the request header. It
then

1. verifies the Ed25519 signature over the seal's canonical bytes
   (`cc.seal.v1`, the same encoding as `crates/cc-core/src/v1/seal.rs`) and
   requires the signing key to be `CC_SEAL_NODE_KEY`;
2. requires the seal's instance, fold and `filter_version` to equal the
   identity recomputed from this checkout and the env file (`v1_identity.py`);
3. requires the seal to succeed the log head: a later node clock, no fewer
   candidates, and an unchanged corpus digest and commitment unless the
   candidate count grew;
4. appends one NDJSON line `{"prev_sha256", "seal", "fetched_at"}` to the
   private log `CC_SEAL_LOG`, where `prev_sha256` is the SHA-256 of the
   previous line's exact bytes (64 zeros for the first line);
5. rewrites `seal-status.json` in `CC_OPS_STATE_DIR`.

Success is quiet. Any refusal is named, written to the status file, raised as
a macOS notification and exits 1. Nothing here writes to the node.

    seal_v1.py run --env-file PATH      fetch, verify and append one seal
    seal_v1.py verify --env-file PATH   re-verify the whole log, then print a summary
    seal_v1.py install --env-file PATH  PRINT the hourly LaunchAgent plist and the
                                        command that would install it; never installs

The env file (mode 0600, outside the checkout) holds CC_FLY_APP or CC_NODE_URL,
CC_OPS_STATE_DIR, CC_SEAL_LOG, CC_SEAL_NODE_KEY, CC_NODE_READ_KEY and the three
CC_V1_* values. The read key leaves this process only as the request header.

What a verified log proves: the node key signed these states in this order
with these clock readings, and nothing in the log was rewritten since this
operator recorded it. It does not prove the states are true, that no other
store was served to someone else, or when a seal existed in anyone else's
eyes; see docs/design/SEALING.md.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

from fly_proxy import FlyProxy, ProxyFailed
import owner_jobs
from v1_identity import HEX64, Expected, frame, u16, u32, u64
from v1_update import IdentityDrift, ReadOnlyNode

LABEL = owner_jobs.LABEL_PREFIX + 'seal'
INTERVAL = 60 * 60
STATUS = 'seal-status.json'
SCHEMA = 'cc.v1-seal-status.v1'
DOMAIN = 'cc.seal.v1'
GENESIS_PREV = '0' * 64
MAX_BUILD = 64
BUSY_ATTEMPTS = 5
REQUIRED = ('CC_OPS_STATE_DIR', 'CC_SEAL_LOG', 'CC_SEAL_NODE_KEY', 'CC_NODE_READ_KEY')
ENTRY_KEYS = frozenset({'prev_sha256', 'seal', 'fetched_at'})
SEAL_KEYS = frozenset({'instance', 'node_key', 'fold_version', 'filter_version', 'corpus_digest',
                       'commitment', 'counts', 'build', 'sealed_at_us'})


class NoSealKey(RuntimeError):
    """The node has no CC_V1_NODE_SEED: 503 no_seal_key."""


class Unauthorized(RuntimeError):
    """The node refused the read key (401/403)."""


class SealRefused(RuntimeError):
    """Any other non-200 answer from /v1/seal."""


class SealInvalid(ValueError):
    """The seal document is malformed or its signature does not verify."""


class NodeKeyMismatch(ValueError):
    """The seal was signed by a key other than CC_SEAL_NODE_KEY."""


class LogBroken(ValueError):
    """The log file is not a valid chain of entries."""


class Regression(ValueError):
    """A seal does not succeed the one before it; `kind` names how."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def classify(error):
    if isinstance(error, NoSealKey):
        return 'no_seal_key'
    if isinstance(error, Unauthorized):
        return 'unauthorized'
    if isinstance(error, SealRefused):
        return 'node_error'
    if isinstance(error, SealInvalid):
        return 'bad_signature'
    if isinstance(error, NodeKeyMismatch):
        return 'node_key_mismatch'
    if isinstance(error, IdentityDrift):
        return 'identity_drift'
    if isinstance(error, Regression):
        return error.kind
    if isinstance(error, LogBroken):
        return 'log_broken'
    if isinstance(error, (ProxyFailed, OSError)):
        return 'unreachable'
    if isinstance(error, owner_jobs.ConfigError):
        return 'configuration'
    return 'error'


# --- the seal record -------------------------------------------------------

def _u64(value, name):
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise SealInvalid(f'{name} is not an unsigned 64-bit integer')
    return value


def _hex32(value, name):
    """Exactly 64 lowercase hex characters: the node serves hashes in no other form."""
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise SealInvalid(f'{name} is not a 32-byte lowercase hex hash')
    return value


def normalize_seal(seal):
    """The seal fields a `/v1/seal` answer carries, checked for shape."""
    if not isinstance(seal, dict) or set(seal) != SEAL_KEYS:
        raise SealInvalid('seal does not have exactly the cc.seal.v1 fields')
    fold = seal['fold_version']
    if not isinstance(fold, dict) or set(fold) != {'version', 'manifest'}:
        raise SealInvalid('fold_version is not {version, manifest}')
    if type(fold['version']) is not int or not 0 <= fold['version'] <= 0xFFFF:
        raise SealInvalid('fold_version.version is not a 16-bit integer')
    counts = seal['counts']
    if not isinstance(counts, dict) or set(counts) != {'candidates'}:
        raise SealInvalid('counts is not {candidates}')
    build = seal['build']
    if not isinstance(build, str) or not 0 < len(build.encode()) <= MAX_BUILD \
            or not all(33 <= ord(c) <= 126 for c in build):
        raise SealInvalid('build is not a short printable ASCII string')
    return {'instance': _hex32(seal['instance'], 'instance'),
            'node_key': _hex32(seal['node_key'], 'node_key'),
            'fold_version': {'version': fold['version'],
                             'manifest': _hex32(fold['manifest'], 'fold manifest')},
            'filter_version': _hex32(seal['filter_version'], 'filter_version'),
            'corpus_digest': _hex32(seal['corpus_digest'], 'corpus_digest'),
            'commitment': _hex32(seal['commitment'], 'commitment'),
            'counts': {'candidates': _u64(counts['candidates'], 'counts.candidates')},
            'build': build,
            'sealed_at_us': _u64(seal['sealed_at_us'], 'sealed_at_us')}


def encode_seal(seal):
    """The canonical `cc.seal.v1` bytes a seal signature covers (`NodeSealV1::preimage`)."""
    s = normalize_seal(seal)
    build = s['build'].encode()
    return (frame(DOMAIN) + bytes.fromhex(s['instance']) + bytes.fromhex(s['node_key'])
            + u16(s['fold_version']['version']) + bytes.fromhex(s['fold_version']['manifest'])
            + bytes.fromhex(s['filter_version']) + bytes.fromhex(s['corpus_digest'])
            + bytes.fromhex(s['commitment']) + u64(s['counts']['candidates'])
            + u32(len(build)) + build + u64(s['sealed_at_us']))


def verify_signed(doc, node_key):
    """A `/v1/seal` answer `{seal, signature, node_key}` must verify under exactly `node_key`.

    Returns the normalized seal. The key comparison comes first: a seal from
    another key is a different refusal from a forged signature.
    """
    if not isinstance(doc, dict) or set(doc) != {'seal', 'signature', 'node_key'}:
        raise SealInvalid('seal document does not have exactly {seal, signature, node_key}')
    seal = normalize_seal(doc['seal'])
    if not isinstance(node_key, str) or not HEX64.fullmatch(node_key):
        raise owner_jobs.ConfigError('CC_SEAL_NODE_KEY must be 64 lowercase hex characters')
    if doc['node_key'] != node_key or seal['node_key'] != node_key:
        raise NodeKeyMismatch('seal was signed by a key other than CC_SEAL_NODE_KEY')
    signature = doc['signature']
    if not isinstance(signature, str) or len(signature) != 128 or not HEX64.fullmatch(signature[:64]) \
            or not HEX64.fullmatch(signature[64:]):
        raise SealInvalid('signature is not 64 bytes of lowercase hex')
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(node_key)).verify(
            bytes.fromhex(signature), encode_seal(seal))
    except (InvalidSignature, ValueError):
        raise SealInvalid('seal signature does not verify under CC_SEAL_NODE_KEY') from None
    return seal


def require_seal_identity(seal, expected):
    """The seal must name the expected instance, fold and filter_version."""
    want = {'instance': expected.instance, 'fold_version': dict(expected.fold),
            'filter_version': expected.filter_version}
    fields = [f for f in ('instance', 'fold_version', 'filter_version') if seal[f] != want[f]]
    if fields:
        raise IdentityDrift('seal identity differs from the expected identity: ' + ', '.join(fields))
    return seal


def require_succession(previous, seal):
    """`seal` must follow `previous`: later clock, no fewer candidates, and the
    same corpus digest and commitment unless candidates grew."""
    if seal['sealed_at_us'] <= previous['sealed_at_us']:
        raise Regression('time_regression', 'sealed_at_us is not later than the log head')
    before, after = previous['counts']['candidates'], seal['counts']['candidates']
    if after < before:
        raise Regression('count_decrease', f'candidates fell from {before} to {after}')
    changed = [f for f in ('corpus_digest', 'commitment') if seal[f] != previous[f]]
    if changed and after == before:
        raise Regression('commitment_changed',
                         ', '.join(changed) + ' changed with no new candidate')
    if not changed and after != before:
        raise Regression('commitment_changed',
                         f'candidates grew from {before} to {after} with the same corpus digest')
    return seal


# --- the log -----------------------------------------------------------------

def line_digest(line):
    return hashlib.sha256(line).hexdigest()


def encode_entry(entry):
    return json.dumps(entry, sort_keys=True, separators=(',', ':')).encode()


def log_path(env, root=owner_jobs.ROOT):
    """`CC_SEAL_LOG`: a private regular file (or not yet existing) outside the checkout."""
    path = owner_jobs.outside_checkout(env['CC_SEAL_LOG'], root)
    if path.is_symlink():
        raise owner_jobs.ConfigError('CC_SEAL_LOG must not be a symlink')
    if path.exists():
        info = path.lstat()
        if not path.is_file():
            raise owner_jobs.ConfigError('CC_SEAL_LOG must be a regular file')
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise owner_jobs.ConfigError('CC_SEAL_LOG must be owned by this user with mode 0600')
    return path


def read_log(path):
    """Every entry with its exact line bytes; the chain of `prev_sha256` must hold."""
    path = Path(path)
    if not path.exists():
        return []
    data = path.read_bytes()
    if data and not data.endswith(b'\n'):
        raise LogBroken('log does not end with a newline')
    entries, prev = [], GENESIS_PREV
    for number, line in enumerate(data.split(b'\n')[:-1] if data else [], 1):
        try:
            entry = json.loads(line)
        except ValueError:
            raise LogBroken(f'log line {number} is not JSON') from None
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise LogBroken(f'log line {number} is not a seal entry')
        if entry['prev_sha256'] != prev:
            raise LogBroken(f'log line {number} does not name the digest of line {number - 1}')
        if not isinstance(entry['fetched_at'], str):
            raise LogBroken(f'log line {number} has no fetched_at')
        if encode_entry(entry) != line:
            raise LogBroken(f'log line {number} is not in canonical form')
        entries.append((line, entry))
        prev = line_digest(line)
    return entries


def verify_log(path, expected, node_key):
    """Re-verify a whole log: chain, every signature, identity and succession."""
    entries = read_log(path)
    previous, verified = None, []
    for number, (line, entry) in enumerate(entries, 1):
        try:
            seal = require_seal_identity(verify_signed(entry['seal'], node_key), expected)
            if previous is not None:
                require_succession(previous, seal)
        except Regression as error:
            raise Regression(error.kind, f'log line {number}: {error}') from None
        except (SealInvalid, NodeKeyMismatch, IdentityDrift) as error:
            raise type(error)(f'log line {number}: {error}') from None
        verified.append(seal)
        previous = seal
    head = entries[-1][0] if entries else None
    return {'entries': len(entries), 'head_sha256': line_digest(head) if head else None,
            'head': verified[-1] if verified else None}


def append_entry(path, entry):
    """Append one canonical line to a 0600 log that only this user can read."""
    line = encode_entry(entry) + b'\n'
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'ab') as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())
    return line[:-1]


# --- fetching ----------------------------------------------------------------

def fetch_seal(node, read_key, sleep=None, attempts=BUSY_ATTEMPTS):
    """GET /v1/seal with the read key. Only 503 `busy` is retried."""
    for attempt in range(attempts):
        status, raw = node.get('/v1/seal', read_key)
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        error = body.get('error') if isinstance(body, dict) else None
        if status == 503 and error == 'busy' and attempt < attempts - 1:
            (sleep or time.sleep)(1)
            continue
        if status == 503 and error == 'no_seal_key':
            raise NoSealKey('the node has no seal key (CC_V1_NODE_SEED is not set)')
        if status in (401, 403):
            raise Unauthorized(f'/v1/seal: HTTP {status}')
        if status != 200:
            raise SealRefused(f'/v1/seal: HTTP {status}' + (f' ({error})' if isinstance(error, str) else ''))
        if body is None:
            raise SealInvalid('/v1/seal is not JSON')
        return body
    raise SealRefused('/v1/seal stayed busy')  # unreachable: the last attempt never retries


def node_url(env):
    """`CC_NODE_URL` when set (a node you already reach, such as an open proxy), else None."""
    url = env.get('CC_NODE_URL')
    if url is None:
        return None
    if not url.startswith(('http://', 'https://')) or ' ' in url:
        raise owner_jobs.ConfigError('CC_NODE_URL must be an http(s) URL')
    return url.rstrip('/')


def record(url, env, expected, log, *, now):
    node = ReadOnlyNode(url)
    doc = fetch_seal(node, env['CC_NODE_READ_KEY'])
    seal = require_seal_identity(verify_signed(doc, env['CC_SEAL_NODE_KEY']), expected)
    entries = read_log(log)
    if entries:
        head_line, head_entry = entries[-1]
        require_succession(verify_signed(head_entry['seal'], env['CC_SEAL_NODE_KEY']), seal)
        prev = line_digest(head_line)
    else:
        prev = GENESIS_PREV
    line = append_entry(log, {'prev_sha256': prev, 'seal': doc, 'fetched_at': now.isoformat()})
    return seal, len(entries) + 1, line_digest(line)


def run(env_file, *, proxy=FlyProxy, notify=owner_jobs.notify, stderr=sys.stderr):
    env, state = {}, None
    started = owner_jobs.now()
    try:
        env = owner_jobs.load_env_file(env_file)
        owner_jobs.require(env, *REQUIRED)
        state = owner_jobs.private_dir(env['CC_OPS_STATE_DIR'])
        try:
            expected = Expected.from_env(env, production=True)
        except ValueError as error:
            raise owner_jobs.ConfigError(str(error)) from None
        if not HEX64.fullmatch(env['CC_SEAL_NODE_KEY']):
            raise owner_jobs.ConfigError('CC_SEAL_NODE_KEY must be 64 lowercase hex characters')
        log = log_path(env)
        given = node_url(env)
        if given is None:
            owner_jobs.require(env, 'CC_FLY_APP')
        with owner_jobs.JobLock(state, 'seal') as locked:
            if not locked:
                return 0  # the previous run is still working; it will report
            orphan = {}
            if given is not None:
                seal, entries, head = record(given, env, expected, log, now=started)
            else:
                tunnel = proxy(env['CC_FLY_APP'], state, 'seal')
                with tunnel as url:
                    seal, entries, head = record(url, env, expected, log, now=started)
                orphan = owner_jobs.proxy_orphan(tunnel)
        owner_jobs.write_status(state / STATUS, {
            'schema': SCHEMA, 'result': 'ok', 'fetched_at': started.isoformat(),
            'entries': entries, 'head_sha256': head, 'sealed_at_us': seal['sealed_at_us'],
            'candidates': seal['counts']['candidates'], 'corpus_digest': seal['corpus_digest'],
            'commitment': seal['commitment'], 'build': seal['build'], **orphan})
        if orphan:
            notify('Clockchain seal', owner_jobs.orphan_message(orphan))
        return 0
    except Exception as error:
        kind = classify(error)
        message = owner_jobs.redact(f'{type(error).__name__}: {error}', env)
        if state is not None:
            owner_jobs.write_status(state / STATUS, {
                'schema': SCHEMA, 'result': 'alert', 'kind': kind,
                'fetched_at': started.isoformat(), 'error': message})
        notify('Clockchain seal', f'{kind.replace("_", " ")}: see {STATUS}')
        print(f'seal alert ({kind}): {message}', file=stderr)
        return 1


def verify(env_file, *, stdout=sys.stdout, stderr=sys.stderr):
    env = {}
    try:
        env = owner_jobs.load_env_file(env_file)
        owner_jobs.require(env, 'CC_SEAL_LOG', 'CC_SEAL_NODE_KEY')
        try:
            expected = Expected.from_env(env, production=True)
        except ValueError as error:
            raise owner_jobs.ConfigError(str(error)) from None
        report = verify_log(log_path(env), expected, env['CC_SEAL_NODE_KEY'])
        json.dump({'result': 'ok', **report}, stdout, indent=2, sort_keys=True)
        stdout.write('\n')
        return 0
    except Exception as error:
        kind = classify(error)
        print(f'seal log refused ({kind}): ' + owner_jobs.redact(f'{type(error).__name__}: {error}', env),
              file=stderr)
        return 1


def install_text(env_file, state):
    """The plist and the command an owner would run by hand. Nothing is written or loaded."""
    data = owner_jobs.plist(LABEL, __file__, env_file, state, interval=INTERVAL).decode()
    target = owner_jobs.agents_dir() / (LABEL + '.plist')
    return (f'# Not installed. Save the plist below as {target} and run:\n'
            f'#   launchctl bootstrap gui/{os.getuid()} {target}\n'
            f'# To remove it later:\n'
            f'#   launchctl bootout gui/{os.getuid()}/{LABEL}\n' + data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('run', 'verify', 'install'))
    parser.add_argument('--env-file', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == 'run':
        return run(args.env_file)
    if args.command == 'verify':
        return verify(args.env_file)
    env = owner_jobs.load_env_file(args.env_file)
    owner_jobs.require(env, *REQUIRED)
    if node_url(env) is None:
        owner_jobs.require(env, 'CC_FLY_APP')
    Expected.from_env(env, production=True)
    state = owner_jobs.private_dir(env['CC_OPS_STATE_DIR'])
    sys.stdout.write(install_text(args.env_file, state))
    return 0


if __name__ == '__main__':
    sys.exit(main())
