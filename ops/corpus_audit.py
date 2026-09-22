#!/usr/bin/env python3
"""Read-only corpus crawl: integrity and evidence coverage, never automatic truth.

Private snapshot/report paths must be outside the checkout. Capture uses one
repeatable-read, read-only SQL transaction and an explicit table/column list.
No approvals, staged proposals, credentials, or publication commands are read.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import ssl
import subprocess
import time
import urllib.parse
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHEMA = 'cc.corpus-snapshot.v1'
TABLES = {
    'events': 'event_id,kind,author_key,signature,event_time,record_time,payload,supersedes',
    'entities': 'entity_id,birth_event,birth_event_time,resolution_key,canonical_name,window_start,start_state,closure_state,window_end,asserter',
    'moments': 'root_event_id,head_event_id,subject,coord,record_coord,posture,body_hash,author_key',
    'edges': 'edge_id,src_entity,dst_entity,relation,evidence_class,asserter,event_time,status,in_g,cross_writer',
    'attestations': 'event_id,target,author',
    'vocabulary': 'claim_type,label,declared_by,declared_at,band_start,start_state,band_end,closure_state',
    'taxonomy_tags': 'event_id,lens,tag',
    'claim_bodies': 'body_hash,body',
    'edge_evidence': 'event_id,admitted_coord,evidence,evidence_sha256,author_key,signature',
    'ledger_stats': 'entity_count,moment_count,edge_count,attestation_count,contested_edges,cross_writer_contested',
    'commitment_log': 'seq,event_id,epoch',
    'roots': 'root_id,height,moment_id,tree_size,prev_root',
    'anchors': 'root_id,status,anchored_at,txid',
}
RELATIONS = {0: 'co_occurrence', 1: 'influence', 2: 'causation', 3: 'participation', 4: 'attestation', 5: 'supersession'}


def private_path(path):
    path = Path(path).expanduser().resolve()
    repo = Path(__file__).resolve().parents[1]
    if path.is_relative_to(repo) and (repo / '.git').exists():
        raise ValueError('Live evidence must stay outside the checkout')
    return path


def save(path, data):
    path = private_path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')



def decode_reply(stdout):
    """psql JSON aggregates can contain real newlines between array rows."""
    lines = stdout.splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith('{"schema"')]
    if len(starts) != 1:
        raise ValueError('Expected exactly one report object')
    return json.loads('\n'.join(lines[starts[0]:]))


def capture(app, database, user):
    fields = ','.join("'%s',(SELECT coalesce(json_agg(t),'[]'::json) FROM (SELECT %s FROM %s) t)" % (name, cols, name)
                      for name, cols in TABLES.items())
    sql = ("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; "
           "SET LOCAL statement_timeout='30s'; SELECT json_build_object("
           "'schema','cc.corpus-snapshot.v1','captured_at',now(),"
           "'database_bytes',pg_database_size(current_database()),'tables',json_build_object(" + fields + ")); COMMIT;")
    # The password stays in the DB machine's existing environment, never argv.
    remote = ('PGPASSWORD="$OPERATOR_PASSWORD" psql -h 127.0.0.1 -X -qAt -v ON_ERROR_STOP=1 -U '
              + shlex.quote(user) + ' -d ' + shlex.quote(database) + ' -c ' + shlex.quote(sql))
    result = subprocess.run(['fly', 'ssh', 'console', '-a', app, '-C', 'sh -lc ' + shlex.quote(remote)],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Fly read-only snapshot failed; no snapshot accepted')
    data = decode_reply(result.stdout)
    if data.get('schema') != SCHEMA or set(data.get('tables', {})) != set(TABLES):
        raise ValueError('Incomplete snapshot')
    return data



def aggregate(app, database, user):
    """Remote counts only; no production rows or operational records exported."""
    sql = """BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
    SET LOCAL statement_timeout='25s';
    WITH RECURSIVE reach(src,dst) AS (
      SELECT src_entity,dst_entity FROM edges WHERE relation IN (1,2)
      UNION SELECT r.src,e.dst_entity FROM reach r JOIN edges e ON r.dst=e.src_entity WHERE e.relation IN (1,2)
    ) SELECT json_build_object(
      'schema','cc.aggregate-audit.v1','captured_at',now(),
      'database_bytes',pg_database_size(current_database()),
      'events',(SELECT count(*) FROM events),'entities',(SELECT count(*) FROM entities),
      'moments',(SELECT count(*) FROM moments),'edges',(SELECT count(*) FROM edges),
      'claim_bodies',(SELECT count(*) FROM claim_bodies),
      'historical_moments',(SELECT count(*) FROM moments WHERE subject<>0),
      'system_moments',(SELECT count(*) FROM moments WHERE subject=0),
      'dangling_moments',(SELECT count(*) FROM moments m LEFT JOIN entities e ON e.entity_id=m.subject WHERE e.entity_id IS NULL),
      'missing_claim_bodies',(SELECT count(*) FROM moments m LEFT JOIN claim_bodies b USING(body_hash) WHERE m.subject<>0 AND b.body_hash IS NULL),
      'dangling_edges',(SELECT count(*) FROM edges x LEFT JOIN entities s ON s.entity_id=x.src_entity LEFT JOIN entities d ON d.entity_id=x.dst_entity WHERE s.entity_id IS NULL OR d.entity_id IS NULL),
      'causation_edges',(SELECT count(*) FROM edges WHERE relation=2),
      'influence_edges',(SELECT count(*) FROM edges WHERE relation=1),
      'assertion_edges',(SELECT count(*) FROM edges WHERE evidence_class=3),
      'proposed_edges',(SELECT count(*) FROM edges WHERE status=0),
      'edge_evidence_records',(SELECT count(*) FROM edge_evidence),
      'claims_with_cited_urls',(SELECT count(*) FROM claim_bodies WHERE (body::jsonb->'prov_asserted')::text ~ 'https?://'),
      'claims_disclaiming_sources',(SELECT count(*) FROM claim_bodies WHERE body::jsonb->'prov_asserted'->>'historical_claim' LIKE '%no source was consulted%'),
      'reverse_chronology_edges',(SELECT count(*) FROM edges x JOIN entities s ON s.entity_id=x.src_entity JOIN entities d ON d.entity_id=x.dst_entity WHERE x.relation IN (1,2) AND s.start_state=0 AND d.start_state=0 AND s.window_start>d.window_start),
      'cycle_nodes',(SELECT count(*) FROM reach WHERE src=dst),
      'isolated_non_system_entities',(SELECT count(*) FROM entities e WHERE entity_id<>0 AND NOT EXISTS (SELECT FROM edges x WHERE x.src_entity=e.entity_id OR x.dst_entity=e.entity_id)),
      'multiple_live_readings',(SELECT count(*) FROM (SELECT subject FROM moments WHERE subject<>0 GROUP BY subject HAVING count(*)>1) x),
      'duplicate_resolution_keys',(SELECT count(*) FROM (SELECT resolution_key FROM entities GROUP BY resolution_key HAVING count(*)>1) x),
      'unknown_entity_starts',(SELECT count(*) FROM entities WHERE start_state<>0),
      'entity_authors',(SELECT count(DISTINCT asserter) FROM entities),
      'attestations',(SELECT count(*) FROM attestations),
      'counts_match',(SELECT entity_count=(SELECT count(*) FROM entities) AND moment_count=(SELECT count(*) FROM moments) AND edge_count=(SELECT count(*) FROM edges) AND attestation_count=(SELECT count(*) FROM attestations) FROM ledger_stats),
      'canonical_replay','not_run','historical_truth','not_assessed'); COMMIT;"""
    remote = ('PGPASSWORD="$OPERATOR_PASSWORD" psql -h 127.0.0.1 -X -qAt -v ON_ERROR_STOP=1 -U '
              + shlex.quote(user) + ' -d ' + shlex.quote(database) + ' -c ' + shlex.quote(sql))
    r = subprocess.run(['fly', 'ssh', 'console', '-a', app, '-C', 'sh -lc ' + shlex.quote(remote)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise RuntimeError('Remote aggregate audit failed')
    return decode_reply(r.stdout)

def raw(value):
    return bytes.fromhex(value.removeprefix('\\x'))


def framed(value):
    return len(value).to_bytes(4, 'big') + value


def body_digest(body):
    return hashlib.sha256(framed(b'claim_v4') + framed(body.encode())).digest()


def year_coord(year):
    y = year - 1
    era, yoe = divmod(y, 400)
    days = era * 146097 + yoe * 365 + yoe // 4 - yoe // 100 + 306 - 719468
    return ((days * 86400 - 946728000) << 64) + (1 << 255)


def urls(value):
    if isinstance(value, dict):
        return set().union(*(urls(v) for v in value.values())) if value else set()
    if isinstance(value, list):
        return set().union(*(urls(v) for v in value)) if value else set()
    if isinstance(value, str):
        return {s.rstrip('.,;)]}') for s in re.findall(r'https?://[^\s<>"\x27]+', value)}
    return set()


def merkle(leaves):
    if not leaves:
        return hashlib.sha256(b'').digest()
    if len(leaves) == 1:
        return hashlib.sha256(b'\x00' + leaves[0]).digest()
    split = 1 << ((len(leaves) - 1).bit_length() - 1)
    return hashlib.sha256(b'\x01' + merkle(leaves[:split]) + merkle(leaves[split:])).digest()


def audit(snapshot):
    if snapshot.get('schema') != SCHEMA or set(snapshot.get('tables', {})) != set(TABLES):
        raise ValueError('Missing or unsupported snapshot tables; refusing partial PASS')
    t = snapshot['tables']
    if any(not isinstance(rows, list) for rows in t.values()) or not t['events']:
        raise ValueError('Malformed or empty snapshot')
    findings, queue = [], []

    def note(code, item, detail=''):
        findings.append({'code': code, 'id': str(item), 'detail': detail})

    def index(table, key):
        result = {}
        for row in t[table]:
            if row[key] in result:
                note('duplicate_' + table + '_key', row[key])
            result[row[key]] = row
        return result

    events = index('events', 'event_id')
    entities = index('entities', 'entity_id')
    bodies = index('claim_bodies', 'body_hash')
    evidence = index('edge_evidence', 'event_id')
    verified = 0
    for eid, e in events.items():
        try:
            if hashlib.sha256(raw(e['payload'])).digest() != raw(eid):
                note('event_content_hash_mismatch', eid)
            Ed25519PublicKey.from_public_bytes(raw(e['author_key'])).verify(raw(e['signature']), raw(eid))
            verified += 1
        except (ValueError, InvalidSignature, TypeError):
            note('event_signature_or_encoding_invalid', eid)
        if e['supersedes'] and e['supersedes'] not in events:
            note('missing_superseded_event', eid)

    for eid, e in entities.items():
        if e['birth_event'] not in events:
            note('missing_entity_birth', eid)
        if e['start_state'] == 0 and e['closure_state'] == 1 and raw(e['window_start']) > raw(e['window_end']):
            note('inverted_entity_window', eid)
    for key, count in Counter(e['resolution_key'] for e in entities.values()).items():
        if count > 1:
            note('duplicate_resolution_key', key, str(count))

    parsed = {}
    for bh, b in bodies.items():
        if body_digest(b['body']) != raw(bh):
            note('claim_body_hash_mismatch', bh)
        try:
            parsed[bh] = json.loads(b['body'])
            if not isinstance(parsed[bh], dict):
                raise ValueError()
        except (ValueError, TypeError):
            parsed.pop(bh, None)
            note('claim_body_not_object', bh)
    refs = defaultdict(list)
    for m in t['moments']:
        refs[m['subject']].append(m)
        for key in ['root_event_id', 'head_event_id']:
            if m[key] not in events:
                note('missing_moment_event', m[key])
        if m['subject'] not in entities:
            note('dangling_moment', m['root_event_id'])
        if m['subject'] != 0 and m['body_hash'] not in bodies:
            note('missing_claim_body', m['root_event_id'])
        b = parsed.get(m['body_hash'])
        if not b or m['subject'] == 0:
            continue
        year = b.get('year')
        if type(year) is int:
            if not year_coord(year) <= int.from_bytes(raw(m['coord']), 'big') < year_coord(year + 1):
                note('claim_year_coordinate_mismatch', m['root_event_id'])
        else:
            note('claim_year_missing_or_invalid', m['root_event_id'])
    claim_queue = []
    for sid, readings in refs.items():
        if sid == 0:
            continue
        if len(readings) > 1:
            note('multiple_live_readings_review', sid, str(len(readings)))
        for m in readings:
            b = parsed.get(m['body_hash'], {})
            sources = sorted(urls(b.get('prov_asserted', {})))
            item = {'kind': 'claim', 'id': m['root_event_id'], 'entity_id': str(sid),
                    'body_hash': m['body_hash'], 'title': b.get('title'), 'year': b.get('year'),
                    'sources': sources, 'provenance': b.get('prov_asserted'),
                    'source_support': 'not_assessed' if sources else 'no_cited_url',
                    'historical_truth': 'not_assessed'}
            claim_queue.append(item)
    queue.extend(claim_queue)

    adj = defaultdict(set)
    backwards, causal = [], []
    for e in t['edges']:
        eid, src, dst = e['edge_id'], e['src_entity'], e['dst_entity']
        if eid not in events:
            note('missing_edge_event', eid)
        if src not in entities or dst not in entities:
            note('dangling_edge', eid)
        if src == dst:
            note('self_edge', eid)
        record = evidence.get(eid)
        ev = None
        if record:
            try:
                digest = hashlib.sha256(record['evidence'].encode()).digest()
                if digest != raw(record['evidence_sha256']):
                    note('edge_evidence_hash_mismatch', eid)
                Ed25519PublicKey.from_public_bytes(raw(record['author_key'])).verify(
                    raw(record['signature']), b'cc.edge-evidence.v1\x00' + raw(eid) + digest)
                ev = json.loads(record['evidence'])
                if not isinstance(ev, dict):
                    raise ValueError('Evidence must be an object')
            except (ValueError, TypeError, InvalidSignature):
                note('edge_evidence_invalid', eid)
        if e['relation'] in (1, 2):
            causal.append(e)
            adj[src].add(dst)
            s, d = entities.get(src), entities.get(dst)
            # Only assert a temporal conflict when both starts are known.
            reverse = bool(s and d and s['start_state'] == d['start_state'] == 0
                           and raw(s['window_start']) > raw(d['window_start']))
            if reverse:
                backwards.append(eid)
                note('reverse_chronology_requires_review', eid)
            queue.append({'kind': 'edge', 'id': eid, 'src_entity': str(src), 'dst_entity': str(dst),
                          'relation': RELATIONS[e['relation']], 'evidence_class': e['evidence_class'],
                          'sources': sorted(urls(ev)), 'evidence_recorded': record is not None,
                          'reverse_chronology': reverse, 'causal_support': 'not_assessed'})
    # Cycles are a review trigger, not automatic disproof of feedback processes.
    def reachable(start, target):
        seen, todo = set(), [start]
        while todo:
            n = todo.pop()
            if n == target:
                return True
            if n not in seen:
                seen.add(n)
                todo.extend(adj[n] - seen)
        return False
    cyclic = [e['edge_id'] for e in causal if reachable(e['dst_entity'], e['src_entity'])]
    connected = {x for e in t['edges'] for x in (e['src_entity'], e['dst_entity'])}

    for name, table in [('entity', 'entities'), ('moment', 'moments'), ('edge', 'edges'), ('attestation', 'attestations')]:
        if len(t['ledger_stats']) != 1 or t['ledger_stats'][0][name + '_count'] != len(t[table]):
            note('maintained_count_mismatch', name)
    leaves = sorted(t['commitment_log'], key=lambda r: r['seq'])
    if [r['seq'] for r in leaves] != list(range(len(leaves))):
        note('commitment_sequence_gap', 'commitment_log')
    if len({r['event_id'] for r in leaves}) != len(leaves):
        note('duplicate_commitment_leaf', 'commitment_log')
    for leaf in leaves:
        if leaf['event_id'] not in events:
            note('commitment_missing_event', leaf['event_id'])
    for root in t['roots']:
        n = root['tree_size']
        if not 0 < n <= len(leaves) or merkle([raw(r['event_id']) for r in leaves[:n]]) != raw(root['root_id']):
            note('merkle_root_mismatch', root['root_id'])
    counts = Counter(f['code'] for f in findings)
    review_codes = {'multiple_live_readings_review', 'reverse_chronology_requires_review'}
    return {'schema': 'cc.corpus-audit.v1', 'captured_at': snapshot.get('captured_at'),
            'snapshot_sha256': hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'integrity': 'fail' if set(counts) - review_codes else 'pass',
            'canonical_replay': 'not_run', 'historical_truth': 'not_assessed',
            'counts': {name: len(rows) for name, rows in t.items()},
            'event_signatures_verified': verified,
            'claims_with_cited_urls': sum(bool(q['sources']) for q in claim_queue),
            'claim_readings_audited': len(claim_queue), 'causal_or_influence_edges': len(causal),
            'causal_or_influence_with_evidence': sum(e['edge_id'] in evidence for e in causal),
            'reverse_chronology_edges': backwards, 'cycle_edges': cyclic,
            'isolated_non_system_entities': sum(s != 0 and s not in connected for s in entities),
            'findings_by_code': dict(counts), 'findings': findings, 'review_queue': queue,
            'limits': ['URL retrieval cannot prove historical truth or causality.',
                       'Missing URLs do not prove no offline source exists.',
                       'Signature checks bind keys to hashes; canonical replay is a separate check.',
                       'as_of is event-time slicing, not knowledge-time replay.']}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError('Authenticated API redirects refused')


def api_get(node, path, key):
    u = urllib.parse.urlsplit(node)
    if u.username or u.password or u.query or u.fragment or u.path not in ('', '/'):
        raise ValueError('Invalid API origin')
    if u.scheme != 'https' and not (u.scheme == 'http' and u.hostname in ('127.0.0.1', '::1')):
        raise ValueError('API requires HTTPS or a literal loopback Fly proxy')
    request = urllib.request.Request(node.rstrip('/') + path, headers={'Authorization': 'Bearer ' + key})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        body = response.read(2_000_001)
    if len(body) > 2_000_000:
        raise ValueError('API response too large')
    return json.loads(body)


def crawl_api(snapshot, node, key, as_of, delay):
    before = api_get(node, '/health/deep', key)
    results, digests = [], set()
    for entity in sorted(snapshot['tables']['entities'], key=lambda e: e['entity_id']):
        eid = entity['entity_id']
        try:
            data = api_get(node, '/v1/entities/' + str(eid) + '?' + urllib.parse.urlencode({'as_of': as_of}), key)
            digests.add(data['corpus_digest'])
            valid = (data['entity']['entity_id'] == eid
                     and raw(data['entity']['birth_event']) == raw(entity['birth_event'])
                     and data['entity']['canonical_name'] == entity['canonical_name'])
            results.append({'entity_id': str(eid), 'status': 'pass' if valid else 'mismatch', 'response': data})
        except (OSError, ValueError, KeyError):
            results.append({'entity_id': str(eid), 'status': 'unavailable'})
        time.sleep(delay)
    after = api_get(node, '/health/deep', key)
    return {'as_of': as_of, 'atomic': False, 'before': before, 'after': after,
            'stable_observed_digest': len(digests) == 1, 'results': results,
            'limits': 'DB snapshot and API requests are separate observations; changes require recapture.'}


def fetch_source(url, hosts, max_bytes=2_000_000):
    """Fetch a bounded HTTPS public source, pinning DNS and never sending keys."""
    for _ in range(6):
        u = urllib.parse.urlsplit(url)
        if u.scheme != 'https' or u.username or u.password or u.port not in (None, 443) or u.hostname not in hosts:
            raise ValueError('Source must use HTTPS and an explicitly allowed host')
        addresses = {r[4][0] for r in socket.getaddrinfo(u.hostname, 443, type=socket.SOCK_STREAM)}
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise ValueError('Non-public source address refused')
        address = sorted(addresses)[0]
        connection = http.client.HTTPSConnection(u.hostname, timeout=15)
        # Pin the checked address; TLS still verifies the original hostname.
        connection.sock = ssl.create_default_context().wrap_socket(
            socket.create_connection((address, 443), timeout=15), server_hostname=u.hostname)
        try:
            connection.request('GET', urllib.parse.urlunsplit(('', '', u.path or '/', u.query, '')),
                               headers={'User-Agent': 'ClockchainEvidenceAudit/1.0', 'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, response.getheader('Location', ''))
                continue
            content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ValueError('Source exceeds size limit')
            return {'url': url, 'http_status': response.status, 'sha256': hashlib.sha256(content).hexdigest(),
                    'byte_count': len(content), 'content_type': response.getheader('Content-Type'),
                    'retrieved_at': datetime.now(timezone.utc).isoformat(), 'historical_support': 'not_assessed'}, content
        finally:
            connection.close()
    raise ValueError('Too many source redirects')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for command in ('capture', 'aggregate'):
        cap = sub.add_parser(command)
        for arg in ('fly-db', 'database', 'user', 'output'):
            cap.add_argument('--' + arg, required=True)
    run = sub.add_parser('audit')
    run.add_argument('snapshot', type=Path)
    run.add_argument('--output', required=True, type=Path)
    run.add_argument('--node')
    run.add_argument('--as-of')
    run.add_argument('--delay', type=float, default=0.05)
    run.add_argument('--source-host', action='append', default=[])
    run.add_argument('--max-sources', type=int, default=30)
    args = parser.parse_args()
    if args.command in ('capture', 'aggregate'):
        destination = private_path(args.output)
        if destination.exists():
            parser.error('Output already exists')
        data = (capture if args.command == 'capture' else aggregate)(args.fly_db, args.database, args.user)
        save(destination, data)
        print(json.dumps(data) if args.command == 'aggregate' else 'Private read-only snapshot saved')
        return 0
    if args.delay < 0 or args.max_sources < 0:
        parser.error('Limits must be nonnegative')
    output = private_path(args.output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    snapshot = json.loads(args.snapshot.read_text())
    report = audit(snapshot)
    if args.node:
        if not args.as_of or not os.environ.get('CC_NODE_READ_KEY'):
            parser.error('API crawl needs --as-of and CC_NODE_READ_KEY')
        crawl = crawl_api(snapshot, args.node, os.environ['CC_NODE_READ_KEY'], args.as_of, args.delay)
        save(output / 'api.json', crawl)
        report['api'] = {'statuses': dict(Counter(r['status'] for r in crawl['results'])),
                         'stable_observed_digest': crawl['stable_observed_digest'], 'atomic': False}
    source_urls = sorted({u for q in report['review_queue'] for u in q['sources']})
    report['sources'] = []
    for i, url in enumerate(source_urls[:args.max_sources] if args.source_host else []):
        try:
            result, content = fetch_source(url, set(args.source_host))
            fd = os.open(output / ('source-%04d.bin' % i), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
            result['capture'] = 'source-%04d.bin' % i
        except (OSError, ValueError, http.client.HTTPException):
            result = {'url': url, 'retrieval': 'unavailable_or_refused', 'historical_support': 'not_assessed'}
        report['sources'].append(result)
        time.sleep(max(args.delay, 0.2))
    report['source_urls_total'] = len(source_urls)
    report['source_urls_not_fetched'] = len(source_urls) - len(report['sources'])
    save(output / 'report.json', report)
    save(output / 'review-queue.json', report.pop('review_queue'))
    report.pop('findings')
    print(json.dumps(report, indent=2))
    api_failed = report.get('api') and (not report['api']['stable_observed_digest'] or any(k != 'pass' for k in report['api']['statuses']))
    return 1 if report['integrity'] == 'fail' or api_failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
