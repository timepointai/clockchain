"""Synthetic adversarial fixtures; never production records."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import corpus_audit as a

def hx(value):
    return '\\x' + value.hex()

def fixture():
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = hx(sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    coord = hx(a.year_coord(2000).to_bytes(32, 'big'))
    t = {name: [] for name in a.TABLES}
    body = json.dumps({'title': 'Synthetic event', 'year': 2000, 'prov_asserted': {'historical_claim': 'model assertion; no source'}})
    bh = hx(a.body_digest(body))
    payload = a.framed(b'cc.moment.v0') + bytes(4) + a.raw(coord) + b'\0' + (1).to_bytes(8, 'big') + a.raw(bh)
    eid = hx(hashlib.sha256(payload).digest())
    t['events'] = [dict(event_id=eid, kind=1, author_key=public, signature=hx(sk.sign(a.raw(eid))), payload=hx(payload), event_time=coord, record_time=coord, supersedes=None)]
    t['entities'] = [dict(entity_id=1, birth_event=eid, birth_event_time=coord, resolution_key='synthetic', canonical_name='Synthetic event', start_state=0, closure_state=0, window_start=coord, window_end=hx(bytes([255])*32), asserter=public)]
    t['moments'] = [dict(root_event_id=eid, head_event_id=eid, subject=1, coord=coord, record_coord=coord, posture=0, body_hash=bh, author_key=public)]
    t['claim_bodies'] = [dict(body_hash=bh, body=body)]
    t['ledger_stats'] = [dict(entity_count=1, moment_count=1, edge_count=0, attestation_count=0, contested_edges=0, cross_writer_contested=0)]
    t['commitment_log'] = [dict(seq=0, event_id=eid, epoch=0)]
    t['roots'] = [dict(root_id=hx(a.merkle([a.raw(eid)])), height=0, moment_id=None, tree_size=1, prev_root=None)]
    return {'schema': a.SCHEMA, 'captured_at': 'synthetic', 'tables': t}

class AuditTests(unittest.TestCase):
    def test_multiline_psql_json_and_incomplete_output(self):
        self.assertEqual(a.decode_reply('Connecting...\n{"schema":"test","rows":[1,\n2]}\n')['rows'], [1, 2])
        for text in ('{"schema":"test","rows":[1,', '{"schema":"test"}\n{"schema":"other"}', '{"schema":"test"} trailing'):
            with self.assertRaises(ValueError):
                a.decode_reply(text)

    def test_signature_pass_is_not_replay_or_truth(self):
        r = a.audit(fixture())
        self.assertEqual(r['event_signatures_verified'], 1)
        self.assertEqual(r['canonical_replay'], 'not_run')
        self.assertEqual(r['historical_truth'], 'not_assessed')
        self.assertEqual(r['claims_with_cited_urls'], 0)

    def test_tampering(self):
        s = fixture()
        s['tables']['claim_bodies'][0]['body'] += ' '
        s['tables']['events'][0]['payload'] = '\\x00'
        s['tables']['events'][0]['signature'] = hx(bytes(64))
        r = a.audit(s)
        for code in ('claim_body_hash_mismatch', 'event_content_hash_mismatch', 'event_signature_or_encoding_invalid'):
            self.assertIn(code, r['findings_by_code'])
        self.assertEqual(r['integrity'], 'fail')

    def test_incomplete_input_refused(self):
        s = fixture()
        del s['tables']['edges']
        with self.assertRaises(ValueError): a.audit(s)
        s = fixture()
        s['tables']['events'] = []
        with self.assertRaises(ValueError): a.audit(s)

    def test_dangling_subject_missing_body_counter_drift(self):
        s = fixture()
        s['tables']['moments'][0]['subject'] = 99
        s['tables']['claim_bodies'] = []
        s['tables']['ledger_stats'][0]['entity_count'] = 999
        codes = a.audit(s)['findings_by_code']
        for code in ('dangling_moment', 'missing_claim_body', 'maintained_count_mismatch'):
            self.assertIn(code, codes)

    def test_reverse_chronology_and_cycles(self):
        s = fixture()
        t = s['tables']
        second = copy.deepcopy(t['entities'][0])
        second.update(entity_id=2, resolution_key='other', window_start=hx(a.year_coord(1990).to_bytes(32, 'big')))
        t['entities'].append(second)
        t['edges'] = [dict(edge_id=t['events'][0]['event_id'], src_entity=src, dst_entity=dst, relation=2, evidence_class=3) for src, dst in [(1, 2), (2, 1)]]
        t['ledger_stats'][0].update(entity_count=2, edge_count=2)
        r = a.audit(s)
        self.assertEqual(len(r['reverse_chronology_edges']), 1)
        self.assertEqual(len(r['cycle_edges']), 2)
        self.assertEqual(r['causal_or_influence_with_evidence'], 0)
        self.assertTrue(all(q['causal_support'] == 'not_assessed' for q in r['review_queue'] if q['kind'] == 'edge'))

    def test_merkle_tampering_and_leaf_gap(self):
        s = fixture()
        s['tables']['roots'][0]['root_id'] = hx(bytes(32))
        s['tables']['commitment_log'][0]['seq'] = 1
        codes = a.audit(s)['findings_by_code']
        self.assertIn('merkle_root_mismatch', codes)
        self.assertIn('commitment_sequence_gap', codes)

    def test_year_coordinates(self):
        self.assertEqual((a.year_coord(1970) - (1 << 255)) >> 64, -946728000)
        self.assertEqual((a.year_coord(2000) - (1 << 255)) >> 64, -43200)
        self.assertEqual((a.year_coord(1) - a.year_coord(0)) >> 64, 366 * 86400)

    def test_urls(self):
        self.assertEqual(a.urls({'sources': ['https://example.org/a', {'url': 'https://example.org/a'}]}), {'https://example.org/a'})
        self.assertEqual(a.urls({'historical_claim': 'model assertion'}), set())

    def test_private_files_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'report.json'
            a.save(p, {})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): a.save(p, {})

    def test_api_cleartext_and_redirects_refused(self):
        with self.assertRaises(ValueError): a.api_get('http://example.org', '/health', 'secret')
        with self.assertRaises(ValueError): a.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://elsewhere.example')

    def test_sources_require_allowed_public_host(self):
        for url in ('https://user:password@example.org', 'http://example.org', 'https://other.example'):
            with self.assertRaises(ValueError): a.fetch_source(url, {'example.org'})
        with patch.object(a.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(ValueError): a.fetch_source('https://example.org', {'example.org'})

if __name__ == '__main__': unittest.main()
