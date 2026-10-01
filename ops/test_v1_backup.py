"""v1 backup inspection, guard proof and restore, against real Postgres and mocked Fly.

Every store here is synthetic: the real `v1.sql` bytes with made-up identity
rows and candidates whose "signature" is 64 zero bytes. Each test owns a
uniquely named throwaway database on the TEST_DATABASE_URL server; nothing
touches production, Fly or Docker (those calls are mocked).
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import backup_fly
from test_v1_checks import CURATORS
import v1_identity
from v1_backup import compare_export, inspect_v1, prove_guards, require_fresh, verify_contents
from v1_identity import TABLES, Expected, corpus_digest, filter_canonical, fold_manifest, schema_hash

OPS = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get('TEST_DATABASE_URL')
EXPECTED = Expected('11' * 32, ','.join(CURATORS), '4')
OTHER = Expected('11' * 32, ','.join(CURATORS), '5')
ZEROS = {t: 0 for t in TABLES}
BYTEA = 17  # pg_type oid
sha = lambda data: hashlib.sha256(data).digest()


def psql_text(value, type_oid=None):
    """Render one value the way `psql -At` prints it."""
    if value is None:
        return ''
    if isinstance(value, bool):
        return 't' if value else 'f'
    if isinstance(value, (bytes, bytearray, memoryview)):
        # A SQL_ASCII server hands text columns over as bytes; psql prints them raw.
        return '\\x' + bytes(value).hex() if type_oid == BYTEA else bytes(value).decode()
    return str(value)


class Database:
    """A uniquely named throwaway database; dropped WITH (FORCE) after the test."""

    def __init__(self, case):
        import psycopg
        from psycopg import sql as pgsql
        self.psycopg = psycopg
        self.name = 'cc_v1_backup_test_' + uuid.uuid4().hex[:16]
        ident = pgsql.Identifier(self.name)
        case.admin.execute(pgsql.SQL('CREATE DATABASE {}').format(ident))
        case.addCleanup(case.admin.execute, pgsql.SQL('DROP DATABASE {} WITH (FORCE)').format(ident))
        self.conn = psycopg.connect(urlsplit(DATABASE_URL)._replace(path='/' + self.name).geturl(),
                                    autocommit=True)
        case.addCleanup(self.conn.close)

    def execute(self, query, params=None):
        self.conn.execute(query, params)

    def rows(self, query, params=None):
        with self.conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchall() if cur.description is not None else []

    def sql(self, query):
        """`psql -At -c query`: rows by newline, columns by '|', stripped."""
        with self.conn.cursor() as cur:
            cur.execute(query)
            if cur.description is None:
                return ''
            oids = [column.type_code for column in cur.description]
            return '\n'.join('|'.join(psql_text(v, oid) for v, oid in zip(row, oids))
                             for row in cur.fetchall()).strip()

    def attempt(self, query):
        """`psql -c query` for prove_guards: a failed statement exits non-zero with its error."""
        idle = self.psycopg.pq.TransactionStatus.IDLE
        try:
            self.conn.execute(query)
        except self.psycopg.Error as error:
            return subprocess.CompletedProcess(query, 1, '', 'ERROR:  ' + str(error) + '\n')
        finally:
            if self.conn.info.transaction_status != idle:
                self.conn.execute('ROLLBACK')
        return subprocess.CompletedProcess(query, 0, 'BEGIN\nROLLBACK\n', '')

    # --- synthetic v1 store -------------------------------------------------
    def bootstrap(self):
        self.execute(v1_identity.SCHEMA_FILE.read_bytes())

    def identity(self, instance=EXPECTED.instance, schema=None):
        self.execute('INSERT INTO cc_v1.identity VALUES (true, %s, 1, %s)',
                     (bytes.fromhex(instance), schema or schema_hash()))

    def bind(self, canonical=None, fold_version=1, manifest=None):
        self.execute('INSERT INTO cc_v1.rule_identity VALUES (true, %s, %s, %s)',
                     (fold_version, manifest or fold_manifest(),
                      EXPECTED.filter_canonical if canonical is None else canonical))

    def candidate(self, preimage, event_id=None, envelope=None):
        envelope = preimage + bytes(64) if envelope is None else envelope
        event_id = sha(preimage) if event_id is None else event_id
        self.execute('INSERT INTO cc_v1.candidates VALUES (%s, %s)', (event_id, envelope))
        return event_id

    def receipt(self, event_id, label):
        self.execute('INSERT INTO cc_v1.receipts VALUES (%s, %s, %s)',
                     (sha(b'receipt:' + label), event_id, label + bytes(64)))

    def body(self, data, key=None):
        self.execute('INSERT INTO cc_v1.bodies VALUES (%s, %s)', (key or sha(data), data))

    def rejection(self, label):
        self.execute('INSERT INTO cc_v1.rejections VALUES (%s, %s)',
                     (sha(b'rejected:' + label), 'synthetic malformed input'))

    def fingerprint(self):
        """Every relation, every table's rows (count + md5) and every trigger."""
        from psycopg import sql as pgsql
        relations = self.rows(
            "SELECT n.nspname, c.relname, c.relkind::text FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' "
            "AND n.nspname <> 'information_schema' ORDER BY 1, 2")
        contents = {}
        for schema, name, kind in relations:
            if kind in ('r', 'p'):
                contents[schema + '.' + name] = self.rows(pgsql.SQL(
                    "SELECT count(*), coalesce(md5(string_agg(t::text, ',' ORDER BY t::text)), '') "
                    "FROM {} t").format(pgsql.Identifier(schema, name)))[0]
        triggers = self.rows("SELECT c.relname, t.tgname, t.tgenabled::text, t.tgtype "
                             "FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid ORDER BY 1, 2")
        return relations, contents, triggers


@unittest.skipUnless(DATABASE_URL, 'TEST_DATABASE_URL required for real Postgres')
class PgCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg  # required whenever TEST_DATABASE_URL asks for the real-Postgres tests
        cls.admin = psycopg.connect(DATABASE_URL, autocommit=True)
        cls.addClassCleanup(cls.admin.close)

    def database(self):
        return Database(self)

    def store(self, *, rule=True, candidates=(), bodies=(), rejections=(), receipts=False):
        db = self.database()
        db.bootstrap()
        db.identity()
        if rule:
            db.bind()
        ids = [db.candidate(p) for p in candidates]
        if receipts:
            for event_id in ids:
                db.receipt(event_id, event_id[:4])
        for data in bodies:
            db.body(data)
        for label in rejections:
            db.rejection(label)
        return db


class InspectTests(PgCase):
    def test_empty_database_is_uninitialized(self):
        report = inspect_v1(self.database().sql, EXPECTED)
        self.assertEqual(report, {'state': 'uninitialized', 'counts': ZEROS})
        self.assertIs(require_fresh(report), report)

    def test_bound_store_reports_identity_and_counts(self):
        db = self.store(candidates=(b'synthetic one', b'synthetic two'), receipts=True,
                        bodies=(b'synthetic body',), rejections=(b'synthetic',))
        report = inspect_v1(db.sql, EXPECTED)
        self.assertEqual(report, {
            'state': 'bound', 'instance': EXPECTED.instance, 'filter_version': EXPECTED.filter_version,
            'counts': {'bodies': 1, 'candidates': 2, 'identity': 1, 'receipts': 2,
                       'rejections': 1, 'rule_identity': 1}})

    def test_provisioned_store_without_rule_identity_is_unbound(self):
        report = inspect_v1(self.store(rule=False).sql, EXPECTED)
        self.assertEqual(report, {'state': 'provisioned_unbound', 'instance': EXPECTED.instance,
                                  'counts': dict(ZEROS, identity=1)})

    def test_require_fresh_accepts_only_stores_without_evidence(self):
        for rule in (True, False):
            report = inspect_v1(self.store(rule=rule).sql, EXPECTED)
            self.assertIs(require_fresh(report), report)
        for kind, rows in (('candidates', {'candidates': (b'synthetic',)}),
                           ('bodies', {'bodies': (b'synthetic body',)}),
                           ('rejections', {'rejections': (b'synthetic',)})):
            with self.subTest(kind):
                report = inspect_v1(self.store(**rows).sql, EXPECTED)
                self.assertEqual(report['counts'][kind], 1)
                with self.assertRaisesRegex(ValueError, f'not fresh: {kind}=1$'):
                    require_fresh(report)

    def test_refuses_relations_outside_cc_v1(self):
        bound, empty = self.store(), self.database()
        for db in (bound, empty):
            db.execute('CREATE TABLE public.events(id int)')
            with self.assertRaisesRegex(ValueError, 'relations outside cc_v1'):
                inspect_v1(db.sql, EXPECTED)

    def test_refuses_partial_schema(self):
        bare, half = self.database(), self.database()
        bare.execute('CREATE SCHEMA cc_v1')
        half.execute('CREATE SCHEMA cc_v1; CREATE TABLE cc_v1.candidates(event_id bytea PRIMARY KEY)')
        for db in (bare, half):
            with self.assertRaisesRegex(ValueError, 'partial cc_v1 schema'):
                inspect_v1(db.sql, EXPECTED)

    def test_refuses_extra_table_in_cc_v1(self):
        db = self.store()
        db.execute('CREATE TABLE cc_v1.extra(id int)')
        with self.assertRaisesRegex(ValueError, 'unexpected cc_v1 tables: bodies,candidates,extra,'):
            inspect_v1(db.sql, EXPECTED)

    def test_refuses_missing_identity_row(self):
        db = self.database()
        db.bootstrap()
        with self.assertRaisesRegex(ValueError, 'not singletons'):
            inspect_v1(db.sql, EXPECTED)

    def test_refuses_other_instance(self):
        db = self.database()
        db.bootstrap()
        db.identity(instance='22' * 32)
        db.bind()
        with self.assertRaisesRegex(ValueError, 'stored instance differs'):
            inspect_v1(db.sql, EXPECTED)
        self.assertEqual(inspect_v1(db.sql, Expected('22' * 32, ','.join(CURATORS), '4'))['state'], 'bound')

    def test_refuses_other_schema_hash(self):
        db = self.database()
        db.bootstrap()
        db.identity(schema=sha(b'synthetic other schema'))
        with self.assertRaisesRegex(ValueError, 'stored schema identity differs'):
            inspect_v1(db.sql, EXPECTED)

    def test_refuses_other_fold_identity(self):
        for version, manifest in ((2, None), (1, sha(b'synthetic other manifest'))):
            with self.subTest(version=version, manifest=manifest):
                db = self.store(rule=False)
                db.bind(fold_version=version, manifest=manifest)
                with self.assertRaisesRegex(ValueError, 'stored fold identity differs'):
                    inspect_v1(db.sql, EXPECTED)

    def test_refuses_other_rule_identity(self):
        for curators, hops in ((CURATORS[:3], '4'), (CURATORS, '5')):
            with self.subTest(curators=len(curators), hops=hops):
                db = self.store(rule=False)
                db.bind(canonical=filter_canonical([bytes.fromhex(k) for k in curators], int(hops)))
                with self.assertRaisesRegex(ValueError, 'stored rule identity differs'):
                    inspect_v1(db.sql, EXPECTED)
                # The same store is accepted by its own identity: only the rule differed.
                own = Expected(EXPECTED.instance, ','.join(curators), hops)
                self.assertEqual(inspect_v1(db.sql, own)['filter_version'], own.filter_version)


class GuardTests(PgCase):
    ALL = {t: 'proven' for t in TABLES}

    def populated(self):
        return self.store(candidates=(b'synthetic one', b'synthetic two'), receipts=True,
                          bodies=(b'synthetic body',), rejections=(b'synthetic',))

    def replace_trigger(self, db, table, definition):
        db.execute(f'DROP TRIGGER immutable_{table} ON cc_v1.{table}; '
                   f'CREATE TRIGGER immutable_{table} {definition} ON cc_v1.{table} '
                   'FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only()')

    def test_real_schema_guards_hold_on_empty_tables(self):
        db = self.store()
        before = db.fingerprint()
        self.assertEqual(prove_guards(db.attempt, db.sql), self.ALL)
        self.assertEqual(db.fingerprint(), before)

    def test_real_schema_guards_hold_with_rows(self):
        db = self.populated()
        before = db.fingerprint()
        self.assertEqual(prove_guards(db.attempt, db.sql), self.ALL)
        self.assertEqual(db.fingerprint(), before)

    def test_dropped_trigger_is_detected(self):
        db = self.populated()
        db.execute('DROP TRIGGER immutable_candidates ON cc_v1.candidates')
        before = db.fingerprint()
        with self.assertRaisesRegex(ValueError, r'guard missing: UPDATE cc_v1\.candidates '):
            prove_guards(db.attempt, db.sql)
        self.assertEqual(db.fingerprint(), before)

    def test_disabled_trigger_is_detected(self):
        db = self.store()
        db.execute('ALTER TABLE cc_v1.bodies DISABLE TRIGGER immutable_bodies')
        with self.assertRaisesRegex(ValueError, r'guard missing: UPDATE cc_v1\.bodies '):
            prove_guards(db.attempt, db.sql)

    def test_trigger_without_truncate_is_detected(self):
        db = self.store()
        self.replace_trigger(db, 'bodies', 'BEFORE UPDATE OR DELETE')
        with self.assertRaisesRegex(ValueError, r'guard missing: TRUNCATE cc_v1\.bodies$'):
            prove_guards(db.attempt, db.sql)

    def test_fk_referenced_table_needs_truncate_in_its_catalog_trigger(self):
        # candidates refuses a plain TRUNCATE through the receipts foreign key
        # anyway, so only the catalog can show its own trigger lost TRUNCATE.
        db = self.populated()
        self.replace_trigger(db, 'candidates', 'BEFORE UPDATE OR DELETE')
        with self.assertRaisesRegex(ValueError, r'trigger missing from catalog: cc_v1\.candidates$'):
            prove_guards(db.attempt, db.sql)

    def test_disabled_trigger_fails_the_catalog_or_behavior(self):
        db = self.store()
        db.execute('ALTER TABLE cc_v1.candidates DISABLE TRIGGER immutable_candidates')
        with self.assertRaisesRegex(ValueError, r'cc_v1\.candidates'):
            prove_guards(db.attempt, db.sql)

    def test_row_level_trigger_does_not_guard_an_empty_table(self):
        db = self.store()
        db.execute('DROP TRIGGER immutable_bodies ON cc_v1.bodies; '
                   'CREATE TRIGGER immutable_bodies BEFORE UPDATE OR DELETE ON cc_v1.bodies '
                   'FOR EACH ROW EXECUTE FUNCTION cc_v1.append_only(); '
                   'CREATE TRIGGER immutable_bodies_truncate BEFORE TRUNCATE ON cc_v1.bodies '
                   'FOR EACH STATEMENT EXECUTE FUNCTION cc_v1.append_only()')
        with self.assertRaisesRegex(ValueError, r'guard missing: UPDATE cc_v1\.bodies '):
            prove_guards(db.attempt, db.sql)

    def test_unrelated_refusal_is_not_the_guard(self):
        db = self.store()
        db.execute("CREATE FUNCTION public.refuse() RETURNS trigger LANGUAGE plpgsql AS "
                   "$$ BEGIN RAISE EXCEPTION 'synthetic unrelated refusal'; END; $$; "
                   'DROP TRIGGER immutable_bodies ON cc_v1.bodies; '
                   'CREATE TRIGGER immutable_bodies BEFORE UPDATE OR DELETE OR TRUNCATE ON cc_v1.bodies '
                   'FOR EACH STATEMENT EXECUTE FUNCTION public.refuse()')
        with self.assertRaisesRegex(ValueError, r'guard missing: UPDATE cc_v1\.bodies '):
            prove_guards(db.attempt, db.sql)


class ContentTests(PgCase):
    def test_empty_store_has_the_empty_corpus(self):
        self.assertEqual(verify_contents(self.store().sql),
                         {'events': [], 'envelopes': [], 'corpus_digest': corpus_digest([]).hex()})

    def test_corpus_digest_is_recomputed_from_retained_envelopes(self):
        preimages = (b'synthetic c', b'synthetic a', b'synthetic b')
        db = self.store(candidates=preimages, bodies=(b'synthetic body', b''))
        ids = sorted(sha(p) for p in preimages)
        contents = verify_contents(db.sql)
        self.assertEqual(contents['events'], [i.hex() for i in ids])
        by_id = {sha(p): (p + bytes(64)).hex() for p in preimages}
        self.assertEqual(contents['envelopes'], [by_id[i] for i in ids])
        self.assertEqual(contents['corpus_digest'], v1_identity.corpus_digest(ids).hex())
        self.assertNotEqual(contents['corpus_digest'], corpus_digest([]).hex())

    def test_candidate_must_hash_to_its_event_id(self):
        preimage = b'synthetic candidate'
        envelope = preimage + bytes(64)
        for name, event_id, wire in (('other id', sha(b'synthetic other'), envelope),
                                     ('id over signature', sha(envelope), envelope),
                                     ('signature only', sha(b''), bytes(64))):
            with self.subTest(name):
                db = self.store(candidates=(b'synthetic honest',))
                db.candidate(preimage, event_id=event_id, envelope=wire)
                with self.assertRaisesRegex(ValueError, 'does not hash to its event id: ' + event_id.hex()):
                    verify_contents(db.sql)

    def test_body_must_hash_to_its_key(self):
        db = self.store(bodies=(b'synthetic honest body',))
        key = sha(b'synthetic other body')
        db.body(b'synthetic body', key=key)
        with self.assertRaisesRegex(ValueError, 'does not hash to its key: ' + key.hex()):
            verify_contents(db.sql)


class ExportTests(PgCase):
    COMMITMENT = sha(b'synthetic populated commitment').hex()

    def setUp(self):
        self.contents = verify_contents(self.store(candidates=(b'synthetic x', b'synthetic y')).sql)

    def export(self, ints=True, **changes):
        c = self.contents
        as_hash = (lambda h: list(bytes.fromhex(h))) if ints else (lambda h: h)
        export = {'corpus_digest': as_hash(c['corpus_digest']),
                  'envelopes': [e.upper() for e in c['envelopes']],
                  'rule': {'fold_version': 1, 'fold_manifest': as_hash(fold_manifest().hex()),
                           'filter_version': as_hash(EXPECTED.filter_version)},
                  'commitment': as_hash(self.COMMITMENT)}
        export.update(changes)
        return export

    def test_matching_export_passes_with_int_array_or_hex_hashes(self):
        for ints in (True, False):
            with self.subTest(ints=ints):
                self.assertIsNone(compare_export(self.export(ints), self.contents, EXPECTED,
                                                 self.COMMITMENT))

    def test_mismatched_export_is_refused(self):
        envelopes, events = self.contents['envelopes'], self.contents['events']
        flipped = envelopes[0][:-2] + ('01' if envelopes[0][-2:] != '01' else '02')
        rule = self.export(False)['rule']
        cases = [
            ('envelopes differ', {'envelopes': envelopes[:1]}),
            ('envelopes differ', {'envelopes': envelopes[::-1]}),
            ('envelopes differ', {'envelopes': [flipped, envelopes[1]]}),
            ('envelopes differ', {'envelopes': envelopes + envelopes[:1]}),
            ('corpus digest differs', {'corpus_digest': corpus_digest([bytes.fromhex(events[0])]).hex()}),
            ('corpus digest differs', {'corpus_digest': corpus_digest([]).hex()}),
            ('rule identity differs', {'rule': dict(rule, filter_version=OTHER.filter_version)}),
            ('rule identity differs', {'rule': dict(rule, fold_version=2)}),
            ('rule identity differs', {'rule': dict(rule, fold_manifest='00' * 32)}),
            ('commitment differs', {'commitment': OTHER.empty_commitment}),
            ('commitment differs', {'commitment': EXPECTED.empty_commitment}),
            ('not a 32-byte hash', {'commitment': self.COMMITMENT[:-2]}),
        ]
        for message, changes in cases:
            with self.subTest(message, changes=list(changes)):
                with self.assertRaisesRegex(ValueError, message):
                    compare_export(self.export(**changes), self.contents, EXPECTED, self.COMMITMENT)
        # Against another expected identity the honest export is refused too.
        with self.assertRaisesRegex(ValueError, 'rule identity differs'):
            compare_export(self.export(), self.contents, OTHER, self.COMMITMENT)


def pg18_tools():
    """None when psql, pg_dump and pg_restore are all version 18, else the skip reason."""
    for tool in ('psql', 'pg_dump', 'pg_restore'):
        if not shutil.which(tool):
            return f'{tool} is not on PATH'
        version = subprocess.run([tool, '--version'], capture_output=True, text=True).stdout.strip()
        if ' 18.' not in version:
            return f'{tool} must be version 18 for backup_restore.py, found {version!r}'
    return None


class BackupRestoreV1Tests(PgCase):
    """`backup_restore.py --v1` end to end: real pg_dump/pg_restore between throwaway databases."""

    @classmethod
    def setUpClass(cls):
        reason = pg18_tools()
        if reason:
            raise unittest.SkipTest(reason)
        super().setUpClass()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_tool(self, source, restore, *args, **identity):
        url = urlsplit(DATABASE_URL)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('PG', 'CC_'))}
        for prefix, db in (('CC_SOURCE_', source), ('CC_RESTORE_', restore)):
            env.update({prefix + 'PGHOST': url.hostname, prefix + 'PGPORT': str(url.port or 5432),
                        prefix + 'PGUSER': url.username, prefix + 'PGPASSWORD': url.password or '',
                        prefix + 'PGDATABASE': db.name})
        env.update({'CC_V1_INSTANCE': EXPECTED.instance, 'CC_V1_CURATORS': ','.join(CURATORS),
                    'CC_V1_MAX_HOPS': '4'}, **identity)
        output = Path(self.tmp.name) / uuid.uuid4().hex / 'out'  # must not exist yet
        result = subprocess.run([sys.executable, str(OPS / 'backup_restore.py'), '--v1',
                                 '--output', str(output), *args], cwd=OPS.parent, env=env,
                                capture_output=True, text=True, timeout=300)
        return result, output

    def refused(self, source, message, *args, **identity):
        """The tool exits non-zero naming `message`, writes no manifest and leaves the source alone."""
        before = source.fingerprint()
        result, output = self.run_tool(source, self.database(), *args, **identity)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertFalse((output / 'manifest.json').exists())
        self.assertEqual(source.fingerprint(), before)
        return result

    def test_bound_empty_store_round_trips(self):
        source, restore = self.store(), self.database()
        before = source.fingerprint()
        result, output = self.run_tool(source, restore)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((output / 'manifest.json').read_text())
        self.assertEqual(manifest['guards'], {t: 'proven' for t in TABLES})
        self.assertEqual(manifest['commitment'], EXPECTED.empty_commitment)
        self.assertEqual(manifest['commitment_basis'], 'recomputed_empty_corpus')
        self.assertEqual((manifest['state'], manifest['counts']),
                         ('bound', dict(ZEROS, identity=1, rule_identity=1)))
        self.assertEqual((manifest['corpus_digest'], manifest['events']), (corpus_digest([]).hex(), []))
        self.assertFalse(manifest['production_export_matched'])
        self.assertEqual(manifest['dump_sha256'],
                         hashlib.sha256((output / 'database.dump').read_bytes()).hexdigest())
        self.assertEqual(json.loads(result.stdout)['commitment'], EXPECTED.empty_commitment)
        self.assertEqual(inspect_v1(restore.sql, EXPECTED), inspect_v1(source.sql, EXPECTED))
        self.assertEqual(source.fingerprint(), before)

    def test_populated_store_needs_node_bin(self):
        source = self.store(candidates=(b'synthetic populated',))
        self.refused(source, 'needs --node-bin')

    def test_restored_copy_without_candidates_trigger_is_refused(self):
        source = self.store()
        source.execute('DROP TRIGGER immutable_candidates ON cc_v1.candidates')
        self.refused(source, 'append-only guard missing: UPDATE cc_v1.candidates')

    def test_v0_table_is_refused(self):
        source = self.store()
        source.execute('CREATE TABLE public.events(id int)')
        self.refused(source, 'relations outside cc_v1')

    def test_wrong_instance_is_refused(self):
        self.refused(self.store(), 'stored instance differs', CC_V1_INSTANCE='22' * 32)

    def test_uninitialized_source_is_refused(self):
        self.refused(self.database(), 'source holds no v1 store')

    def test_export_must_match(self):
        export = Path(self.tmp.name) / 'export.json'
        honest = {'corpus_digest': corpus_digest([]).hex(), 'envelopes': [],
                  'rule': {'fold_version': 1, 'fold_manifest': fold_manifest().hex(),
                           'filter_version': EXPECTED.filter_version},
                  'commitment': EXPECTED.empty_commitment}
        export.write_text(json.dumps(dict(honest, commitment=OTHER.empty_commitment)))
        self.refused(self.store(), 'export commitment differs', '--export', str(export))
        export.write_text(json.dumps(honest))
        result, output = self.run_tool(self.store(), self.database(), '--export', str(export))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads((output / 'manifest.json').read_text())['production_export_matched'])


class RemoteSqlTests(unittest.TestCase):
    def test_query_travels_base64_and_the_password_stays_on_the_machine(self):
        secret = 'synthetic-operator-password'
        query = "SELECT 'it''s' || \"col\" FROM cc_v1.identity -- $HOME `id`\n;"
        calls = []
        def run(*args, **kwargs):
            calls.append(args)
            return 't|1\n'
        with patch.object(backup_fly, 'run', side_effect=run), \
                patch.dict(os.environ, {'OPERATOR_PASSWORD': secret, 'PGPASSWORD': secret}):
            self.assertEqual(backup_fly.remote_sql('cc-db', 'clockchain', 'operator')(query), 't|1')
        self.assertEqual(len(calls), 1)
        argv = calls[0]
        self.assertEqual(argv[:6], ('flyctl', 'ssh', 'console', '--app', 'cc-db', '-C'))
        flat = '\n'.join(argv)
        for fragment in (query.strip(), "'it''s'", '"col"', 'cc_v1.identity', '$HOME', '`id`', secret):
            self.assertNotIn(fragment, flat)
        shell = shlex.split(argv[6])
        self.assertEqual(shell[:2], ['sh', '-lc'])
        command = shell[2]
        # The only quotes the remote shell sees are around the machine's own password variable.
        self.assertEqual((command.count("'"), command.count('"')), (0, 2))
        match = re.fullmatch(r'echo ([A-Za-z0-9+/]+=*) \| base64 -d \| PGPASSWORD="\$OPERATOR_PASSWORD" '
                             r'psql --host 127\.0\.0\.1 --username operator -X -At -v ON_ERROR_STOP=1 '
                             r'-f - clockchain', command)
        self.assertIsNotNone(match, command)
        self.assertEqual(base64.b64decode(match.group(1), validate=True).decode(), query)


class CaptureV1Tests(unittest.TestCase):
    """`capture_v1` with Fly SSH, sftp, inspection and the Docker restore all mocked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.events = []

    def capture(self, source, restored, *, fresh, version='pg_dump (PostgreSQL) 18.6\n'):
        # capture_v1 refuses an existing bundle directory, so every call gets its own.
        self.bundle = Path(self.tmp.name) / uuid.uuid4().hex
        def ssh(target, command):
            self.assertEqual(target, 'cc-db')  # only the database machine is ever reached
            self.events.append(('ssh', command))
            return version if command == 'pg_dump --version' else ''
        def run(*args, **kwargs):
            self.events.append(('run',) + args)
            return ''
        def inspect(sql, expected):
            self.events.append(('inspect',))
            self.assertIs(expected, EXPECTED)
            return source
        def restore(bundle, expected, **kwargs):
            self.events.append(('restore', kwargs))
            return dict(restored)
        with patch.object(backup_fly, 'ssh', side_effect=ssh), \
                patch.object(backup_fly, 'run', side_effect=run), \
                patch.object(backup_fly, 'inspect_v1', side_effect=inspect), \
                patch.object(backup_fly, 'restore_verify_v1', side_effect=restore):
            return backup_fly.capture_v1('cc-db', 'clockchain', 'operator', self.bundle, EXPECTED,
                                         fresh=fresh)

    def dumped(self):
        return [i for i, e in enumerate(self.events) if e[0] == 'ssh' and '--file' in e[1]]

    def test_fresh_refuses_evidence_before_any_dump(self):
        for table in ('candidates', 'bodies', 'rejections', 'receipts'):
            with self.subTest(table):
                self.events = []
                source = {'state': 'bound', 'counts': dict(ZEROS, identity=1, rule_identity=1, **{table: 1})}
                with self.assertRaisesRegex(ValueError, f'not fresh: {table}=1'):
                    self.capture(source, source, fresh=True)
                self.assertEqual(self.events, [('ssh', 'pg_dump --version'), ('inspect',)])

    def test_fresh_empty_source_is_inspected_before_the_dump(self):
        source = {'state': 'bound', 'counts': dict(ZEROS, identity=1, rule_identity=1)}
        report = self.capture(source, dict(source, restore_verified=True), fresh=True)
        inspected = self.events.index(('inspect',))
        self.assertEqual(len(self.dumped()), 1)
        self.assertLess(inspected, self.dumped()[0])
        self.assertIn('PGPASSWORD="$OPERATOR_PASSWORD" pg_dump --host 127.0.0.1', self.events[self.dumped()[0]][1])
        self.assertEqual(self.events[-1], ('restore', {'allow_uninitialized': True, 'export': None, 'image': None}))
        self.assertEqual(report['source'], source)
        self.assertEqual(json.loads((self.bundle / 'manifest.json').read_text())['source'], source)

    def test_restored_copy_must_match_the_inspected_source(self):
        source = {'state': 'bound', 'counts': dict(ZEROS, identity=1, rule_identity=1, candidates=2)}
        for restored in ({'state': 'bound', 'counts': dict(source['counts'], candidates=1)},
                         {'state': 'bound', 'counts': dict(source['counts'], receipts=1)},
                         {'state': 'provisioned_unbound', 'counts': source['counts']}):
            with self.subTest(restored=restored):
                with self.assertRaisesRegex(ValueError, 'differs from the inspected source'):
                    self.capture(source, restored, fresh=False)
                self.assertFalse((self.bundle / 'manifest.json').exists())
        self.assertEqual(self.capture(source, dict(source), fresh=False)['source'], source)

    def test_remote_pg_dump_must_be_18(self):
        with self.assertRaisesRegex(ValueError, 'version 18'):
            self.capture({}, {}, fresh=True, version='pg_dump (PostgreSQL) 17.2\n')
        self.assertEqual(self.events, [('ssh', 'pg_dump --version')])


class RestoreVerifyV1Tests(unittest.TestCase):
    """`restore_verify_v1` with every docker call mocked."""

    def verify(self, state, guards=None, contents=None, **kwargs):
        calls, cleanup = [], []
        def run(*args, **kw):
            calls.append(args)
            return ''
        def removed(argv, **kw):
            cleanup.append(argv)
            return subprocess.CompletedProcess(argv, 0)
        refuse = AssertionError('guards and contents must not run for an uninitialized restore')
        with tempfile.TemporaryDirectory() as d, \
                patch.object(backup_fly, 'run', side_effect=run), \
                patch.object(backup_fly, 'inspect_v1', return_value=state), \
                patch.object(backup_fly, 'file_sha', return_value='ab' * 32), \
                patch.object(backup_fly, 'prove_guards', side_effect=None if guards else refuse,
                             return_value=guards), \
                patch.object(backup_fly, 'verify_contents', side_effect=None if contents else refuse,
                             return_value=contents), \
                patch.object(backup_fly.subprocess, 'run', side_effect=removed):
            try:
                report = backup_fly.restore_verify_v1(Path(d), EXPECTED, **kwargs)
                return report, json.loads((Path(d) / 'manifest.json').read_text())
            except ValueError:
                self.assertFalse((Path(d) / 'manifest.json').exists())
                raise
            finally:
                self.assertTrue(calls and all(c[0] == 'docker' for c in calls))
                self.assertTrue(any('pg_restore' in c for c in calls))
                self.assertEqual([c[:4] for c in cleanup], [['docker', 'rm', '-f', '-v']])

    def test_uninitialized_restore_requires_explicit_allowance(self):
        state = {'state': 'uninitialized', 'counts': dict(ZEROS)}
        with self.assertRaisesRegex(ValueError, 'restored v1 database is uninitialized'):
            self.verify(state)
        report, manifest = self.verify(state, allow_uninitialized=True)
        self.assertEqual(report, manifest)
        self.assertEqual((report['state'], report['guards'], report['commitment'], report['commitment_basis']),
                         ('uninitialized', 'not_run_uninitialized', None, 'not_applicable_uninitialized'))
        self.assertEqual(report['dump_sha256'], 'ab' * 32)

    def test_bound_empty_restore_proves_guards_and_recomputes_the_empty_commitment(self):
        state = {'state': 'bound', 'counts': dict(ZEROS, identity=1, rule_identity=1)}
        guards = {t: 'proven' for t in TABLES}
        empty = {'events': [], 'envelopes': [], 'corpus_digest': corpus_digest([]).hex()}
        report, manifest = self.verify(state, guards, empty)
        self.assertEqual(report, manifest)
        self.assertEqual((report['guards'], report['commitment'], report['commitment_basis']),
                         (guards, EXPECTED.empty_commitment, 'recomputed_empty_corpus'))


if __name__ == '__main__':
    unittest.main()
