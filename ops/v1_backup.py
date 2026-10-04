"""v1 store inspection shared by the Fly and manual backup tools.

Every function takes `sql(query) -> str` (stripped `psql -At` output) so the
same assertions run against the Fly database over SSH, a restored Docker copy
or an isolated local restore. Nothing here writes.
"""
import hashlib

from v1_identity import (APPEND_ONLY_ERROR, FOLD_VERSION, TABLES, corpus_digest, fold_manifest,
                         hexbytes, schema_hash)

# The same relation census `Store::provision` uses to refuse a non-v1 database.
RELATIONS = ("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
             "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
             "AND c.relkind IN ('r','p','v','m','S','f')")
FOREIGN = RELATIONS + " AND n.nspname <> 'cc_v1'"
OWN = RELATIONS + " AND n.nspname = 'cc_v1'"
EVIDENCE = ('bodies', 'candidates', 'receipts', 'rejections')
SIGNATURE = 64
MAX_ENVELOPE = 1024 * 1024


def inspect_v1(sql, expected):
    """Classify a database as an uninitialized or provisioned v1 store of `expected`.

    Anything else — v0 tables, a partial schema, another instance, another
    schema or another rule identity — raises before a release can proceed.
    """
    if int(sql(FOREIGN)):
        raise ValueError('database holds relations outside cc_v1; refusing a non-v1 store')
    if sql("SELECT to_regclass('cc_v1.identity') IS NOT NULL") != 't':
        if int(sql(OWN)) or int(sql("SELECT count(*) FROM pg_namespace WHERE nspname='cc_v1'")):
            raise ValueError('partial cc_v1 schema')
        return {'state': 'uninitialized', 'counts': {t: 0 for t in TABLES}}
    tables = tuple(sql("SELECT tablename FROM pg_tables WHERE schemaname='cc_v1' "
                       "ORDER BY tablename").splitlines())
    if tables != TABLES:
        raise ValueError('unexpected cc_v1 tables: ' + ','.join(tables))
    counts = {t: int(sql(f'SELECT count(*) FROM cc_v1.{t}')) for t in TABLES}
    if counts['identity'] != 1 or counts['rule_identity'] > 1:
        raise ValueError('cc_v1 identity rows are not singletons')
    instance, encoding, schema = sql(
        "SELECT encode(instance,'hex')||'|'||encoding||'|'||encode(schema_hash,'hex') "
        "FROM cc_v1.identity").split('|')
    if instance != expected.instance:
        raise ValueError('stored instance differs from CC_V1_INSTANCE')
    if encoding != '1' or schema != schema_hash().hex():
        raise ValueError('stored schema identity differs from this checkout')
    report = {'state': 'provisioned_unbound', 'counts': counts, 'instance': instance}
    rule = sql("SELECT fold_version||'|'||encode(fold_manifest,'hex')||'|'||"
               "encode(filter_identity,'hex') FROM cc_v1.rule_identity")
    if rule:
        version, manifest, canonical = rule.split('|')
        if int(version) != FOLD_VERSION or manifest != fold_manifest().hex():
            raise ValueError('stored fold identity differs from this checkout')
        if canonical != expected.filter_canonical.hex():
            raise ValueError('stored rule identity differs from CC_V1_CURATORS/CC_V1_MAX_HOPS')
        report.update(state='bound', filter_version=expected.filter_version)
    return report


def require_fresh(report):
    """A first release accepts only an empty store: no evidence rows of any kind."""
    if any(report['counts'][t] for t in EVIDENCE):
        raise ValueError('v1 database is not fresh: ' + ', '.join(
            f'{t}={report["counts"][t]}' for t in EVIDENCE if report['counts'][t]))
    return report


def verify_contents(sql):
    """Recompute event ids, body hashes and the corpus digest from retained bytes."""
    envelopes = []
    for line in sql("SELECT encode(event_id,'hex')||'|'||encode(envelope,'hex') "
                    "FROM cc_v1.candidates ORDER BY event_id").splitlines():
        event, wire = line.split('|')
        raw = bytes.fromhex(wire)
        if not SIGNATURE < len(raw) <= MAX_ENVELOPE or \
                hashlib.sha256(raw[:-SIGNATURE]).hexdigest() != event:
            raise ValueError('retained candidate does not hash to its event id: ' + event)
        envelopes.append((event, wire))
    for line in sql("SELECT encode(body_hash,'hex')||'|'||encode(sha256(bytes),'hex') "
                    "FROM cc_v1.bodies ORDER BY body_hash").splitlines():
        expected, actual = line.split('|')
        if expected != actual:
            raise ValueError('retained body does not hash to its key: ' + expected)
    corpus = corpus_digest([bytes.fromhex(e) for e, _ in envelopes]).hex()
    return {'events': [e for e, _ in envelopes], 'envelopes': [w for _, w in envelopes],
            'corpus_digest': corpus}


def compare_export(export, contents, expected, commitment):
    """A production export must name exactly the restored corpus, rule and commitment."""
    if hexbytes(export.get('corpus_digest'), 'corpus_digest') != contents['corpus_digest']:
        raise ValueError('export corpus digest differs from the restored backup')
    if [e.lower() for e in export.get('envelopes', [])] != contents['envelopes']:
        raise ValueError('export envelopes differ from the restored backup')
    rule = export.get('rule') or {}
    if rule.get('fold_version') != FOLD_VERSION or \
            hexbytes(rule.get('fold_manifest'), 'fold_manifest') != fold_manifest().hex() or \
            hexbytes(rule.get('filter_version'), 'filter_version') != expected.filter_version:
        raise ValueError('export rule identity differs from the expected identity')
    if hexbytes(export.get('commitment'), 'commitment') != hexbytes(commitment, 'commitment'):
        raise ValueError('export commitment differs from the restored backup')


# BEFORE (2) + DELETE (8) + UPDATE (16) + TRUNCATE (32), FOR EACH STATEMENT (row bit 1 clear).
GUARD_TYPE, GUARD_MASK = 58, 59


def prove_guards(run, sql):
    """Every cc_v1 table refuses UPDATE, DELETE and TRUNCATE, with or without rows.

    Behavior first: the triggers are statement-level, so UPDATE and DELETE are
    refused on empty tables too. A table another table references by foreign
    key (candidates, from receipts) refuses a plain TRUNCATE in the foreign-key
    check before any trigger runs, and a CASCADE would let the referencing
    table's trigger answer for it; so for such a table the refusal is required
    and the trigger's TRUNCATE coverage is proven from the catalog. The catalog
    check then requires, for every table, an enabled statement-level BEFORE
    UPDATE/DELETE/TRUNCATE trigger calling `cc_v1.append_only`.

    `run` returns an object with `returncode` and `stderr`; `sql` returns
    stripped `psql -At` output. Use only on an isolated restored copy.
    """
    column = {'bodies': 'body_hash', 'candidates': 'event_id', 'identity': 'singleton',
              'receipts': 'receipt_digest', 'rejections': 'input_digest',
              'rule_identity': 'singleton'}
    proven = {}
    for table in TABLES:
        referenced = int(sql("SELECT count(*) FROM pg_constraint WHERE contype='f' "
                             f"AND confrelid='cc_v1.{table}'::regclass"))
        for statement in (f'UPDATE cc_v1.{table} SET {column[table]}={column[table]}',
                          f'DELETE FROM cc_v1.{table}', f'TRUNCATE cc_v1.{table}'):
            result = run('BEGIN; ' + statement + '; ROLLBACK;')
            refused_by_fk = referenced and statement.startswith('TRUNCATE') and result.returncode
            if not refused_by_fk and (result.returncode == 0 or APPEND_ONLY_ERROR not in result.stderr):
                raise ValueError(f'append-only guard missing: {statement}')
        triggers = int(sql(
            "SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            f"WHERE t.tgrelid='cc_v1.{table}'::regclass AND NOT t.tgisinternal "
            f"AND t.tgenabled IN ('O','A') AND t.tgtype & {GUARD_MASK} = {GUARD_TYPE} "
            "AND n.nspname='cc_v1' AND p.proname='append_only'"))
        if triggers != 1:
            raise ValueError(f'append-only trigger missing from catalog: cc_v1.{table}')
        proven[table] = 'proven'
    return proven


def fingerprint_v1(sql):
    """Row count and SHA-256 of every cc_v1 table's ordered rows. Read-only.

    Equal fingerprints before and after a step prove the step wrote nothing to
    the store: an update's `provision-v1` on a matching store, for instance.
    """
    # Each row is hashed on its own and the sorted row hashes are hashed again,
    # so no intermediate value grows with the store beyond 64 bytes a row.
    query = ' UNION ALL '.join(
        f"SELECT '{t}'||'|'||count(*)||'|'||encode(sha256(convert_to(coalesce(string_agg(h, "
        f"'' ORDER BY h), ''), 'UTF8')), 'hex') FROM (SELECT encode(sha256(convert_to("
        f"r::text, 'UTF8')), 'hex') AS h FROM cc_v1.{t} r) rows"
        for t in TABLES)
    rows = {}
    for line in sql(query).splitlines():
        table, count, digest = line.split('|')
        rows[table] = {'rows': int(count), 'sha256': digest}
    if tuple(sorted(rows)) != TABLES:
        raise ValueError('store fingerprint does not cover every cc_v1 table')
    return rows
