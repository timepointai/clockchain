"""End-to-end v1 release checks against the real binaries and real PostgreSQL.

The same sequence `v1_acceptance.accept_v1` runs inside Docker, with the
workspace's debug `cc-node` and `cc-publisher` as local processes instead of the
exact image: refused migrate, idempotent provision, zero check, synthetic
Genesis through the publisher, populated check, `pg_dump -n cc_v1` restore with
an identity check and equal commitment, and `backup_restore.py --v1`. Skipped
unless TEST_DATABASE_URL is set and both binaries implement v1.
"""
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_acceptance import MIGRATE_REFUSED, SYNTHETIC_BODY, SYNTHETIC_KIND, check_provision
from v1_backup import RELATIONS
from v1_checks import check_v1_populated, check_v1_zero, http, load_entry
from v1_identity import Expected

ROOT = Path(__file__).resolve().parents[1]
NODE = ROOT / 'target/debug/cc-node'
PUBLISHER = ROOT / 'target/debug/cc-publisher'
DATABASE = os.environ.get('TEST_DATABASE_URL')


def implements_v1():
    if not (DATABASE and NODE.exists() and PUBLISHER.exists()):
        return False
    env = {k: v for k, v in os.environ.items() if not k.startswith(('CC_', 'DATABASE_URL'))}
    probe = subprocess.run([str(NODE), 'provision-v1'], env=env, capture_output=True, text=True)
    publisher = subprocess.run([str(PUBLISHER), 'v1', '--help'], capture_output=True, text=True)
    return 'unknown subcommand' not in probe.stderr and publisher.returncode == 0


def pg18(tool):
    found = shutil.which(tool)
    return bool(found) and ' 18.' in subprocess.run([found, '--version'], capture_output=True,
                                                    text=True).stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(implements_v1(), 'needs TEST_DATABASE_URL and v1-capable debug binaries')
class V1EndToEnd(unittest.TestCase):
    def setUp(self):
        import psycopg
        self.psycopg = psycopg
        self.admin = psycopg.connect(DATABASE, autocommit=True)
        self.addCleanup(self.admin.close)
        self.tmp = Path(tempfile.mkdtemp(prefix='cc-v1-e2e-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.processes = []
        self.addCleanup(self.stop)

    def database(self):
        name = 'cc_v1_e2e_' + secrets.token_hex(6)
        self.admin.execute(f'CREATE DATABASE {name}')
        self.addCleanup(self.admin.execute, f'DROP DATABASE IF EXISTS {name} WITH (FORCE)')
        parts = urlsplit(DATABASE)
        return name, urlunsplit(parts._replace(path='/' + name))

    def query(self, url, sql):
        with self.psycopg.connect(url) as conn:
            return conn.execute(sql).fetchone()[0]

    def stop(self):
        for process in self.processes:
            process.terminate()
            process.wait(timeout=10)

    def node_env(self, url, **override):
        env = {k: v for k, v in os.environ.items() if not k.startswith(('CC_', 'DATABASE_URL', 'PG'))}
        env.update({'DATABASE_URL': url, 'CC_NODE_API_KEY': self.key,
                    'CC_NODE_READ_KEY': self.read_key, 'CC_NODE_POSTURE': 'live',
                    'CC_NODE_LEDGER': 'v1', 'CC_V1_INSTANCE': self.instance,
                    'CC_V1_CURATORS': self.curator, 'CC_V1_MAX_HOPS': '4'})
        env.update(override)
        return env

    def node(self, *args, env):
        return subprocess.run([str(NODE), *args], env=env, capture_output=True, text=True)

    def publisher(self, *args, env=None):
        result = subprocess.run([str(PUBLISHER), 'v1', *args], capture_output=True, text=True,
                                env={**{k: v for k, v in os.environ.items()
                                        if not k.startswith('CC_')}, **(env or {})})
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def serve(self, url):
        port = free_port()
        process = subprocess.Popen([str(NODE), 'serve'], env=self.node_env(url, PORT=str(port)),
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        base = f'http://127.0.0.1:{port}'
        for _ in range(100):
            try:
                if http(base, 'GET', '/health')[0] == 200:
                    return base
            except OSError:
                pass
            time.sleep(0.1)
        self.fail('node did not serve')

    def test_release_sequence_and_backup(self):
        self.key, self.read_key, self.instance = (secrets.token_hex(32) for _ in range(3))
        self.curator = self.publisher('keygen', '--out', str(self.tmp / 'curator.seed')).strip()
        self.assertEqual((self.tmp / 'curator.seed').stat().st_mode & 0o777, 0o600)
        expected = Expected(self.instance, self.curator, '4')
        _, source = self.database()

        refused = self.node('migrate', env=self.node_env(source))
        self.assertEqual(refused.returncode, MIGRATE_REFUSED, refused.stderr)
        self.assertEqual(self.query(source, RELATIONS), 0)

        first = self.node('provision-v1', env=self.node_env(source))
        self.assertEqual(first.returncode, 0, first.stderr)
        identity = check_provision(json.loads(first.stdout), expected)
        again = self.node('provision-v1', env=self.node_env(source))
        self.assertEqual(json.loads(again.stdout), identity)

        base = self.serve(source)
        revision = json.loads(http(base, 'GET', '/health')[1])['build'].ljust(40, '0')
        zero = check_v1_zero(base, revision, self.key, self.read_key, expected, probe_candidates=True)
        self.assertEqual(zero['commitment'], expected.empty_commitment)
        for table in ('candidates', 'rejections', 'bodies'):
            self.assertEqual(self.query(source, f'SELECT count(*) FROM cc_v1.{table}'), 0, table)

        (self.tmp / 'body.txt').write_bytes(SYNTHETIC_BODY)
        out = self.tmp / 'genesis'
        self.publisher('genesis', '--key', str(self.tmp / 'curator.seed'), '--instance',
                       self.instance, '--kind', SYNTHETIC_KIND, '--namespace', 'cc.test',
                       '--value', 'e2e-' + secrets.token_hex(4), '--body', str(self.tmp / 'body.txt'),
                       '--asserted-time', '2000-01-01', '--out', str(out))
        self.publisher('submit', '--node', base, '--dir', str(out), env={'CC_NODE_API_KEY': self.key})
        entry = load_entry(out)
        self.publisher('verify', '--node', base, '--subject', entry['subject'], '--dir', str(out),
                       env={'CC_NODE_READ_KEY': self.read_key})
        populated = check_v1_populated(base, revision, self.key, self.read_key, expected, entry,
                                       probe_candidates=True)
        self.assertNotEqual(populated['commitment'], expected.empty_commitment)
        export = json.loads(http(base, 'GET', '/v1/export', self.key)[1])

        if not (pg18('pg_dump') and pg18('pg_restore') and pg18('psql')):
            self.skipTest('dump/restore half needs pg_dump, pg_restore and psql 18')
        restored_name, restored = self.database()
        dump = self.tmp / 'cc_v1.dump'
        subprocess.run(['pg_dump', '-n', 'cc_v1', '--format=custom', '--no-owner',
                        '--no-privileges', '-f', str(dump), '--dbname', source], check=True)
        subprocess.run(['pg_restore', '--exit-on-error', '--no-owner', '--no-privileges',
                        '--dbname', restored, str(dump)], check=True)
        self.assertEqual(json.loads(self.node('provision-v1', env=self.node_env(restored)).stdout),
                         identity)
        self.assertNotEqual(self.node('provision-v1', env=self.node_env(
            restored, CC_V1_INSTANCE=secrets.token_hex(32))).returncode, 0)
        restored_base = self.serve(restored)
        again = check_v1_populated(restored_base, revision, self.key, self.read_key, expected, entry)
        self.assertEqual(again['commitment'], populated['commitment'])
        self.assertEqual(json.loads(http(restored_base, 'GET', '/v1/export', self.key)[1]), export)

        # The manual backup tool, re-serving its restored copy with the same binary.
        target_name, _ = self.database()
        (self.tmp / 'export.json').write_text(json.dumps(export))
        parts = urlsplit(DATABASE)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('CC_', 'PG'))}
        for prefix, name in (('CC_SOURCE_', restored_name), ('CC_RESTORE_', target_name)):
            env.update({prefix + 'PGHOST': parts.hostname, prefix + 'PGPORT': str(parts.port or 5432),
                        prefix + 'PGUSER': parts.username, prefix + 'PGPASSWORD': parts.password or '',
                        prefix + 'PGDATABASE': name})
        env.update({'CC_V1_INSTANCE': self.instance, 'CC_V1_CURATORS': self.curator,
                    'CC_V1_MAX_HOPS': '4'})
        backup = subprocess.run([sys.executable, str(ROOT / 'ops/backup_restore.py'), '--v1',
                                 '--node-bin', str(NODE), '--export', str(self.tmp / 'export.json'),
                                 '--output', str(self.tmp / 'backup')], env=env,
                                capture_output=True, text=True)
        self.assertEqual(backup.returncode, 0, backup.stderr)
        manifest = json.loads((self.tmp / 'backup/manifest.json').read_text())
        self.assertEqual(manifest['commitment'], populated['commitment'])
        self.assertEqual(manifest['counts']['candidates'], 1)
        self.assertTrue(all(v == 'proven' for v in manifest['guards'].values()))


if __name__ == '__main__':
    unittest.main()
