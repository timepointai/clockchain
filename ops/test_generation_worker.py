"""Worker integration against a disposable real Postgres database."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

import generation_worker as worker


@unittest.skipUnless(os.environ.get('TEST_DATABASE_URL'), 'TEST_DATABASE_URL required for real Postgres')
class WorkerDatabaseTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        from urllib.parse import urlsplit
        self.admin = psycopg.connect(os.environ['TEST_DATABASE_URL'], autocommit=True)
        self.addCleanup(self.admin.close)
        name = 'cc_worker_test_'+uuid.uuid4().hex
        self.admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
        self.addCleanup(lambda: self.admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name))))
        dsn = urlsplit(os.environ['TEST_DATABASE_URL'])._replace(path='/'+name).geturl()
        binary = Path(__file__).resolve().parents[1]/'target/debug/cc-node'
        migration = subprocess.run([str(binary),'migrate'],env={**os.environ,'DATABASE_URL':dsn},
                                   capture_output=True,text=True,timeout=60)
        self.assertEqual(migration.returncode,0,migration.stderr)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        env = {'DATABASE_URL':dsn,'CC_GENERATION_ENABLED':'1'}
        for key in ('MIGRATOR_SECRET_KEY','GENESIS_SECRET_KEY','CC_LEDGER_SIGNING_KEY','CC_NODE_API_KEY'):
            env[key] = ''
        self.patch = patch.dict(os.environ,env); self.patch.start(); self.addCleanup(self.patch.stop)
        self.jobs = worker.Jobs(self.temp.name); self.addCleanup(self.jobs.db.close)
        self.jobs.db.execute('UPDATE publication_control SET paused=false WHERE singleton')
        self.jobs.db.execute('SET ROLE cc_generation_worker')

    def test_lease_fencing_pause_and_worker_role(self):
        self.jobs.enqueue('test','private-human-brief')
        fence,_ = self.jobs.acquire('test',30)
        self.jobs.guard('test',fence)
        with self.assertRaisesRegex(ValueError,'leased'): self.jobs.acquire('test')
        with self.assertRaisesRegex(ValueError,'stale'): self.jobs.guard('test',fence+1)
        import psycopg
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.jobs.db.execute('TRUNCATE events CASCADE')
        self.jobs.db.execute('RESET ROLE')
        self.jobs.db.execute('UPDATE publication_control SET paused=true WHERE singleton')
        self.jobs.db.execute('SET ROLE cc_generation_worker')
        with self.assertRaisesRegex(ValueError,'pause'): self.jobs.guard('test',fence)
        with self.assertRaisesRegex(ValueError,'pause'): self.jobs.finish('test',fence,'ready','candidate')

    def test_local_stop_and_signing_key_refuse_generation(self):
        self.jobs.enabled()
        Path(self.temp.name,'STOP').touch()
        with self.assertRaisesRegex(ValueError,'disabled'): self.jobs.enabled()
        Path(self.temp.name,'STOP').unlink()
        with patch.dict(os.environ,{'GENESIS_SECRET_KEY':'synthetic-forbidden-key'}):
            with self.assertRaisesRegex(ValueError,'signing'): self.jobs.enabled()


if __name__ == '__main__': unittest.main()
