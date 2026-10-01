import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import v1_acceptance
from v1_acceptance import PG_IMAGE, PREFIX, SYNTHETIC_BODY, accept_v1, synthetic_node
from v1_backup import RELATIONS
from v1_identity import TABLES, Expected, fold_manifest

IMAGE = 'registry.example.invalid/clockchain@sha256:' + 'ab' * 32
SHA = '0123456789abcdef0123456789abcdef01234567'
MANIFEST = fold_manifest().hex()
PORT = '127.0.0.1:49152'
LOOPBACK = 'http://' + PORT
ZERO = {'schema': 'cc.v1-zero-check.v1', 'checks': ['health', 'empty snapshot'],
        'corpus_digest': '1a' * 32, 'commitment': '1b' * 32}
POPULATED = {'schema': 'cc.v1-populated-check.v1', 'checks': ['snapshot', 'export'],
             'corpus_digest': '2a' * 32, 'commitment': '2b' * 32}
RESTORED = dict(POPULATED, checks=['restored snapshot'])
EXPORT = {'corpus_digest': '2a' * 32, 'commitment': '2b' * 32, 'envelopes': ['01ff']}
STORED = {'bodies': 1, 'candidates': 1, 'identity': 1, 'receipts': 0, 'rejections': 0,
          'rule_identity': 1}
EVIDENCE = {'acceptance.json', 'provision.json', 'v1-zero.json', 'v1-populated.json',
            'v1-restore.json', 'cleanup.json'}
SENTINELS = {'CC_NODE_API_KEY': 'PRODUCTION-SENTINEL-full-key-7f3a',
             'CC_NODE_READ_KEY': 'PRODUCTION-SENTINEL-read-key-91c2',
             'DATABASE_URL': 'postgres://prod:PRODUCTION-SENTINEL-pw@prod-db.internal:5432/clockchain',
             'CC_V1_INSTANCE': '9e' * 32, 'CC_V1_CURATORS': '8d' * 32,
             'FLY_API_TOKEN': 'FlyV1 PRODUCTION-SENTINEL-fly-token'}
sha = lambda data: hashlib.sha256(data).hexdigest()


def pubkey(name):
    """Deterministic synthetic public key, distinct per seed file name."""
    return sha(b'synthetic acceptance curator ' + name.encode())


def empty_db():
    return {'identity': None, 'counts': {t: 0 for t in TABLES}}


class FakeDocker:
    """Interprets the docker argv accept_v1 sends; nothing is ever executed."""
    VALUED = ('--platform', '--network', '--user', '-v', '--env-file', '--name', '--label', '-p',
              '-e', '--env')

    def __init__(self, *, migrate_rc=78, seed_mode=0o600, provision_drift=False,
                 accept_mismatch=(), fail_rm=lambda name: False, fold_matches_build=True,
                 guard_hole=None, probe_residue=False, extra_rows=False):
        # guard_hole: a statement prefix the restored copy wrongly accepts.
        # probe_residue: the zero-check probes leave a rejection row behind.
        # extra_rows: the synthetic submit stores more rows than one Genesis.
        self.guard_hole, self.probe_residue, self.extra_rows = guard_hole, probe_residue, extra_rows
        self.migrate_rc, self.seed_mode, self.provision_drift = migrate_rc, seed_mode, provision_drift
        self.fold_matches_build = fold_matches_build
        self.accept_mismatch, self.fail_rm = set(accept_mismatch), fail_rm
        self.calls, self.kwargs, self.events = [], [], []
        self.env_reads, self.mounts, self.publisher, self.provisions = [], [], [], []
        self.networks, self.created_networks = set(), []
        self.containers, self.created_containers, self.removed = {}, [], []
        self.databases, self.dump, self.dump_path = {}, None, None

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        if argv[0] != 'docker' or not all(isinstance(a, str) for a in argv):
            raise AssertionError(f'not a docker argv: {argv!r}')
        rc, out, err = self.dispatch(argv[1:])
        return subprocess.CompletedProcess(argv, rc, out, err)

    def event(self, label):
        self.events.append(label)

    def dump_sha(self):
        return sha(json.dumps(self.dump, sort_keys=True).encode())

    def dispatch(self, args):
        cmd, rest = args[0], args[1:]
        if cmd == 'pull':
            self.event('pull')
            return 0, 'pulled\n', ''
        if args[:2] == ['image', 'inspect']:
            return 0, json.dumps([{'Id': 'sha256:' + 'cd' * 32, 'RepoDigests': [args[2]]}]), ''
        if args[:2] == ['network', 'create']:
            self.networks.add(args[-1])
            self.created_networks.append(args[-1])
            self.event('network create')
            return 0, 'network-id\n', ''
        if args[:2] == ['network', 'rm']:
            name = args[2]
            if self.fail_rm(name) or any(c['network'] == name for c in self.containers.values()):
                return 1, '', 'network has active endpoints'
            self.networks.discard(name)
            self.removed.append(name)
            return 0, name + '\n', ''
        if cmd == 'run':
            return self.run(rest)
        if cmd == 'exec':
            return self.exec(rest[0], rest[1:])
        if cmd == 'port':
            if rest[0] not in self.containers or rest[1:] != ['8080/tcp']:
                return 1, '', 'no public port'
            return 0, PORT + '\n', ''
        if cmd == 'logs':
            self.event('logs')
            if rest[0] not in self.containers:
                return 1, '', 'No such container: ' + rest[0]
            return 0, 'synthetic log of ' + rest[0] + '\n', ''
        if cmd == 'rm':
            if rest[:2] != ['-f', '-v']:
                raise AssertionError(f'unexpected rm {rest!r}')
            if self.fail_rm(rest[2]):
                return 1, '', 'removal failed'
            self.containers.pop(rest[2], None)
            self.removed.append(rest[2])
            return 0, rest[2] + '\n', ''
        raise AssertionError(f'unexpected docker command {args!r}')

    def run(self, args):
        flags, opts, i = set(), {}, 0
        while args[i].startswith('-'):
            if args[i] in ('--rm', '-d'):
                flags.add(args[i])
                i += 1
            elif args[i] in self.VALUED:
                opts.setdefault(args[i], []).append(args[i + 1])
                i += 2
            else:
                raise AssertionError('unexpected docker run option ' + args[i])
        image, command = args[i], args[i + 1:]
        if len(opts.get('--network', [])) != 1:
            raise AssertionError('every container must name exactly one network')
        network = opts['--network'][0]
        if network != 'none' and network not in self.networks:
            return 125, '', 'network not found'
        env, env_name = {}, None
        for path in opts.get('--env-file', []):
            text = Path(path).read_text()
            self.env_reads.append((path, text))
            env.update(line.split('=', 1) for line in text.splitlines())
            env_name = Path(path).name
        if '-d' in flags:
            return self.start(opts['--name'][0], image, network, env)
        if '--rm' not in flags or image != IMAGE:
            raise AssertionError(f'unexpected one-off container {args!r}')
        if command[:1] == ['cc-publisher']:
            return self.publish(opts, network, env, env_name, command)
        if command == ['cc-node', 'migrate']:
            self.event('migrate')
            return self.migrate_rc, '', 'refused in v1 mode' if self.migrate_rc else ''
        if command == ['cc-node', 'provision-v1']:
            return self.provision(network, env, env_name)
        raise AssertionError(f'unexpected container command {command!r}')

    def start(self, name, image, network, env):
        if name in self.containers:
            return 125, '', 'name already in use'
        self.containers[name] = {'image': image, 'network': network, 'env': env}
        self.created_containers.append(name)
        if image == PG_IMAGE:
            self.databases = {env['POSTGRES_DB']: empty_db()}
            self.event('run db')
        elif image == IMAGE:
            self.event('serve ' + name.rsplit('-', 1)[1])
        else:
            raise AssertionError('unexpected image ' + image)
        return 0, 'container-id\n', ''

    def node(self, url, network):
        for name, c in self.containers.items():
            if url == f'http://{name}:8080' and c['image'] == IMAGE and c['network'] == network:
                return c
        return None

    def publish(self, opts, network, env, env_name, command):
        if command[1] != 'v1':
            raise AssertionError('publisher must use the v1 commands')
        sub, rest = command[2], command[3:]
        params = dict(zip(rest[::2], rest[1::2]))
        host, _, target = opts['-v'][0].rpartition(':')
        if target != '/work':
            raise AssertionError('publisher mount must be /work')
        host = Path(host)
        self.mounts.append(host)
        self.publisher.append((sub, network, params, env_name))
        self.event('keygen ' + Path(params['--out']).name if sub == 'keygen' else sub)
        local = lambda p: host / Path(p).relative_to('/work')
        if sub == 'keygen':
            out = local(params['--out'])
            fd = os.open(out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.seed_mode)
            os.fchmod(fd, self.seed_mode)  # exact mode regardless of the test umask
            with os.fdopen(fd, 'wb') as f:
                f.write(b'synthetic seed ' + out.name.encode())
            return 0, f'wrote {params["--out"]}\npublic key: {pubkey(out.name)}\n', ''
        if sub == 'pubkey':
            key = local(params['--key'])
            return (0, pubkey(key.name) + '\n', '') if key.is_file() else (1, '', 'no key')
        if sub == 'genesis':
            key, body, out = local(params['--key']), local(params['--body']), local(params['--out'])
            if not key.is_file():
                return 1, '', 'no key'
            raw = body.read_bytes()
            envelope = b'\x01synthetic genesis ' + params['--instance'].encode() + \
                params['--value'].encode() + bytes(64)
            preview = {'event': sha(envelope[:-64]), 'subject': sha(b'subject' + envelope),
                       'revision': sha(b'revision' + envelope),
                       'body': {'sha256': sha(raw), 'bytes': len(raw)},
                       'author': pubkey(key.name), 'instance': params['--instance']}
            out.mkdir()
            (out / 'preview.json').write_text(json.dumps(preview))
            (out / 'envelope.bin').write_bytes(envelope)
            (out / 'body.bin').write_bytes(raw)
            return 0, 'genesis written\n', ''
        node = self.node(params.get('--node'), network)
        if node is None:
            return 1, '', 'could not resolve node'
        if sub == 'node-info':
            e = Expected(*(node['env'][n] for n in ('CC_V1_INSTANCE', 'CC_V1_CURATORS',
                                                   'CC_V1_MAX_HOPS')))
            return 0, json.dumps({
                'fold_matches_build': self.fold_matches_build, 'filter_version_consistent': True,
                'health': {'ledger': 'v1', 'instance': e.instance, 'filter_version': e.filter_version,
                           'fold_version': {'version': 1, 'manifest': MANIFEST}}}), ''
        if sub == 'submit':
            if env.get('CC_NODE_API_KEY') != node['env']['CC_NODE_API_KEY']:
                return 1, '', 'HTTP 401'
            directory = local(params['--dir'])
            preview = json.loads((directory / 'preview.json').read_text())
            (directory / 'receipt.json').write_text(json.dumps({'event': preview['event']}))
            database = urlsplit(node['env']['DATABASE_URL']).path.lstrip('/')
            self.databases[database]['counts'].update(bodies=1, candidates=1)
            if self.extra_rows:
                self.databases[database]['counts']['bodies'] += 1
            return 0, 'admitted\n', ''
        if sub == 'verify':
            if env.get('CC_NODE_READ_KEY') != node['env']['CC_NODE_READ_KEY']:
                return 1, '', 'HTTP 401'
            preview = json.loads((local(params['--dir']) / 'preview.json').read_text())
            if preview['subject'] != params['--subject']:
                return 1, '', 'subject differs from the signed Genesis'
            return 0, 'verified\n', ''
        raise AssertionError('unexpected publisher command ' + sub)

    def provision(self, network, env, env_name):
        self.event('provision ' + env_name)
        url = urlsplit(env['DATABASE_URL'])
        pg = self.containers.get(url.hostname)
        database = self.databases.get(url.path.lstrip('/'))
        identity = (env['CC_V1_INSTANCE'], env['CC_V1_CURATORS'], env['CC_V1_MAX_HOPS'])
        rc, out = 65, ''  # provision-v1's identity-mismatch status
        if not pg or pg['network'] != network or url.password != pg['env']['POSTGRES_PASSWORD'] \
                or database is None:
            rc = 69
        elif database['identity'] is None:
            database['identity'] = identity
            database['counts'].update(identity=1, rule_identity=1)
            if self.probe_residue:
                database['counts']['rejections'] = 1
            rc = 0
        elif database['identity'] == identity or env_name in self.accept_mismatch:
            rc = 0
        if rc == 0:
            e = Expected(*identity)
            report = {'instance': e.instance, 'fold_version': {'version': 1, 'manifest': MANIFEST},
                      'filter_version': e.filter_version, 'semantic': 'ready'}
            if self.provision_drift:
                report['attempt'] = len(self.provisions)
            out = json.dumps(report)
        self.provisions.append((env_name, rc, out))
        return rc, out, '' if rc == 0 else 'provision-v1: stored identity differs'

    def exec(self, name, args):
        pg = self.containers.get(name)
        if not pg or pg['image'] != PG_IMAGE:
            return 1, '', 'No such container: ' + name
        tool = args[0]
        if tool == 'pg_isready':
            return 0, 'accepting connections\n', ''
        if tool == 'psql':
            return self.psql(args)
        if tool == 'pg_dump':
            if args[args.index('-n') + 1] != 'cc_v1':
                raise AssertionError('dump must be limited to cc_v1')
            self.dump = copy.deepcopy(self.databases[args[-1]])
            self.dump_path = args[args.index('-f') + 1]
            self.event('pg_dump')
            return 0, '', ''
        if tool == 'sha256sum':
            if self.dump is None or args[1:] != [self.dump_path]:
                return 1, '', 'no such file'
            return 0, f'{self.dump_sha()}  {self.dump_path}\n', ''
        if tool == 'pg_restore':
            target = self.databases.get(args[args.index('-d') + 1])
            if target is None or target['identity'] is not None or args[-1] != self.dump_path:
                return 1, '', 'pg_restore failed'
            target.update(copy.deepcopy(self.dump))
            self.event('pg_restore')
            return 0, '', ''
        raise AssertionError(f'unexpected exec {args!r}')

    def psql(self, args):
        if '-Atc' in args:
            query, database = args[args.index('-Atc') + 1], 'postgres'
        else:
            query, database = args[args.index('-c') + 1], args[args.index('-d') + 1]
        if database == 'postgres':
            if query == 'SELECT 1':
                return 0, '1\n', ''
            if query == 'CREATE DATABASE restored' and 'restored' not in self.databases:
                self.databases['restored'] = empty_db()
                self.event('create restored')
                return 0, 'CREATE DATABASE\n', ''
            raise AssertionError('unexpected maintenance query ' + query)
        db = self.databases.get(database)
        if db is None:
            return 2, '', f'database "{database}" does not exist'
        provisioned = db['identity'] is not None
        if query == RELATIONS:
            return 0, f'{len(TABLES) if provisioned else 0}\n', ''
        for t in TABLES:
            if query == f'SELECT count(*) FROM cc_v1.{t}':
                return (0, f'{db["counts"][t]}\n', '') if provisioned else (1, '', 'no relation')
        if query.startswith('BEGIN; ') and query.endswith('; ROLLBACK;'):
            self.event('guard')
            if self.guard_hole and query.startswith('BEGIN; ' + self.guard_hole):
                return 0, 'BEGIN\nROLLBACK\n', ''
            return 1, '', 'ERROR:  v1 append-only evidence: cc_v1 refuses mutation\n'
        # prove_guards' catalog half: receipts references candidates; one guard trigger each.
        if query.startswith("SELECT count(*) FROM pg_constraint WHERE contype='f'"):
            return 0, ('1' if "'cc_v1.candidates'" in query else '0') + '\n', ''
        if query.startswith('SELECT count(*) FROM pg_trigger t'):
            self.event('guard catalog')
            return 0, '1\n', ''
        raise AssertionError('unexpected query ' + query)


class V1AcceptanceTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        self.tmp = self.root / 'tmp'  # every mkdtemp of the run lands here
        self.tmp.mkdir()
        self.evidence = self.root / 'evidence'
        self.checked = []

    def accept(self, fake, *, evidence=None, restored_export=None, image=IMAGE, revision=SHA):
        exports = [EXPORT, restored_export or EXPORT]
        populated = [POPULATED, RESTORED]

        def zero(url, sha_, key, read_key, expected, **kw):
            fake.event('zero')
            self.checked.append(('zero', url, key, read_key, expected, kw))
            return copy.deepcopy(ZERO)

        def check_populated(url, sha_, key, read_key, expected, entry, **kw):
            fake.event('populated')
            self.checked.append(('populated', url, key, read_key, expected, kw))
            if entry['instance'] != expected.instance or entry['author'] not in expected.curators:
                raise AssertionError('entry does not match the expected identity')
            return copy.deepcopy(populated.pop(0))

        def http(url, method, path, key=None, body=None):
            fake.event('export')
            if (url, method, path, body) != (LOOPBACK, 'GET', '/v1/export', None):
                raise AssertionError('unexpected HTTP request')
            return 200, json.dumps(exports.pop(0)).encode()

        def wait(url, *args, **kwargs):
            if url != LOOPBACK:
                raise AssertionError('readiness probe left loopback')
            fake.event('wait')

        with patch.object(v1_acceptance.subprocess, 'run', fake), \
                patch.object(v1_acceptance, 'check_v1_zero', zero), \
                patch.object(v1_acceptance, 'check_v1_populated', check_populated), \
                patch.object(v1_acceptance, 'http', http), \
                patch.object(v1_acceptance, 'wait_http', wait), \
                patch.object(v1_acceptance.time, 'sleep', side_effect=AssertionError('slept')), \
                patch.object(tempfile, 'tempdir', str(self.tmp)):
            return accept_v1(image, revision, evidence or self.evidence)

    def env_file(self, fake, name):
        [text] = [t for p, t in fake.env_reads if Path(p).name == name][:1]
        return dict(line.split('=', 1) for line in text.splitlines())

    def assertNothingLeft(self, fake):
        self.assertTrue(fake.created_networks)
        self.assertEqual(fake.containers, {})
        self.assertEqual(fake.networks, set())
        self.assertEqual(sorted(fake.removed), sorted(fake.created_containers + fake.created_networks))
        self.assertEqual(list(self.tmp.iterdir()), [])

    def assertCleanFailure(self, fake, evidence=None):
        evidence = evidence or self.evidence
        self.assertTrue((evidence / 'FAILED').is_file())
        self.assertFalse((evidence / 'acceptance.json').exists())
        self.assertEqual(json.loads((evidence / 'cleanup.json').read_text()),
                         {'removed': True, 'remaining': []})
        self.assertNothingLeft(fake)

    # Happy path ------------------------------------------------------------

    def test_happy_path_passes_writes_evidence_and_removes_everything(self):
        fake = FakeDocker()
        result = self.accept(fake)
        self.assertEqual(result['result'], 'pass')
        self.assertEqual({p.name for p in self.evidence.iterdir()}, EVIDENCE)
        read = lambda name: json.loads((self.evidence / name).read_text())
        self.assertEqual(read('acceptance.json'), result)
        self.assertEqual(result['checks'], ZERO['checks'] + POPULATED['checks'] + RESTORED['checks'])
        self.assertEqual((result['image'], result['sha'], result['commitment']),
                         (IMAGE, SHA, POPULATED['commitment']))
        self.assertEqual(read('cleanup.json'), {'removed': True, 'remaining': []})
        self.assertEqual(read('provision.json'), json.loads(fake.provisions[0][2]))
        self.assertEqual(read('provision.json')['instance'],
                         self.env_file(fake, 'node.env')['CC_V1_INSTANCE'])
        self.assertEqual(read('v1-zero.json'), ZERO)
        self.assertEqual(read('v1-populated.json'), POPULATED)
        restore = read('v1-restore.json')
        self.assertEqual(restore['counts'], STORED)
        self.assertEqual(restore['guards'], {t: 'proven' for t in TABLES})
        self.assertEqual(restore['dump_sha256'], fake.dump_sha())
        self.assertTrue(restore['export_equal'])
        # Every container and the network were created by this run and removed.
        [network] = fake.created_networks
        self.assertRegex(network, '^' + PREFIX + '[0-9a-f]{12}$')
        self.assertEqual(sorted(fake.created_containers),
                         sorted(network + s for s in ('-db', '-app', '-restored')))
        self.assertNothingLeft(fake)
        # Both temporary directories, as named in the docker argv, are gone.
        work, private = set(fake.mounts), {Path(p).parent for p, _ in fake.env_reads}
        self.assertEqual((len(work), len(private)), (1, 1))
        self.assertNotEqual(work, private)
        for directory in work | private:
            self.assertEqual(directory.parent, self.tmp)
            self.assertFalse(directory.exists())

    def test_no_production_credentials_reach_any_container(self):
        fake = FakeDocker()
        with patch.dict(os.environ, SENTINELS):
            self.accept(fake)
        # Every env file passed to a container was read by the fake, all six of them.
        self.assertEqual(len(fake.env_reads), sum(argv.count('--env-file') for argv in fake.calls))
        self.assertEqual({Path(p).name for p, _ in fake.env_reads},
                         {'node.env', 'restored.env', 'wrong-instance.env', 'wrong-curators.env',
                          'submit.env', 'read.env'})
        argvs = [' '.join(argv) for argv in fake.calls]
        reports = [p.read_text() for p in self.evidence.iterdir()]
        for name, value in SENTINELS.items():
            for text in argvs + [t for _, t in fake.env_reads] + reports:
                self.assertNotIn(value, text, name)
        for argv in fake.calls:
            for flag, value in zip(argv, argv[1:]):
                if flag in ('-e', '--env'):
                    self.assertIn('=', value, 'inherits a host variable into a container')
            self.assertFalse(set(argv) & set(SENTINELS), 'bare host variable name in argv')
            self.assertFalse(any(a.startswith(('--env=', '-e')) and a != '-e' for a in argv))
        for kwargs in fake.kwargs:
            self.assertNotIn('env', kwargs)
        # Node credentials are generated per run, never on argv or in evidence,
        # and the HTTP checks use exactly those synthetic credentials.
        node = self.env_file(fake, 'node.env')
        [private] = {Path(p).parent for p, _ in fake.env_reads}
        for name in ('CC_NODE_API_KEY', 'CC_NODE_READ_KEY', 'POSTGRES_PASSWORD'):
            self.assertRegex(node[name], '^[0-9a-f]{64}$')
            for text in argvs + reports:
                self.assertNotIn(node[name], text, name)
        self.assertEqual({(c[2], c[3]) for c in self.checked},
                         {(node['CC_NODE_API_KEY'], node['CC_NODE_READ_KEY'])})
        self.assertEqual(urlsplit(node['DATABASE_URL']).hostname, fake.created_networks[0] + '-db')
        for argv in fake.calls:  # the credential directory is never mounted
            for flag, value in zip(argv, argv[1:]):
                if flag == '-v':
                    self.assertNotIn(str(private), value)

    # Synthetic target guard ----------------------------------------------

    def test_synthetic_node_accepts_only_this_runs_container_names(self):
        for suffix in ('app', 'restored'):
            name = PREFIX + '0123456789ab-' + suffix
            self.assertEqual(synthetic_node(name), f'http://{name}:8080')
        for bad in ('timepoint-clockchain-prod', 'cc-accept-v1-xyz-app',
                    'http://cc-accept-v1-0123456789ab-app:8080', 'https://example.org',
                    PREFIX + '0123456789ab-app-extra', PREFIX + '0123456789ab-app.fly.dev',
                    PREFIX + '0123456789ab-app\n', PREFIX + '0123456789ab-db',
                    PREFIX + '0123456789AB-app', PREFIX + '0123456789abc-app',
                    'x' + PREFIX + '0123456789ab-app', ''):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'temporary acceptance'):
                synthetic_node(bad)

    def test_publisher_writes_target_only_this_runs_node_on_its_network(self):
        fake = FakeDocker()
        self.accept(fake)
        [network] = fake.created_networks
        seen = {}
        for sub, net, params, env_name in fake.publisher:
            seen[sub] = seen.get(sub, 0) + 1
            if sub in ('submit', 'node-info', 'verify'):
                self.assertEqual(params['--node'], f'http://{network}-app:8080')
                self.assertEqual(net, network)
            else:
                self.assertEqual(net, 'none', sub)
                self.assertNotIn('--node', params)
            self.assertEqual(env_name, {'submit': 'submit.env', 'verify': 'read.env'}.get(sub))
        self.assertEqual(seen, {'keygen': 2, 'pubkey': 1, 'node-info': 1, 'genesis': 1,
                                'submit': 1, 'verify': 1})
        self.assertEqual(set(self.env_file(fake, 'submit.env')), {'CC_NODE_API_KEY'})
        self.assertEqual(set(self.env_file(fake, 'read.env')), {'CC_NODE_READ_KEY'})
        for argv in fake.calls:
            for flag, value in zip(argv, argv[1:]):
                if flag == '-p':
                    self.assertEqual(value, '127.0.0.1::8080')
        self.assertEqual({c[1] for c in self.checked}, {LOOPBACK})

    # Ordering ----------------------------------------------------------------

    def test_lifecycle_order_and_mismatched_identities_refused(self):
        fake = FakeDocker()
        self.accept(fake)
        e = fake.events
        at = e.index
        provisions = [i for i, label in enumerate(e) if label == 'provision node.env']
        populated = [i for i, label in enumerate(e) if label == 'populated']
        self.assertEqual((len(provisions), len(populated)), (2, 2))
        self.assertLess(at('run db'), at('migrate'))
        self.assertLess(at('migrate'), provisions[0])
        self.assertLess(provisions[1], at('serve app'))
        self.assertLess(at('serve app'), at('zero'))
        self.assertLess(at('zero'), at('genesis'))
        self.assertLess(at('genesis'), at('submit'))
        self.assertLess(at('submit'), populated[0])
        self.assertLess(at('pg_dump'), at('pg_restore'))
        self.assertLess(at('pg_restore'), at('provision restored.env'))
        self.assertLess(at('provision restored.env'), at('serve restored'))
        self.assertLess(at('serve restored'), populated[1])
        self.assertEqual({n: rc for n, rc, _ in fake.provisions},
                         {'node.env': 0, 'restored.env': 0, 'wrong-instance.env': 65,
                          'wrong-curators.env': 65})
        refusals = json.loads((self.evidence / 'v1-restore.json').read_text())['mismatch_refusals']
        self.assertEqual(refusals, {'wrong_instance': 65, 'wrong_curators': 65})
        node = self.env_file(fake, 'node.env')
        wrong_instance = self.env_file(fake, 'wrong-instance.env')
        wrong_curators = self.env_file(fake, 'wrong-curators.env')
        self.assertNotEqual(wrong_instance['CC_V1_INSTANCE'], node['CC_V1_INSTANCE'])
        self.assertEqual(wrong_curators['CC_V1_INSTANCE'], node['CC_V1_INSTANCE'])
        self.assertIn(node['CC_V1_CURATORS'], wrong_curators['CC_V1_CURATORS'].split(','))
        self.assertEqual(len(wrong_curators['CC_V1_CURATORS'].split(',')), 2)

    def test_restored_copy_without_a_guard_fails(self):
        for hole in ('TRUNCATE cc_v1.bodies', 'UPDATE cc_v1.identity', 'DELETE FROM cc_v1.receipts'):
            with self.subTest(hole):
                fake, evidence = FakeDocker(guard_hole=hole), self.root / ('guard-' + hole.split()[0])
                with self.assertRaisesRegex(ValueError, 'append-only guard missing: ' + hole):
                    self.accept(fake, evidence=evidence)
                self.assertFalse((evidence / 'acceptance.json').exists())

    def test_denial_probes_leaving_rows_fail(self):
        with self.assertRaisesRegex(AssertionError, 'denial probes left rows'):
            self.accept(FakeDocker(probe_residue=True))

    def test_more_than_one_genesis_worth_of_rows_fails(self):
        with self.assertRaisesRegex(AssertionError, 'unexpected stored rows'):
            self.accept(FakeDocker(extra_rows=True))

    def test_acceptance_runs_the_candidate_probes_production_skips(self):
        self.accept(FakeDocker())
        kinds = {(kind, kw.get('probe_candidates')) for kind, _, _, _, _, kw in self.checked}
        # Zero and the first populated check probe candidates; the restored node is read only.
        self.assertEqual(kinds, {('zero', True), ('populated', True), ('populated', None)})

    def test_mismatch_refused_with_the_wrong_status_fails(self):
        fake = FakeDocker()
        original = fake.provision
        def wrong_status(network, env, env_name):
            rc, out, err = original(network, env, env_name)
            return (1 if rc == 65 else rc), out, err
        fake.provision = wrong_status
        with self.assertRaisesRegex(AssertionError, 'must refuse a mismatched identity with 65, not 1'):
            self.accept(fake)

    def test_provision_accepting_a_mismatched_identity_fails(self):
        for env_name in ('wrong-instance.env', 'wrong-curators.env'):
            with self.subTest(env_name):
                fake, evidence = FakeDocker(accept_mismatch={env_name}), self.root / env_name
                with self.assertRaisesRegex(AssertionError, 'mismatched identity'):
                    self.accept(fake, evidence=evidence)
                self.assertCleanFailure(fake, evidence)

    # Failure paths -----------------------------------------------------------

    def test_migrate_not_refused_fails_and_still_cleans_up(self):
        for rc in (0, 1):
            with self.subTest(rc=rc):
                fake, evidence = FakeDocker(migrate_rc=rc), self.root / f'migrate-{rc}'
                with self.assertRaisesRegex(AssertionError, 'refuse with 78'):
                    self.accept(fake, evidence=evidence)
                self.assertTrue((evidence / 'FAILED').read_text().startswith('AssertionError: cc-node migrate must refuse'))
                self.assertNotIn('provision node.env', fake.events)
                self.assertCleanFailure(fake, evidence)

    def test_provision_not_idempotent_fails(self):
        fake = FakeDocker(provision_drift=True)
        with self.assertRaisesRegex(AssertionError, 'not idempotent'):
            self.accept(fake)
        self.assertNotIn('serve app', fake.events)
        self.assertCleanFailure(fake)

    def test_node_info_reporting_foreign_fold_fails(self):
        fake = FakeDocker(fold_matches_build=False)
        with self.assertRaisesRegex(AssertionError, 'node-info does not match'):
            self.accept(fake)
        self.assertNotIn('genesis', fake.events)
        self.assertNotIn('submit', fake.events)
        self.assertCleanFailure(fake)

    def test_seed_written_with_open_mode_fails(self):
        fake = FakeDocker(seed_mode=0o644)
        with self.assertRaisesRegex(AssertionError, 'mode 0600'):
            self.accept(fake)
        self.assertNotIn('pubkey', fake.events)
        self.assertCleanFailure(fake)

    def test_restored_export_differing_fails(self):
        fake = FakeDocker()
        with self.assertRaisesRegex(AssertionError, 'restored export differs'):
            self.accept(fake, restored_export=dict(EXPORT, envelopes=['02ff']))
        self.assertFalse((self.evidence / 'v1-restore.json').exists())
        self.assertCleanFailure(fake)

    def test_mutable_image_or_short_sha_rejected_before_docker(self):
        cases = [(img, SHA) for img in (
            'registry.example.invalid/clockchain:latest', 'registry.example.invalid/clockchain',
            'registry.example.invalid/clockchain@sha256:' + 'ab' * 31, IMAGE.upper(), IMAGE + '\n',
            '@sha256:' + 'ab' * 32)] + \
            [(IMAGE, s) for s in ('abc1234', SHA[:39], SHA + '0', SHA.upper(), '')]
        for image, revision in cases:
            with self.subTest(image=image, sha=revision):
                fake = FakeDocker()
                with self.assertRaises(ValueError):
                    self.accept(fake, image=image, revision=revision)
                self.assertEqual(fake.calls, [])
                self.assertFalse(self.evidence.exists())
                self.assertEqual(list(self.tmp.iterdir()), [])

    def test_existing_evidence_directory_refused(self):
        self.evidence.mkdir()
        (self.evidence / 'earlier.json').write_text('{}\n')
        fake = FakeDocker()
        with self.assertRaises(FileExistsError):
            self.accept(fake)
        self.assertEqual(fake.calls, [])
        self.assertEqual([p.name for p in self.evidence.iterdir()], ['earlier.json'])
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_cleanup_failure_names_remaining_resource(self):
        is_db = lambda name: name.endswith('-db')
        is_network = lambda name: len(name) == len(PREFIX) + 12
        for label, failing in (('db', is_db), ('network', is_network)):
            with self.subTest(label):
                fake, evidence = FakeDocker(fail_rm=failing), self.root / ('cleanup-' + label)
                with self.assertRaises(RuntimeError) as caught:
                    self.accept(fake, evidence=evidence)
                [network] = fake.created_networks
                stuck = network + '-db' if label == 'db' else network
                self.assertIn(stuck, str(caught.exception))
                cleanup = json.loads((evidence / 'cleanup.json').read_text())
                self.assertFalse(cleanup['removed'])
                self.assertIn(stuck, cleanup['remaining'])
                # The run itself passed; leftover resources must still mark it failed.
                self.assertIn('cleanup failed: ' + stuck, (evidence / 'FAILED').read_text())
                self.assertIn(network, fake.networks)  # really left behind in the fake
                for name in (network + '-app', network + '-restored'):
                    self.assertNotIn(name, fake.containers)
                self.assertEqual(list(self.tmp.iterdir()), [])  # directories still removed


if __name__ == '__main__':
    unittest.main()
