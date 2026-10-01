import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import deploy_digest as subject
import release
from test_v1_checks import CURATORS
from v1_identity import Expected
from verify_fly_machines import verify_v1

FLY = str(Path(__file__).resolve().parents[1] / 'fly.toml')
ROOT = Path(FLY).parent
SHA = 'b' * 40
OLD = 'sha256:' + 'a' * 64
NEW = 'registry.fly.io/timepoint-clockchain-prod@sha256:' + 'b' * 64
NEW_DIGEST = NEW.split('@')[1]
EXPECTED = Expected('11' * 32, ','.join(CURATORS), '4')
OTHER_COMMITMENT = Expected('11' * 32, ','.join(CURATORS), '5').empty_commitment
V0_CONFIG = '[env]\nCC_NODE_POSTURE = "live"\n\n[deploy]\nrelease_command = "cc-node migrate"\n'
ENV = {'CC_NODE_URL': 'https://example.invalid', 'CC_NODE_API_KEY': 'full', 'CC_NODE_READ_KEY': 'read',
       'CC_BACKUP_DB_APP': 'db', 'CC_BACKUP_DATABASE': 'db', 'CC_BACKUP_USER': 'test',
       'CC_V1_INSTANCE': '11' * 32, 'CC_V1_CURATORS': ','.join(CURATORS), 'CC_V1_MAX_HOPS': '4'}
EXPORT = {'envelopes': [], 'commitment': EXPECTED.empty_commitment}
BACKUP = {'state': 'bound', 'counts': {'identity': 1, 'rule_identity': 1},
          'commitment': EXPECTED.empty_commitment, 'commitment_basis': 'x', 'dump_sha256': 'd'}


def machine(group, state='stopped', schedule=None, digest=OLD, id=None):
    """Shaped like test_deploy_digest.fleet(); `group=None` has no process group."""
    config = {'image': 'registry.fly.io/timepoint-clockchain-prod@' + digest,
              'metadata': {'fly_process_group': group} if group else {},
              'mounts': [{'path': '/data/media'}], 'restart': {'policy': 'no'}}
    if schedule:
        config['schedule'] = schedule
    return dict(id=id or group or 'unnamed', state=state, image_ref={'digest': digest}, config=config)


def app(state='started', **kw):
    return machine('app', state, **kw)


def write(directory, text):
    path = Path(directory) / 'fly.toml'
    path.write_text(text)
    return str(path)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir, self.text = tmp.name, Path(FLY).read_text()

    def test_checked_in_config_is_v1_only(self):
        self.assertEqual(subject.check_config(FLY, True)['deploy']['release_command'], 'cc-node provision-v1')
        with self.assertRaisesRegex(ValueError, 'v0 release mode cannot deploy a v1'):
            subject.check_config(FLY, False)

    def test_v0_config_is_v0_only(self):
        subject.check_config(write(self.dir, V0_CONFIG), False)
        with self.assertRaisesRegex(ValueError, 'CC_NODE_LEDGER=v1'):
            subject.check_config(write(self.dir, V0_CONFIG), True)
        # Either v1 marker alone is enough for a v0 mode to refuse.
        for text in (V0_CONFIG.replace('[env]\n', '[env]\nCC_NODE_LEDGER = "v1"\n'),
                     V0_CONFIG.replace('cc-node migrate', 'cc-node provision-v1')):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'v0 release mode'):
                subject.check_config(write(self.dir, text), False)

    def test_v1_requirements_each_refused(self):
        checks = re.compile(r'\n  \[\[http_service\.checks\]\]\n(?:    .*\n)+')
        hops = 'CC_V1_MAX_HOPS = "4"'
        for name, mutate, message in (
                ('health path', lambda t: t.replace('path = "/health"', 'path = "/ready"'), '/health'),
                ('no health check', lambda t: checks.sub('\n', t), '/health'),
                ('v0 release command', lambda t: t.replace('"cc-node provision-v1"', '"cc-node migrate"'),
                 'release_command'),
                ('no ledger', lambda t: t.replace('CC_NODE_LEDGER = "v1"', ''), 'CC_NODE_LEDGER=v1'),
                ('hops 5', lambda t: t.replace(hops, 'CC_V1_MAX_HOPS = "5"'), 'CC_V1_MAX_HOPS'),
                ('hops absent', lambda t: t.replace(hops, ''), 'CC_V1_MAX_HOPS'),
                ('hops integer', lambda t: t.replace(hops, 'CC_V1_MAX_HOPS = 4'), 'CC_V1_MAX_HOPS')):
            text = mutate(self.text)
            self.assertNotEqual(text, self.text, name)
            with self.subTest(name), self.assertRaisesRegex(ValueError, message):
                subject.check_config(write(self.dir, text), True)


class TickGuardTests(unittest.TestCase):
    def test_single_started_app_without_tick_passes(self):
        self.assertEqual(verify_v1([app()], OLD), {'app': 'app', 'app_digest': OLD, 'ticks': []})

    def test_stopped_unscheduled_tick_passes(self):
        self.assertEqual(verify_v1([app(), machine('tick')], OLD)['ticks'], ['tick'])

    def test_scheduled_tick_refused_even_when_stopped(self):
        with self.assertRaisesRegex(ValueError, "tick has schedule 'hourly'"):
            verify_v1([app(), machine('tick', schedule='hourly')])

    def test_running_tick_refused_without_schedule(self):
        for state in ('started', 'starting'):
            with self.subTest(state), self.assertRaisesRegex(ValueError, 'tick machine is ' + state):
                verify_v1([app(), machine('tick', state)])

    def test_any_scheduled_machine_refused(self):
        for fleet, message in (([app(), machine('worker', schedule='daily')], "worker has schedule 'daily'"),
                               ([app(), machine(None, schedule='hourly')], 'unnamed has schedule'),
                               ([app(schedule='hourly')], "app has schedule 'hourly'")):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                verify_v1(fleet)

    def test_running_non_app_machine_refused(self):
        for fleet, message in (([app(), machine('worker', 'started')], 'running machine in group worker'),
                               ([app(), machine(None, 'started')], 'running machine in group unnamed')):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                verify_v1(fleet)

    def test_exactly_one_started_app_on_expected_digest(self):
        for fleet, message in (([app('stopped')], 'app is not started'),
                               ([], 'one app machine, found 0'),
                               ([machine('tick')], 'one app machine, found 0'),
                               ([app(), app(id='app2')], 'one app machine, found 2')):
            with self.subTest(message), self.assertRaisesRegex(ValueError, message):
                verify_v1(fleet)
        with self.assertRaisesRegex(ValueError, 'app release digest differs'):
            verify_v1([app()], NEW_DIGEST)


class PromoteV1Tests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp, self.runs = Path(tmp.name), 0

    SECRETS = [{'name': n, 'digest': 'd' * 16, 'status': 'Staged'} for n in
               ('CC_NODE_API_KEY', 'CC_NODE_READ_KEY', 'CC_V1_CURATORS', 'CC_V1_INSTANCE', 'DATABASE_URL')]

    def promote(self, before=None, raises=None, *, fail_checks=False, backup=None, env=None, drop=(),
                extra=(), config=FLY, after_digest=NEW_DIGEST, secrets=None, list_errors=0):
        self.runs += 1
        self.evidence, self.log = self.tmp / f'evidence-{self.runs}', []

        def fly(*args):
            self.log.append(('fly', args))
            if args[:2] == ('secrets', 'list'):
                return json.dumps(self.SECRETS if secrets is None else secrets)
            return ''

        def capture_v1(*args, **kw):
            self.log.append(('capture_v1', args))
            return dict(BACKUP, **((backup or {}) if 'export' in kw else {}))

        def check(*args, **kw):
            if fail_checks:
                raise AssertionError('synthetic check failure')
            return {'commitment': EXPECTED.empty_commitment, 'checks': []}

        def http(base, method, path, key=None, body=None):
            return (200, json.dumps(EXPORT).encode()) if (method, path) == ('GET', '/v1/export') else (404, b'')

        argv = ['deploy_digest.py', '--app', 'production', '--image', NEW, '--sha', SHA,
                '--evidence', str(self.evidence), '--v1-fresh', '--config', config, *extra]
        m, self.stderr = SimpleNamespace(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, dict(ENV, **(env or {}))))
            for name in drop:
                del os.environ[name]
            stack.enter_context(patch('sys.argv', argv))
            stack.enter_context(patch.object(subject.time, 'sleep'))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            listing = [before or [app()]] + [subprocess.CalledProcessError(1, ['flyctl'])] * list_errors
            for name, effect in (('fly', fly), ('machines', listing + [[app(digest=after_digest)]] * 12),
                                 ('capture_v1', capture_v1), ('check_v1_zero', check), ('http', http),
                                 ('seed', None), ('capture', None), ('wake', None), ('request', None)):
                setattr(m, name, stack.enter_context(patch.object(subject, name, side_effect=effect)))
            m.acceptance_seed = stack.enter_context(patch('acceptance_seed.seed'))
            if raises:
                with self.assertRaises(raises) as self.error:
                    subject.main()
            else:
                subject.main()
        return m

    def fly_calls(self):
        return [args for kind, args in self.log if kind == 'fly']

    def assert_read_only(self, m):
        """No synthetic write, no v0 publication control, no tick, no v0 path."""
        for args in self.fly_calls():
            self.assertFalse(any('cc-publisher' in str(a) for a in args), args)
            self.assertNotIn('ssh', args)
            self.assertNotEqual(args[:2], ('machine', 'update'))
        for call in m.check_v1_zero.call_args_list:
            self.assertFalse(call.kwargs.get('probe_candidates', False))
            self.assertEqual(call.args[2:4], ('full', 'read'))
        self.assertEqual({c.args[1] for c in m.http.call_args_list} - {'GET'}, set())
        for mock in (m.seed, m.acceptance_seed, m.capture, m.wake, m.request):
            mock.assert_not_called()

    def test_success_backs_up_around_one_plain_deploy_and_leaves_entry_to_owner(self):
        m = self.promote()
        result = json.loads((self.evidence / 'acceptance.json').read_text())
        self.assertEqual((result['entry'], result['tick']), ('left_to_owner', 'none_running_or_scheduled'))
        self.assertEqual(result['backup_after']['commitment'], EXPECTED.empty_commitment)
        self.assertEqual([kind if kind == 'capture_v1' else args[0] for kind, args in self.log
                          if kind == 'capture_v1' or args[0] == 'deploy'], ['capture_v1', 'deploy', 'capture_v1'])
        first, second = m.capture_v1.call_args_list
        self.assertEqual((first.kwargs['fresh'], second.kwargs['fresh']), (True, True))
        self.assertIsNone(first.kwargs.get('export'))
        self.assertEqual(second.kwargs['export'], EXPORT)
        self.assertEqual(first.args[4].summary(), EXPECTED.summary())
        deploy, = [args for args in self.fly_calls() if args[0] == 'deploy']
        self.assertNotIn('--skip-release-command', deploy)
        self.assertEqual((deploy[deploy.index('--image') + 1], deploy[deploy.index('--config') + 1]), (NEW, FLY))
        self.assertTrue(m.http.called)
        self.assert_read_only(m)

    def test_never_touches_publisher_tick_or_writes(self):
        self.assert_read_only(self.promote())
        self.assert_read_only(self.promote(raises=AssertionError, fail_checks=True))

    def test_scheduled_or_running_tick_refused_before_backup_or_deploy(self):
        for before, message in (([app(), machine('tick', schedule='hourly')], 'schedule'),
                                ([app(), machine('tick', 'started')], 'tick machine is started')):
            with self.subTest(message):
                m = self.promote(before, ValueError)
                self.assertRegex(str(self.error.exception), message)
                m.capture_v1.assert_not_called()
                m.fly.assert_not_called()
                m.check_v1_zero.assert_not_called()

    def test_failure_after_deploy_records_no_rollback_and_reraises(self):
        m = self.promote(raises=AssertionError, fail_checks=True)
        self.assertEqual(str(self.error.exception), 'synthetic check failure')
        self.assertEqual(m.check_v1_zero.call_count, 12)
        self.assertTrue((self.evidence / 'FAILED').exists())
        self.assertFalse((self.evidence / 'acceptance.json').exists())
        recovery = json.loads((self.evidence / 'recovery.json').read_text())
        self.assertEqual(recovery['status'], 'NOT RUN')
        self.assertEqual(recovery['previous_image'], 'registry.fly.io/timepoint-clockchain-prod@' + OLD)
        self.assertEqual([args[0] for args in self.fly_calls()].count('deploy'), 1)
        self.assertFalse(any('--skip-release-command' in args for args in self.fly_calls()))
        self.assertEqual(m.capture_v1.call_count, 1)

    def test_app_left_on_the_old_digest_fails_after_retries(self):
        # The deploy "succeeded" but the app still runs the previous image.
        m = self.promote(raises=ValueError, after_digest=OLD)
        self.assertEqual(str(self.error.exception), 'app release digest differs')
        self.assertEqual(m.machines.call_count, 13)
        self.assertTrue((self.evidence / 'FAILED').exists())
        self.assertFalse((self.evidence / 'acceptance.json').exists())

    def test_secret_overrides_or_missing_v1_secrets_refused_before_backup_or_deploy(self):
        cases = [(self.SECRETS + [{'name': 'CC_V1_MAX_HOPS', 'digest': 'e', 'status': 'Deployed'}],
                  'override fly.toml .env.; unset them .--stage.: CC_V1_MAX_HOPS'),
                 (self.SECRETS + [{'name': 'CC_NODE_POSTURE'}, {'name': 'CC_NODE_LEDGER'}],
                  'CC_NODE_LEDGER, CC_NODE_POSTURE'),
                 ([e for e in self.SECRETS if e['name'] != 'CC_V1_CURATORS'],
                  'v1 secrets missing: CC_V1_CURATORS'),
                 ({'name': 'DATABASE_URL'}, 'unexpected')]
        for secrets, message in cases:
            with self.subTest(message):
                m = self.promote(raises=ValueError, secrets=secrets)
                self.assertRegex(str(self.error.exception), message)
                m.capture_v1.assert_not_called()
                self.assertFalse(any(args[0] == 'deploy' for args in self.fly_calls()))

    def test_secret_census_reads_names_only_in_either_key_casing(self):
        capitalized = [{'Name': e['name'], 'Digest': e['digest']} for e in self.SECRETS]
        self.promote(secrets=capitalized)
        rollback = json.loads((self.evidence / 'rollback.json').read_text())
        self.assertEqual(rollback['secret_names'], sorted(e['name'] for e in self.SECRETS))
        self.assertNotIn('d' * 16, (self.evidence / 'rollback.json').read_text())

    def test_transient_machine_listing_failure_after_deploy_is_retried(self):
        # Production is already deployed; one failed `flyctl machines list` must not report FAILED.
        self.promote(list_errors=1)
        self.assertTrue((self.evidence / 'acceptance.json').exists())
        self.assertFalse((self.evidence / 'FAILED').exists())
        # The retry is bounded: a listing that never recovers still fails.
        self.promote(raises=subprocess.CalledProcessError, list_errors=12)
        self.assertTrue((self.evidence / 'FAILED').exists())

    def test_post_deploy_backup_must_hold_checked_commitment(self):
        for backup in ({'commitment': OTHER_COMMITMENT}, {'commitment': None}, {'state': 'provisioned_unbound'}):
            with self.subTest(backup=backup):
                m = self.promote(raises=ValueError, backup=backup)
                self.assertRegex(str(self.error.exception), 'post-deploy backup')
                self.assertEqual(m.capture_v1.call_count, 2)
                self.assertTrue((self.evidence / 'FAILED').exists())
                self.assertFalse((self.evidence / 'acceptance.json').exists())

    def test_identity_and_config_refused_before_any_fly_call(self):
        v0 = write(self.tmp, V0_CONFIG)
        for kw, message in (({'drop': ('CC_V1_INSTANCE',)}, 'CC_V1_INSTANCE'),
                            ({'drop': ('CC_V1_CURATORS',)}, 'CC_V1_CURATORS'),
                            ({'env': {'CC_V1_MAX_HOPS': '5'}}, 'CC_V1_MAX_HOPS must be 4'),
                            ({'env': {'CC_V1_CURATORS': ','.join(reversed(CURATORS))}}, 'strictly sorted'),
                            ({'config': v0}, 'CC_NODE_LEDGER=v1'),
                            ({'env': {'CC_NODE_READ_KEY': 'full'}}, 'Distinct full and read-only')):
            with self.subTest(message):
                m = self.promote(raises=ValueError, **kw)
                self.assertRegex(str(self.error.exception), message)
                for mock in (m.fly, m.machines, m.capture_v1, m.check_v1_zero):
                    mock.assert_not_called()

    def test_v1_fresh_is_production_only_and_exclusive(self):
        for flag, message in (('--acceptance', 'production only'), ('--zero-events', 'not allowed with'),
                              ('--empty-corpus', 'not allowed with')):
            with self.subTest(flag):
                m = self.promote(raises=SystemExit, extra=[flag])
                self.assertIn(message, self.stderr.getvalue())
                m.fly.assert_not_called()
                m.machines.assert_not_called()


class Stop(Exception):
    """Ends release.main() at acceptance, right after validation."""


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.evidence = self.tmp / 'evidence'

    def output(self, *args):
        self.commands.append(args)
        for prefix, reply in ((('git', 'rev-parse', '--show-toplevel'), str(ROOT)),
                              (('git', 'status', '--porcelain'), ''),
                              (('git', 'rev-parse', 'HEAD'), SHA),
                              (('git', 'ls-remote'), f'{SHA}\trefs/heads/main'),
                              (('gh', 'run', 'list'), json.dumps(
                                  [{'headSha': SHA, 'status': 'completed', 'conclusion': 'success'}])),
                              (('flyctl', 'auth', 'docker'), ''),
                              (('flyctl', 'ips', 'list'), '[]')):
            if args[:len(prefix)] == prefix:
                return reply
        raise AssertionError(f'unexpected command {args}')

    def release(self, *flags, raises=Stop, env=None, drop=(), config=FLY, accepted=Stop):
        self.commands, self.stderr = [], io.StringIO()
        argv = ['release.py', '--app', 'timepoint-clockchain-prod', '--image', NEW, '--config', config,
                '--evidence', str(self.evidence), *flags]
        m = SimpleNamespace()
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, dict(ENV, HOME=str(self.tmp / 'home'), **(env or {}))))
            for name in drop:
                del os.environ[name]
            stack.enter_context(patch('sys.argv', argv))
            stack.enter_context(contextlib.redirect_stderr(self.stderr))
            stack.enter_context(patch.object(release, 'output', side_effect=self.output))
            m.chdir = stack.enter_context(patch.object(release.os, 'chdir'))
            m.accept = stack.enter_context(patch.object(release, 'accept', side_effect=accepted))
            m.accept_v1 = stack.enter_context(patch.object(release, 'accept_v1', side_effect=accepted))
            m.run = stack.enter_context(patch.object(release.subprocess, 'run'))
            m.popen = stack.enter_context(patch.object(release.subprocess, 'Popen'))
            m.popen.return_value.poll.return_value = None
            stack.enter_context(patch.object(release, 'request', return_value=(200, b'{}')))
            m.stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            if raises:
                with self.assertRaises(raises):
                    release.main()
            else:
                release.main()
        return m

    def assert_refused(self, m, message):
        self.assertIn(message, self.stderr.getvalue())
        m.accept_v1.assert_not_called()
        m.accept.assert_not_called()
        self.assertFalse(any(c[0] == 'flyctl' for c in self.commands))
        self.assertFalse(self.evidence.exists())

    def test_mode_flag(self):
        modes = dict(v1_fresh=False, empty_corpus=False, zero_events=False)
        self.assertEqual(release.mode_flag(argparse.Namespace(**modes)), [])
        for name, flag in (('v1_fresh', '--v1-fresh'), ('empty_corpus', '--empty-corpus'),
                           ('zero_events', '--zero-events')):
            self.assertEqual(release.mode_flag(argparse.Namespace(**dict(modes, **{name: True}))), [flag])

    def test_v1_fresh_validates_then_runs_v1_acceptance(self):
        m = self.release('--v1-fresh')
        m.accept_v1.assert_called_once_with(NEW, SHA, self.evidence.resolve() / 'acceptance')
        m.accept.assert_not_called()
        m.chdir.assert_called_once_with(ROOT)
        self.assertIn(('flyctl', 'auth', 'docker'), self.commands)

    def test_v1_fresh_promotes_with_v1_fresh_flag(self):
        m = self.release('--v1-fresh', raises=None, accepted=None)
        (command,), kw = m.run.call_args
        self.assertEqual(command[1:2] + command[-1:], ['ops/deploy_digest.py', '--v1-fresh'])
        self.assertEqual(command[command.index('--config') + 1], FLY)
        self.assertTrue(kw['env']['CC_NODE_URL'].startswith('http://127.0.0.1:'))
        self.assertIn('inaugural entry remains', m.stdout.getvalue())

    def test_v1_identity_refused_before_acceptance(self):
        for kw, message in (({'drop': ('CC_V1_CURATORS',)}, 'CC_V1_CURATORS'),
                            ({'env': {'CC_V1_MAX_HOPS': '3'}}, 'CC_V1_MAX_HOPS must be 4'),
                            ({'env': {'CC_V1_CURATORS': ','.join(reversed(CURATORS))}}, 'strictly sorted'),
                            ({'env': {'CC_NODE_READ_KEY': ENV['CC_NODE_API_KEY']}}, 'distinct full and read-only')):
            with self.subTest(message):
                self.assert_refused(self.release('--v1-fresh', raises=SystemExit, **kw), message)

    def test_v1_fresh_excludes_other_modes(self):
        for flag in ('--zero-events', '--empty-corpus'):
            with self.subTest(flag):
                m = self.release('--v1-fresh', flag, raises=SystemExit)
                self.assert_refused(m, 'not allowed with argument')
                self.assertEqual(self.commands, [])

    def test_mode_and_config_must_match(self):
        self.assert_refused(self.release(raises=SystemExit, env={'CC_SMOKE_ENTITY': '1'}),
                            'v0 release mode cannot deploy a v1')
        v0 = write(self.tmp, V0_CONFIG)
        self.assert_refused(self.release('--v1-fresh', raises=SystemExit, config=v0), 'CC_NODE_LEDGER=v1')
        # The same v0 run with a v0 config does reach v0 acceptance.
        m = self.release(env={'CC_SMOKE_ENTITY': '1'}, config=v0)
        m.accept.assert_called_once()
        m.accept_v1.assert_not_called()


if __name__ == '__main__':
    unittest.main()
