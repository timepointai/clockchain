"""owner_jobs: private env files and directories, redaction, status, launchd plists.

Every file lives in a temporary directory outside the checkout; launchctl and
osascript are never run (an injected runner records what would be run).
"""
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also runnable by file path from the root
import monitor_v1
import owner_jobs
from owner_jobs import ConfigError, JobLock, REDACTED

CURATORS = ['8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394',
            '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c',
            'ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c',
            'ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1']


class TempDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()
        # The checkout guard would refuse everything if the temp dir were inside it.
        self.assertFalse(self.dir.is_relative_to(owner_jobs.ROOT))

    def env_file(self, text, mode=0o600, name='job.env', directory=None):
        path = (directory or self.dir) / name
        path.write_text(text)
        path.chmod(mode)
        return path


class EnvFileTests(TempDirTest):
    def test_private_file_parses_names_values_comments_and_blanks(self):
        path = self.env_file('# a comment\n\nCC_FLY_APP=cc-test-app\n  CC_URL=http://x.invalid/?a=b  \n'
                             'CC_EMPTY=\n   # indented comment\n')
        self.assertEqual(owner_jobs.load_env_file(path),
                         {'CC_FLY_APP': 'cc-test-app', 'CC_URL': 'http://x.invalid/?a=b', 'CC_EMPTY': ''})

    def test_stricter_than_0600_is_accepted(self):
        path = self.env_file('CC_A=1\n', mode=0o400)
        self.assertEqual(owner_jobs.load_env_file(path), {'CC_A': '1'})

    def test_group_or_other_access_is_refused(self):
        for mode in (0o640, 0o644, 0o604, 0o660, 0o610):
            with self.subTest(mode=oct(mode)):
                path = self.env_file('CC_A=secret-value\n', mode=mode)
                with self.assertRaisesRegex(ConfigError, 'chmod 600'):
                    owner_jobs.load_env_file(path)

    def test_symlink_is_refused_even_to_a_private_file(self):
        target = self.env_file('CC_A=secret-value\n')
        link = self.dir / 'link.env'
        link.symlink_to(target)
        with self.assertRaisesRegex(ConfigError, 'regular file'):
            owner_jobs.load_env_file(link)

    def test_directory_and_missing_file_are_refused(self):
        with self.assertRaisesRegex(ConfigError, 'regular file'):
            owner_jobs.load_env_file(self.dir)
        with self.assertRaisesRegex(ConfigError, 'does not exist'):
            owner_jobs.load_env_file(self.dir / 'absent.env')

    def test_file_inside_the_checkout_is_refused(self):
        checkout = self.dir / 'checkout'
        checkout.mkdir()
        inside = self.env_file('CC_A=secret-value\n', directory=checkout)
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.load_env_file(inside, root=checkout)
        # A link from outside that points into the checkout is refused as well.
        link = self.dir / 'outside.env'
        link.symlink_to(inside)
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.load_env_file(link, root=checkout)
        # The default root is this repository; the guard fires before any file access.
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.load_env_file(owner_jobs.ROOT / 'ops' / 'no-such-owner.env')
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.load_env_file(owner_jobs.ROOT)

    def test_malformed_lines_are_refused_without_echoing_them(self):
        for line in ('cc_lower=secret-value', 'NO_SEPARATOR secret-value', '1CC=secret-value',
                     'export CC_A=secret-value', 'CC-A=secret-value', '=secret-value'):
            with self.subTest(line=line):
                path = self.env_file(f'# ok\nCC_OK=1\n{line}\n')
                with self.assertRaises(ConfigError) as caught:
                    owner_jobs.load_env_file(path)
                self.assertEqual(str(caught.exception), 'env file line 3 is not NAME=value')
                self.assertNotIn('secret-value', str(caught.exception))

    def test_require_names_missing_or_empty_values_only(self):
        env = {'CC_A': 'secret-a', 'CC_B': '', 'CC_C': 'secret-c'}
        self.assertEqual(owner_jobs.require(env, 'CC_A', 'CC_C'), ['secret-a', 'secret-c'])
        with self.assertRaises(ConfigError) as caught:
            owner_jobs.require(env, 'CC_A', 'CC_B', 'CC_D')
        self.assertEqual(str(caught.exception), 'env file needs: CC_B, CC_D')


class PrivateDirTests(TempDirTest):
    def test_creates_missing_directory_0700(self):
        path = owner_jobs.private_dir(self.dir / 'state' / 'nested')
        self.assertTrue(path.is_dir())
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_existing_0700_is_accepted_and_open_modes_refused(self):
        ok = self.dir / 'ok'
        ok.mkdir(mode=0o700)
        self.assertEqual(owner_jobs.private_dir(ok), ok)
        for mode in (0o755, 0o750, 0o701, 0o707):
            with self.subTest(mode=oct(mode)):
                path = self.dir / f'open-{mode:o}'
                path.mkdir()
                path.chmod(mode)
                with self.assertRaisesRegex(ConfigError, 'mode 0700'):
                    owner_jobs.private_dir(path)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)  # not "fixed" silently

    def test_symlinked_directory_is_refused(self):
        real = self.dir / 'real'
        real.mkdir(mode=0o700)
        link = self.dir / 'link'
        link.symlink_to(real)
        with self.assertRaisesRegex(ConfigError, 'real directory'):
            owner_jobs.private_dir(link)

    def test_inside_checkout_is_refused_and_not_created(self):
        checkout = self.dir / 'checkout'
        checkout.mkdir()
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.private_dir(checkout / 'state', root=checkout)
        self.assertFalse((checkout / 'state').exists())
        target = owner_jobs.ROOT / 'ops' / 'no-such-private-state'
        with self.assertRaisesRegex(ConfigError, 'outside the public checkout'):
            owner_jobs.private_dir(target)
        self.assertFalse(target.exists())


class RedactTests(unittest.TestCase):
    def test_every_value_of_four_or_more_characters_is_replaced_longest_first(self):
        env = {'CC_LONG': 'abcdefgh', 'CC_SHORT': 'abcd', 'CC_TINY': 'xyz', 'CC_EMPTY': '',
               'CC_KEY': 's3cr3t-key'}
        text = 'long=abcdefgh short=abcd tiny=xyz key=s3cr3t-key again=s3cr3t-key'
        out = owner_jobs.redact(text, env)
        self.assertEqual(out, f'long={REDACTED} short={REDACTED} tiny=xyz key={REDACTED} again={REDACTED}')
        self.assertNotIn('efgh', out)  # shortest-first would leave a tail of the longer value

    def test_non_strings_are_rendered_then_redacted(self):
        error = RuntimeError('failed with token s3cr3t-key')
        self.assertEqual(owner_jobs.redact(error, {'K': 's3cr3t-key'}), f'failed with token {REDACTED}')
        self.assertEqual(owner_jobs.redact('nothing here', {}), 'nothing here')


class StatusTests(TempDirTest):
    def test_write_status_replaces_with_a_0600_json_document(self):
        path = self.dir / 'status.json'
        path.write_text('old')
        path.chmod(0o644)
        doc = {'schema': 'x', 'result': 'ok', 'n': 1}
        self.assertEqual(owner_jobs.write_status(path, doc), doc)
        self.assertEqual(json.loads(path.read_text()), doc)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ['status.json'])

    def test_failed_write_leaves_the_previous_status_intact(self):
        path = self.dir / 'status.json'
        owner_jobs.write_status(path, {'result': 'ok'})
        with patch.object(owner_jobs.json, 'dump', side_effect=TypeError('boom')):
            with self.assertRaises(TypeError):
                owner_jobs.write_status(path, {'result': 'alert'})
        self.assertEqual(json.loads(path.read_text()), {'result': 'ok'})

    def test_stamp_is_utc_and_sortable(self):
        import datetime
        moment = datetime.datetime(2026, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
        self.assertEqual(owner_jobs.stamp(moment), '20260102T030405Z')
        self.assertRegex(owner_jobs.stamp(), r'^\d{8}T\d{6}Z$')


class NotifyTests(unittest.TestCase):
    def test_title_and_message_travel_as_argv_after_the_script(self):
        calls = []

        def runner(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0)
        title = 'Title" & do shell script "touch /tmp/x'
        message = "msg'); display dialog (\"x"
        self.assertTrue(owner_jobs.notify(title, message, runner=runner))
        (args, kwargs), = calls
        self.assertEqual(args[0], 'osascript')
        end = args.index('end run')
        self.assertEqual(args[end + 1:], [title, message])
        script = args[1:end + 1]
        self.assertEqual(script[0::2], ['-e'] * (len(script) // 2))
        self.assertTrue(all(title not in s and message not in s for s in script))
        self.assertIn('item 1 of argv', ' '.join(script))
        self.assertIn('item 2 of argv', ' '.join(script))
        self.assertTrue(kwargs.get('capture_output'))
        self.assertIn('timeout', kwargs)

    def test_failures_return_false(self):
        self.assertFalse(owner_jobs.notify('t', 'm', runner=lambda a, **k: subprocess.CompletedProcess(a, 1)))

        def timeout(args, **kwargs):
            raise subprocess.TimeoutExpired(args, 30)
        self.assertFalse(owner_jobs.notify('t', 'm', runner=timeout))

    def test_missing_osascript_returns_false(self):
        with tempfile.TemporaryDirectory() as empty, patch.dict(os.environ, {'PATH': empty}):
            self.assertFalse(owner_jobs.notify('t', 'm'))


class JobLockTests(TempDirTest):
    def test_second_acquire_fails_while_the_first_is_held(self):
        with JobLock(self.dir, 'backup') as first:
            self.assertTrue(first)
            with JobLock(self.dir, 'backup') as second:
                self.assertFalse(second)
            with JobLock(self.dir, 'monitor') as other:
                self.assertTrue(other)
        with JobLock(self.dir, 'backup') as again:
            self.assertTrue(again)
        self.assertTrue((self.dir / 'backup.lock').exists())

    def test_lock_is_held_against_another_process(self):
        probe = ('import fcntl, sys\nf = open(sys.argv[1], "a")\n'
                 'try:\n    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)\nexcept BlockingIOError:\n'
                 '    sys.exit(3)\n')
        with JobLock(self.dir, 'backup') as held:
            self.assertTrue(held)
            result = subprocess.run([sys.executable, '-c', probe, str(self.dir / 'backup.lock')])
            self.assertEqual(result.returncode, 3)
        result = subprocess.run([sys.executable, '-c', probe, str(self.dir / 'backup.lock')])
        self.assertEqual(result.returncode, 0)


class ParseTimeTests(unittest.TestCase):
    def test_valid_times(self):
        for value, want in {'09:00': (9, 0), '7:05': (7, 5), '23:59': (23, 59), '00:00': (0, 0),
                            '19:30': (19, 30)}.items():
            with self.subTest(value=value):
                self.assertEqual(owner_jobs.parse_time(value), want)

    def test_invalid_times(self):
        for value in ('24:00', '9', '09:60', 'ab', '', None, '9:5', '009:00', ' 09:00', '09:00 ',
                      '-1:00', '12:00:00', '９:00'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'HH:MM'):
                owner_jobs.parse_time(value)


class PlistTests(TempDirTest):
    LABEL = 'local.clockchain.test'

    def make(self, **kwargs):
        env = self.env_file('CC_A=1\n')
        data = owner_jobs.plist(self.LABEL, owner_jobs.__file__, env, self.dir / 'logs', **kwargs)
        return plistlib.loads(data), env

    def test_calendar_job(self):
        doc, env = self.make(calendar=(7, 5), python='/usr/bin/python3', path_env='/usr/bin:/bin')
        self.assertEqual(doc['StartCalendarInterval'], {'Hour': 7, 'Minute': 5})
        self.assertNotIn('StartInterval', doc)
        self.assertEqual(doc['Label'], self.LABEL)
        self.assertEqual(doc['ProgramArguments'],
                         ['/usr/bin/python3', str(Path(owner_jobs.__file__).resolve()), 'run',
                          '--env-file', str(env.resolve())])
        self.assertEqual(doc['EnvironmentVariables'], {'PATH': '/usr/bin:/bin'})
        self.assertEqual(doc['StandardOutPath'], str(self.dir / 'logs' / (self.LABEL + '.log')))
        self.assertEqual(doc['StandardErrorPath'], doc['StandardOutPath'])
        self.assertEqual(doc['WorkingDirectory'], str(owner_jobs.ROOT))
        self.assertIs(doc['RunAtLoad'], False)

    def test_interval_job(self):
        doc, env = self.make(interval=900)
        self.assertEqual(doc['StartInterval'], 900)
        self.assertNotIn('StartCalendarInterval', doc)
        self.assertEqual(doc['ProgramArguments'][0], sys.executable)
        self.assertEqual(doc['ProgramArguments'][-3:], ['run', '--env-file', str(env.resolve())])
        self.assertTrue(os.path.isabs(doc['ProgramArguments'][-1]))

    def test_exactly_one_schedule(self):
        with self.assertRaisesRegex(ValueError, 'exactly one schedule'):
            self.make()
        with self.assertRaisesRegex(ValueError, 'exactly one schedule'):
            self.make(calendar=(9, 0), interval=900)

    def test_generated_monitor_plist_never_contains_env_values(self):
        state = self.dir / 'state'
        secrets = {
            'CC_FLY_APP': 'sentinel-fly-app-qz7',
            'CC_V1_INSTANCE': 'a1b2' * 16,
            'CC_V1_CURATORS': ','.join(CURATORS),
            'CC_V1_MAX_HOPS': '4',
            'CC_EXTRA_TOKEN': 'SENTINEL-TOKEN-8f3a1c',
            'CC_NODE_API_KEY': 'SENTINEL-API-KEY-77e2d9',
        }
        env = self.env_file(''.join(f'{k}={v}\n' for k, v in secrets.items())
                            + f'CC_OPS_STATE_DIR={state}\n')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(monitor_v1.main(['generate', '--env-file', str(env)]), 0)
        data = out.getvalue()
        doc = plistlib.loads(data.encode())
        self.assertEqual(doc['ProgramArguments'][-3:], ['run', '--env-file', str(env.resolve())])
        self.assertEqual(doc['StartInterval'], 900)
        values = [v for v in secrets.values() if len(v) >= 4] + CURATORS
        for value in values:
            self.assertNotIn(value, data)
        # The state directory is a path, not a secret: it is where launchd writes the log.
        self.assertEqual(doc['StandardOutPath'], str(state / (monitor_v1.LABEL + '.log')))
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)


class InterpreterTests(TempDirTest):
    """The interpreter a plist pins must be able to run the job; a broken pyexpat must not stop a run."""

    def test_working_interpreter_passes_with_the_job_imports(self):
        self.assertEqual(owner_jobs.check_interpreter(
            sys.executable, ('plistlib', 'pyexpat', 'monitor_v1', 'schedule_backups')), sys.executable)

    def test_missing_import_is_refused_with_an_actionable_message(self):
        with self.assertRaises(ConfigError) as caught:
            owner_jobs.check_interpreter(sys.executable, ('plistlib', 'cc_no_such_module_9f2'))
        message = str(caught.exception)
        self.assertIn('cc_no_such_module_9f2', message)
        self.assertIn('import plistlib, cryptography', message)
        self.assertIn('ops/requirements.txt', message)

    def test_job_imports_name_plistlib_pyexpat_and_cryptography(self):
        self.assertTrue({'plistlib', 'pyexpat', 'cryptography'} <= set(owner_jobs.JOB_IMPORTS))

    def test_a_broken_pyexpat_does_not_stop_a_scheduled_run(self):
        # Simulate a Python whose pyexpat cannot load: importing it raises.
        code = ("import sys; sys.modules['pyexpat'] = None\n"
                "import owner_jobs, monitor_v1, schedule_backups\n"
                "try:\n"
                "    owner_jobs.plist('l', 'x', 'e', '/tmp', interval=900)\n"
                "except ImportError:\n"
                "    print('plist-refused')\n")
        result = subprocess.run([sys.executable, '-c', code], cwd=str(owner_jobs.ROOT / 'ops'),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'plist-refused')

    def test_install_checks_the_interpreter_before_writing_anything(self):
        state = self.dir / 'state'
        env = self.env_file(f'CC_FLY_APP=cc-test-app\nCC_OPS_STATE_DIR={state}\n'
                            f'CC_V1_INSTANCE={"ab" * 32}\nCC_V1_CURATORS={CURATORS[0]}\n'
                            'CC_V1_MAX_HOPS=4\n')
        refusal = ConfigError('interpreter cannot run this job')
        with patch.object(owner_jobs, 'check_interpreter', side_effect=refusal) as check, \
                patch.object(owner_jobs, 'install') as install:
            with self.assertRaises(ConfigError):
                monitor_v1.main(['install', '--env-file', str(env)])
        check.assert_called_once_with(sys.executable, owner_jobs.JOB_IMPORTS + ('monitor_v1',))
        install.assert_not_called()


class LaunchctlTests(TempDirTest):
    LABEL = 'local.clockchain.test'

    def runner(self, path=None):
        calls = []

        def run(args, **kwargs):
            calls.append((list(args), kwargs, path.read_bytes() if path and path.exists() else None))
            return subprocess.CompletedProcess(args, 0)
        return calls, run

    def test_install_boots_out_writes_then_bootstraps(self):
        agents = self.dir / 'LaunchAgents'
        path = agents / (self.LABEL + '.plist')
        domain = f'gui/{os.getuid()}'
        for data in (b'<plist>first</plist>', b'<plist>second</plist>'):
            with self.subTest(data=data):
                calls, run = self.runner(path)
                self.assertEqual(owner_jobs.install(self.LABEL, data, directory=agents, runner=run), path)
                self.assertEqual([c[0] for c in calls],
                                 [['launchctl', 'bootout', f'{domain}/{self.LABEL}'],
                                  ['launchctl', 'bootstrap', domain, str(path)]])
                self.assertNotEqual(calls[0][2], data)  # the new plist is written after bootout
                self.assertEqual(calls[1][2], data)     # and is in place when bootstrapped
                self.assertTrue(calls[1][1].get('check'))
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertEqual(sorted(p.name for p in agents.iterdir()), [self.LABEL + '.plist'])

    def test_failed_bootstrap_propagates(self):
        def run(args, **kwargs):
            if args[1] == 'bootstrap':
                raise subprocess.CalledProcessError(5, args)
            return subprocess.CompletedProcess(args, 3)  # bootout of an unloaded job is fine
        with self.assertRaises(subprocess.CalledProcessError):
            owner_jobs.install(self.LABEL, b'<plist/>', directory=self.dir, runner=run)

    def test_remove_boots_out_and_deletes(self):
        path = self.dir / (self.LABEL + '.plist')
        path.write_bytes(b'<plist/>')
        calls, run = self.runner()
        self.assertTrue(owner_jobs.remove(self.LABEL, directory=self.dir, runner=run))
        self.assertFalse(path.exists())
        self.assertEqual([c[0] for c in calls],
                         [['launchctl', 'bootout', f'gui/{os.getuid()}/{self.LABEL}']])
        calls, run = self.runner()
        self.assertFalse(owner_jobs.remove(self.LABEL, directory=self.dir, runner=run))
        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
