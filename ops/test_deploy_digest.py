import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deploy_digest as subject


SHA = 'b' * 40
OLD = 'sha256:' + 'a' * 64
NEW = 'registry.fly.io/timepoint-clockchain-prod@sha256:' + 'b' * 64


def fleet():
    # Measured production representation: bare digest on app; tag+digest on tick.
    return [dict(id=g, state='started' if g == 'app' else 'stopped',
                 image_ref={'digest': OLD},
                 config={'image': 'registry.fly.io/timepoint-clockchain-prod' +
                         (':git-old' if g == 'tick' else '') + '@' + OLD,
                         'metadata': {'fly_process_group': g},
                         'mounts': [{'path': '/data/media'}], 'schedule': 'hourly',
                         'restart': {'policy': 'no'}}) for g in ('app', 'tick')]


class PromotionTests(unittest.TestCase):
    def test_only_rollback_skips_old_migrator(self):
        with patch.object(subject, 'fly') as fly:
            subject.deploy('acceptance', 'fly.toml', NEW)
            self.assertNotIn('--skip-release-command', fly.call_args.args)
            subject.deploy('acceptance', 'fly.toml', NEW, rollback=True)
            self.assertIn('--skip-release-command', fly.call_args.args)

    def test_machine_references_keep_digest_with_or_without_existing_tag(self):
        self.assertEqual(subject.machine_image(NEW, 'git-' + SHA),
                         NEW.replace('@', ':git-' + SHA + '@'))
        tick = fleet()[1]
        self.assertEqual(subject.previous_image(tick), tick['config']['image'])
        app = fleet()[0]
        self.assertEqual(subject.previous_image(app),
                         app['config']['image'])
        # A floating historical tag still needs the machine's resolved digest.
        tick['config']['image'] = 'registry.fly.io/timepoint-clockchain-prod:older-tag'
        self.assertEqual(subject.previous_image(tick), tick['config']['image'] + '@' + OLD)

    def run_promotion(self, directory, fail=None, pause_fails=False, recovery_bad=False,
                      acceptance=False, bootstrap=False):
        before = [] if bootstrap else fleet()
        if acceptance and before:
            before = before[:1]
        after = copy.deepcopy(before)
        for machine in after:
            machine['image_ref']['digest'] = NEW.split('@')[1]
        restored = copy.deepcopy(before)
        if recovery_bad:
            restored[0]['image_ref']['digest'] = NEW.split('@')[1]
        calls = []

        def fly(*args):
            calls.append(args)
            if args[:2] == ('ssh', 'console'):
                if args[-1] == 'cc-publisher status':
                    return '{"paused":true}'
                if pause_fails and 'deployment-failed' in args[-1]:
                    raise subprocess.CalledProcessError(1, ['redacted'])
            if args[0] == 'deploy' and fail == 'migrate' and '--skip-release-command' not in args:
                raise subprocess.CalledProcessError(101, ['new migration failed'])
            if args[0] == 'deploy' and fail == 'recovery' and '--skip-release-command' in args:
                raise subprocess.CalledProcessError(1, ['recovery failed'])
            return ''

        def request(url, path, key=None):
            return (200, b'{"build":"old-build"}') if path == '/health' else (200, b'{}')

        def check(*args):
            if fail in ('checks', 'recovery'):
                raise AssertionError('original promotion failure')
            return {'checks': ['stubbed HTTP boundary']}

        machine_calls = [before]
        if fail != 'migrate':
            machine_calls += [after] * (12 if fail in ('checks', 'recovery') else 1)
        machine_calls += [restored] * 12
        argv = ['deploy_digest.py', '--app', 'acceptance' if acceptance else 'production',
                '--image', NEW, '--sha', SHA, '--evidence', str(directory)]
        if acceptance:
            argv += ['--acceptance']
        env = {'CC_NODE_URL': 'https://example.invalid', 'CC_NODE_API_KEY': 'full',
               'CC_NODE_READ_KEY': 'read', 'CC_SMOKE_ENTITY': '1',
               'CC_BACKUP_DB_APP': 'db', 'CC_BACKUP_DATABASE': 'db', 'CC_BACKUP_USER': 'test'}
        with patch.dict(os.environ, env), patch('sys.argv', argv), \
                patch.object(subject, 'fly', side_effect=fly), \
                patch.object(subject, 'machines', side_effect=machine_calls), \
                patch.object(subject, 'request', side_effect=request, create=True), \
                patch.object(subject, 'check', side_effect=check), \
                patch.object(subject, 'capture'), patch.object(subject, 'wake'), \
                patch.object(subject.time, 'sleep'):
            if fail:
                with self.assertRaises(subprocess.CalledProcessError if fail == 'migrate' else AssertionError) as error:
                    subject.main()
                if fail != 'migrate':
                    self.assertEqual(str(error.exception), 'original promotion failure')
            else:
                subject.main()
        return calls

    def test_success_pins_tick_to_release_tag_and_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = self.run_promotion(directory)
            update = next(c for c in calls if c[:2] == ('machine', 'update'))
            self.assertEqual(update[update.index('--image') + 1],
                             NEW.replace('@', ':git-' + SHA + '@'))
            self.assertIn('--skip-start', update)
            self.assertTrue((Path(directory) / 'acceptance.json').exists())

    def test_failed_checks_restore_both_images_without_rerunning_migrations(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = self.run_promotion(directory, fail='checks')
            recovery = json.loads((Path(directory) / 'recovery.json').read_text())
            self.assertEqual(recovery['status'], 'PASS')
            self.assertFalse((Path(directory) / 'acceptance.json').exists())
            rollback = [c for c in calls if c[0] == 'deploy'][-1]
            self.assertIn('--skip-release-command', rollback)
            self.assertTrue(rollback[rollback.index('--image') + 1].endswith('@' + OLD))
            self.assertFalse(any('resume' in str(c) for c in calls))

    def test_release_command_failure_also_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_promotion(directory, fail='migrate')
            self.assertEqual(json.loads((Path(directory) / 'recovery.json').read_text())['status'], 'PASS')

    def test_pause_failure_does_not_prevent_app_or_tick_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = self.run_promotion(directory, fail='checks', pause_fails=True)
            steps = json.loads((Path(directory) / 'recovery.json').read_text())['steps']
            self.assertTrue(steps['pause_before'].startswith('FAIL'))
            self.assertEqual(steps['app'], 'PASS')
            self.assertEqual(steps['tick'], 'PASS')
            self.assertEqual(len([c for c in calls if c[0] == 'deploy']), 2)

    def test_recovery_failure_preserves_original_error_and_attempts_tick(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_promotion(directory, fail='recovery')
            recovery = json.loads((Path(directory) / 'recovery.json').read_text())
            self.assertEqual(recovery['status'], 'FAIL')
            self.assertEqual(recovery['steps']['tick'], 'PASS')

    def test_wrong_recovery_digest_cannot_report_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            self.run_promotion(directory, fail='checks', recovery_bad=True)
            self.assertEqual(json.loads((Path(directory) / 'recovery.json').read_text())['status'], 'FAIL')

    def test_empty_acceptance_has_no_rollback_to_invent(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = self.run_promotion(directory, fail='migrate', acceptance=True, bootstrap=True)
            self.assertEqual(json.loads((Path(directory) / 'recovery.json').read_text())['status'], 'NOT RUN')
            self.assertEqual(len([c for c in calls if c[0] == 'deploy']), 1)


if __name__ == '__main__':
    unittest.main()
