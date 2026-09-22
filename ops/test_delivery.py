import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from backup_restore import verify_objects
from backup_fly import wake
from verify_fly_machines import verify
from deployed_checks import check


class DeliveryTests(unittest.TestCase):
    def machines(self):
        digest = 'sha256:' + 'a' * 64
        return digest, [dict(id=group, state='started', image_ref={'digest': digest},
            config={'metadata': {'fly_process_group': group}, 'mounts': [{'path': '/data/media'}],
                    'schedule': 'hourly', 'restart': {'policy': 'no'}}) for group in ('app', 'tick')]

    def test_machine_digest_drift_and_duplicate_writer_fail(self):
        digest, machines = self.machines()
        verify(machines, digest)
        machines[1]['image_ref']['digest'] = 'sha256:' + 'b' * 64
        with self.assertRaises(ValueError):
            verify(machines, digest)
        machines.append(machines[0])
        with self.assertRaises(ValueError):
            verify(machines)

    def test_tick_schedule_and_restart_fail(self):
        for field, value in [('schedule', None), ('restart', {'policy': 'always'})]:
            digest, machines = self.machines()
            machines[1]['config'][field] = value
            with self.assertRaises(ValueError):
                verify(machines, digest)

    def test_backup_leaves_stopped_tick_alone_when_app_is_running(self):
        _, machines = self.machines()
        machines[1]['state'] = 'stopped'
        with patch('backup_fly.run', return_value=json.dumps(machines)) as run:
            wake('test-app')
        self.assertFalse(any(call.args[1:3] == ('machine', 'start')
                             for call in run.call_args_list))

    def test_backup_wakes_only_the_stopped_app_and_does_not_wait_for_tick(self):
        _, machines = self.machines()
        for machine in machines:
            machine['state'] = 'stopped'
        before = json.dumps(machines)
        machines[0]['state'] = 'started'
        with patch('backup_fly.run', side_effect=[before, '', json.dumps(machines)]) as run:
            wake('test-app')
        starts = [call.args for call in run.call_args_list if call.args[1:3] == ('machine', 'start')]
        self.assertEqual(starts, [('flyctl', 'machine', 'start', 'app', '--app', 'test-app')])

    def test_backup_refuses_missing_or_duplicate_app_without_starting_anything(self):
        _, machines = self.machines()
        for fleet in ([], [machines[1]], [machines[0], machines[0], machines[1]]):
            with patch('backup_fly.run', return_value=json.dumps(fleet)) as run:
                with self.assertRaises(ValueError):
                    wake('test-app')
                self.assertEqual(run.call_count, 1)

    def test_backup_reports_app_start_timeout(self):
        _, machines = self.machines()
        machines[0]['state'] = 'stopped'
        with patch('backup_fly.run', return_value=json.dumps(machines)), patch('backup_fly.time.sleep'):
            with self.assertRaisesRegex(ValueError, 'app machine did not start'):
                wake('test-app')

    def test_restore_detects_missing_and_corrupt_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'actual image bytes'
            digest = hashlib.sha256(raw).hexdigest()
            rows = [(digest, len(raw))]
            with self.assertRaises(ValueError):
                verify_objects(rows, root)
            path = root / (digest + '.png')
            path.write_bytes(raw)
            self.assertEqual(verify_objects(rows, root), {digest: len(raw)})
            path.write_bytes(b'x' * len(raw))
            with self.assertRaises(ValueError):
                verify_objects(rows, root)

    def test_wrong_build_stops_before_any_write(self):
        with patch('deployed_checks.request', return_value=(200, b'{"build":"old","posture":"live"}')) as call:
            with self.assertRaises(AssertionError):
                check('https://node', 'a'*40, '1', 'full', 'read')
            self.assertEqual(call.call_count, 1)


if __name__ == '__main__':
    unittest.main()
