"""Offline permission and storage tests. No provider credentials or API calls."""
from contextlib import redirect_stdout, redirect_stderr
from datetime import date
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import stability_image as subject


class ImageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.permission = self.root / 'permission.json'
        self.output = self.root / 'candidate'
        self.prompt = self.root / 'prompt.txt'
        self.prompt.write_text('Offline test fixture; never sent to a provider.')
        (self.root / 'grant.txt').write_text('TEST ONLY: not a real provider grant')
        self.record = dict(status='approved', provider='stability.ai', model=subject.MODEL,
                           training_including_competing_models=True, dataset_redistribution=True,
                           reviewer='test fixture', grant_reference='offline fixture only',
                           reviewed_at=date.today().isoformat(), valid_through=date.today().isoformat(),
                           grant_file='grant.txt', grant_sha256=subject.sha((self.root / 'grant.txt').read_bytes()))

    def run_cli(self):
        self.permission.write_text(json.dumps(self.record))
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return subject.main(['--approval', str(self.permission), '--prompt-file', str(self.prompt),
                                 '--output', str(self.output)])

    def test_denied_permissions_never_contact_provider(self):
        for update in ({'status': 'blocked'}, {'training_including_competing_models': False},
                       {'dataset_redistribution': False}, {'grant_sha256': '0' * 64},
                       {'model': 'different-model'}, {'valid_through': '2000-01-01'}):
            with self.subTest(update=update), patch.object(subject.urllib.request, 'build_opener') as network:
                previous = self.record.copy()
                self.record.update(update)
                self.assertEqual(self.run_cli(), 2)
                network.assert_not_called()
                self.assertFalse(self.output.exists())
                self.record = previous

    def test_original_bytes_and_pending_admission(self):
        # Transport fixture, not a generated image or a visual-quality test.
        raw = b'\x89PNG\r\n\x1a\n' + b'opaque-test-content-credentials'
        response = MagicMock()
        response.read.return_value = raw
        response.headers = {'finish-reason': 'SUCCESS', 'seed': '742091'}
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.dict(subject.os.environ, {'STABILITY_API_KEY': 'offline-fake-key'}, clear=True), \
             patch.object(subject.urllib.request, 'build_opener', return_value=opener):
            self.assertEqual(self.run_cli(), 0)
        opener.open.assert_called_once()
        manifest_text = (self.output / 'manifest.json').read_text()
        self.assertNotIn('offline-fake-key', manifest_text)
        manifest = json.loads(manifest_text)
        self.assertEqual((self.output / manifest['image_file']).read_bytes(), raw)
        self.assertEqual(manifest['training_admission'], 'pending_review')
        self.assertFalse(manifest['ledger_write'])

    def test_redirect_refused(self):
        with self.assertRaises(ValueError):
            subject.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.com')

    def test_preview_is_excluded_without_permission(self):
        response = MagicMock()
        response.read.return_value = b'\x89PNG\r\n\x1a\nfixture'
        response.headers = {}
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.dict(subject.os.environ, {'STABILITY_API_KEY': 'offline-fake-key'}, clear=True), \
             patch.object(subject.urllib.request, 'build_opener', return_value=opener), \
             redirect_stdout(io.StringIO()):
            self.assertEqual(subject.main(['--preview-only', '--prompt-file', str(self.prompt),
                                           '--output', str(self.output)]), 0)
        manifest = json.loads((self.output / 'manifest.json').read_text())
        self.assertEqual(manifest['training_admission'], 'excluded')
        self.assertEqual(manifest['permission']['status'], 'not_approved')
        self.assertFalse(manifest['ledger_write'])


if __name__ == '__main__':
    unittest.main()
