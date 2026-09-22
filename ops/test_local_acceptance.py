import hashlib
import os
from unittest.mock import patch
import acceptance_seed
import struct
import tempfile
import unittest
from pathlib import Path
from local_acceptance import accept
from acceptance_seed import png, seed

class AcceptanceBoundaryTests(unittest.TestCase):
    def test_private_fixture_permissions_are_transferred_to_runtime_owner(self):
        observed = []
        def command(args):
            if args[1] == 'cp':
                self.assertEqual(Path(args[2]).stat().st_mode & 0o777, 0o600)
            observed.append(args)
        mask = os.umask(0o077)
        try:
            with patch.object(acceptance_seed, 'local_container', return_value='isolated'), \
                 patch.object(acceptance_seed.subprocess, 'check_call', side_effect=command):
                acceptance_seed.put('docker:isolated', 'source.txt', b'synthetic only')
        finally:
            os.umask(mask)
        self.assertIn(['docker','exec','--user','root','isolated','chown','clockchain:clockchain','/tmp/cc-acceptance/source.txt'], observed)
        self.assertIn(['docker','exec','--user','root','isolated','chmod','600','/tmp/cc-acceptance/source.txt'], observed)

    def test_fixture_matches_production_size_class(self):
        raw = png()
        self.assertGreater(len(raw), 1700000)
        self.assertLess(len(raw), 2000000)
        self.assertEqual(struct.unpack('>II', raw[16:24]), (768, 768))
        self.assertEqual(hashlib.sha256(raw).digest(), hashlib.sha256(png()).digest())

    def test_mutable_image_rejected_before_resource_creation(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'evidence'
            with self.assertRaisesRegex(ValueError, 'immutable'):
                accept('registry.fly.io/example:latest', 'a' * 40, path)
            self.assertFalse(path.exists())

    def test_production_and_remote_seed_targets_refused(self):
        with self.assertRaisesRegex(ValueError, 'never targets production'):
            seed('timepoint-clockchain-prod', 'http://127.0.0.1:18080', 'unused')
        with self.assertRaisesRegex(ValueError, 'loopback'):
            seed('docker:fixture', 'https://example.org', 'unused')
