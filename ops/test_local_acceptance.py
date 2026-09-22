import hashlib
import struct
import tempfile
import unittest
from pathlib import Path
from local_acceptance import accept
from acceptance_seed import png, seed

class AcceptanceBoundaryTests(unittest.TestCase):
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
