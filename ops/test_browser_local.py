import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

import model_policy as policy

spec = importlib.util.spec_from_file_location('browser_local', Path(__file__).with_name('browser_local.py'))
viewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(viewer)


class ProposalViewerTests(unittest.TestCase):
    def fixture(self, root):
        png = b'\x89PNG\r\n\x1a\nsynthetic test bytes'
        (root/'image.png').write_bytes(png)
        proposal = {'entries': [], 'edges': [], 'images': [
            {'path': 'image.png', 'sha256': policy.digest(png)}]}
        self.save_proposal(root, proposal)
        return proposal

    def save_proposal(self, root, proposal):
        body = json.dumps(proposal).encode()
        (root/'proposal.json').write_bytes(body)
        receipt = {'schema': 'cc.image-preparation.v1', 'status': 'prepared',
                   'candidate_sha256': 'synthetic', 'proposal_sha256': policy.digest(body)}
        (root/'result.json').write_text(json.dumps(receipt))
        receipt.update(schema='cc.application-image-preparation.v1', admission='pass', published=False)
        (root/'application-admission.json').write_text(json.dumps(receipt))

    def test_prepared_images_and_tampering(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root)
            self.assertIn('/images/0.png', viewer.load_attempt(root)[2])
            (root/'image.png').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'image bytes changed'):
                viewer.load_attempt(root)

    def test_symlink_cannot_expose_outside_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base/'attempt'
            root.mkdir()
            self.fixture(root)
            (root/'image.png').rename(base/'outside.png')
            (root/'image.png').symlink_to(base/'outside.png')
            with self.assertRaisesRegex(ValueError, 'inside the private attempt'):
                viewer.load_attempt(root)

    def test_stale_application_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proposal = self.fixture(root)
            proposal['images'] = []
            (root/'proposal.json').write_text(json.dumps(proposal))
            with self.assertRaisesRegex(ValueError, 'application-validated'):
                viewer.load_attempt(root)
