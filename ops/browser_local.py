"""Verified local candidate loading for the Clockchain browser."""
from pathlib import Path
import model_policy as policy


def load_attempt(attempt):
    proposal = policy.read(attempt/'proposal.json')
    result = policy.read(attempt/'result.json')
    digest = policy.digest((attempt/'proposal.json').read_bytes())
    if result.get('status') == 'prepared':
        admission = policy.read(attempt/'application-admission.json')
        if (result.get('schema') != 'cc.image-preparation.v1'
                or admission.get('schema') != 'cc.application-image-preparation.v1'
                or admission.get('admission') != 'pass'
                or admission.get('proposal_sha256') != digest
                or admission.get('candidate_sha256') != result.get('candidate_sha256')
                or admission.get('published') is not False):
            raise ValueError('application-validated image preparation required')
    elif result.get('status') != 'proposal' or result.get('admission') != 'pass':
        raise ValueError('validated proposal required')
    if digest != result.get('proposal_sha256'):
        raise ValueError('proposal changed after validation')
    assets = {}
    for i, item in enumerate(proposal.get('images', [])):
        path = Path(item['path'])
        path = (path if path.is_absolute() else attempt/path).resolve()
        if not path.is_relative_to(attempt.resolve()):
            raise ValueError('image must be inside the private attempt')
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('image exceeds size limit')
        data = path.read_bytes()
        if not data.startswith(b'\x89PNG\r\n\x1a\n') or policy.digest(data) != item['sha256']:
            raise ValueError('image bytes changed after preparation')
        assets[f'/images/{i}.png'] = data
    return proposal, result, assets

