"""Read one configured local image candidate; never query or write the ledger."""
import hashlib
import html
import json
from pathlib import Path
import struct


def load(directory):
    root = Path(directory).resolve()
    manifest = json.loads((root / 'manifest.json').read_text())
    digest = manifest['image_sha256']
    if len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
        raise ValueError('Invalid image hash')
    if manifest['image_file'] != digest + '.png':
        raise ValueError('Image filename does not match hash')
    path = root / manifest['image_file']
    if path.resolve().parent != root:
        raise ValueError('Image must stay in the configured directory')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest or not raw.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Image integrity check failed')
    return manifest, raw


def page(manifest, raw):
    esc = html.escape
    width, height = struct.unpack('>II', raw[16:24])
    fields = {
        'Generator': manifest['model_requested'],
        'Dimensions': f'{width} × {height}',
        'File size': f'{len(raw) / 1024 / 1024:.2f} MiB · PNG',
        'Generated': manifest['generated_at'],
        'Training admission': manifest['training_admission'],
        'Historical verification': manifest['historical_verification'],
        'SHA-256': manifest['image_sha256'],
    }
    rows = ''.join(f'<dt>{esc(k)}</dt><dd>{esc(str(v))}</dd>' for k, v in fields.items())
    prompt = esc(manifest.get('parameters', {}).get('prompt', ''))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Clockchain · Image preview</title>
<style>
*{{box-sizing:border-box}}body{{margin:0;background:#0f1115;color:#d7dae0;font:15px/1.6 system-ui,sans-serif}}
header,main{{max-width:1400px;margin:auto;padding:24px}}header{{border-bottom:1px solid #303540}}
a{{color:#9dc4ff}}h1{{font-size:28px;margin:12px 0 0}}p{{color:#bbc2cc}}
.badge{{color:#efce88;font-size:12px;text-transform:uppercase;letter-spacing:.1em}}
img{{display:block;width:100%;height:auto;border-radius:8px}}figure{{margin:0}}
figcaption{{padding:12px 0;color:#aeb6c2}}dl{{display:grid;grid-template-columns:180px 1fr;gap:8px}}
dt{{color:#aeb6c2}}dd{{margin:0;overflow-wrap:anywhere}}details{{border-top:1px solid #303540;padding-top:16px}}
@media(max-width:600px){{dl{{grid-template-columns:1fr}}header,main{{padding:16px}}}}
</style><header><a href="http://127.0.0.1:8766/">← Live Clockchain browser</a>
<h1>Manuscript workshop</h1><span class="badge">Local image preview · Not a ledger entry</span>
<p>Stability-generated historical illustration. Downstream training permission remains unresolved.</p>
</header><main><figure><img src="/image-preview.png" width="{width}" height="{height}"
alt="Generated illustration of monks working with manuscripts in a sunlit stone workshop">
<figcaption>Carolingian-inspired manuscript workshop. Synthetic illustration; historical accuracy has not been verified.</figcaption>
</figure><a href="/image-preview.png" download="clockchain-manuscript-workshop.png">Download original PNG</a>
<dl>{rows}</dl><details><summary>Generation prompt</summary><p>{prompt}</p></details>
</main></html>'''.encode()
