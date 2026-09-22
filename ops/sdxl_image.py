#!/usr/bin/env python3
"""Generate one local SDXL 1.0 candidate with pinned weights/license provenance.

Requires diffusers==0.35.1, torch, transformers, accelerate, invisible-watermark.
No hosted inference, Stability credential, ledger writes, or automatic admission.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil

MODEL = 'stabilityai/stable-diffusion-xl-base-1.0'
REVISION = '462165984030d82259a11f4367a4eed129e94a7b'


def sha(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prompt-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--device', choices=['mps','cpu'], default='mps')
    parser.add_argument('--source-entity', type=Path,
                        help='captured authenticated entity response with explicit as_of')
    args = parser.parse_args()
    prompt = args.prompt_file.read_text().strip()
    source = json.loads(args.source_entity.read_text()) if args.source_entity else None
    if source:
        body_hash = source['readings']['this']
        if body_hash not in [r['body_hash'] for r in source['readings']['all']]:
            parser.error('Source body must be one of the captured entity readings')
    if not prompt or args.output.exists():
        parser.error('A nonempty prompt and a new output directory are required')
    args.cache.mkdir(parents=True, exist_ok=True)
    cached = sum(p.stat().st_size for p in args.cache.glob('models--stabilityai--stable-diffusion-xl-base-1.0/snapshots/' + REVISION + '/**/*.safetensors'))
    required = max(2 * 1024**3, 8 * 1024**3 - cached)
    if shutil.disk_usage(args.cache).free < required:
        parser.error('Insufficient disk space for missing SDXL weights and runtime headroom')
    import torch
    from huggingface_hub import snapshot_download
    from diffusers import StableDiffusionXLPipeline
    if args.device=='mps' and not torch.backends.mps.is_available():
        parser.error('This pilot requires the available Apple Metal GPU')
    print('Downloading pinned SDXL fp16 weights', flush=True)
    components = ('text_encoder', 'text_encoder_2', 'unet', 'vae')
    patterns = ['LICENSE.md', 'model_index.json', 'scheduler/*.json',
                'tokenizer/*', 'tokenizer_2/*']
    for component in components:
        patterns += [component + '/config.json', component + '/*.fp16.safetensors']
    snapshot = Path(snapshot_download(MODEL, revision=REVISION, cache_dir=str(args.cache),
                                      allow_patterns=patterns, max_workers=2))
    license_file = snapshot / 'LICENSE.md'
    if 'CreativeML Open RAIL++-M' not in license_file.read_text():
        raise ValueError('Unexpected checkpoint license')
    weights = {str(p.relative_to(snapshot)): sha(p) for p in snapshot.rglob('*.safetensors')}
    print('Loading self-hosted SDXL on ' + args.device, flush=True)
    pipe = StableDiffusionXLPipeline.from_pretrained(str(snapshot), variant='fp16',
        torch_dtype=torch.float16 if args.device=='mps' else torch.float32, use_safetensors=True, local_files_only=True,
        add_watermarker=True)
    pipe.to(args.device)
    if args.device == "mps":
        pipe.enable_attention_slicing()
    pipe.enable_vae_tiling()
    parameters = dict(prompt=prompt, width=1024, height=1024,
                      num_inference_steps=30, guidance_scale=7.0)
    print('Generating one image', flush=True)
    result = pipe(**parameters, generator=torch.Generator(device='cpu').manual_seed(742091))
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    image_path = args.output / 'candidate.png'
    result.images[0].save(image_path)
    digest = sha(image_path)
    final = args.output / (digest + '.png')
    image_path.rename(final)
    shutil.copyfile(license_file, args.output / 'MODEL-LICENSE.txt')
    manifest = dict(schema='cc.image-candidate.v1', provider='local_inference',
        model_requested=MODEL, model_revision=REVISION, weights_sha256=weights,
        generator_sha256=sha(Path(__file__)),
        generated_at=datetime.now(timezone.utc).isoformat(), parameters={**parameters, 'seed':742091},
        image_sha256=digest, image_file=final.name, byte_count=final.stat().st_size,
        mime_type='image/png', synthetic=True, historical_verification='not_assessed',
        visual_review='pending', ledger_write=False, training_admission='pending_review',
        prompt_and_manifest_in_training=False,
        permission=dict(status='conditional_model_license', license='CreativeML Open RAIL++-M',
            license_url=f'https://huggingface.co/{MODEL}/blob/{REVISION}/LICENSE.md',
            license_sha256=sha(license_file), hosted_api_used=False,
            conditions=['Attachment A use restrictions',
                        'Derivative models must retain required notices, license and use restrictions'],
            unrestricted=False),
        source=dict(entity_id=source['entity']['entity_id'], body_hash=body_hash,
                    content_hash=source['tt']['envelope']['content_hash'],
                    as_of=source['as_of'], capture_sha256=sha(args.source_entity),
                    relationship='generated_interpretation_of_claim',
                    live_projection_recheck_required=True) if source else None,
        software={name:importlib.metadata.version(name) for name in ('torch','diffusers','transformers','invisible-watermark')})
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({'image':str(final),'training_admission':'pending_review','ledger_write':False}),flush=True)


if __name__ == '__main__':
    main()
