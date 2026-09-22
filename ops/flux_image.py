#!/usr/bin/env python3
"""Generate one pinned Apache FLUX klein 4B candidate on our own CUDA worker.

No historical source data or Clockchain credentials are needed on the worker.
Optional private HF dataset upload stores the candidate, not an admitted entry.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prompt-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--upload-repo')
    parser.add_argument('--upload-prefix', default='')
    args = parser.parse_args()
    if args.output.exists():
        parser.error('Output directory already exists')
    prompt = args.prompt_file.read_text().strip()
    if not prompt:
        parser.error('Prompt is empty')
    profile = json.loads(Path(__file__).with_name('flux_profile.json').read_text())
    import torch
    from diffusers import Flux2KleinPipeline
    from huggingface_hub import HfApi, snapshot_download
    if not torch.cuda.is_available():
        parser.error('CUDA GPU required')
    api = HfApi()
    if args.upload_repo and not api.repo_info(args.upload_repo, repo_type='dataset').private:
        parser.error('Candidate output repository must be private')
    print('Downloading the pinned Apache checkpoint', flush=True)
    snapshot = Path(snapshot_download(profile['model'], revision=profile['model_revision'],
        allow_patterns=['LICENSE.md', 'model_index.json', 'scheduler/*', 'tokenizer/*',
                        'text_encoder/*', 'transformer/*', 'vae/*']))
    if sha(snapshot / 'LICENSE.md') != profile['license_sha256']:
        raise ValueError('License hash mismatch')
    weights = {name: sha(snapshot / name) for name in profile['weights_sha256']}
    if weights != profile['weights_sha256']:
        raise ValueError('Weight hash mismatch')
    print('Loading FLUX klein 4B', flush=True)
    pipe = Flux2KleinPipeline.from_pretrained(str(snapshot), torch_dtype=torch.bfloat16,
                                             local_files_only=True)
    pipe.enable_model_cpu_offload()
    params = dict(prompt=prompt, width=1024, height=1024, num_inference_steps=4,
                  guidance_scale=1.0)
    seed = 742092
    print('Generating one image', flush=True)
    result = pipe(**params, generator=torch.Generator(device='cuda').manual_seed(seed))
    args.output.mkdir(mode=0o700, parents=True)
    initial = args.output / 'candidate.png'
    result.images[0].save(initial)
    digest = sha(initial)
    final = args.output / (digest + '.png')
    initial.rename(final)
    shutil.copyfile(snapshot / 'LICENSE.md', args.output / 'MODEL-LICENSE.txt')
    manifest = dict(schema='cc.image-candidate.v1', provider='local_inference',
        execution_platform='huggingface_jobs', model_requested=profile['model'],
        model_revision=profile['model_revision'], weights_sha256=weights,
        generator_sha256=sha(Path(__file__)), generated_at=datetime.now(timezone.utc).isoformat(),
        parameters={**params, 'seed': seed}, image_sha256=digest, image_file=final.name,
        byte_count=final.stat().st_size, mime_type='image/png', synthetic=True,
        historical_verification='not_assessed', visual_review='pending', ledger_write=False,
        training_admission='pending_review', prompt_and_manifest_in_training=False,
        permission=dict(status='permissive_model_license', license='Apache-2.0',
            profile=profile['permission_profile'], license_url=profile['license_url'],
            license_sha256=profile['license_sha256'], hosted_api_used=False,
            conditions=['Apache-2.0 notice obligations apply when redistributing licensed model material',
                        'No model-license prohibition on downstream training using outputs; third-party rights still apply']),
        source=None,
        software={name: importlib.metadata.version(name) for name in
                  ('torch', 'diffusers', 'transformers', 'accelerate', 'huggingface-hub')})
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    if args.upload_repo:
        api.upload_folder(repo_id=args.upload_repo, repo_type='dataset', folder_path=args.output, path_in_repo=args.upload_prefix,
                          commit_message='Store one unadmitted FLUX candidate and provenance')
    print(json.dumps({'image_sha256': digest, 'training_admission': 'pending_review'}), flush=True)


if __name__ == '__main__':
    main()
