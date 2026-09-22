# Apache-licensed FLUX image contributions

`flux-klein-4b-apache-local-v1` admits self-hosted FLUX.2 klein **4B** under
Apache-2.0. It does not admit 9B, dev, pro, third-party adapters, or arbitrary
checkpoints. Exact model revision, license and all inference weight hashes are
pinned in [flux_profile.json](flux_profile.json) and checked by the node.

The model license has no competing-model output-training ban, revenue threshold,
or downstream-model share-alike requirement. Apache notices apply when distributing
licensed model material; generated images are not automatically Apache-licensed
copyright works. Third-party rights still apply. Hosted inference provider terms
require separate review and are not authorized by this self-hosted profile.

## Generate one candidate

Run `flux_image.py` on our own CUDA worker with Diffusers 0.40.0,
Transformers 5.16.1 and Accelerate 1.14.0. The pilot uses a Hugging Face Job,
PyTorch 2.6.0 CUDA 12.4, L4 hardware and a 1,200-second timeout. Review current
hardware prices before each run. No persistent endpoint is required.

```sh
python ops/flux_image.py --prompt-file prompt.txt --output candidate
```

The script uses four inference steps for one 1024×1024 image, validates downloaded
weights and license, and records software versions and its own source hash.
`--upload-repo OWNER/PRIVATE_DATASET` optionally saves the candidate in a private
HF dataset using `HF_TOKEN`; a public destination is refused. Never place a token
in source, logs, job commands, or manifests. HF job credentials must use secrets.

Download the original PNG, license and manifest before cleanup. Preserve the
original generation manifest, inspect the PNG, and bind the candidate locally to
a captured source entity/body hash. No private historical records or Clockchain
credentials need to reach the generator. Record `visual_review` as
`accepted_as_illustration` only after inspection; historical accuracy stays
`not_assessed`. Submit with the shared `ops/submit_image.py` tool.

Admission creates a separate signed media attachment, not a historical claim
event or Bitcoin-anchored image. PNG objects and PostgreSQL metadata use the
existing image store. Original SDXL attachments retain their own conditions.

Sources: [pinned model license](https://huggingface.co/black-forest-labs/FLUX.2-klein-4B/blob/e7b7dc27f91deacad38e78976d1f2b499d76a294/LICENSE.md),
[HF job pricing](https://huggingface.co/docs/hub/jobs-pricing).
