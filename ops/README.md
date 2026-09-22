# Operator tools

Start with [private owner releases](../docs/CICD-FLY.md). GitHub CI has no production
credentials and never deploys. Keep operator evidence and credentials outside this repo.

| Tool | Purpose |
|---|---|
| `release.py` / `deploy-fly.sh` | Owner release: exact main/CI, temporary acceptance, backup, promotion and verification |
| `local_acceptance.py` | Disposable Docker + PG18 checks against the exact image with realistic-size synthetic media |
| `deploy_digest.py` | Immutable-image promotion, app/tick reconciliation and schema-aware recovery |
| `backup_fly.py` | Database/media capture with independent restore and append-only guard verification |
| `deployed_checks.py` | Auth, evidence and media checks; production replays existing signed media |
| `capture_evidence.py`, `evidence_eval.py`, `validate.py` | Capture and evaluate evidence without confusing integrity with truth |
| `corpus_audit.py` | [Read-only corpus/source audit](../docs/evaluation/corpus-audit.md): aggregates, private capture, API crawl and evidence review queue |
| `tt-differential.py` | Compare pinned upstream classification vectors |
| `ccdb.py` | Explicit operator database connection |
| `local_generate.py` | [Local open-model pilot](../docs/LOCAL-GENERATION.md), at most three entries; no publication capability |

Content publication needs its own human approvals and execution. A deploy authorization
is not a content approval. Do not edit approved artifact bytes, applied migrations,
ledger identity, or signed evidence during cleanup. Missing checks remain NOT RUN.

Legacy repair and Railway scripts are historical utilities. Do not use them against
production based on their presence here. Current deployment uses Fly only.
