# Small local open-model pilot

For the planned shared hosted/local pipeline and recurring model qualification,
see [adaptive generation](ADAPTIVE-GENERATION.md). The bounded pilot below remains
the current local implementation.

Start with an empty production corpus and keep publication paused. Production data,
model responses, source captures, policies and legacy archives stay outside this
repository. Test fixtures are software tests, never the historical corpus.

`ops/local_generate.py` runs one local Ollama model request, limited to three
entries and two edges. It cannot stage, approve, sign or publish. It refuses an
environment containing database or publication credentials. Only a reviewed
Apache-2.0 or MIT model policy with output training allowed is accepted. The
installed model digest and installed license must match before and after the call;
retained model/runtime license files must match their reviewed hashes. Local
inference has no provider API charge; it still uses the owner's hardware.

The model generates titles, summaries, historical claims, source selections and
causal rationales. Software adds measured provenance and validates literal source
excerpts; it does not repair historical prose. Requests and raw responses are saved
privately, including rejected runs. A successful response is a proposal, not truth
or permission to publish. Exact candidate admission and publication approvals
remain in the publisher. Source-content rights are separate from model licenses.

```sh
python3 ops/local_generate.py --brief /private/pilot/brief.json \
  --sources /private/pilot/sources.json --policy /private/pilot/policy.json \
  --output /private/pilot/run-1
cargo run -p cc-publisher -- validate --path /private/pilot/run-1/proposal.json
```

Brief fields: `max_entries` (1–3), `max_edges` (0–2), and a bounded scope/instruction.
Sources: an array of `id`, `url`, `publisher`, `license`, `locator`, `retrieved_at`,
`capture_path`, `content_sha256` and `passages`. Every passage must occur literally
in the retained UTF-8 capture. The model sees passages and compact TT labels, not
operator files or credentials.

Policy schema `cc.local-model-policy.v1` includes `model`, exact `model_digest`,
`provider: local-ollama`, `license_spdx`, `output_training_allowed: true`,
`reviewed_by`, `reviewed_at`, `installed_license_sha256`, and `model_license` /
`runtime_license` objects with HTTPS `url`, local `path` and `sha256`. A policy
records a specific license assessment; an SPDX label alone does not establish
source rights or publishability. It does not represent human content approval.

Qwen3-8B is an available Apache-2.0 starting point:
https://huggingface.co/Qwen/Qwen3-8B/blob/main/LICENSE . Pin the actually installed
quantized weights separately. Ollama's local runtime is MIT:
https://github.com/ollama/ollama/blob/main/LICENSE . These local licenses contain
no prohibition on using generated output for downstream training; do not assume
that a hosted endpoint, another model, or third-party source material shares that
permission. No hosted fallback is configured.

For a genesis-only deployment, add `--empty-corpus` to `ops/release.py` (or the
shell wrapper). The exact immutable image still runs the full isolated synthetic
acceptance suite, plus genesis-only checks. Production verification requires only
system records, zero historical entities/edges and zero media. Publication remains
paused. Existing nonempty releases retain their genuine-media replay checks.

The old projection-deletion SQL is disabled: deleting a projection does not remove
its immutable events, and replay restores it. Corpus replacement uses a verified
private archive and a fresh database. Preserve migrations and signing identity.

## Inspect a populated local test

The existing `ops/browse-v4.py` viewer uses `CC_DATABASE_URL` for a read-only
loopback PostgreSQL URI (without query parameters), `CC_NODE_URL` for the matching local node, and
`CC_NODE_READ_KEY` for scoped API reads. Put `psql` on `PATH`, then run
`python3 ops/browse-v4.py 8766` and open `http://127.0.0.1:8766`. The viewer binds
only to loopback and does not discover credentials or retired hosting. Use a
read-only database role and the node's frozen posture for retained rehearsals.

The graph shows stored edge directions, evidence classes and attached mechanism
evidence. Claim details retain source passages, model provenance and date precision.
Year-based placement does not establish within-day chronology. The walk button
checks undirected recorded-graph feasibility, not causal direction or historical
truth; verify directed endpoints and source entailment separately.

Use `--think` on `ops/local_generate.py` to request native chat reasoning in a
supporting local model. This path permits reasoning before final JSON instead of
forcing a JSON-only output grammar; publisher admission is still required. The
request, complete response and presence or absence of a reasoning trace remain
in the private run directory. Reasoning mode does not authorize publication.

The wire request preserves JSON-schema field order so nodes precede edges.
`request-wire.json` retains those exact request bytes; provenance request hashes
use the order-independent canonical JSON representation. Qwen sampling follows
its upstream recommendations (temperature 0.6/top-p 0.95 when reasoning is
requested, 0.7/0.8 otherwise, top-k 20, min-p 0). The seed and all settings are
retained; a fixed seed is not a guarantee of reproducibility across runtimes.
See https://huggingface.co/Qwen/Qwen3-8B#best-practices .

For a slower local runtime, `--stream` retains every response chunk in
`response-stream.ndjson` and reports character progress. A missing completion,
model change, output truncation, or stream exceeding 8 MB / 20 minutes is a
refusal, not a partial candidate. `--context 8192` and `--max-output 4096` can
bound a small request; ensure the selected context fits the brief and sources.
An optional brief `allowed_claim_types` list selects only valid pinned TT labels
for a domain-specific pilot. These controls never repair historical prose.
