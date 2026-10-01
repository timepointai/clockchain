# Human-selected models and daily review

Humans choose the model, serving provider and reasoning configuration. The daily
job discovers changes and prepares a review report. It never selects a route,
makes paid inference calls, enables generation, or publishes content. An explicit
owner command activates a reviewed configuration; a model's own recommendation
is not approval. Keep all real configuration and evidence outside this checkout.

Historical truth is the quality objective. Apply the
[historical evidence standard](evaluation/design-boundaries.md) to model outputs:
evaluate supported conclusions, competing explanations and appropriate uncertainty,
including the distinction between documented quotations and reconstructed dialogue.
Strong evidence can justify a historical conclusion without deductive certainty.

## Daily cycle

1. `python3 ops/model_catalog.py --registry /private/model-registry refresh`
   captures the public OpenRouter catalog and lists new, changed and removed
   models. `daily-review.html` is the human inbox. Recency is not intelligence.
2. Review each promising model **and its exact serving provider** for commercial
   output use and downstream training. Capture the model license, router terms,
   provider terms and evaluation evidence with SHA-256 hashes and an expiry.
   Weight licensing alone is insufficient. Unknown rights exclude a route.
3. Put a reviewed challenger in a separate qualification registry and run frozen
   evaluation cases with a finite budget. Compare source support, critical errors,
   useful coverage, abstention, cost including failures, and latency. Keep case
   labels out of prompts. Inspect every field and causal mechanism against the
   retained sources; historical assessment weighs that evidence, while deterministic
   admission checks the software contract.
4. A human selects an incumbent with an explicit reason and decision reference:

   ```sh
   python3 ops/model_catalog.py --registry /private/model-registry select \
     --route /private/model-registry/routes/reviewed-route.json \
     --chosen-by 'owner' --reason 'Reviewed comparison and task fit' \
     --decision-reference '/private/review/decision.md'
   ```

   Selection records are immutable and hashed. Existing in-flight attempts stop
   when the selection changes. Rollback is another explicit human selection.
5. Reuse regression cases and add failures to future suites; reserve unseen cases
   for qualification. No single NASA example qualifies a model for all domains.

On macOS, `python3 ops/model_daily.py --registry /private/model-registry --hour 9`
installs an owner LaunchAgent. It runs on load and daily at local 09:00 while the
owner session is available; it is not an always-on cloud scheduler. It needs no
provider key. Logs and reports stay in the registry. On other systems schedule
the `refresh` command with the operating-system scheduler. Failures leave the
previous timestamped report intact; check its age. `status` verifies the active
selection and shows spend and unresolved reservations.

## Current runtime contract

`ops/model_policy.py` strictly validates `cc.model-route.v1`. Each private route
contains the model ID, provider name and slug, endpoint name, quantization, known
or unknown weight digest, reasoning, sampling, token/deadline limits and price
ceilings. Its rights section requires Apache-2.0 or MIT, affirmative commercial
use/output-training review, reviewer, effective/expiry timestamps, conditions and
captured evidence. Evaluation is an exact file hash plus an explicit scope.
See the synthetic fixtures in `ops/test_model_runtime.py` for the field structure;
those fixtures confer no rights on a real model.

Changing any selected bytes, evidence, expiry or endpoint capability stops use.
The runtime checks the provider's current endpoint information before submission,
pins routing with fallback disabled, and verifies the returned model and provider.
Hosted weight identity remains unknown when the provider supplies no digest.
Reasoning is **requested**, not inferred to have been honored from a token count.
Daily catalog discovery does not automatically determine changed legal terms;
humans must renew the captured rights review before its expiry and stop use when
a restriction becomes known. Create `STOP` in the registry for an immediate hold.

The private `budget.json` contract is:

```json
{"schema":"cc.model-budget.v1","total_limit_micro_usd":100000,
 "daily_limit_micro_usd":50000,"max_daily_calls":2}
```

Amounts are integer millionths of a US dollar. SQLite reservations serialize
concurrent processes sharing **one operator registry on one host**. Unknown
charges retain the full conservative reservation, including across days. A
reported overrun freezes the budget. Do not copy the budget database to multiple
workers and assume a global cap. Distributed settlement is future work.

Only `openrouter-chat` is implemented in this adapter. Unknown transports are
rejected. The existing `local_generate.py` Ollama pilot remains separate until
qualified under this contract. Hosted batches need asynchronous IDs, cancellation,
idempotency and settlement support before enablement. These boundaries allow new
models to be configuration changes without pretending all new transports work.

## Generation, evaluation and local review

The Rust application exposes proposal generation without a database connection:

```sh
cc-publisher generate --registry /private/model-registry \
  --brief /private/brief.json --sources /private/sources.json \
  --base /private/previous-attempt/proposal.json --output /private/next-attempt \
  --python /private/runtime/bin/python
```

Omit `--base` for an initial proposal. With a base, the app validates it before
spending, hashes it, and preserves its entries, edges and media exactly. The model
returns only new entries and edges; the combined candidate must fit the brief's
limits. Every new entry must be reachable from the base through new directed
edges. Unsupported connections produce abstention or a rejected attempt, never
an automatically invented edge. Historical fields and relationship rationales
come from the selected model. Base context is not new source evidence.

`classification_details: true` in the brief requests the optional classification
profile, competing types and cross-lens flag from the model. Rust validates them
against the pinned TT rules; software does not normalize or repair model output.
The source is `derived` because this is the same generation call, not an
independent classifier. Empty alternatives are legitimate. Classification mass
is not historical confidence. Existing base fields remain unchanged.

`cc-publisher source-window --sources /private/sources.json --source-id source-1
--start 'unique literal beginning' --end 'unique literal ending'
--output /private/expanded-sources.json` appends an exact slice of an already
captured, rights-reviewed source. It verifies the original hash, requires unique
markers and preserves the source attribution and license. It adds no historical
prose and grants no additional rights. The operator must limit windows to material
covered by the recorded rights review.

### Prepare required images before staging

`cc-publisher generate --media-plan --base /private/proposal.json` uses the
selected text route to author one prompt and reconstruction disclosure per entry.
It takes the same registry, brief, sources, output, and optional Python arguments
as text generation. It emits `media-plan.json`, preserves every historical field,
and charges the shared registry. Prompts are preparation artifacts, not images.

`cc-publisher image-generate --registry /private/models --route /private/image-route.json
--candidate /private/proposal.json --plan /private/media-attempt --output /private/images`
executes the separately human-selected, pinned FLUX 4B profile on Hugging Face
Jobs. The route pins the CUDA container digest, generator/profile/bootstrap hashes,
hardware, timeout, price ceiling, private output repository, owner decision, and
captured rights evidence with an expiry. See `ops/image_prepare.py` for the exact
`cc.image-route.v1` contract. Install `ops/requirements-images.txt` in the operator
Python environment, or use the shipped image's environment. No database,
publication, or OpenRouter credentials reach the GPU worker; its HF credential
is supplied as a job secret. Only prompts authored by the selected text model
reach image inference.

The app rechecks model-response and candidate hashes before spending, reserves
the entire GPU timeout plus a billing unit, verifies downloaded weights/license
and PNG provenance, and binds images using `cc-publisher image-bindings`. Those
bindings use the same claim identity and body serialization as publication. The
original generation manifests are retained beside the bound manifests. The
output candidate changes only its image list. Visual review stays pending.

GPU completion is not a billing receipt: the full reservation remains held until
provider billing is reconciled. The shared budget must cover text and images;
never reset its history or silently increase the owner's finite allowance.
No command in this preparation path initializes, stages, approves, signs, or
publishes content. Human publication must also submit the separately signed media
attachments; an image listed in a publisher receipt is not an admitted attachment.
Transferring capture paths changes claim-body hashes, so prepare or rebind media
against the exact final candidate before human approval.

Set `images_required: true` in the final human brief to enforce image coverage.
The publisher checks it at staging, candidate approval, and publication: each
entry needs an image marked `accepted_as_illustration` whose entity and body hash
match that entry exactly. Missing, pending, or stale images fail the gate. This
review flag is an operator assessment, not cryptographic evidence of accuracy.
Use `cc-publisher validate --path /private/proposal.json --brief /private/brief.json`
to check the same required-image gate without database access or staging.

`generate` delegates transport and shared budget accounting to the bundled
adapter with a cleared environment containing only the inference credential and
basic process settings. It then independently validates the returned candidate
and writes `application-admission.json`. It never stages, approves, signs or
publishes. Images and signed media-absence decisions remain separate operations;
their absence is not a completed media workflow.

Supply `OPENROUTER_API_KEY` privately to the inference process only. Do not put keys
in arguments, the checkout or reports. The runner refuses database, node and
signing credentials. `CC_PUBLISHER_BIN` may point to a local built publisher.

```sh
python3 ops/model_runtime.py --registry /private/model-registry \
  --brief /private/brief.json --sources /private/sources.json \
  --output /private/new-attempt
python3 ops/model_evaluate.py --registry /private/model-registry \
  --suite /private/suite.json --output /private/new-evaluation --workers 2
python3 ops/browse.py --config /private/browser.json --open
```

The suite contract `cc.model-suite.v1` has `id`, `split` (`development`, `held_out`
or `audit`) and `cases`: each has `id`, brief/source paths, `expected_status` and
`max_edges`. Fixtures are validated and hashed before parallel calls. Source
manifests use the [local generation contract](LOCAL-GENERATION.md); software checks
capture hashes and literal passages before and after inference. The model chooses
source IDs and passage indices; software attaches measured evidence.

Bounds are maxima, never quotas: one to three entries and zero to two edges.
`abstained`, `needs_evidence` and `conflicting_evidence` are results, not empty
publishable candidates. All raw responses, failed attempts, route/request hashes,
costs and admission results are retained. Human semantic review remains pending
until actually completed; a passing structural score does not promote a model.
The viewer serves only the specified validated proposal on loopback, including
all node and link fields and their evidence. It has no database or publish action.

## Integration and live-test handoff

`generation_worker.py` accepts a `cc.generation-policy.v2` with `registry`,
`reviewer` and `gpu`. Human briefs bind both policy bytes and `selection_sha256`,
literal source passages, `max_entries` and `max_edges`. Existing operational
database leases, fence checks and publication pause surround a credential-isolated
inference child. Legacy v1 free routes remain supported. V2 paid accounting uses
the shared registry, not the legacy integer-cent SQL table. No applied migration
bytes change. The image ships the runtime tools, but starts only the existing node
and scheduled anchor processes; no generation worker is implicitly enabled.

A live test starts with an explicitly authorized brief and frozen sources, runs
the selected route locally or on a separately configured operator host, and
passes the result to the existing human-operated publisher. Initializing an empty
chain, staging, approving, signing and publishing remain the designated operator's
actions. Model selection and software deployment grant none of those permissions.
The release can preserve a zero-event ledger with publication paused. Keep the
exact production handoff and credentials privately; never copy local test history
into production as a deployment step.

The [shared browser configuration](BROWSER.md) selects the current attempt and
any local or deployed node sources in one durable read-only viewer.
