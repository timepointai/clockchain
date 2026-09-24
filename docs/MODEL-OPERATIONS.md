# Human-selected models and daily review

Humans choose the model, serving provider and reasoning configuration. The daily
job discovers changes and prepares a review report. It never selects a route,
makes paid inference calls, enables generation, or publishes content. An explicit
owner command activates a reviewed configuration; a model's own recommendation
is not approval. Keep all real configuration and evidence outside this checkout.

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
   retained sources; deterministic admission is not historical verification.
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

Supply `OPENROUTER_API_KEY` privately to the inference process only. Do not put keys
in arguments, the checkout or reports. The runner refuses database, node and
signing credentials. `CC_PUBLISHER_BIN` may point to a local built publisher.

```sh
python3 ops/model_runtime.py --registry /private/model-registry \
  --brief /private/brief.json --sources /private/sources.json \
  --output /private/new-attempt
python3 ops/model_evaluate.py --registry /private/model-registry \
  --suite /private/suite.json --output /private/new-evaluation --workers 2
python3 ops/proposal_view.py --attempt /private/new-attempt --port 8766
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
