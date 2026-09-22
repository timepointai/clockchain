# Evidence audit and evaluation

The API now states `evidence_scope: recorded_graph_feasibility`,
`factual_verification: not_assessed`, and
`verdict_policy: first_zero_in_factor_order`. `audit.schema` is
`cc.evidence-audit.v1`; `audit.absences` and `audit.contradictions` enumerate all
failing factors already evaluated by certification, including contradictory
factors masked by an earlier absence. These additions are diagnostic. Existing
`result`, witnesses, filter version, and consensus projection remain unchanged.
An existing client may ignore the new fields. New clients must not interpret
`Supported` as proof that a particular historical interaction happened.

Changing the governed verdict to give contradictions precedence requires a
separately recorded governance decision. This round does not create that record.
The mixed-evidence regression tests expose both subject orders while preserving
the current rule. The pre-existing golden digest remains pinned.

## Run without credentials

`python3 ops/validate.py --fixture /path/to/evidence.json`

Exit 0 means the API evidence contract checks passed; 1 means failure; 2 means
NOT RUN. Quality and usefulness each retain their own status. A contract PASS
never means historical accuracy, signature verification, or complete replay.
No command in this mode contacts a network, generates content, or writes records.
The existing database validator remains available without `--fixture`.

Fixture schema `cc.evidence-eval.v1` contains:

- `manifest`: explicit `as_of`, `filter_version`, `ontology_sha256`, `source`,
  `captured_at`. A corpus digest is preserved for each response; a capture across
  multiple requests is not represented as an atomic snapshot.
- `cases`: nonempty list of unique `id`, captured `response`, and optional
  `expect` fields (`result` or `contradiction_count`, for example).
- Optional `preregistration`: externally prepared `specification` plus its
  SHA-256 under sorted-key, compact JSON. `specification.labels` maps every case
  id to `expected_verdict`, `sources`, and `reviewer`. Store the digest before
  collecting outcomes: a matching hash alone does not establish chronology or
  reviewer independence.
- Optional `consumer_runs`: matched `generation`, `retrieval`, `clockchain` arms.
  Every row has `id`, `model`, externally graded `correct`, `abstained`,
  `latency_ms`, and `cost_usd`. Report correct/incorrect answers, abstentions,
  total cost, mean latency, and denominator. No significance claim is computed.

The evaluator's tests contain a minimal executable schema example:
`python3 -m unittest discover -s ops -p test_evidence_eval.py`.
They are software fixtures, never historical corpus or downstream training data.

## Downstream training policy

Free pricing is not a training-rights grant. Each consumer-run model must have
an entry in `model_policy` with `downstream_training_allowed: true`,
`license_url`, `terms_sha256`, `reviewed_by`, and `reviewed_at`.
An absent, incomplete, or unapproved policy fails evaluation. The evaluator
checks recorded approval, not the legal validity of a license. The reviewer
must evaluate the exact model, provider, terms, output use, and applicable
restrictions. Provider names alone never approve every model they host.

Codex-authored text must not enter Clockchain records. This tool has no model
client or ledger-write capability. Externally generated permitted-model outputs
can be evaluated separately; approval for evaluation is not ledger admission.
Any future image pipeline likewise needs exact-model license review, generated
provenance, TT admission, and media by reference outside content identity.

## Product evaluation protocol

Freeze a source-backed held-out question set and rubric before collecting runs.
Compare the same evidence and questions in all three arms. Evaluate answer
correctness separately from structural verdict agreement. Include missing data,
closed existence windows, unknown closure, valid paths lacking evidence of the
requested interaction, and corrections discovered after the historical event.
Keep event time and knowledge/capture time explicit. Existing `as_of` alone is
not a claim of bitemporal replay.

A first pilot should exercise one research assistant's historical claim-checking
workflow. Do not infer willingness to pay from recording gaps. Proceed to a
pricing experiment only after measuring useful answers retained, errors avoided,
and the added latency and cost. No pilot results are claimed by this release.

## Capture the running node

Supply `CC_NODE_READ_KEY` through the environment, then run:

```sh
python3 ops/capture_evidence.py queries.json capture.json --as-of 842389200
python3 ops/validate.py --fixture capture.json
```

`queries.json` is a nonempty array of unique `id`, two string `subjects`, and a
TT-label string `claim`. Choose the explicit time for the investigation.
The capture reuses `graphview.feasibility`, the existing browser reader. Output
is private by default and existing files are never overwritten. Review captured
corpus material before sharing; do not commit live captures as training data.
The manifest hashes the local ontology artifact and labels that limited scope.
