> Owner deployments are private. Open the Fly proxy described in [CICD-FLY.md](CICD-FLY.md) before using these examples.

# Using the node

The live base URL is `http://127.0.0.1:18080`. `/health` alone is
anonymous. Corpus reads require an issued Bearer credential and explicit `as_of`.

```sh
BASE=http://127.0.0.1:18080
AS_OF=842389200
# Supply CC_NODE_READ_KEY through the environment; never paste it into source.
curl -fsS "$BASE/health"
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" "$BASE/health/deep"
curl -fsS -H "Authorization: Bearer $CC_NODE_READ_KEY" \
  "$BASE/v1/entities/3582419940486658630?as_of=$AS_OF"
```

## Access and coordinates

| Credential | Read surface |
|---|---|
| Read | All reads, including feasibility; cannot submit events |
| Gallery | `/v1/recents` only |
| Beta | Entity detail and feasibility |
| Telemetry | Entity detail, feasibility and recents |

The full API credential also permits writes when the node is live. Consumer tools
should use the narrower credential they need. Missing/invalid authentication is
`401`; a read key attempting a write is `403`. A valid scoped key cannot access
routes outside its scope. A valid full/read key gets `404` for an unknown route.

`as_of` accepts whole ticks since Clock Zero (J2000.0 TCB, one tick per SI second)
or `0x` followed by 64 hex characters. Negative coordinates are valid; zero is the
epoch, not the beginning of history. Entity ids should be strings in JavaScript
to avoid integer precision loss. This time slice is not a guarantee of what a
reader could have known at that date.

## Ask a feasibility question

```sh
curl -fsS "$BASE/v1/feasibility" \
  -H "Authorization: Bearer $CC_NODE_READ_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subjects":["3582419940486658630","2972449720562630121"],"as_of":"842389200","claim":"conflict-and-warfare"}'
```

Use an exact TT label for `claim`. Legacy numeric codes cannot distinguish an
unknown label from a valid type that the corpus has not recorded.

| `result` | Meaning under the governed first-failing-factor policy |
|---|---|
| `Supported` | Windows, type admissibility and bounded reachability all held |
| `Unsupported` | The first failing factor lacked evidence |
| `Contradicted` | The first failing factor had positive contrary evidence |

The rule checks both subject windows, admissibility, then reachability. An absence
earlier in that order can determine `Unsupported` even when a later factor is
contradicted. Always inspect the complete audit before interpreting the evidence.
This release exposes those factors without changing the governed verdict policy.

Every certificate carries:

- `evidence_scope: recorded_graph_feasibility` and `factual_verification: not_assessed`.
- `verdict_policy: first_zero_in_factor_order`.
- `filter_version`, `corpus_digest`, and the explicit `as_of` coordinate.
- `consulted`: sorted, deduplicated event ids used by certification.
- `audit.schema: cc.evidence-audit.v1`, `audit.absences`, and `audit.contradictions`.

`Supported` additionally carries `phi_support: true`. `Unsupported` carries
`vanished`; `Contradicted` carries `contradicted_by`. Missing evidence is not proof
of impossibility, and a feasible path is not proof of a particular historical claim.
A `503` is a read/evaluation failure, never a verdict. Missing `as_of`, an invalid
TT label, or a hop bound above the governed maximum is a `400`.

## Read records and verify signatures

`/v1/recents?as_of=…&limit=…` accepts up to 50 records per request. It may be dominated
by operational seals; a recent seal does not establish new historical coverage.
Entity responses expose their stored readings and a computed relation. Matching
entity identity does not by itself mean matching content hashes.

`ops/verify-triple.py` checks served signatures with stock Ed25519. That verifies
the signature on an event id, not the JSON-to-canonical-content mapping or historical
truth. A page-level check is not a full-corpus audit.

## Settlement and evaluation

Authenticated `/health/deep` reports root, tree size, anchor status and block height.
Pending is not confirmed Bitcoin inclusion. A confirmed timestamp would establish
a commitment to bytes, not truth. The live check on 2026-09-07 reported Pending and
no committed founding exhibit; re-read rather than assuming either has changed.

Use the [evaluation guide](evaluation/README.md) to capture responses and validate
them offline. Quality and usefulness require external labels and matched consumer
runs; neither follows from an integrity PASS.

Operate and deploy through [the Fly guide](CICD-FLY.md). Railway URLs and deployment
commands belong to the retired host.

## Source date precision in controlled publication

Candidates may supply `prov_asserted.event_date` as a strict `YYYY-MM-DD`
and `prov_asserted.date_precision: "day"`. The Gregorian date must match
the claim year (CE 1–2100); captured source evidence must explicitly include
`date` support. Publication uses the start of that calendar day for entity
windows, moments and vocabulary, and the later endpoint for an edge. A cause
or influence dated after its effect is rejected, including within one year.

This is a day bucket under the existing calendar-to-coordinate convention,
not evidence of an exact instant or within-day order. Causal mechanisms need
separate source evidence. The title/year identity and TT envelope stay unchanged.
Candidates without a day retain their existing year mapping; applied events and
migration bytes are never rewritten. A source interval must not be represented
as an invented exact day.
