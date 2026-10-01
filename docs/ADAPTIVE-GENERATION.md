# Generation capabilities and boundaries

The implemented runtime supports human-selected hosted generation, free catalog
discovery, bounded evaluation and an optional worker integration. See
[model operations](MODEL-OPERATIONS.md) for contracts and commands, and the
[session handoff](SESSION-HANDOFF.md) to prepare the first live brief and sources.
Private research plans, route selections and qualification evidence stay outside
this repository. This document describes available software, not an active roadmap.

| Component | Implemented behavior | Boundary |
|---|---|---|
| `model_catalog.py`, `model_daily.py` | Free discovery and a human review inbox | No paid inference, model activation or publication by discovery |
| `model_policy.py` | Pinned route, terms evidence, expiry and integer budget reservations | One registry on one host; unknown charges retain holds |
| `model_runtime.py`, `model_transport.py` | OpenRouter synchronous proposals with pinned provider and fallback disabled | Credential-isolated inference; requested reasoning is not proof it was honored |
| `model_evaluate.py` | Frozen suites and bounded parallel requests | Structural admission does not establish source support |
| `local_generate.py` | Separate bounded Ollama pilot | Local digest/license checks; no hosted fallback |
| `generation_worker.py` | Optional database leases/fences and v1/v2 policies | Deployment does not enable a worker; private operator scope governs use |
| `browse.py` | Local candidates and node API records with images in one loopback browser | Read-only; private source configuration, no database or publication action |
| `cc-publisher` | Admission, exact approvals, current-head checks and signed commit | Human-operated publication is separate from generation |
| `cc-publisher generate` | Selected-model generation and immutable-base extension, optional model-authored classification, Rust admission | No database access, signing or publication; only source-supported connections |

Hosted asynchronous batches, distributed budget settlement and a unified local
adapter are not implemented. No automatic route promotion, paid evaluation daemon
or continuous generation is enabled by this code's deployment. Media requires a
separate rights assessment and qualification.

Generation aims at historically accurate, evidence-supported content under the
[historical evidence standard](evaluation/design-boundaries.md).
Model outputs supply historical content. Software binds measured evidence and
validates literal excerpts without repairing generated historical prose. Bounds
are maxima: one to three entries and zero to two edges. Abstention and incomplete
or conflicting evidence are valid outcomes, not publishable empty candidates.
Keep every attempt and its cost; assess confidence through sources and reasoning,
with model agreement alone providing no independent corroboration.

TT remains upstream for ontology, identity and conformance. Preserve applied
migration bytes, exact signed bodies and explicit unknown evidence. Public tests
use synthetic fixtures; real captures and human approvals remain private.
