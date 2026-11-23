# Docs index

Each file in `docs/`, sorted by what you probably want from it. If you are new,
read the "Start here" group and skip the last group until you need it.

## Start here

- [ARCHITECTURE.md](ARCHITECTURE.md): how the pieces fit together, in one read.
- [TOPOLOGY.md](TOPOLOGY.md): every surface of the stack (node, gateway, explorer, clients) and where its source lives.
- [USING-THE-NODE.md](USING-THE-NODE.md): how to call the node, including v1 mode.
- [PUBLIC-ACCESS.md](PUBLIC-ACCESS.md): the read-only public gateway contract.
- [LOCAL-DEV.md](LOCAL-DEV.md): build, test and run on your own machine.
- [evaluation/design-boundaries.md](evaluation/design-boundaries.md): the historical evidence standard; why the ledger separates evidence from conclusions.

## Reference

- [reference/openapi.json](reference/openapi.json): every HTTP route, OpenAPI 3.1. CI checks it against the routers.
- [PUBLISHER-V1.md](PUBLISHER-V1.md): what `cc-publisher v1` does.
- [AUTHORING-V1.md](AUTHORING-V1.md): corrections, edges, attestations and entry packets.
- [KEYS.md](KEYS.md): cold root key and hot delegate key.
- [ADMISSION-REVIEW.md](ADMISSION-REVIEW.md): the admission and review contract.
- [TYPED-MEDIA-ABSENCE.md](TYPED-MEDIA-ABSENCE.md): how a missing image or body is recorded as a distinct state.
- [IMAGE-INTEGRITY.md](IMAGE-INTEGRITY.md): the image attachment checks in the v0 deep health report.
- [INTEGRATIONS.md](INTEGRATIONS.md): audited consumers of the node API and the typed clients in [../clients/](../clients/README.md).
- [design/MULTI-SIGNER.md](design/MULTI-SIGNER.md): the multi-signer admission and projection design.
- [design/SEALING.md](design/SEALING.md): options for sealing and anchoring commitments, and the decision.
- [design/stage0/README.md](design/stage0/README.md): the executable reference fold (Python), with its result files.
- [evaluation/README.md](evaluation/README.md) and [evaluation/corpus-audit.md](evaluation/corpus-audit.md): evidence audit and corpus checks.

## Operations

For the node's operator. Most of it needs access you will not have.

- [OPERATIONS.md](OPERATIONS.md): update releases, backups, monitoring and the seal log.
- [CICD-FLY.md](CICD-FLY.md): how releases are made. CI never deploys.
- [GREEN-DELIVERY.md](GREEN-DELIVERY.md): the delivery contract, in a few lines.
- [SESSION-HANDOFF.md](SESSION-HANDOFF.md): how an agent continues an owner session.
- [LOCAL-GENERATION.md](LOCAL-GENERATION.md), [MODEL-OPERATIONS.md](MODEL-OPERATIONS.md), [ADAPTIVE-GENERATION.md](ADAPTIVE-GENERATION.md): held, v0-era generation tooling. Generation is held by [../HOLD.md](../HOLD.md).

## Historical records

Dated records of how v1 was built and launched. Accurate for their date; skip them unless you need the history.

- [FIRST-ENTRY.md](FIRST-ENTRY.md): the completed one-time launch runbook (October 2026). Do not rerun it.
- [LAUNCH-EVIDENCE.md](LAUNCH-EVIDENCE.md): maps each launch gate of issue #6 to merged PRs and tests.
- [releases/v1.0.md](releases/v1.0.md), [releases/v1.1.md](releases/v1.1.md), [releases/v1.2.md](releases/v1.2.md): release notes.
- [design/STAGE-A.md](design/STAGE-A.md) to [design/STAGE-G.md](design/STAGE-G.md): the stage-by-stage build record. STAGE-G also holds the contracts for the public gateway and clients.
- [TEST-ACCOUNTING.md](TEST-ACCOUNTING.md) and [python-test-inventory.json](python-test-inventory.json): one-off Python test counts for an old PR.
