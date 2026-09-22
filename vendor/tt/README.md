# Vendored Timepoint Telemetry taxonomy

`taxonomy-v2.1.json` — TT ontology **v2.1.0**, sha256
`31ed385e26522a5b548f7404f7757ee370ed9783dbd550b05cd69e89e9462113`.

**Do not edit.** This is upstream's artifact, pinned by content. Its hash is
`cc_filter::version::TT_TAXONOMY_SHA256`, which is the `vocabulary` field of the governed filter
params — so a verdict commits to *which taxonomy it judged under*, and editing this file silently
changes every verdict's provenance.

`cc-filter` deliberately hashes the **artifact**, not a dependency on `tt-core`. What we need from
TT is the taxonomy, not its code, and the filter's minimal dependency tree and empty wasm
host-import table are load-bearing properties.

Updating: replace the file, update the constant, and let
`tt_taxonomy_bundle_matches_the_pinned_hash` fail if you get it wrong. A bundle release is a
governance event — it moves `filter_version`, so genesis must be re-recorded with it.

Lineage note: the taxonomy descends from this corpus (**Clockchain → SNAG → TT**), which is why
all 61 claim types in the ledger are already exact node ids here.
