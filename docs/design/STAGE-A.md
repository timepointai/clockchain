# Stage (a): v1 encoding and candidate admission

This records PR #8's boundary. Subsequent authority implementation is described
in [Stage (b)](STAGE-B.md); the normal node remains non-serving for canonical v1.

This implements the encoding and candidate-store foundation of
[MULTI-SIGNER.md](MULTI-SIGNER.md). It is **non-serving**. The node binary and its
legacy router do not enable v1; `Store::readiness()` and the review router's
`/ready` always refuse. No production migration, projection, support verdict,
media record or publication path is introduced. The owner has selected the full (a)–(e) ship sequence.

`cc_core::CANON_VERSION` is now 1. Existing `canon_event` explicitly uses
`LEGACY_CANON_VERSION = 0`, preserving all v0 identities and applied migrations.
`cc_core::v1::Signed::decode` has no legacy fallback. It validates versions,
canonical framing/sets, UTF-8, bounds, and the author-bound Ed25519 signature.
Eight independent stdlib-framed preimage/hash vectors cover every event tag;
their generator is `crates/cc-core/tests/vectors/v1_reference.py`.

The v1 module signs the preimage, not its hash. Signed wire bytes are exactly
`preimage || signature[64]`. The preimage uses the design's field order. Empty
subject/grant references and the absent subject tuple on non-subject events use
the canonical optional tag. Subject tuples are byte-exact and inspectable.

| Wire item | Encoding |
| --- | --- |
| Integers, lengths | Big-endian; counts/frames u32; versions/event/enum tags u16 |
| Hashes/keys; signatures | Fixed 32 bytes; fixed 64 bytes |
| Optional; bool | Required byte 0 or 1; optional 1 followed by value |
| Sets | u32 count, strictly increasing encoded fixed references; duplicate references reject |
| Text | u32 byte length, valid UTF-8, no normalization |
| Subject key | kind, namespace, value; each 1–1,024 UTF-8 bytes |
| Asserted time | coordinate[32], precision text; no authority/ordering use |
| Pin | subject, basis, revision, body, each 32 bytes; source then target in a pin pair |
| Decision | kind, rationale, evidence set, parents set, old value, new value |
| Value tags 0–8 | none, body, grant(issuer/grantee), active grant, revoked grant(grant/cascade), heads, revision, pins, parent pins |
| Selection tags 0–1 | existing revision, merged body |
| Disposition tags 1–3 | selected, merged, not_selected; each disposition includes parent and rationale |
| Attestation target tags 1–2 | event, revision |

Payload fields follow the typed Rust declaration order in `cc-core/src/v1.rs`;
the header carries the event tag once. The envelope cap includes the signature
(1 MiB); each set is limited to 1,024 members. Structured sets sort by their
32-byte parent reference and reject repeated parents even with different
dispositions/pins. No byte decoder
silently sorts, deduplicates, normalizes, ignores a version or infers cascade.

`cc_ledger::v1::Store::admit` is the sole v1 write entry point. HTTP, import and
restore call it. A signed, correctly framed instance-local candidate is retained
even when semantic classification is pending or invalid. Malformed, foreign-
instance and bad-signature input receives a separate input-digest rejection;
bad signatures cannot poison a later valid event. Replay recomputes from verified
bytes and checks each row's event ID. Duplicate delivery is idempotent. Each
envelope is atomic; import/restore are ordered sequences of these transactions,
not an all-or-nothing batch.

Fresh provisioning refuses existing user tables, including a migrated v0 store
whose projections happen to be empty. Reopen checks instance, encoding and the
stage schema hash. The fresh bootstrap is separate from the immutable v0
migrations. Candidate, rejection and identity rows reject update/delete/truncate.
Database-owner tampering is not signer authority; review refuses corrupted IDs
or wire bytes. There is no public raw v1 append method or verification bypass.

Stage (a)'s `valid` means **branch-local candidate validity**, not an admitted
public head. Genesis and root-signed Corrections check subject identity, parent
dependencies, root authority and the exact old/new body decision. Bodies may be
unavailable; no body prose or historical adequacy is inferred. All subject
transitions check stable identity when their parents are known. Delegate/Revoke,
Resolve, edges and attestations retain explicit later-stage pending reasons;
they grant no authority or support. No production fold identity is claimed.
The interim store cannot become serving by toggling a flag. Later stages must
change the schema/rule contract explicitly; the rejected single-key alternative would have required rejecting Delegate/Revoke
before candidate storage.

`cc_node::v1::review_router` exists for operator integration tests against fresh
synthetic stores. Its only write route is `POST /v1/candidates` with raw signed
bytes and a separately supplied writer credential digest. A read credential
does not grant writes. Authentication and the body cap are transport concerns;
the semantic response is the shared admission result. `/ready` returns 503;
there are no entity, filter or media routes. Nothing wires it into normal boot.

The initial differential harness compares **1,728** generated G/C delivery cases
against the accepted Stage 0 fold: all one-parent DAGs through four events,
three final-signer choices, every ordering/prefix and duplicate set union. It
normalizes model head/superseded/branch to branch-local `valid`; it does not claim
projection equivalence. HTTP/import/restore also compare identical prefixes and
wire inputs on three real Postgres stores, including child-before-parent,
signature/version rejection, wrong signer/instance, changed subject and replay.
Stage (b) must add grants/revocations; (c) must compare complete `View` rows,
frontiers and effects. The accepted model/checker and full-bound receipt are
unchanged by this adapter.

Run `make check` with synthetic `TEST_DATABASE_URL`, the Wasm build, and the
operator unittest suite per AGENTS.md. Cargo's differential test requires
`python3` (or `CC_MODEL_PYTHON`) and only the standard library; CI's normal Cargo
job runs it. The separate Stage 0 job still runs its bounded checker and all
mutants. Refs #6. Its final disposition remains the owner's explicit action after
Stage (e) and operational evidence.
