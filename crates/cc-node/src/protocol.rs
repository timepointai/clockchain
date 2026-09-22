//! The protocol identity this binary is running, and the governed parameters the
//! consensus rule is compiled from.
//!
//! Two nodes that disagree on a verdict must be diagnosable by comparing
//! strings, not by attaching a debugger. That is the entire job of this module:
//! it assembles the one set of governed parameters this binary judges under,
//! derives the filter-version hash from them, and renders the whole identity as
//! the frozen bytes `/health` publishes.
//!
//! **These parameters are not this crate's to invent**, and this module does not
//! invent them: they are governed constants belonging to the ledger as the
//! `protocol_constants_v0` node-0 moment, defined once in `cc-filter` and used
//! verbatim by both `cc-migrator genesis` (which records their hash) and this
//! node (which publishes it). Only some have been blessed; the unblessed ones
//! carry readable `UNBLESSED` markers so the version hash changes when they are
//! finally settled — a build that has not made a governance call must not
//! silently share a version with one that has.

use cc_core::{B256Constants as CoreB256, ExhibitId, FilterVersionId, ProtocolConstants};
use cc_filter::{Filter, FilterParams, FilterVersion};

/// The build revision, baked by `build.rs`.
pub const BUILD_REV: &str = env!("CC_BUILD_REV");

/// The governed parameters this node's filter is compiled from.
///
/// Not authored here. `cc_filter::v0_params()` is the single definition, and it
/// has to be: `cc-migrator genesis` records the hash of these parameters as the
/// `protocol_constants_v0` node-0 moment, and this node publishes the hash of
/// whatever it judges under. If those two were assembled independently — even
/// from identical-looking literals — the ledger's founding moment would name one
/// rule while the node applied another, and the filter version would have failed
/// at precisely the job it exists for. This crate re-exports rather than
/// restates so that divergence is not expressible.
pub fn genesis_filter_params() -> FilterParams {
    cc_filter::v0_params()
}

/// The governed integer/fraction split, which every coordinate parse needs.
pub fn split() -> cc_core::FractionalBits {
    CoreB256::V0.split
}

/// Complete the published constant set with the version of the rule this build
/// actually runs.
///
/// `cc-core` deliberately has no `const V0` for the full set: half of it is a
/// hash over compiled logic, which is not knowable at `cc-core` compile time. So
/// the completion happens here, from the real filter's real version — never from
/// a constant that merely claims to describe it.
pub fn protocol_constants(filter: &Filter) -> ProtocolConstants {
    ProtocolConstants::v0(FilterVersionId(*filter.version().as_bytes()))
}

/// The identity document `/health` publishes, assembled once at boot.
///
/// Serialized with a fixed field order (struct order) and no clock and no I/O,
/// so a monitor can pin the exact bytes for a deploy and a mismatch means the
/// running code or the boot config changed — never that the check ran at a
/// different second.
#[derive(serde::Serialize)]
pub struct HealthDoc {
    /// Always `"ok"`: this endpoint answers liveness, and liveness is not
    /// capability. A dead database must not take it down.
    pub status: &'static str,
    pub service: &'static str,
    /// The artifact, not the machine. See `build.rs`.
    pub build: &'static str,
    /// `live` | `frozen` — boot-frozen, so the pinned bytes always describe the
    /// running posture. A monitor needs this to know whether a non-growing event
    /// count is critical or expected.
    pub posture: &'static str,
    /// The governed constants plus the identity of the rule that judges against
    /// them. A difference in `filter_version` between two nodes is a governance
    /// event; a difference in the per-verdict `corpus_digest` is a
    /// gossip-horizon gap. The two are never folded together.
    pub protocol: ProtocolConstants,
    /// The committed hash of the founding exhibit this node was seeded from, or
    /// The exhibit the OPERATOR pinned, from `CC_GENESIS_EXHIBIT`. `null` where
    /// none was pinned. Never a placeholder hash: a wrong exhibit id is worse
    /// than an absent one.
    ///
    /// **This is configuration, not a ledger fact.** It says what the operator
    /// declared, never what the chain committed — and the two can differ. A
    /// stale value here was once read as proof the chain attested a predecessor
    /// corpus it had never committed, on a surface about to be quoted publicly.
    /// The committed exhibit is published by `/health/deep` as
    /// `exhibit_committed`, read from the `exhibits` table; compare the two
    /// rather than trusting this one.
    pub genesis_exhibit: Option<String>,
}

/// Render the boot-time identity document.
pub fn health_doc(
    filter: &Filter,
    posture: &'static str,
    genesis_exhibit: Option<ExhibitId>,
) -> HealthDoc {
    HealthDoc {
        status: "ok",
        service: "cc-node",
        build: BUILD_REV,
        posture,
        protocol: protocol_constants(filter),
        genesis_exhibit: genesis_exhibit.map(|e| e.to_hex()),
    }
}

/// Lowercase hex of a filter version — the form `/health` and every verdict
/// publish, so an operator comparing two nodes compares identical strings.
pub fn hex_version(v: FilterVersion) -> String {
    hex::encode(v.as_bytes())
}
