//! Parsing the `as_of` coordinate off the wire.
//!
//! **A read with no `as_of` is a malformed request, not a read of "now".** The
//! `CorpusView` seam makes `as_of` mandatory on every method because an
//! unbounded read would let a later moment leak into a pinned verdict silently.
//! That discipline is worth nothing if the HTTP layer helpfully substitutes the
//! system clock when the caller omits the parameter — the leak would just move
//! one layer up, and the consensus path would consult a live clock after all.
//! So there is no default here, and there is no function in this module that
//! can produce a coordinate without being handed one.
//!
//! **Two spellings, both exact, neither clamped.** A coordinate is either
//!
//! * `0x` followed by exactly 64 hex characters — the canonical offset-binary
//!   bytes, the single serialized form of a `Tick` anywhere in the system, so
//!   the caller can name *any* coordinate including fractional sub-ticks; or
//! * a decimal integer — a count of **whole ticks** since Clock Zero, shifted
//!   by the governed split. Human-writable, and exact on the whole-tick lattice
//!   every stored coordinate in the genesis corpus sits on.
//!
//! Anything else is refused. Not rounded, not clamped into a sanctioned range,
//! not interpreted as a date: a silently-adjusted coordinate would make the
//! filter version a lie about the search that produced the answer.

use cc_core::Tick;

use crate::protocol::split;

/// Ways a coordinate fails to be one.
#[derive(Debug, thiserror::Error)]
pub enum CoordError {
    #[error("`as_of` is required: a read with no coordinate is a malformed request, never a read of the current time")]
    Missing,
    #[error("`as_of` must be a decimal whole-tick count or `0x` + 64 hex characters; got {0:?}")]
    Malformed(String),
    #[error(
        "`as_of` is the reserved existence-window sentinel, which is a bound and not a coordinate"
    )]
    Sentinel,
}

/// Parse an `as_of` value. See the module docs for the accepted spellings.
pub fn parse_as_of(raw: Option<&str>) -> Result<Tick, CoordError> {
    let raw = raw.ok_or(CoordError::Missing)?;
    let s = raw.trim();
    if s.is_empty() {
        return Err(CoordError::Missing);
    }

    let tick = if let Some(hexpart) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if hexpart.len() != 64 {
            return Err(CoordError::Malformed(raw.to_string()));
        }
        let bytes = hex::decode(hexpart).map_err(|_| CoordError::Malformed(raw.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CoordError::Malformed(raw.to_string()))?;
        Tick::from_canon_bytes(arr)
    } else {
        // Whole ticks. `i64` overflow is a refusal, not a wrap: a coordinate the
        // caller could not have meant must not become one they did not name.
        let whole: i64 = s
            .parse()
            .map_err(|_| CoordError::Malformed(raw.to_string()))?;
        Tick::from_whole_ticks(whole, split())
    };

    // The sentinel is the reserved maximal bound that makes `t_q <= end(f)` hold
    // with no special case. Admitting it as a *query* coordinate would make
    // every open window trivially satisfied at the one coordinate where the
    // arithmetic carries no information. The filter refuses it too; refusing it
    // here as well means a plain corpus read cannot be pinned to it either.
    if tick == Tick::SENTINEL {
        return Err(CoordError::Sentinel);
    }
    Ok(tick)
}

/// The wire rendering of a coordinate: both spellings, so a caller can see
/// exactly which coordinate answered and replay it byte-for-byte.
#[derive(serde::Serialize)]
pub struct Coord {
    /// `0x` + 64 hex: the canonical, lossless form.
    pub canonical: String,
    /// Whole ticks since Clock Zero. Present only when the coordinate sits on
    /// the whole-tick lattice — a coordinate with fractional bits has no exact
    /// whole-tick rendering, and rendering a rounded one would be the clamp this
    /// module exists to refuse.
    pub whole_ticks: Option<i64>,
}

/// Render a coordinate for a response body.
pub fn render(t: Tick) -> Coord {
    Coord {
        canonical: format!("0x{}", hex::encode(t.to_canon_bytes())),
        whole_ticks: whole_ticks_i64(t),
    }
}

/// The whole-tick count, iff the coordinate is exactly that count.
///
/// Everything is decided by the closing round-trip: whatever candidate the byte
/// arithmetic produces is *only* returned if shifting it back up under the
/// governed split reproduces the coordinate bit-for-bit. That single check
/// subsumes every failure mode — fractional bits set, a magnitude past `i64`, a
/// split this byte-level shift cannot express — so none of them can leak out as
/// a plausible-looking rounded number.
fn whole_ticks_i64(t: Tick) -> Option<i64> {
    let s = split().0;
    if !s.is_multiple_of(8) || s > 192 {
        return None;
    }
    let mut b = t.to_canon_bytes();
    b[0] ^= 0x80; // offset-binary -> two's complement, big-endian
    let keep = 32 - (s as usize / 8); // bytes holding the whole part; >= 8
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[keep - 8..keep]);
    let candidate = i64::from_be_bytes(w);
    (Tick::from_whole_ticks(candidate, split()) == t).then_some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_is_refused() {
        assert!(matches!(parse_as_of(None), Err(CoordError::Missing)));
        assert!(matches!(parse_as_of(Some("  ")), Err(CoordError::Missing)));
    }

    #[test]
    fn decimal_whole_ticks_round_trip() {
        let t = parse_as_of(Some("1234")).unwrap();
        assert_eq!(t, Tick::from_whole_ticks(1234, split()));
        let r = render(t);
        assert_eq!(r.whole_ticks, Some(1234));
        assert_eq!(parse_as_of(Some(&r.canonical)).unwrap(), t);
    }

    #[test]
    fn negative_coordinates_are_ordinary() {
        // The corpus is mostly pre-Clock-Zero; a negative coordinate is the
        // common case, not an edge case.
        let t = parse_as_of(Some("-63000000000")).unwrap();
        assert_eq!(t, Tick::from_whole_ticks(-63_000_000_000, split()));
    }

    #[test]
    fn garbage_is_refused_not_coerced() {
        for bad in ["now", "2026-08-12", "1.5", "0x00", "0xzz", "", "12 34"] {
            assert!(
                matches!(
                    parse_as_of(Some(bad)),
                    Err(CoordError::Malformed(_)) | Err(CoordError::Missing)
                ),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn sentinel_is_refused() {
        let s = format!("0x{}", hex::encode(Tick::SENTINEL.to_canon_bytes()));
        assert!(matches!(parse_as_of(Some(&s)), Err(CoordError::Sentinel)));
    }

    #[test]
    fn fractional_coordinates_have_no_whole_tick_rendering() {
        // One sub-tick past whole tick 5. Offset-binary is order-preserving and
        // monotone, so incrementing the canonical bytes increments the
        // coordinate — which is how we build a sub-tick value without naming
        // `bnum`'s I256 (cc-core does not re-export it).
        let mut b = Tick::from_whole_ticks(5, split()).to_canon_bytes();
        assert_eq!(b[31], 0, "whole ticks have a zero low byte under split 64");
        b[31] = 1;
        let t = Tick::from_canon_bytes(b);
        let r = render(t);
        // Exact in canonical form, and deliberately *absent* rather than rounded
        // in the decimal one.
        assert_eq!(r.whole_ticks, None);
        assert_eq!(parse_as_of(Some(&r.canonical)).unwrap(), t);
    }
}
