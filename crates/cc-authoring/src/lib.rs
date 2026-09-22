pub mod admission;
pub mod classification;
use cc_core::{B256Constants, Tick};
use sha2::{Digest, Sha256};
const UNIX_TO_J2000_SECS: i64 = 946_728_000;

/// The entity id and resolution digest for a claim.
///
/// Identity is the CLAIM — the normalised title plus the year — never a path, a
/// slug or a surrogate. Hoisted out of `mint` because an edge must resolve its
/// endpoints by exactly this rule: an edge deriving ids any other way would
/// point at entities that do not exist, and would do it silently.
pub fn claim_identity(title: &str, year: i64) -> (i64, [u8; 32]) {
    let mut key = String::new();
    for c in title.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            key.push(c);
        } else if !key.ends_with(' ') {
            key.push(' ');
        }
    }
    let mut h = Sha256::new();
    h.update(format!("{}|{}", key.trim(), year).as_bytes());
    let d: [u8; 32] = h.finalize().into();
    // 62 bits, always positive, never 0 — node 0 is the ledger itself.
    let id = (i64::from_be_bytes(d[0..8].try_into().unwrap()) & 0x3fff_ffff_ffff_ffff).max(1);
    (id, d)
}

/// The coordinate of 1 January of `year`, proleptic Gregorian.
///
/// Exact rather than approximated: a mean-year multiplication would drift by
/// days over two millennia and by weeks at -4000, and a coordinate that is
/// quietly wrong is worse than one that is obviously missing. This is
/// Hinnant's days-from-civil, which is exact for all years including negative
/// ones, where year 0 exists and equals 1 BCE.
pub fn year_tick(year: i64) -> Tick {
    let (y, m, d) = (year, 1i64, 1i64);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468; // days since 1970-01-01
    Tick::from_whole_ticks(days * 86_400 - UNIX_TO_J2000_SECS, B256Constants::V0.split)
}

/// Record-time is *our* clock, floored to the governed tick. Never backfilled:
/// `sign(event_time - record_time)` is the posture, so a fabricated record-time
/// would manufacture one (whitepaper §postures).
pub fn now_tick() -> Tick {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before the Unix epoch")
        .as_secs() as i64;
    Tick::from_whole_ticks(secs - UNIX_TO_J2000_SECS, B256Constants::V0.split)
}

/// A moment's `body_hash` commits to its content; the content itself lives in
/// the projection. Length-framed so `(kind, payload)` cannot be re-split.
pub fn body_hash(kind: &str, payload: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((kind.len() as u32).to_be_bytes());
    h.update(kind.as_bytes());
    h.update((payload.len() as u32).to_be_bytes());
    h.update(payload.as_bytes());
    h.finalize().into()
}
