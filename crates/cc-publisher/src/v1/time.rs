//! Asserted time for a v1 event, as `cc_core::v1::AssertedTime`.
//!
//! Accepted syntax, proleptic Gregorian with astronomical year numbering
//! (year `0000` is 1 BCE, `-0043` is 44 BCE):
//!
//! | Input        | `precision` | Instant encoded in `coordinate`     |
//! | ------------ | ----------- | ----------------------------------- |
//! | `YYYY`       | `year`      | 00:00:00 UTC on 1 January of `YYYY` |
//! | `YYYY-MM`    | `month`     | 00:00:00 UTC on day 1 of that month |
//! | `YYYY-MM-DD` | `day`       | 00:00:00 UTC on that day            |
//!
//! Exactly four year digits with an optional leading `-`, two month digits
//! and two day digits; nothing else (no time of day, zone or whitespace).
//! `-0000` is refused because `0000` names the same year. The coordinate is
//! the `cc_core::Tick` of that instant: whole seconds since J2000.0
//! (2000-01-01T12:00:00 UTC), counting every day as 86,400 seconds, shifted
//! left by the governed 64 fractional bits and serialized by
//! `Tick::to_canon_bytes`. It is the mapping `cc_authoring::year_tick` and the
//! v0 publisher's day precision use.
use anyhow::{bail, ensure, Result};
use cc_core::v1::AssertedTime;
use cc_core::{B256Constants, Tick};

/// Unix seconds of J2000.0, 2000-01-01T12:00:00 UTC.
const UNIX_TO_J2000_SECS: i64 = 946_728_000;

/// Parse the syntax in the module documentation.
pub fn parse(input: &str) -> Result<AssertedTime> {
    let (negative, rest) = match input.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, input),
    };
    let parts: Vec<&str> = rest.split('-').collect();
    let widths = [4, 2, 2];
    ensure!(
        (1..=3).contains(&parts.len())
            && parts
                .iter()
                .zip(widths)
                .all(|(p, w)| p.len() == w && p.bytes().all(|b| b.is_ascii_digit())),
        "asserted time {input:?} must be YYYY, YYYY-MM or YYYY-MM-DD (optional leading '-' for years before 0000)"
    );
    let digits: i64 = parts[0].parse()?;
    if negative && digits == 0 {
        bail!("asserted time {input:?}: write year 0000 without a sign");
    }
    let year = if negative { -digits } else { digits };
    let month: i64 = parts.get(1).map_or(Ok(1), |m| m.parse())?;
    let day: i64 = parts.get(2).map_or(Ok(1), |d| d.parse())?;
    ensure!(
        (1..=12).contains(&month),
        "asserted time {input:?}: month must be 01-12"
    );
    ensure!(
        (1..=days_in_month(year, month)).contains(&day),
        "asserted time {input:?}: no such day in that month"
    );
    let precision = ["year", "month", "day"][parts.len() - 1];
    Ok(AssertedTime {
        coordinate: coordinate(year, month, day),
        precision: precision.into(),
    })
}

/// The calendar form of an asserted time, if its coordinate is exactly the
/// instant [`parse`] gives for its precision; otherwise `None`.
pub fn render(t: &AssertedTime) -> Option<String> {
    let seconds = whole_seconds(&t.coordinate)?.checked_add(UNIX_TO_J2000_SECS)?;
    if seconds.rem_euclid(86_400) != 0 {
        return None;
    }
    let (y, m, d) = civil_from_days(seconds.div_euclid(86_400));
    if !(-9999..=9999).contains(&y) {
        return None;
    }
    let year = if y < 0 {
        format!("-{:04}", -y)
    } else {
        format!("{y:04}")
    };
    let text = match t.precision.as_str() {
        "year" if m == 1 && d == 1 => year,
        "month" if d == 1 => format!("{year}-{m:02}"),
        "day" => format!("{year}-{m:02}-{d:02}"),
        _ => return None,
    };
    (parse(&text).ok()? == *t).then_some(text)
}

fn coordinate(year: i64, month: i64, day: i64) -> [u8; 32] {
    let seconds = days_from_civil(year, month, day) * 86_400 - UNIX_TO_J2000_SECS;
    Tick::from_whole_ticks(seconds, B256Constants::V0.split).to_canon_bytes()
}

/// Whole seconds of a canonical coordinate, if it has no fractional part and
/// fits in `i64`. Canon bytes are offset-binary big-endian of `seconds << 64`.
fn whole_seconds(c: &[u8; 32]) -> Option<i64> {
    if c[24..] != [0; 8] {
        return None;
    }
    let seconds = i64::from_be_bytes(c[16..24].try_into().unwrap());
    let fill = if seconds < 0 { 0xff } else { 0x00 };
    (c[0] == fill ^ 0x80 && c[1..16].iter().all(|b| *b == fill)).then_some(seconds)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    let leap = year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Hinnant's days_from_civil).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Inverse of [`days_from_civil`] (Hinnant's civil_from_days).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}
