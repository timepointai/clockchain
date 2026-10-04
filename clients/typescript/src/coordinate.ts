/**
 * v1 time coordinates (`as_of`, `asserted_time.coordinate`) as 64 hex.
 *
 * A coordinate is `cc_core::Tick::to_canon_bytes`: whole seconds since J2000.0
 * (2000-01-01T12:00:00 UTC, every day 86,400 s) shifted left by 64 fractional
 * bits, as a 256-bit two's-complement integer, big-endian, with the top bit
 * flipped (offset binary, so byte order equals time order).
 * docs/PUBLISHER-V1.md "Asserted time" gives the worked example the tests pin.
 *
 * The legacy node's `as_of` was those whole seconds as a decimal string;
 * `coordinateFromSeconds` converts it.
 *
 * Ticks and seconds are `bigint`: a coordinate spans 256 bits. A seconds
 * argument may also be a `number`, if it is a safe integer.
 */

const BITS = 256n;
const FRACTION_BITS = 64n;
const SIGN = 1n << (BITS - 1n);
const MIN = -SIGN;
const MAX = SIGN - 1n;
const J2000_UNIX = 946_728_000n; // 2000-01-01T12:00:00Z in Unix seconds
const COORDINATE = /^[0-9a-f]{64}$/;

/** A raw signed 256-bit tick (seconds << 64 plus fraction) as 64 hex. */
export function coordinateFromTicks(raw: bigint): string {
  if (typeof raw !== "bigint") {
    throw new TypeError("tick must be a bigint");
  }
  if (raw < MIN || raw > MAX) {
    throw new RangeError("tick out of the signed 256-bit range");
  }
  const unsigned = BigInt.asUintN(256, raw);
  return (unsigned ^ SIGN).toString(16).padStart(64, "0");
}

export function ticksFromCoordinate(coordinate: string): bigint {
  if (typeof coordinate !== "string" || !COORDINATE.test(coordinate)) {
    throw new TypeError("coordinate must be 64 lowercase hex");
  }
  return BigInt.asIntN(256, BigInt(`0x${coordinate}`) ^ SIGN);
}

function wholeSeconds(seconds: bigint | number): bigint {
  if (typeof seconds === "bigint") {
    return seconds;
  }
  if (typeof seconds !== "number" || !Number.isInteger(seconds)) {
    throw new TypeError("seconds must be an integer");
  }
  if (!Number.isSafeInteger(seconds)) {
    throw new RangeError("seconds as a number must be a safe integer; pass a bigint");
  }
  return BigInt(seconds);
}

/** Whole seconds since J2000.0 (the legacy `as_of`) as a coordinate. */
export function coordinateFromSeconds(seconds: bigint | number): string {
  return coordinateFromTicks(wholeSeconds(seconds) << FRACTION_BITS);
}

/** Whole seconds since J2000.0, floored (towards earlier time). */
export function secondsFromCoordinate(coordinate: string): bigint {
  // `>>` on a bigint is an arithmetic shift, so a negative tick floors.
  return ticksFromCoordinate(coordinate) >> FRACTION_BITS;
}

function requireInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError("year, month and day must be integers");
  }
  return value;
}

/**
 * 00:00:00 UTC on a proleptic Gregorian date, astronomical year numbering
 * (year 0 is 1 BCE), as `cc-publisher v1 genesis --asserted-time` encodes
 * `YYYY`, `YYYY-MM` and `YYYY-MM-DD`.
 */
export function coordinateFromDate(year: number, month: number = 1, day: number = 1): string {
  requireInteger(year);
  requireInteger(month);
  requireInteger(day);
  if (year < -9999 || year > 9999) {
    throw new RangeError("year must have at most four digits");
  }
  if (month < 1 || month > 12) {
    throw new RangeError("month must be 1..12");
  }
  const last = [31, isLeap(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]!;
  if (day < 1 || day > last) {
    throw new RangeError("no such day");
  }
  return coordinateFromSeconds(BigInt(daysFromCivil(year, month, day)) * 86_400n - J2000_UNIX);
}

/**
 * An instant, floored to the whole second (towards earlier time, also before
 * 1970), as a coordinate. A `Date` is always an absolute instant, so there is
 * no time-zone question to refuse.
 */
export function coordinateFromDateTime(when: Date): string {
  if (!(when instanceof Date)) {
    throw new TypeError("when must be a Date");
  }
  const ms = when.getTime();
  if (Number.isNaN(ms)) {
    throw new RangeError("when is an invalid Date");
  }
  return coordinateFromSeconds(BigInt(Math.floor(ms / 1000)) - J2000_UNIX);
}

/**
 * Days since 1970-01-01, H. Hinnant's days_from_civil, valid for every
 * proleptic Gregorian date including year 0 and negative years. The divisions
 * truncate towards zero, as in the original and in cc-publisher's Rust
 * (`crates/cc-publisher/src/v1/time.rs`); the `- 399` adjustment for negative
 * years assumes truncation, so a flooring division here would be one day
 * early for every date before March of year -1.
 */
function daysFromCivil(year: number, month: number, day: number): number {
  const y = month <= 2 ? year - 1 : year;
  const era = Math.trunc((y >= 0 ? y : y - 399) / 400);
  const yoe = y - era * 400;
  const mp = (month + 9) % 12;
  const doy = Math.trunc((153 * mp + 2) / 5) + day - 1;
  const doe = yoe * 365 + Math.trunc(yoe / 4) - Math.trunc(yoe / 100) + doy;
  return era * 146_097 + doe - 719_468;
}

function isLeap(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}
