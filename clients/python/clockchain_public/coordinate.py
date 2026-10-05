"""v1 time coordinates (`as_of`, `asserted_time.coordinate`) as 64 hex.

A coordinate is `cc_core::Tick::to_canon_bytes`: whole seconds since J2000.0
(2000-01-01T12:00:00 UTC, every day 86,400 s) shifted left by 64 fractional
bits, as a 256-bit two's-complement integer, big-endian, with the top bit
flipped (offset binary, so byte order equals time order). docs/PUBLISHER-V1.md
"Asserted time" gives the worked example the tests pin.

The legacy node's `as_of` was those whole seconds as a decimal string;
`coordinate_from_seconds` converts it.
"""

from __future__ import annotations

import datetime as _dt
import re as _re

_BITS = 256
_FRACTION_BITS = 64
_MIN = -(1 << (_BITS - 1))
_MAX = (1 << (_BITS - 1)) - 1
_J2000_UNIX = 946_728_000  # 2000-01-01T12:00:00Z in Unix seconds
_HEX64 = _re.compile(r"[0-9a-f]{64}\Z")


def coordinate_from_ticks(raw: int) -> str:
    """A raw signed 256-bit tick (seconds << 64 plus fraction) as 64 hex."""
    if isinstance(raw, bool) or not isinstance(raw, int) or not _MIN <= raw <= _MAX:
        raise ValueError("tick out of the signed 256-bit range")
    unsigned = raw & ((1 << _BITS) - 1)
    return (unsigned ^ (1 << (_BITS - 1))).to_bytes(32, "big").hex()


def ticks_from_coordinate(coordinate: str) -> int:
    if not isinstance(coordinate, str) or _HEX64.match(coordinate) is None:
        raise ValueError("coordinate must be 64 lowercase hex")
    v = int.from_bytes(bytes.fromhex(coordinate), "big") ^ (1 << (_BITS - 1))
    return v - (1 << _BITS) if v >> (_BITS - 1) else v


def coordinate_from_seconds(seconds: int) -> str:
    """Whole seconds since J2000.0 (the legacy `as_of`) as a coordinate."""
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("seconds must be an integer")
    return coordinate_from_ticks(seconds << _FRACTION_BITS)


def seconds_from_coordinate(coordinate: str) -> int:
    """Whole seconds since J2000.0, floored (towards earlier time)."""
    return ticks_from_coordinate(coordinate) >> _FRACTION_BITS


def coordinate_from_date(year: int, month: int = 1, day: int = 1) -> str:
    """00:00:00 UTC on a proleptic Gregorian date, astronomical year numbering
    (year 0 is 1 BCE), as `cc-publisher v1 genesis --asserted-time` encodes
    `YYYY`, `YYYY-MM` and `YYYY-MM-DD`."""
    for v in (year, month, day):
        if isinstance(v, bool) or not isinstance(v, int):
            raise ValueError("year, month and day must be integers")
    if not -9999 <= year <= 9999:
        raise ValueError("year must have at most four digits")
    if not 1 <= month <= 12:
        raise ValueError("month must be 1..12")
    # days_from_civil (H. Hinnant), valid for every proleptic Gregorian date,
    # including years datetime.date cannot represent (0 and negative). The
    # C original writes `(y >= 0 ? y : y - 399) / 400` with truncating
    # division; Python's `//` already floors, so it is plain `y // 400`.
    y = year - (month <= 2)
    era = y // 400
    yoe = y - era * 400
    mp = (month + 9) % 12
    last = [31, 29 if _leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    if not 1 <= day <= last:
        raise ValueError("no such day")
    doy = (153 * mp + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return coordinate_from_seconds(days * 86_400 - _J2000_UNIX)


def coordinate_from_datetime(when: _dt.datetime) -> str:
    """An aware datetime, truncated to the whole second, as a coordinate."""
    if when.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    unix = when - _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    seconds = unix.days * 86_400 + unix.seconds
    return coordinate_from_seconds(seconds - _J2000_UNIX)


def _leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
