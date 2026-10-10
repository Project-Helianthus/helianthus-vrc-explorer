from __future__ import annotations

from dataclasses import dataclass
from struct import unpack as _unpack

# --- B516 packed-date helpers -------------------------------------------
#
# The B516 request/reply date field is a little-endian u16: day occupies
# bits 0-4, month bits 5-8, and year (as an offset from 2000) bits 9-15.
# Day and month are 0 for time bases that do not carry a day/month
# component (total, yearly).

_DATE_DAY_MASK = 0x1F
_DATE_MONTH_SHIFT = 5
_DATE_MONTH_MASK = 0x0F
_DATE_YEAR_SHIFT = 9
_DATE_YEAR_BASE = 2000
_DATE_YEAR_MAX_OFFSET = 0x7F  # 7 bits


@dataclass(frozen=True, slots=True)
class B516Date:
    day: int
    month: int
    year: int

    @property
    def plausible(self) -> bool:
        """True when day/month look like a real calendar date (1-31/1-12).

        A plausible date tells the caller the word actually decodes a
        calendar date (as opposed to the 0/0 placeholder used by time
        bases, such as yearly, that do not carry a day or month).
        """
        return 1 <= self.day <= 31 and 1 <= self.month <= 12

    def as_dict(self) -> dict[str, int]:
        return {"day": self.day, "month": self.month, "year": self.year}


def pack_b516_date(*, day: int, month: int, year: int) -> int:
    """Pack a (day, month, year) triple into the B516 16-bit date word."""
    if not (0 <= day <= 31):
        raise ValueError(f"day out of range 0..31: {day}")
    if not (0 <= month <= 12):
        raise ValueError(f"month out of range 0..12: {month}")
    year_offset = year - _DATE_YEAR_BASE
    if not (0 <= year_offset <= _DATE_YEAR_MAX_OFFSET):
        raise ValueError(
            "year out of range "
            f"{_DATE_YEAR_BASE}..{_DATE_YEAR_BASE + _DATE_YEAR_MAX_OFFSET}: {year}"
        )
    return (
        (day & _DATE_DAY_MASK)
        | ((month & _DATE_MONTH_MASK) << _DATE_MONTH_SHIFT)
        | (year_offset << _DATE_YEAR_SHIFT)
    )


def unpack_b516_date(word: int) -> B516Date:
    """Unpack the B516 16-bit date word into a (day, month, year) triple."""
    if not (0 <= word <= 0xFFFF):
        raise ValueError(f"date word out of range 0x0000..0xFFFF: 0x{word:04X}")
    day = word & _DATE_DAY_MASK
    month = (word >> _DATE_MONTH_SHIFT) & _DATE_MONTH_MASK
    year = _DATE_YEAR_BASE + (word >> _DATE_YEAR_SHIFT)
    return B516Date(day=day, month=month, year=year)


def pack_b516_date_bytes(*, day: int, month: int, year: int) -> tuple[int, int]:
    """Pack a date into its little-endian (low_byte, high_byte) pair."""
    word = pack_b516_date(day=day, month=month, year=year)
    return (word & 0xFF, (word >> 8) & 0xFF)


def unpack_b516_date_bytes(low: int, high: int) -> B516Date:
    """Unpack a little-endian (low_byte, high_byte) pair into a date."""
    return unpack_b516_date(low | (high << 8))


# --- Request builders -----------------------------------------------------


def _validate_nibble(name: str, value: int) -> int:
    if not (0x0 <= value <= 0xF):
        raise ValueError(f"{name} out of range 0x0..0xF: 0x{value:X}")
    return value


def build_b516_payload(*, time_base: int, source: int, usage: int, date_word: int) -> bytes:
    """Build a raw B516 request: `10 TB FF FF ET OM D_lo D_hi`.

    `time_base`'s low two bits select total(0)/daily(1)/monthly(2)/yearly(3);
    the read-access bit (bit 2) is always left clear. `source` is the
    observed Vaillant energy type (ET) and `usage` the operation mode (OM).
    `date_word` is the packed date (see `pack_b516_date`).
    """
    if not (0x0 <= time_base <= 0x3):
        raise ValueError(f"time_base out of range 0x0..0x3: 0x{time_base:X}")
    if not (0 <= date_word <= 0xFFFF):
        raise ValueError(f"date_word out of range 0x0000..0xFFFF: 0x{date_word:04X}")
    return bytes(
        (
            0x10,
            time_base,
            0xFF,
            0xFF,
            _validate_nibble("source", source),
            _validate_nibble("usage", usage),
            date_word & 0xFF,
            (date_word >> 8) & 0xFF,
        )
    )


def build_b516_system_payload(*, source: int, usage: int) -> bytes:
    """Build a B516 total (time base 0) request.

    The date field is ignored by the device for total requests. This exact
    byte sequence (".. 00 30") is the one verified on real hardware, so it
    is kept literal here rather than derived from `pack_b516_date` -- it
    happens to equal `pack_b516_date(day=0, month=0, year=2024)`, but that
    is incidental and must not be relied on.
    """
    return bytes(
        (
            0x10,
            0x00,
            0xFF,
            0xFF,
            _validate_nibble("source", source),
            _validate_nibble("usage", usage),
            0x00,
            0x30,
        )
    )


def build_b516_year_payload(*, source: int, usage: int, year: int) -> bytes:
    """Build a B516 yearly (time base 3) request for a real calendar year."""
    date_word = pack_b516_date(day=0, month=0, year=year)
    return build_b516_payload(time_base=0x3, source=source, usage=usage, date_word=date_word)


# --- Response parsing -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class B516Response:
    time_base: int
    access: bool
    return_code: int
    source: int
    usage: int
    date: B516Date
    value_wh: float | None

    @property
    def ok(self) -> bool:
        """True when the device reports the value as present (return code 0)."""
        return self.return_code == 0

    @property
    def value_kwh(self) -> float | None:
        if self.value_wh is None:
            return None
        return self.value_wh / 1000.0


def parse_b516_response(payload: bytes) -> B516Response:
    """Parse an 11-byte B516 reply.

    Byte 0: time base (bits 0-1), access (bit 2), return code (high
    nibble; 0 = value present, non-zero = not OK -- a valid device answer,
    not a transport error). Bytes 1-2: echoed period/energy index (not
    decoded further here). Byte 3: energy type. Byte 4: operation mode.
    Bytes 5-6: packed date (little-endian), echoing the regulator's own
    current date for total requests, even when the return code is
    non-zero. Bytes 7-10: float32 LE value in Wh, only meaningful when the
    return code is 0.
    """
    blob = bytes(payload)
    if len(blob) < 11:
        raise ValueError(f"B516 response must be at least 11 bytes, got {len(blob)}")
    status_byte = blob[0]
    time_base = status_byte & 0x3
    access = bool(status_byte & 0x4)
    return_code = (status_byte >> 4) & 0xF
    source = blob[3] & 0x0F
    usage = blob[4] & 0x0F
    date = unpack_b516_date_bytes(blob[5], blob[6])
    value_wh = float(_unpack("<f", blob[7:11])[0]) if return_code == 0 else None
    return B516Response(
        time_base=time_base,
        access=access,
        return_code=return_code,
        source=source,
        usage=usage,
        date=date,
        value_wh=value_wh,
    )
