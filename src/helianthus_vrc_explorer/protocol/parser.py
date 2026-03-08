from __future__ import annotations

import math
import struct
from datetime import date


class ValueParseError(Exception):
    """Raised when response bytes cannot be parsed into a typed value."""


class ValueEncodeError(Exception):
    """Raised when a typed value cannot be encoded into bytes."""


def _expect_len(type_spec: str, data: bytes, expected_len: int) -> None:
    if len(data) != expected_len:
        raise ValueParseError(f"{type_spec} expects {expected_len} bytes, got {len(data)} bytes")


def _decode_bcd(type_spec: str, field: str, value: int) -> int:
    """Decode a single byte containing a BCD-encoded decimal number."""

    high = (value >> 4) & 0xF
    low = value & 0xF
    if high > 9 or low > 9:
        raise ValueParseError(f"{type_spec} invalid BCD for {field}: 0x{value:02X}")
    return high * 10 + low


def _encode_bcd(type_spec: str, field: str, value: int) -> int:
    """Encode a 0..99 integer into a single BCD byte."""

    if not (0 <= value <= 99):
        raise ValueEncodeError(f"{type_spec} {field} must be 0..99, got {value}")
    tens = value // 10
    ones = value % 10
    return (tens << 4) | ones


def parse_exp(data: bytes) -> float | None:
    """Parse an `EXP` value (float32le).

    Notes:
        - NaN values are returned as `None` so they can later be rendered as JSON `null`.
    """

    _expect_len("EXP", data, 4)
    value = struct.unpack("<f", data)[0]
    if math.isnan(value):
        return None
    return float(value)


def parse_uin(data: bytes) -> int:
    """Parse an `UIN` value (u16le)."""

    _expect_len("UIN", data, 2)
    return int.from_bytes(data, byteorder="little", signed=False)


def parse_uch(data: bytes) -> int:
    """Parse an `UCH` value (u8)."""

    _expect_len("UCH", data, 1)
    return data[0]


def parse_i8(data: bytes) -> int:
    """Parse an `I8` value (i8)."""

    _expect_len("I8", data, 1)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_i16(data: bytes) -> int:
    """Parse an `I16` value (i16le)."""

    _expect_len("I16", data, 2)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_u32(data: bytes) -> int:
    """Parse an `U32` value (u32le)."""

    _expect_len("U32", data, 4)
    return int.from_bytes(data, byteorder="little", signed=False)


def parse_i32(data: bytes) -> int:
    """Parse an `I32` value (i32le)."""

    _expect_len("I32", data, 4)
    return int.from_bytes(data, byteorder="little", signed=True)


def parse_bool(data: bytes) -> bool:
    """Parse a `BOOL` value (u8 -> bool)."""

    _expect_len("BOOL", data, 1)
    return data[0] != 0x00


def parse_hex(type_spec: str, data: bytes, expected_len: int) -> str:
    """Parse a `HEX:n` value as a hex string preserving byte order."""

    _expect_len(type_spec, data, expected_len)
    return "0x" + data.hex()


def parse_str_cstring(data: bytes) -> str:
    """Parse a `STR:*` value (cstring).

    CString semantics stop at the first NUL byte.
    """

    return data.split(b"\x00", 1)[0].decode("latin1")


def parse_hda3_date(data: bytes) -> str:
    """Parse an `HDA:3` value (u24le date encoded as DDMMYY, BCD per byte).

    Returns:
        ISO-ish date string: `YYYY-MM-DD`.

    Notes:
        The underlying schema only gives a 2-digit year. We interpret it as `2000 + YY`
        to match modern VRC firmware dates (2000-2099).
    """

    _expect_len("HDA:3", data, 3)
    day = _decode_bcd("HDA:3", "day", data[0])
    month = _decode_bcd("HDA:3", "month", data[1])
    year_2digit = _decode_bcd("HDA:3", "year", data[2])

    year = 2000 + year_2digit
    try:
        return date(year, month, day).isoformat()
    except ValueError as exc:
        raise ValueParseError(
            f"HDA:3 invalid date DDMMYY={day:02d}{month:02d}{year_2digit:02d}"
        ) from exc


def parse_hti_time(data: bytes) -> str:
    """Parse an `HTI` value (u24le time encoded as HH:MM:SS, BCD per byte).

    Returns:
        ISO-ish time string: `HH:MM:SS`.
    """

    _expect_len("HTI", data, 3)
    hour = _decode_bcd("HTI", "hour", data[0])
    minute = _decode_bcd("HTI", "minute", data[1])
    second = _decode_bcd("HTI", "second", data[2])

    if hour > 23:
        raise ValueParseError(f"HTI hour must be 0..23, got {hour}")
    if minute > 59:
        raise ValueParseError(f"HTI minute must be 0..59, got {minute}")
    if second > 59:
        raise ValueParseError(f"HTI second must be 0..59, got {second}")

    return f"{hour:02d}:{minute:02d}:{second:02d}"


def parse_fw(data: bytes) -> str:
    """Parse an `FW` value (u24 firmware version encoded as BCD bytes).

    Returns:
        Canonical firmware version string: `MM.mm.pp`.
    """

    _expect_len("FW", data, 3)
    major = _decode_bcd("FW", "major", data[0])
    minor = _decode_bcd("FW", "minor", data[1])
    patch = _decode_bcd("FW", "patch", data[2])
    return f"{major:02d}.{minor:02d}.{patch:02d}"


def encode_exp(value: float) -> bytes:
    """Encode an `EXP` value (float32le)."""

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueEncodeError(f"EXP expects float, got {type(value).__name__}")
    if math.isnan(float(value)):
        raise ValueEncodeError("EXP cannot encode NaN")
    return struct.pack("<f", float(value))


def encode_uin(value: int) -> bytes:
    """Encode an `UIN` value (u16le)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"UIN expects int, got {type(value).__name__}")
    if not (0 <= value <= 0xFFFF):
        raise ValueEncodeError(f"UIN out of range 0..65535, got {value}")
    return int(value).to_bytes(2, byteorder="little", signed=False)


def encode_uch(value: int) -> bytes:
    """Encode an `UCH` value (u8)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"UCH expects int, got {type(value).__name__}")
    if not (0 <= value <= 0xFF):
        raise ValueEncodeError(f"UCH out of range 0..255, got {value}")
    return bytes((int(value),))


def encode_i8(value: int) -> bytes:
    """Encode an `I8` value (i8)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"I8 expects int, got {type(value).__name__}")
    if not (-0x80 <= value <= 0x7F):
        raise ValueEncodeError(f"I8 out of range -128..127, got {value}")
    return int(value).to_bytes(1, byteorder="little", signed=True)


def encode_i16(value: int) -> bytes:
    """Encode an `I16` value (i16le)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"I16 expects int, got {type(value).__name__}")
    if not (-0x8000 <= value <= 0x7FFF):
        raise ValueEncodeError(f"I16 out of range -32768..32767, got {value}")
    return int(value).to_bytes(2, byteorder="little", signed=True)


def encode_u32(value: int) -> bytes:
    """Encode an `U32` value (u32le)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"U32 expects int, got {type(value).__name__}")
    if not (0 <= value <= 0xFFFFFFFF):
        raise ValueEncodeError(f"U32 out of range 0..4294967295, got {value}")
    return int(value).to_bytes(4, byteorder="little", signed=False)


def encode_i32(value: int) -> bytes:
    """Encode an `I32` value (i32le)."""

    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueEncodeError(f"I32 expects int, got {type(value).__name__}")
    if not (-0x80000000 <= value <= 0x7FFFFFFF):
        raise ValueEncodeError(f"I32 out of range -2147483648..2147483647, got {value}")
    return int(value).to_bytes(4, byteorder="little", signed=True)


def encode_bool(value: bool) -> bytes:
    """Encode a `BOOL` value as a single u8 byte."""

    if not isinstance(value, bool):
        raise ValueEncodeError(f"BOOL expects bool, got {type(value).__name__}")
    return b"\x01" if value else b"\x00"


def encode_str_cstring(value: str) -> bytes:
    """Encode a `STR:*` value as latin1 + NUL terminator."""

    if not isinstance(value, str):
        raise ValueEncodeError(f"STR expects str, got {type(value).__name__}")
    return value.encode("latin1") + b"\x00"


def encode_hex(type_spec: str, value: str, expected_len: int) -> bytes:
    """Encode a `HEX:n` value from a hex string."""

    if not isinstance(value, str):
        raise ValueEncodeError(f"{type_spec} expects hex string, got {type(value).__name__}")
    text = value.strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if len(text) % 2:
        raise ValueEncodeError(f"{type_spec} hex string must have even length")
    try:
        data = bytes.fromhex(text)
    except ValueError as exc:
        raise ValueEncodeError(f"{type_spec} invalid hex string") from exc
    if len(data) != expected_len:
        raise ValueEncodeError(f"{type_spec} expects {expected_len} bytes, got {len(data)} bytes")
    return data


def encode_hda3_date(value: str) -> bytes:
    """Encode an `HDA:3` value from `YYYY-MM-DD`."""

    if not isinstance(value, str):
        raise ValueEncodeError(f"HDA:3 expects str, got {type(value).__name__}")
    try:
        yyyy_s, mm_s, dd_s = value.split("-", 2)
        yyyy = int(yyyy_s)
        mm = int(mm_s)
        dd = int(dd_s)
    except Exception as exc:
        raise ValueEncodeError("HDA:3 expects YYYY-MM-DD") from exc
    if not (2000 <= yyyy <= 2099):
        raise ValueEncodeError(f"HDA:3 year must be 2000..2099, got {yyyy}")
    yy = yyyy - 2000
    return bytes(
        (
            _encode_bcd("HDA:3", "day", dd),
            _encode_bcd("HDA:3", "month", mm),
            _encode_bcd("HDA:3", "year", yy),
        )
    )


def encode_hti_time(value: str) -> bytes:
    """Encode an `HTI` value from `HH:MM:SS`."""

    if not isinstance(value, str):
        raise ValueEncodeError(f"HTI expects str, got {type(value).__name__}")
    try:
        hh_s, mm_s, ss_s = value.split(":", 2)
        hh = int(hh_s)
        mm = int(mm_s)
        ss = int(ss_s)
    except Exception as exc:
        raise ValueEncodeError("HTI expects HH:MM:SS") from exc
    if not (0 <= hh <= 23):
        raise ValueEncodeError(f"HTI hour must be 0..23, got {hh}")
    if not (0 <= mm <= 59):
        raise ValueEncodeError(f"HTI minute must be 0..59, got {mm}")
    if not (0 <= ss <= 59):
        raise ValueEncodeError(f"HTI second must be 0..59, got {ss}")
    return bytes(
        (
            _encode_bcd("HTI", "hour", hh),
            _encode_bcd("HTI", "minute", mm),
            _encode_bcd("HTI", "second", ss),
        )
    )


def encode_fw(value: str) -> bytes:
    """Encode an `FW` value from `MM.mm.pp`."""

    if not isinstance(value, str):
        raise ValueEncodeError(f"FW expects str, got {type(value).__name__}")

    parts = value.split(".")
    if len(parts) != 3 or any(len(part) != 2 or not part.isdigit() for part in parts):
        raise ValueEncodeError("FW expects MM.mm.pp")

    major, minor, patch = (int(part) for part in parts)
    return bytes(
        (
            _encode_bcd("FW", "major", major),
            _encode_bcd("FW", "minor", minor),
            _encode_bcd("FW", "patch", patch),
        )
    )


def encode_typed_value(type_spec: str, value: object) -> bytes:
    """Encode a typed value into bytes compatible with ebusd schema type specs."""

    normalized = type_spec.strip().upper()

    if normalized.startswith("STR:"):
        return encode_str_cstring(value)  # type: ignore[arg-type]

    if normalized.startswith("HEX:"):
        try:
            expected = int(normalized.split(":", 1)[1], 10)
        except ValueError as exc:
            raise ValueEncodeError(f"Invalid HEX length in type spec: {type_spec!r}") from exc
        return encode_hex(normalized, value, expected_len=expected)  # type: ignore[arg-type]

    match normalized:
        case "EXP":
            return encode_exp(value)  # type: ignore[arg-type]
        case "UIN":
            return encode_uin(value)  # type: ignore[arg-type]
        case "UCH":
            return encode_uch(value)  # type: ignore[arg-type]
        case "I8":
            return encode_i8(value)  # type: ignore[arg-type]
        case "I16":
            return encode_i16(value)  # type: ignore[arg-type]
        case "U32":
            return encode_u32(value)  # type: ignore[arg-type]
        case "I32":
            return encode_i32(value)  # type: ignore[arg-type]
        case "BOOL":
            return encode_bool(value)  # type: ignore[arg-type]
        case "HDA:3":
            return encode_hda3_date(value)  # type: ignore[arg-type]
        case "HTI":
            return encode_hti_time(value)  # type: ignore[arg-type]
        case "FW":
            return encode_fw(value)  # type: ignore[arg-type]
        case _:
            raise ValueEncodeError(f"Unknown type spec: {type_spec!r}")


def parse_typed_value(type_spec: str, data: bytes) -> object:
    """Parse a typed value from a B524 response tail.

    The type is taken from the ebusd CSV schema (`type` column). Only the minimal set
    needed for B524 register reads is implemented:

    - `EXP`: float32le (`NaN` -> `None`)
    - `UIN`: u16le
    - `UCH`: u8
    - `STR:*`: cstring (latin1, trailing NULs stripped)
    - `HDA:3`: u24le date encoded as DDMMYY (BCD per byte, `YYYY-MM-DD`)
    - `HTI`: u24le time encoded as HH:MM:SS (BCD per byte, `HH:MM:SS`)
    - `FW`: 3-byte firmware version encoded as BCD bytes (`MM.mm.pp`)

    Args:
        type_spec: Type spec string (e.g. `"EXP"`, `"STR:*"`).
        data: Raw bytes for the value (after stripping the 4-byte echo header).

    Returns:
        Parsed Python value. `EXP` may return `None` if the decoded float is NaN.

    Raises:
        ValueParseError: On unknown type, wrong length, or malformed values.
    """

    normalized = type_spec.strip().upper()

    if normalized.startswith("STR:"):
        return parse_str_cstring(data)

    if normalized.startswith("HEX:"):
        try:
            expected = int(normalized.split(":", 1)[1], 10)
        except ValueError as exc:
            raise ValueParseError(f"Invalid HEX length in type spec: {type_spec!r}") from exc
        return parse_hex(normalized, data, expected_len=expected)

    match normalized:
        case "EXP":
            return parse_exp(data)
        case "UIN":
            return parse_uin(data)
        case "UCH":
            return parse_uch(data)
        case "I8":
            return parse_i8(data)
        case "I16":
            return parse_i16(data)
        case "U32":
            return parse_u32(data)
        case "I32":
            return parse_i32(data)
        case "BOOL":
            return parse_bool(data)
        case "HDA:3":
            return parse_hda3_date(data)
        case "HTI":
            return parse_hti_time(data)
        case "FW":
            return parse_fw(data)
        case _:
            raise ValueParseError(f"Unknown type spec: {type_spec!r}")
