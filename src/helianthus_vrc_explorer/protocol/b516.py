from __future__ import annotations

from dataclasses import dataclass
from struct import unpack as _unpack


def _validate_nibble(name: str, value: int) -> int:
    if not (0x0 <= value <= 0xF):
        raise ValueError(f"{name} out of range 0x0..0xF: 0x{value:X}")
    return value


def build_b516_payload(*, period: int, source: int, usage: int, w: int, v: int, q: int) -> bytes:
    return bytes(
        (
            0x10,
            _validate_nibble("period", period),
            0xFF,
            0xFF,
            _validate_nibble("source", source),
            _validate_nibble("usage", usage),
            (_validate_nibble("w", w) << 4) | _validate_nibble("v", v),
            0x30 | _validate_nibble("q", q),
        )
    )


def build_b516_system_payload(*, source: int, usage: int) -> bytes:
    return build_b516_payload(period=0x0, source=source, usage=usage, w=0x0, v=0x0, q=0x0)


def build_b516_year_payload(*, source: int, usage: int, current: bool) -> bytes:
    return build_b516_payload(
        period=0x3,
        source=source,
        usage=usage,
        w=0x0,
        v=0x0,
        q=0x2 if current else 0x0,
    )


@dataclass(frozen=True, slots=True)
class B516Response:
    period: int
    source: int
    usage: int
    packed_window: int
    qualifier: int
    value_wh: float

    @property
    def value_kwh(self) -> float:
        return self.value_wh / 1000.0


def parse_b516_response(payload: bytes) -> B516Response:
    blob = bytes(payload)
    if len(blob) < 11:
        raise ValueError(f"B516 response must be at least 11 bytes, got {len(blob)}")
    return B516Response(
        period=blob[0] & 0x0F,
        source=blob[3] & 0x0F,
        usage=blob[4] & 0x0F,
        packed_window=blob[5],
        qualifier=blob[6] & 0x0F,
        value_wh=float(_unpack("<f", blob[-4:])[0]),
    )
