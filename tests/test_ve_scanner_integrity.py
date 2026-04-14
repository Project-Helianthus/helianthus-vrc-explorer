"""Tests for VE27, VE29, VE30, and C7 scanner subsystem fixes."""
from __future__ import annotations

import math
import struct

import pytest

from helianthus_vrc_explorer.scanner.b509 import parse_b509_range
from helianthus_vrc_explorer.scanner.plan import parse_int_set
from helianthus_vrc_explorer.scanner.register import _sentinel_value_display
from helianthus_vrc_explorer.scanner.scan import (
    ConstraintEntry,
    _decode_constraint_date,
    _parse_constraint_entry,
)

# Header helper: tt + group(0x01) + register(0x02) + extra(0x00)
GG = 0x01
RR = 0x02


def _make_response(tt: int, body: bytes) -> bytes:
    return bytes((tt, GG, RR, 0x00)) + body


class TestVE27NanInfGuard:
    """VE27: f32 NaN/Inf must not produce invalid JSON."""

    def test_nan_min_replaced_with_none(self) -> None:
        nan_bytes = struct.pack("<f", float("nan"))
        normal = struct.pack("<f", 1.0)
        body = nan_bytes + normal + normal
        response = _make_response(0x0F, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.min_value is None
        assert entry.max_value == pytest.approx(1.0)
        assert entry.step_value == pytest.approx(1.0)

    def test_inf_max_replaced_with_none(self) -> None:
        normal = struct.pack("<f", 0.0)
        inf_bytes = struct.pack("<f", float("inf"))
        body = normal + inf_bytes + normal
        response = _make_response(0x0F, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.min_value == pytest.approx(0.0)
        assert entry.max_value is None

    def test_neg_inf_step_replaced_with_none(self) -> None:
        normal = struct.pack("<f", 0.0)
        neg_inf = struct.pack("<f", float("-inf"))
        body = normal + normal + neg_inf
        response = _make_response(0x0F, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.step_value is None

    def test_normal_f32_preserved(self) -> None:
        body = struct.pack("<f", 5.0) + struct.pack("<f", 95.0) + struct.pack("<f", 0.5)
        response = _make_response(0x0F, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.min_value == pytest.approx(5.0)
        assert entry.max_value == pytest.approx(95.0)
        assert entry.step_value == pytest.approx(0.5)


class TestVE29ImpossibleDate:
    """VE29: Impossible dates must be rejected."""

    def test_feb_30_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid date triplet"):
            _decode_constraint_date(bytes((30, 2, 26)))  # Feb 30, 2026

    def test_apr_31_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid date triplet"):
            _decode_constraint_date(bytes((31, 4, 26)))  # Apr 31, 2026

    def test_feb_29_non_leap_rejected(self) -> None:
        with pytest.raises(ValueError, match="Invalid date triplet"):
            _decode_constraint_date(bytes((29, 2, 25)))  # Feb 29, 2025 (non-leap)

    def test_feb_29_leap_accepted(self) -> None:
        result = _decode_constraint_date(bytes((29, 2, 24)))  # Feb 29, 2024 (leap)
        assert result == "2024-02-29"

    def test_valid_date_passes(self) -> None:
        result = _decode_constraint_date(bytes((15, 6, 26)))  # Jun 15, 2026
        assert result == "2026-06-15"

    def test_month_zero_rejected(self) -> None:
        with pytest.raises(ValueError):
            _decode_constraint_date(bytes((15, 0, 26)))

    def test_day_zero_rejected(self) -> None:
        with pytest.raises(ValueError):
            _decode_constraint_date(bytes((0, 6, 26)))


class TestVE30StepZero:
    """VE30: step=0 must be replaced with None to prevent division-by-zero."""

    def test_u8_step_zero_becomes_none(self) -> None:
        body = bytes((0, 255, 0))  # min=0, max=255, step=0
        response = _make_response(0x06, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.step_value is None
        assert entry.min_value == 0
        assert entry.max_value == 255

    def test_u8_step_nonzero_preserved(self) -> None:
        body = bytes((0, 100, 5))
        response = _make_response(0x06, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.step_value == 5

    def test_u16_step_zero_becomes_none(self) -> None:
        body = (
            (0).to_bytes(2, "little")
            + (1000).to_bytes(2, "little")
            + (0).to_bytes(2, "little")
        )
        response = _make_response(0x09, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.step_value is None

    def test_u16_step_nonzero_preserved(self) -> None:
        body = (
            (0).to_bytes(2, "little")
            + (500).to_bytes(2, "little")
            + (10).to_bytes(2, "little")
        )
        response = _make_response(0x09, body)
        entry = _parse_constraint_entry(group=GG, register=RR, response=response)
        assert entry.step_value == 10


# ---- C7 scanner subsystem fixes ----


class TestVE27R2B509Opcode:
    """VE27-R2: B509 opcode field must be 0x09, not 0x0d."""

    def test_b509_register_entry_uses_0x09(self) -> None:
        """The B509RegisterEntry TypedDict uses '0x09' in the op field."""
        # We verify at the source level: the hardcoded literal in scan_b509
        # is "0x09" (not the old incorrect "0x0d").
        import inspect

        from helianthus_vrc_explorer.scanner import b509

        source = inspect.getsource(b509.scan_b509)
        assert '"0x09"' in source or "'0x09'" in source
        assert '"0x0d"' not in source and "'0x0d'" not in source


class TestVE16R2B509RangeCap:
    """VE16-R2: B509 scan range must be capped at 4096."""

    def test_range_within_cap_accepted(self) -> None:
        start, end = parse_b509_range("0x2700..0x27FF")
        assert end - start + 1 == 256

    def test_range_at_cap_accepted(self) -> None:
        start, end = parse_b509_range("0x0000..0x0FFF")
        assert end - start + 1 == 4096

    def test_range_exceeding_cap_rejected(self) -> None:
        with pytest.raises(ValueError, match="too large"):
            parse_b509_range("0x0000..0x1000")  # 4097 addresses

    def test_full_address_space_rejected(self) -> None:
        with pytest.raises(ValueError, match="too large"):
            parse_b509_range("0x0000..0xFFFF")


class TestVE23R3ParseIntSetDotDotRange:
    """VE23-R3: parse_int_set supports '..' as unambiguous hex range separator."""

    def test_dot_dot_hex_range(self) -> None:
        result = parse_int_set("0x0A..0x0F", min_value=0, max_value=255)
        assert result == [10, 11, 12, 13, 14, 15]

    def test_dot_dot_decimal_range(self) -> None:
        result = parse_int_set("10..15", min_value=0, max_value=255)
        assert result == [10, 11, 12, 13, 14, 15]

    def test_dot_dot_mixed_with_commas(self) -> None:
        result = parse_int_set("0x00..0x02,5,0x0A..0x0C", min_value=0, max_value=255)
        assert result == [0, 1, 2, 5, 10, 11, 12]


class TestVE24R3U32Sentinel:
    """VE24-R3: U32 sentinel 0xFFFFFFFF must be annotated."""

    def test_u32_sentinel_detected(self) -> None:
        result = _sentinel_value_display(
            value=0xFFFFFFFF,
            raw_hex="ffffffff",
            value_type="U32",
        )
        assert result is not None
        assert "sentinel" in result
        assert "0xFFFFFFFF" in result

    def test_u32_non_sentinel_returns_none(self) -> None:
        result = _sentinel_value_display(
            value=42,
            raw_hex="2a000000",
            value_type="U32",
        )
        assert result is None

    def test_i32_sentinel_still_works(self) -> None:
        result = _sentinel_value_display(
            value=0x7FFFFFFF,
            raw_hex="ffffff7f",
            value_type="I32",
        )
        assert result is not None
        assert "0x7FFFFFFF" in result


class TestVE18R2ErrorSanitisation:
    """VE18-R2: Transport error text must not leak endpoint details."""

    def test_error_format_uses_class_name_only(self) -> None:
        """Verify the error string template uses type(exc).__name__."""
        import inspect

        from helianthus_vrc_explorer.scanner import register

        source = inspect.getsource(register.read_register)
        # Must use the sanitised form, not the raw exc string.
        assert "type(exc).__name__" in source
