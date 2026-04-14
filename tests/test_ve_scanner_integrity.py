"""Tests for VE27, VE29, VE30 — scanner data integrity guards."""
from __future__ import annotations

import math
import struct

import pytest

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
