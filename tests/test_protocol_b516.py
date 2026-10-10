from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b516 import (
    B516Date,
    build_b516_system_payload,
    build_b516_year_payload,
    pack_b516_date,
    parse_b516_response,
    unpack_b516_date,
    unpack_b516_date_bytes,
)

# Real recorded test vectors (see issue #289).
_TOTAL_OK = "0000000303873400545d46"
_TOTAL_NOT_OK = "1000ff0304873400000000"
_YEARLY_NOT_OK = "13ffff0303003200000000"


def test_build_b516_system_payload_is_literal_and_ignores_date() -> None:
    assert build_b516_system_payload(source=0x4, usage=0x3) == bytes.fromhex("1000ffff04030030")
    assert build_b516_system_payload(source=0x3, usage=0x4) == bytes.fromhex("1000ffff03040030")


def test_build_b516_year_payload_uses_real_calendar_year() -> None:
    assert build_b516_year_payload(source=0x3, usage=0x4, year=2025) == bytes.fromhex(
        "1003ffff03040032"
    )
    assert build_b516_year_payload(source=0x3, usage=0x4, year=2024) == bytes.fromhex(
        "1003ffff03040030"
    )
    # A year further out packs into a different (non-hardcoded) date word.
    assert build_b516_year_payload(source=0x4, usage=0x3, year=2026) == bytes.fromhex(
        "1003ffff04030034"
    )


@pytest.mark.parametrize(
    ("source", "usage"),
    [
        (0x10, 0x3),
        (0x4, 0x10),
    ],
)
def test_build_b516_payloads_validate_nibbles(source: int, usage: int) -> None:
    with pytest.raises(ValueError):
        build_b516_system_payload(source=source, usage=usage)


def test_pack_and_unpack_b516_date_round_trip() -> None:
    word = pack_b516_date(day=7, month=4, year=2026)
    assert unpack_b516_date(word) == B516Date(day=7, month=4, year=2026)


def test_pack_b516_date_zero_day_month_for_time_bases_without_them() -> None:
    word = pack_b516_date(day=0, month=0, year=2025)
    date = unpack_b516_date(word)
    assert date == B516Date(day=0, month=0, year=2025)
    assert date.plausible is False


@pytest.mark.parametrize(
    ("day", "month", "year"),
    [
        (32, 1, 2025),
        (1, 13, 2025),
        (1, 1, 1999),
        (1, 1, 2128),
    ],
)
def test_pack_b516_date_validates_range(day: int, month: int, year: int) -> None:
    with pytest.raises(ValueError):
        pack_b516_date(day=day, month=month, year=year)


def test_unpack_b516_date_bytes_matches_real_total_ok_vector() -> None:
    # Real recorded vector: total OK, date bytes (5, 6) = 87 34 -> 2026-04-07.
    date = unpack_b516_date_bytes(0x87, 0x34)
    assert date == B516Date(day=7, month=4, year=2026)
    assert date.plausible is True


def test_parse_b516_response_total_ok_real_vector() -> None:
    parsed = parse_b516_response(bytes.fromhex(_TOTAL_OK))
    assert parsed.time_base == 0
    assert parsed.access is False
    assert parsed.return_code == 0
    assert parsed.ok is True
    assert parsed.source == 0x3
    assert parsed.usage == 0x3
    assert parsed.date == B516Date(day=7, month=4, year=2026)
    assert parsed.value_wh == pytest.approx(14165.0)
    assert parsed.value_kwh == pytest.approx(14.165)


def test_parse_b516_response_total_not_ok_real_vector_has_no_value() -> None:
    parsed = parse_b516_response(bytes.fromhex(_TOTAL_NOT_OK))
    assert parsed.return_code == 0x1
    assert parsed.ok is False
    # A non-OK reply still echoes the regulator's own current date.
    assert parsed.date == B516Date(day=7, month=4, year=2026)
    # The value is never surfaced when the return code is non-zero, even
    # though the raw bytes happen to be zero.
    assert parsed.value_wh is None
    assert parsed.value_kwh is None


def test_parse_b516_response_yearly_not_ok_real_vector_has_no_value() -> None:
    parsed = parse_b516_response(bytes.fromhex(_YEARLY_NOT_OK))
    assert parsed.time_base == 0x3
    assert parsed.return_code == 0x1
    assert parsed.ok is False
    assert parsed.date == B516Date(day=0, month=0, year=2025)
    assert parsed.value_wh is None
    assert parsed.value_kwh is None


def test_parse_b516_response_requires_min_length() -> None:
    with pytest.raises(ValueError):
        parse_b516_response(bytes.fromhex("03aabb0403"))
