from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b516 import (
    build_b516_system_payload,
    build_b516_year_payload,
    parse_b516_response,
)


def test_build_b516_payloads() -> None:
    assert build_b516_system_payload(source=0x4, usage=0x3) == bytes.fromhex("1000ffff04030030")
    assert build_b516_year_payload(source=0x3, usage=0x4, current=True) == bytes.fromhex(
        "1003ffff03040032"
    )
    assert build_b516_year_payload(source=0x3, usage=0x4, current=False) == bytes.fromhex(
        "1003ffff03040030"
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


def test_parse_b516_response() -> None:
    parsed = parse_b516_response(bytes.fromhex("03aabb0403003200004842"))
    assert parsed.period == 0x3
    assert parsed.source == 0x4
    assert parsed.usage == 0x3
    assert parsed.packed_window == 0x00
    assert parsed.qualifier == 0x2
    assert parsed.value_wh == 50.0
    assert parsed.value_kwh == 0.05


def test_parse_b516_response_requires_min_length() -> None:
    with pytest.raises(ValueError):
        parse_b516_response(bytes.fromhex("03aabb0403"))
