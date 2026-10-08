from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b524_schedules import (
    build_event_read_payload,
    build_event_setpoint_read_payload,
    build_event_setpoint_write_payload,
    build_event_write_payload,
    build_timer_read_payload,
    build_timer_write_payload,
    build_vr91_read_payload,
    parse_event_response,
    parse_event_setpoint_response,
    parse_timer_response,
    parse_vr91_response,
)


def test_timer_builders_use_documented_vrc700_selectors() -> None:
    assert build_timer_read_payload("ventilation", instance=0, weekday=0) == bytes.fromhex(
        "0300000100"
    )
    assert build_timer_read_payload("noise-reduction", instance=0, weekday=6) == bytes.fromhex(
        "0300000206"
    )
    assert build_timer_read_payload("zone-heating", instance=2, weekday=1) == bytes.fromhex(
        "0303020201"
    )
    assert build_timer_write_payload(
        "dhw",
        instance=0,
        weekday=0,
        slots=((0, 36), (48, 72), None),
    ) == bytes.fromhex("0401000100002430489090")


def test_timer_parser_preserves_raw_and_decodes_three_slots() -> None:
    parsed = parse_timer_response(bytes.fromhex("03002430489090"))

    assert parsed.parameter_config == 0x03
    assert parsed.raw_hex == "03002430489090"
    assert parsed.slots[0].start_minutes == 0
    assert parsed.slots[0].stop_minutes == 360
    assert parsed.slots[1].start_minutes == 480
    assert parsed.slots[1].stop_minutes == 720
    assert parsed.slots[2].unused is True


def test_timer_parser_accepts_end_of_day_only_as_stop() -> None:
    parsed = parse_timer_response(bytes.fromhex("00069090909090"))
    assert parsed.slots[0].start_minutes == 60
    assert parsed.slots[0].stop_minutes == 1440

    unknown = parse_timer_response(bytes.fromhex("00900690909090"))
    assert unknown.slots[0].start_raw == 0x90
    assert unknown.slots[0].start_minutes is None
    assert unknown.slots[0].stop_minutes is None


@pytest.mark.parametrize("pair", [(0x91, 0x90), (0x24, 0x10), (0xFF, 0xFF)])
def test_timer_parser_retains_unqualified_pairs(pair: tuple[int, int]) -> None:
    reply = bytes((0, *pair, 0x90, 0x90, 0x90, 0x90))
    parsed = parse_timer_response(reply)
    assert parsed.raw_hex == reply.hex()
    assert (parsed.slots[0].start_raw, parsed.slots[0].stop_raw) == pair
    assert parsed.slots[0].start_minutes is None
    assert parsed.slots[0].stop_minutes is None
    assert parsed.slots[0].unused is False


def test_event_builders_enforce_profile_address_allowlists() -> None:
    assert build_event_read_payload(
        "system", instance=0, address=3, weekday_code=0xFF
    ) == bytes.fromhex("09000003ff")
    assert build_event_write_payload(
        "zone", instance=2, address=1, weekday_code=0, values=(0, 1, 2, 3, 4, 5, 6)
    ) == bytes.fromhex("0a0302010000010203040506")
    assert build_event_setpoint_read_payload(
        "dhw", instance=0, address=2, weekday_code=6
    ) == bytes.fromhex("0b01000206")
    assert build_event_setpoint_write_payload(
        "dhw",
        instance=0,
        address=1,
        weekday_code=0,
        values=(253, 254, 255, 253, 254, 255, 253),
    ) == bytes.fromhex("0c01000100fdfefffdfefffd")

    with pytest.raises(ValueError, match="address"):
        build_event_read_payload("zone", instance=0, address=3, weekday_code=0)
    with pytest.raises(ValueError, match="profile"):
        build_event_read_payload("mixer", instance=0, address=1, weekday_code=0)
    assert build_event_write_payload(
        "system",
        instance=0,
        address=1,
        weekday_code=0,
        values=(0xFF, 1, 2, 3, 4, 5, 0x91),
    ) == bytes.fromhex("0a00000100ff010203040591")
    assert build_event_setpoint_write_payload(
        "dhw",
        instance=0,
        address=1,
        weekday_code=0,
        values=(253, 254, 255, 0, 1, 2, 3),
    ) == bytes.fromhex("0c01000100fdfeff00010203")


def test_event_parser_keeps_first_code_raw_and_decodes_later_time_codes() -> None:
    parsed = parse_event_response(bytes.fromhex("03ff000648908fff"))

    assert parsed.parameter_config == 0x03
    assert parsed.start1_raw == 0xFF
    assert [item.minutes for item in parsed.starts] == [0, 60, 720, 1440, 1430, None]
    assert parsed.raw_hex == "03ff000648908fff"


def test_event_setpoint_parser_is_profile_scoped() -> None:
    numeric = parse_event_setpoint_response(bytes.fromhex("00012d2e2f303132"), "zone")
    assert [item.temperature_c for item in numeric.values] == [
        0.5,
        22.5,
        23.0,
        23.5,
        24.0,
        24.5,
        25.0,
    ]
    assert all(item.state is None for item in numeric.values)

    dhw = parse_event_setpoint_response(bytes.fromhex("00fdfeff00010203"), "dhw")
    assert [item.state for item in dhw.values] == [
        "enable",
        "disable",
        "replacement",
        None,
        None,
        None,
        None,
    ]
    assert all(item.temperature_c is None for item in dhw.values)


def test_vr91_read_is_raw_structural_decode_only() -> None:
    assert build_vr91_read_payload() == b"\x08"
    parsed = parse_vr91_response(bytes.fromhex("0102030405060708"))
    assert parsed.binding_zone == 1
    assert parsed.status_info == 5
    assert parsed.heating_temperature_raw == 7
    assert parsed.cooling_temperature_raw == 8
    assert parsed.raw_hex == "0102030405060708"


@pytest.mark.parametrize(
    ("parser", "payload"),
    [
        (parse_timer_response, b"\x00" * 6),
        (parse_event_response, b"\x00" * 7),
        (lambda payload: parse_event_setpoint_response(payload, "zone"), b"\x00" * 9),
        (parse_vr91_response, b"\x00" * 7),
    ],
)
def test_schedule_parsers_reject_noncanonical_lengths(parser, payload: bytes) -> None:
    with pytest.raises(ValueError, match="must be"):
        parser(payload)
