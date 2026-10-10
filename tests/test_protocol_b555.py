from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b555 import (
    b555_setpoint_unit_label,
    b555_status_label,
    b555_time_program_mode_label,
    build_b555_config_read_payload,
    build_b555_slots_read_payload,
    build_b555_timer_read_payload,
    format_b555_time,
    parse_b555_config_read_response,
    parse_b555_slots_read_response,
    parse_b555_timer_read_response,
)


def test_build_b555_payloads() -> None:
    assert build_b555_config_read_payload(0x00, 0x00) == bytes.fromhex("a30000")
    assert build_b555_slots_read_payload(0xFF, 0x02) == bytes.fromhex("a4ff02")
    assert build_b555_timer_read_payload(0x01, 0x00, 0x06, 0x03) == bytes.fromhex("a501000603")


@pytest.mark.parametrize(
    ("builder", "args"),
    [
        (build_b555_config_read_payload, (0x100, 0x00)),
        (build_b555_slots_read_payload, (0x00, 0x100)),
        (build_b555_timer_read_payload, (0x00, 0x00, 0x07, 0x00)),
        (build_b555_timer_read_payload, (0x00, 0x00, 0x00, 0x100)),
    ],
)
def test_build_b555_payloads_validate_bounds(builder, args: tuple[int, ...]) -> None:
    with pytest.raises(ValueError):
        builder(*args)


def test_parse_b555_config_read_response() -> None:
    parsed = parse_b555_config_read_response(bytes.fromhex("000c0a05010c051e00"))
    assert parsed.status == 0x00
    assert parsed.available is True
    assert parsed.max_slots == 12
    assert parsed.time_resolution_min == 10
    assert parsed.min_duration_min == 5
    assert parsed.has_temperature is True
    assert parsed.temp_slots == 12
    assert parsed.min_temp_c == 5
    assert parsed.max_temp_c == 30
    assert parsed.padding == 0x00


def test_parse_b555_config_read_response_exposes_correctly_named_fields() -> None:
    # Byte 3: setpoint step (raw). Byte 4: setpoint unit code (0=none,
    # 1=celsius, 2=fan stage). Byte 5: number of setpoints. Byte 8: the
    # time-program mode (0=weekly, 1=24-hour).
    parsed = parse_b555_config_read_response(bytes.fromhex("000c0a05010c051e01"))
    assert parsed.setpoint_step_raw == 5
    assert parsed.setpoint_unit_code == 1
    assert b555_setpoint_unit_label(parsed.setpoint_unit_code) == "celsius"
    assert parsed.setpoint_count == 12
    assert parsed.time_program_mode == 1
    assert b555_time_program_mode_label(parsed.time_program_mode) == "24-hour"
    # Deprecated aliases stay available for one release.
    assert parsed.min_duration_min == parsed.setpoint_step_raw
    assert parsed.has_temperature == (parsed.setpoint_unit_code != 0)
    assert parsed.temp_slots == parsed.setpoint_count
    assert parsed.padding == parsed.time_program_mode


def test_b555_setpoint_unit_label_covers_known_and_unknown_codes() -> None:
    assert b555_setpoint_unit_label(0) == "none"
    assert b555_setpoint_unit_label(1) == "celsius"
    assert b555_setpoint_unit_label(2) == "fan_stage"
    assert b555_setpoint_unit_label(9) == "0x09"


def test_parse_b555_slots_read_response() -> None:
    parsed = parse_b555_slots_read_response(bytes.fromhex("000201000000000000"))
    assert parsed.status == 0x00
    assert parsed.available is True
    assert parsed.as_day_map() == {
        "monday": 2,
        "tuesday": 1,
        "wednesday": 0,
        "thursday": 0,
        "friday": 0,
        "saturday": 0,
        "sunday": 0,
    }


def test_parse_b555_slots_read_response_exposes_slot_count_24h() -> None:
    # Byte 8 of the A4 reply is the 24-hour slot count.
    parsed = parse_b555_slots_read_response(bytes.fromhex("000201000000000003"))
    assert parsed.slot_count_24h == 3
    # Deprecated alias stays available for one release.
    assert parsed.padding == parsed.slot_count_24h


def test_parse_b555_timer_read_response() -> None:
    parsed = parse_b555_timer_read_response(bytes.fromhex("0000001800e100"))
    assert parsed.status == 0x00
    assert parsed.start_hour == 0
    assert parsed.start_minute == 0
    assert parsed.end_hour == 24
    assert parsed.end_minute == 0
    assert parsed.temperature_raw_u16 == 225
    assert parsed.temperature_c == 22.5
    assert format_b555_time(parsed.start_hour, parsed.start_minute) == "00:00"
    assert format_b555_time(parsed.end_hour, parsed.end_minute) == "24:00"


def test_parse_b555_timer_read_response_preserves_ffff_sentinel() -> None:
    parsed = parse_b555_timer_read_response(bytes.fromhex("0000001800ffff"))
    assert parsed.temperature_raw_u16 == 0xFFFF
    assert parsed.temperature_c is None


def test_b555_status_label() -> None:
    assert b555_status_label(0x00) == "available"
    assert b555_status_label(0x03) == "unavailable"
    assert b555_status_label(0x06) == "0x06"
