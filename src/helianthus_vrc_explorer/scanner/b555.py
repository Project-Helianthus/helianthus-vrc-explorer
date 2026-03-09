from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from ..protocol.b555 import (
    B555ConfigRead,
    B555SlotsRead,
    B555TimerRead,
    b555_status_label,
    build_b555_config_read_payload,
    build_b555_slots_read_payload,
    build_b555_timer_read_payload,
    format_b555_time,
    parse_b555_config_read_response,
    parse_b555_slots_read_response,
    parse_b555_timer_read_response,
)
from ..transport.base import TransportCommandNotEnabled, TransportError, TransportTimeout
from .observer import ScanObserver

_B555_PRIMARY = 0xB5
_B555_SECONDARY = 0x55
_DAY_NAMES: tuple[str, ...] = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


class _B555Transport(Protocol):
    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class B555ProgramSpec:
    key: str
    label: str
    zone: int
    hc: int


DEFAULT_B555_PROGRAMS: tuple[B555ProgramSpec, ...] = (
    B555ProgramSpec("z1_heating", "Z1 Heating", 0x00, 0x00),
    B555ProgramSpec("z1_cooling", "Z1 Cooling", 0x00, 0x01),
    B555ProgramSpec("z2_heating", "Z2 Heating", 0x01, 0x00),
    B555ProgramSpec("z2_cooling", "Z2 Cooling", 0x01, 0x01),
    B555ProgramSpec("z3_heating", "Z3 Heating", 0x02, 0x00),
    B555ProgramSpec("z3_cooling", "Z3 Cooling", 0x02, 0x01),
    B555ProgramSpec("dhw", "DHW", 0xFF, 0x02),
    B555ProgramSpec("cc", "CC", 0xFF, 0x03),
    B555ProgramSpec("silent", "Silent", 0xFF, 0x04),
)


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _emit_trace_label(transport: _B555Transport, label: str) -> None:
    trace_fn = getattr(transport, "trace_label", None)
    if callable(trace_fn):
        trace_fn(label)


def _config_entry(
    *,
    payload: bytes,
    response: bytes | None,
    parsed: B555ConfigRead | None,
    error: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "op": "0xa3",
        "request_hex": payload.hex(),
        "reply_hex": response.hex() if response is not None else None,
        "status": _hex_u8(parsed.status) if parsed is not None else None,
        "status_label": b555_status_label(parsed.status) if parsed is not None else None,
        "error": error,
    }
    if parsed is None:
        return entry
    entry.update(
        {
            "available": parsed.available,
            "max_slots": parsed.max_slots,
            "time_resolution_min": parsed.time_resolution_min,
            "min_duration_min": parsed.min_duration_min,
            "has_temperature": parsed.has_temperature,
            "temp_slots": parsed.temp_slots,
            "min_temp_c": parsed.min_temp_c,
            "max_temp_c": parsed.max_temp_c,
            "padding": _hex_u8(parsed.padding),
        }
    )
    return entry


def _slots_entry(
    *,
    payload: bytes,
    response: bytes | None,
    parsed: B555SlotsRead | None,
    error: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "op": "0xa4",
        "request_hex": payload.hex(),
        "reply_hex": response.hex() if response is not None else None,
        "status": _hex_u8(parsed.status) if parsed is not None else None,
        "status_label": b555_status_label(parsed.status) if parsed is not None else None,
        "error": error,
    }
    if parsed is None:
        return entry
    entry["available"] = parsed.available
    entry["padding"] = _hex_u8(parsed.padding)
    if parsed.available:
        entry["days"] = dict(zip(_DAY_NAMES, parsed.slot_counts, strict=True))
    return entry


def _timer_entry(
    *,
    payload: bytes,
    response: bytes | None,
    parsed: B555TimerRead | None,
    error: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "op": "0xa5",
        "request_hex": payload.hex(),
        "reply_hex": response.hex() if response is not None else None,
        "status": _hex_u8(parsed.status) if parsed is not None else None,
        "status_label": b555_status_label(parsed.status) if parsed is not None else None,
        "error": error,
    }
    if parsed is None:
        return entry
    entry["available"] = parsed.status == 0x00
    if parsed.status == 0x00:
        entry.update(
            {
                "start_hour": parsed.start_hour,
                "start_minute": parsed.start_minute,
                "start_text": format_b555_time(parsed.start_hour, parsed.start_minute),
                "start_total_minutes": parsed.start_hour * 60 + parsed.start_minute,
                "end_hour": parsed.end_hour,
                "end_minute": parsed.end_minute,
                "end_text": format_b555_time(parsed.end_hour, parsed.end_minute),
                "end_total_minutes": parsed.end_hour * 60 + parsed.end_minute,
                "temperature_raw": _hex_u16(parsed.temperature_raw_u16),
                "temperature_c": parsed.temperature_c,
            }
        )
    return entry


def scan_b555(
    transport: _B555Transport,
    *,
    dst: int,
    observer: ScanObserver | None = None,
) -> dict[str, Any]:
    start_perf = time.perf_counter()
    read_count = 0
    error_count = 0
    incomplete = False
    incomplete_reason: str | None = None

    artifact: dict[str, Any] = {
        "meta": {
            "scan_timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_duration_seconds": 0.0,
            "destination_address": f"0x{dst:02x}",
            "read_count": 0,
            "error_count": 0,
            "incomplete": False,
        },
        "programs": {},
    }
    programs = artifact["programs"]

    discovered_slot_reads = 0
    base_reads = len(DEFAULT_B555_PROGRAMS) * 2

    try:
        if observer is not None:
            observer.phase_start("b555_dump", total=base_reads or 1)
        _emit_trace_label(transport, "B555 Timer Dump")

        for program in DEFAULT_B555_PROGRAMS:
            _emit_trace_label(transport, f"B555 {program.label}")
            program_obj: dict[str, Any] = {
                "label": program.label,
                "selector": {
                    "zone": _hex_u8(program.zone),
                    "hc": _hex_u8(program.hc),
                },
                "config": None,
                "slots_per_weekday": None,
                "weekdays": {},
            }
            programs[program.key] = program_obj

            config_payload = build_b555_config_read_payload(program.zone, program.hc)
            config_response: bytes | None = None
            config_parsed: B555ConfigRead | None = None
            config_error: str | None = None
            if observer is not None:
                observer.status(f"B555 A3 {program.label}")
            try:
                config_response = transport.send_proto(
                    dst, _B555_PRIMARY, _B555_SECONDARY, config_payload
                )
                config_parsed = parse_b555_config_read_response(config_response)
            except TransportTimeout:
                config_error = "timeout"
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                config_error = f"transport_error: {exc}"
            except Exception as exc:
                config_error = f"parse_error: {exc}"
            read_count += 1
            if config_error is not None:
                error_count += 1
            program_obj["config"] = _config_entry(
                payload=config_payload,
                response=config_response,
                parsed=config_parsed,
                error=config_error,
            )
            if observer is not None:
                observer.phase_advance("b555_dump", advance=1)

            if config_parsed is None or config_error is not None:
                continue
            if not config_parsed.available:
                program_obj["skipped_reason"] = f"config_status_{_hex_u8(config_parsed.status)}"
                if observer is not None:
                    skip_label = b555_status_label(config_parsed.status)
                    observer.log(
                        f"B555 {program.label}: skipped ({skip_label})",
                        level="info",
                    )
                continue

            slots_payload = build_b555_slots_read_payload(program.zone, program.hc)
            slots_response: bytes | None = None
            slots_parsed: B555SlotsRead | None = None
            slots_error: str | None = None
            if observer is not None:
                observer.status(f"B555 A4 {program.label}")
            try:
                slots_response = transport.send_proto(
                    dst, _B555_PRIMARY, _B555_SECONDARY, slots_payload
                )
                slots_parsed = parse_b555_slots_read_response(slots_response)
            except TransportTimeout:
                slots_error = "timeout"
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                slots_error = f"transport_error: {exc}"
            except Exception as exc:
                slots_error = f"parse_error: {exc}"
            read_count += 1
            if slots_error is not None:
                error_count += 1
            program_obj["slots_per_weekday"] = _slots_entry(
                payload=slots_payload,
                response=slots_response,
                parsed=slots_parsed,
                error=slots_error,
            )
            if observer is not None:
                observer.phase_advance("b555_dump", advance=1)

            if slots_parsed is None or slots_error is not None:
                continue
            if not slots_parsed.available:
                program_obj["skipped_reason"] = f"slots_status_{_hex_u8(slots_parsed.status)}"
                if observer is not None:
                    skip_label = b555_status_label(slots_parsed.status)
                    observer.log(
                        f"B555 {program.label}: slot map unavailable ({skip_label})",
                        level="info",
                    )
                continue

            slot_counts = slots_parsed.as_day_map()
            for day_name in _DAY_NAMES:
                discovered_slot_reads += min(slot_counts[day_name], config_parsed.max_slots)
            if observer is not None:
                observer.phase_set_total(
                    "b555_dump",
                    total=(base_reads + discovered_slot_reads) or 1,
                )

            for day_index, day_name in enumerate(_DAY_NAMES):
                reported_slot_count = slot_counts[day_name]
                read_slot_count = min(reported_slot_count, config_parsed.max_slots)
                day_obj: dict[str, Any] = {
                    "day_index": _hex_u8(day_index),
                    "reported_slot_count": reported_slot_count,
                    "read_slot_count": read_slot_count,
                    "slots": {},
                }
                program_obj["weekdays"][day_name] = day_obj

                for slot_index in range(read_slot_count):
                    timer_payload = build_b555_timer_read_payload(
                        program.zone, program.hc, day_index, slot_index
                    )
                    timer_response: bytes | None = None
                    timer_parsed: B555TimerRead | None = None
                    timer_error: str | None = None
                    if observer is not None:
                        observer.status(f"B555 A5 {program.label} {day_name} slot {slot_index}")
                    try:
                        timer_response = transport.send_proto(
                            dst, _B555_PRIMARY, _B555_SECONDARY, timer_payload
                        )
                        timer_parsed = parse_b555_timer_read_response(timer_response)
                    except TransportTimeout:
                        timer_error = "timeout"
                    except TransportError as exc:
                        if isinstance(exc, TransportCommandNotEnabled):
                            raise
                        timer_error = f"transport_error: {exc}"
                    except Exception as exc:
                        timer_error = f"parse_error: {exc}"
                    read_count += 1
                    if timer_error is not None:
                        error_count += 1
                    day_obj["slots"][_hex_u8(slot_index)] = _timer_entry(
                        payload=timer_payload,
                        response=timer_response,
                        parsed=timer_parsed,
                        error=timer_error,
                    )
                    if observer is not None:
                        observer.phase_advance("b555_dump", advance=1)

    except KeyboardInterrupt:
        incomplete = True
        incomplete_reason = "user_interrupt"
    finally:
        if observer is not None:
            observer.phase_finish("b555_dump")

    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    artifact["meta"]["read_count"] = read_count
    artifact["meta"]["error_count"] = error_count
    artifact["meta"]["incomplete"] = incomplete
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason
    return artifact
