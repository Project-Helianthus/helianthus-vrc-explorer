"""Strict, offline edit documents shared by the CLI and operation editors."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from typing import Any, cast

from ..protocol.b524_schedules import EventProfileName, TimerChannelName
from .b524_operation_writes import (
    B524OperationWriteRequest,
    concrete_confirmation_text,
    operation_write_availability,
    prepare_event_write,
    prepare_timer_write,
)


def _object(value: object, keys: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ValueError(f"{name} must contain exactly: {', '.join(sorted(keys))}")
    return value


def _byte(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError(f"{name} must be an integer in range 0..255")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be nonempty text")
    return value


def parse_operation_edit(document: object) -> B524OperationWriteRequest:
    """Rebuild a write from validated selectors, values and complete raw baselines."""
    row = _object(
        document,
        {"schema_version", "operation", "selector", "values", "expected_before_raw_hex"},
        "edit document",
    )
    if type(row["schema_version"]) is not int or row["schema_version"] != 1:
        raise ValueError("edit schema_version must be integer 1")
    baseline = row["expected_before_raw_hex"]
    values = row["values"]
    if not isinstance(baseline, list) or not all(isinstance(item, str) for item in baseline):
        raise ValueError("expected_before_raw_hex must be an array of hexadecimal strings")
    if not isinstance(values, list):
        raise ValueError("values must be an array")
    if row["operation"] == "WriteTimer":
        selector = _object(row["selector"], {"channel", "instance", "weekday"}, "selector")
        if len(baseline) != 1 or len(values) != 3:
            raise ValueError("WriteTimer requires one baseline and exactly three slots")
        slots: list[tuple[int, int] | None] = []
        for index, slot in enumerate(values):
            if slot is None:
                slots.append(None)
            elif isinstance(slot, list) and len(slot) == 2:
                slots.append(
                    (_byte(slot[0], f"slot {index} start"), _byte(slot[1], f"slot {index} stop"))
                )
            else:
                raise ValueError("each timer slot must be null or a pair of raw codes")
        return prepare_timer_write(
            channel=cast(TimerChannelName, _text(selector["channel"], "channel")),
            instance=_byte(selector["instance"], "instance"),
            weekday=_byte(selector["weekday"], "weekday"),
            slots=cast(
                tuple[tuple[int, int] | None, tuple[int, int] | None, tuple[int, int] | None],
                tuple(slots),
            ),
            expected_before_raw_hex=baseline[0],
        )
    if row["operation"] in {"SetEvent", "SetEventSetPoint"}:
        selector = _object(
            row["selector"], {"profile", "instance", "address", "weekday_code"}, "selector"
        )
        if len(baseline) != 2 or len(values) != 7:
            raise ValueError("Events require both OP09/OP0B baselines and seven raw values")
        raw_values = tuple(_byte(value, f"value {index}") for index, value in enumerate(values))
        return prepare_event_write(
            setpoint=row["operation"] == "SetEventSetPoint",
            profile=cast(EventProfileName, _text(selector["profile"], "profile")),
            instance=_byte(selector["instance"], "instance"),
            address=_byte(selector["address"], "address"),
            weekday_code=_byte(selector["weekday_code"], "weekday_code"),
            values=cast(tuple[int, int, int, int, int, int, int], raw_values),
            expected_event_raw_hex=baseline[0],
            expected_setpoint_raw_hex=baseline[1],
        )
    raise ValueError("unsupported edit operation; choose WriteTimer, SetEvent or SetEventSetPoint")


def build_operation_edit_preview(document: object, *, dst: int = 0x15) -> dict[str, Any]:
    """Return a complete offline diff and exact action-time confirmation text."""
    request = parse_operation_edit(document)
    before = [value.hex() for value in request.expected_before]
    after = [value.hex() for value in request.expected_after]
    return {
        "schema_version": 1,
        "operation": request.operation,
        "opcode_hex": f"0x{request.opcode:02X}",
        "destination": f"0x{dst:02X}",
        "selector": request.selector,
        "payload_hex": request.write_payload.hex(),
        "expected_before_raw_hex": before,
        "expected_after_raw_hex": after,
        "diff": [
            {"before_raw_hex": old, "after_raw_hex": new, "changed": old != new}
            for old, new in zip(before, after, strict=True)
        ],
        "live_send": False,
        "availability": asdict(operation_write_availability(request.operation)),
        "required_confirmation": concrete_confirmation_text(request, dst=dst),
    }
