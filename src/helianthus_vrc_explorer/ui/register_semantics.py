from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

RegisterStatusKind = Literal[
    "ok", "absent", "dormant", "transport_failure", "decode_error", "error"
]


def _sorted_hex_keys(keys: Iterable[str]) -> list[str]:
    parsed: list[tuple[int, str]] = []
    for key in keys:
        if not isinstance(key, str):
            continue
        try:
            parsed.append((int(key, 0), key))
        except ValueError:
            continue
    parsed.sort(key=lambda item: item[0])
    return [key for (_num, key) in parsed]


def entry_status_kind(entry: dict[str, Any] | None) -> RegisterStatusKind:
    if not isinstance(entry, dict):
        return "error"

    error = entry.get("error")
    if isinstance(error, str) and error.strip():
        lowered = error.strip().lower()
        if lowered.startswith("parse_error:") or lowered.startswith("decode_error:"):
            return "decode_error"
        if (
            lowered == "timeout"
            or lowered.startswith("transport_error:")
            or lowered.startswith("mcp_error:")
        ):
            return "transport_failure"
        return "error"

    flags_access = entry.get("flags_access")
    if isinstance(flags_access, str) and flags_access.strip().lower() == "absent":
        return "absent"
    if isinstance(flags_access, str) and flags_access.strip().lower() == "dormant":
        return "dormant"

    reply_hex = entry.get("reply_hex")
    if isinstance(reply_hex, str) and reply_hex.strip().lower() == "00":
        return "absent"

    return "ok"


def entry_status_label(entry: dict[str, Any] | None) -> str:
    match entry_status_kind(entry):
        case "absent":
            return "Absent / no data"
        case "dormant":
            return "Dormant (feature inactive)"
        case "transport_failure":
            return "Transport failure"
        case "decode_error":
            return "Decode error"
        case "error":
            return "Error"
        case _:
            return "OK"


def entry_display_value_text(entry: dict[str, Any]) -> str:
    status = entry_status_kind(entry)
    if status == "absent":
        return "absent"
    if status == "dormant":
        return "dormant"
    if status == "transport_failure":
        return "transport failure"
    if status == "decode_error":
        return "decode error"
    if status == "error":
        return "error"

    value_display = entry.get("value_display")
    if isinstance(value_display, str) and value_display.strip():
        return value_display

    value = entry.get("value")
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def row_has_explicit_name(instances_obj: dict[str, Any], rr_key: str) -> bool:
    for instance_obj in instances_obj.values():
        if not isinstance(instance_obj, dict):
            continue
        registers = instance_obj.get("registers")
        if not isinstance(registers, dict):
            continue
        entry = registers.get(rr_key)
        if not isinstance(entry, dict):
            continue
        for field in ("myvaillant_name", "ebusd_name"):
            value = entry.get(field)
            if isinstance(value, str) and value.strip():
                return True
    return False


def row_is_absent(instances_obj: dict[str, Any], rr_key: str) -> bool:
    saw_entry = False
    for instance_obj in instances_obj.values():
        if not isinstance(instance_obj, dict):
            continue
        registers = instance_obj.get("registers")
        if not isinstance(registers, dict):
            continue
        entry = registers.get(rr_key)
        if not isinstance(entry, dict):
            continue
        saw_entry = True
        if entry_status_kind(entry) != "absent":
            return False
    return saw_entry


def visible_rr_keys(instances_obj: dict[str, Any]) -> list[str]:
    rr_keys: set[str] = set()
    for instance_obj in instances_obj.values():
        if not isinstance(instance_obj, dict):
            continue
        registers = instance_obj.get("registers")
        if not isinstance(registers, dict):
            continue
        for rr_key in registers:
            if isinstance(rr_key, str):
                rr_keys.add(rr_key)

    visible = [rr_key for rr_key in _sorted_hex_keys(rr_keys) if rr_key != "0x0000"]
    last_keep = -1
    for idx, rr_key in enumerate(visible):
        if row_has_explicit_name(instances_obj, rr_key) or not row_is_absent(instances_obj, rr_key):
            last_keep = idx
    if last_keep < 0:
        return []
    return visible[: last_keep + 1]
