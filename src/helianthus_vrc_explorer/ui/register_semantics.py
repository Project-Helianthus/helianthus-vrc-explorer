from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

RegisterStatusKind = Literal[
    "ok", "absent", "dormant", "status_only", "transport_failure", "decode_error", "error"
]

_STATUS_ONLY_BYTES = frozenset({"00", "ff"})


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


def _one_byte_hex(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if len(normalized) != 2:
        return None
    try:
        int(normalized, 16)
    except ValueError:
        return None
    return normalized


def entry_status_raw_byte(entry: dict[str, Any] | None) -> str | None:
    """Return the raw status byte of a status-only entry, or None for any other entry."""

    if not isinstance(entry, dict) or entry_status_kind(entry) != "status_only":
        return None
    return _one_byte_hex(entry.get("reply_hex"))


def _is_status_only(entry: dict[str, Any]) -> bool:
    response_state = entry.get("response_state")
    if isinstance(response_state, str) and response_state.strip().lower() == "status_only":
        return True
    # Legacy records keep a clean one-byte reply as "active" with no value body.
    raw_hex = entry.get("raw_hex")
    has_value_body = isinstance(raw_hex, str) and bool(raw_hex.strip())
    return _one_byte_hex(entry.get("reply_hex")) in _STATUS_ONLY_BYTES and not has_value_body


def entry_status_kind(entry: dict[str, Any] | None) -> RegisterStatusKind:
    if not isinstance(entry, dict):
        return "error"

    response_state = entry.get("response_state")
    if isinstance(response_state, str):
        lowered_state = response_state.strip().lower()
        if lowered_state == "empty_reply":
            return "dormant"
        if lowered_state in {"timeout", "nack"}:
            return "transport_failure"

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

    # A one-byte status carries no register value, so it makes no presence claim.
    if _is_status_only(entry):
        return "status_only"

    flags_access = entry.get("flags_access")
    if isinstance(flags_access, str) and flags_access.strip().lower() == "absent":
        return "absent"
    if isinstance(flags_access, str) and flags_access.strip().lower() == "dormant":
        return "dormant"

    return "ok"


def entry_status_label(entry: dict[str, Any] | None) -> str:
    match entry_status_kind(entry):
        case "absent":
            return "Absent / no data"
        case "dormant":
            return "Dormant (feature inactive)"
        case "status_only":
            return "Status only"
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
    if status == "status_only":
        raw_byte = entry_status_raw_byte(entry)
        return f"status only ({raw_byte})" if raw_byte else "status only"
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
        for field in ("register_name", "ebusd_name"):
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
