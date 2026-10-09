"""Presentation-only B524 operation-read projections.

These observations deliberately remain separate from scalar registers.  The
decoder qualification is rendered with every candidate interpretation so an
offline browser cannot turn a proposal into a device claim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

_TITLES = {
    0x03: "OP03 ReadTimer",
    0x08: "OP08 ReadVR91",
    0x09: "OP09 GetEvent",
    0x0B: "OP0B GetEventSetPoint",
}


@dataclass(frozen=True, slots=True)
class OperationReadView:
    opcode_hex: str
    title: str
    selector_key: str
    selector_label: str
    request_payload_hex: str
    response_raw_hex: str
    response_state: str
    qualification: str
    selector_correlation: str
    request_attempts: int | None
    fields: tuple[tuple[str, str], ...]


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _opcode(record: Mapping[str, object]) -> int | None:
    value = record.get("opcode_hex")
    if value is None:
        value = record.get("opcode")
    return _as_int(value)


def _selector_parts(selector: Mapping[str, object]) -> tuple[str, str]:
    ordered = ("target", "profile", "group", "gg", "instance", "ii", "address", "weekday_code")
    parts: list[str] = []
    values: list[str] = []
    for key in ordered:
        if key not in selector:
            continue
        value = selector[key]
        rendered = (
            f"0x{value:02x}"
            if key in {"group", "gg", "instance", "ii", "address", "weekday_code"}
            and isinstance(value, int)
            else str(value)
        )
        parts.append(f"{key}={rendered}")
        values.append(f"{key}={value!r}")
    for key in sorted(set(selector) - set(ordered)):
        parts.append(f"{key}={selector[key]}")
        values.append(f"{key}={selector[key]!r}")
    return ", ".join(parts) or "unqualified selector", "|".join(values)


def _raw(value: object) -> str:
    return f"0x{value:02x} (raw)" if isinstance(value, int) else "unknown"


def _event_fields(decoded: object) -> list[tuple[str, str]]:
    if not isinstance(decoded, Mapping):
        return [("response", "empty")]
    fields: list[tuple[str, str]] = []
    values = decoded.get("values", decoded.get("event_values"))
    if not isinstance(values, (list, tuple)):
        starts = decoded.get("starts")
        values = [decoded.get("start1_raw"), *(starts if isinstance(starts, (list, tuple)) else ())]
    for index, entry in enumerate(values, start=1):
        value = entry.get("raw") if isinstance(entry, Mapping) else entry
        if not isinstance(value, int) or index == 1 or value > 0x90:
            fields.append((f"event_value_{index}", _raw(value)))
        else:
            fields.append(
                (
                    f"event_value_{index}",
                    f"0x{value:02x} (candidate {value * 10 // 60:02d}:{value * 10 % 60:02d})",
                )
            )
    if not fields:
        for key, value in decoded.items():
            fields.append((str(key), _raw(value) if isinstance(value, int) else str(value)))
    return fields


def _setpoint_fields(decoded: object, selector: Mapping[str, object]) -> list[tuple[str, str]]:
    if not isinstance(decoded, Mapping):
        return [("response", "empty")]
    values = decoded.get("values", decoded.get("setpoints", ()))
    fields: list[tuple[str, str]] = []
    for index, entry in enumerate(values if isinstance(values, (list, tuple)) else (), start=1):
        value = entry.get("raw") if isinstance(entry, Mapping) else entry
        if not isinstance(value, int):
            text = _raw(value)
        elif isinstance(entry, Mapping) and isinstance(entry.get("temperature_c"), (int, float)):
            text = f"0x{value:02x} (candidate {entry['temperature_c']:g} °C)"
        elif isinstance(entry, Mapping) and isinstance(entry.get("state"), str):
            text = f"0x{value:02x} (candidate {entry['state']})"
        else:
            text = _raw(value)
        fields.append((f"setpoint_{index}", text))
    if not fields:
        fields = [
            (str(key), _raw(value) if isinstance(value, int) else str(value))
            for key, value in decoded.items()
        ]
    return fields or [("response", "empty")]


def _timer_fields(decoded: Mapping[str, object]) -> list[tuple[str, str]]:
    slots = decoded.get("slots")
    if not isinstance(slots, (list, tuple)):
        return [(str(key), str(value)) for key, value in decoded.items()]
    fields: list[tuple[str, str]] = []
    for index, slot in enumerate(slots, start=1):
        if not isinstance(slot, Mapping):
            fields.append((f"slot_{index}", "unknown"))
            continue
        if slot.get("unused") is True:
            fields.append((f"slot_{index}", "unused (0x90/0x90)"))
            continue
        start, stop = slot.get("start_minutes"), slot.get("stop_minutes")
        if isinstance(start, int) and isinstance(stop, int):
            fields.append(
                (
                    f"slot_{index}",
                    f"{start // 60:02d}:{start % 60:02d}–{stop // 60:02d}:{stop % 60:02d}",
                )
            )
        else:
            fields.append(
                (
                    f"slot_{index}",
                    f"start={slot.get('start_raw')} stop={slot.get('stop_raw')} (raw)",
                )
            )
    return fields or [("response", "value (undecoded)")]


def operation_read_views(artifact: Mapping[str, object]) -> list[OperationReadView]:
    """Return recorded operation reads only; no selector is synthesized."""
    raw = artifact.get("b524_operation_reads")
    if not isinstance(raw, list):
        return []
    views: list[OperationReadView] = []
    occurrences: dict[str, int] = {}
    for record in raw:
        if not isinstance(record, Mapping):
            continue
        opcode = _opcode(record)
        if opcode not in _TITLES:
            continue
        selector = record.get("selector")
        selector_obj = selector if isinstance(selector, Mapping) else {}
        if not selector_obj and isinstance(record.get("raw_selector"), Mapping):
            selector_obj = record["raw_selector"]
        selector_label, selector_key = _selector_parts(selector_obj)
        payload_key = str(record.get("request_payload_hex") or "")
        occurrences[payload_key] = occurrences.get(payload_key, 0) + 1
        if occurrences[payload_key] > 1:
            selector_key += f"|observation={occurrences[payload_key]}"
            selector_label += f" · observation {occurrences[payload_key]}"
        state = str(record.get("response_state") or "unknown")
        decoded = record.get("decoded")
        fields: tuple[tuple[str, str], ...]
        if state != "value":
            fields = (("response", state),)
        elif opcode == 0x09:
            fields = tuple(_event_fields(decoded))
        elif opcode == 0x0B:
            fields = tuple(_setpoint_fields(decoded, selector_obj))
        elif opcode == 0x03 and isinstance(decoded, Mapping):
            fields = tuple(_timer_fields(decoded))
        elif isinstance(decoded, Mapping):
            fields = tuple(
                (str(key), _raw(value) if isinstance(value, int) else str(value))
                for key, value in decoded.items()
            )
        else:
            fields = (("response", "value (undecoded)"),)
        attempts = record.get("request_attempts")
        qualification = str(record.get("decode_qualification") or "unknown")
        fields = (("decode_qualification", qualification), *fields)
        views.append(
            OperationReadView(
                opcode_hex=f"0x{opcode:02x}",
                title=_TITLES[opcode],
                selector_key=selector_key,
                selector_label=selector_label,
                request_payload_hex=str(record.get("request_payload_hex") or ""),
                response_raw_hex=str(record.get("response_raw_hex") or ""),
                response_state=state,
                qualification=qualification,
                selector_correlation=str(record.get("selector_correlation") or "unknown"),
                request_attempts=attempts if isinstance(attempts, int) else None,
                fields=fields,
            )
        )
    return views


def operation_edit_document(
    records: Sequence[Mapping[str, object]],
    *,
    operation: str,
    values: list[object],
    destination_address: int,
) -> dict[str, object]:
    """Create an offline edit document from complete recorded raw baselines.

    Callers provide raw codes.  In particular this preserves Event value one
    unchanged unless a separately qualified UI explicitly changes it.
    """
    if (
        isinstance(destination_address, bool)
        or not isinstance(destination_address, int)
        or not 0 <= destination_address <= 0xFF
    ):
        raise ValueError("destination_address must be an integer in range 0..255")
    if operation == "WriteTimer":
        candidates = [record for record in records if _opcode(record) == 0x03]
        if len(candidates) != 1:
            raise ValueError("exactly one OP03 baseline is required for the selected timer")
        source = candidates[0]
        selector = source.get("selector")
        if (
            source.get("response_state") != "value"
            or not isinstance(selector, Mapping)
            or not isinstance(source.get("decoded"), Mapping)
        ):
            raise ValueError("a recorded OP03 selector and baseline are required for timer preview")
        baseline = source.get("response_raw_hex")
        if not isinstance(baseline, str) or not baseline:
            raise ValueError("timer baseline must contain a raw response")
        return {
            "schema_version": 1,
            "destination_address": destination_address,
            "operation": operation,
            "selector": dict(selector),
            "values": list(values),
            "expected_before_raw_hex": [baseline],
        }
    wanted = {"SetEvent": 0x09, "SetEventSetPoint": 0x0B}
    source_opcode = wanted.get(operation)
    if source_opcode is None:
        raise ValueError("only Event and EventSetPoint exports use paired operation baselines")
    sources = [record for record in records if _opcode(record) == source_opcode]
    if len(sources) != 1:
        raise ValueError("select exactly one operation selector and unambiguous baseline")
    source = sources[0]
    selector = source.get("selector")
    if (
        source.get("response_state") != "value"
        or not isinstance(selector, Mapping)
        or not isinstance(source.get("decoded"), Mapping)
    ):
        raise ValueError("operation selector is required for an edit preview")
    events = [
        record
        for record in records
        if _opcode(record) == 0x09 and record.get("selector") == selector
    ]
    setpoints = [
        record
        for record in records
        if _opcode(record) == 0x0B and record.get("selector") == selector
    ]
    if len(events) != 1 or len(setpoints) != 1:
        raise ValueError("both OP09 and OP0B require one unambiguous recorded baseline")
    event, setpoint = events[0], setpoints[0]
    if (
        event.get("response_state") != "value"
        or setpoint.get("response_state") != "value"
        or not isinstance(event.get("decoded"), Mapping)
        or not isinstance(setpoint.get("decoded"), Mapping)
    ):
        raise ValueError("both OP09 and OP0B recorded baselines are required for an edit preview")
    baselines = [event.get("response_raw_hex"), setpoint.get("response_raw_hex")]
    if not all(isinstance(value, str) and value for value in baselines):
        raise ValueError("both operation baselines must contain raw responses")
    return {
        "schema_version": 1,
        "destination_address": destination_address,
        "operation": operation,
        "selector": dict(selector),
        "values": list(values),
        "expected_before_raw_hex": baselines,
    }


def operation_edit_export(
    records: Sequence[Mapping[str, object]],
    *,
    selector: Mapping[str, object],
    operation: str,
    destination_address: int,
) -> dict[str, object]:
    """Build a no-op, offline-editable document for one recorded selector."""
    selected = [record for record in records if record.get("selector") == selector]
    source_opcode = {"WriteTimer": 0x03, "SetEvent": 0x09, "SetEventSetPoint": 0x0B}.get(operation)
    if source_opcode is None:
        raise ValueError("unsupported operation edit")
    source = next((record for record in selected if _opcode(record) == source_opcode), None)
    raw = source.get("response_raw_hex") if source is not None else None
    if not isinstance(raw, str) or not raw:
        raise ValueError("selected operation has no raw baseline to export")
    try:
        payload = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("selected operation baseline is not hexadecimal") from exc
    if operation == "WriteTimer":
        if len(payload) != 7:
            raise ValueError("timer baseline must be seven bytes")
        values: list[object] = [
            None
            if payload[index : index + 2] == b"\x90\x90"
            else [payload[index], payload[index + 1]]
            for index in range(1, 7, 2)
        ]
    else:
        if len(payload) != 8:
            raise ValueError("event baseline must be eight bytes")
        values = list(payload[1:])
    return operation_edit_document(
        selected,
        operation=operation,
        values=values,
        destination_address=destination_address,
    )
