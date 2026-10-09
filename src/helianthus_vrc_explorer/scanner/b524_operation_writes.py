"""Fail-closed orchestration for explicitly qualified B524 operation writes."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, cast

from ..protocol.b524_schedules import (
    EventProfileName,
    TimerChannelName,
    build_event_read_payload,
    build_event_setpoint_read_payload,
    build_event_setpoint_write_payload,
    build_event_write_payload,
    build_timer_read_payload,
    build_timer_write_payload,
    parse_event_response,
    parse_event_setpoint_response,
    parse_timer_response,
)
from ..protocol.basv import parse_scan_identification
from ..transport.base import TransportError, TransportInterface
from .b524_operation_reads import B524OperationReadRequest

type WriteOperationName = Literal["WriteTimer", "SetEvent", "SetEventSetPoint"]
type QualificationScope = Literal[
    "timer_write_op04", "event_write_op0a", "event_setpoint_write_op0c"
]
type WriteOutcome = Literal[
    "verified",
    "not_applied",
    "partial",
    "ambiguous",
    "unexpected",
    "baseline_mismatch",
    "pre_read_failed",
]

_VRC700_DEVICE_IDS = frozenset({"70000", "B7S00"})
_EVENT_OPERATIONS = frozenset({"SetEvent", "SetEventSetPoint"})


@dataclass(frozen=True, slots=True)
class B524NativeWriteQualification:
    """Concrete native evidence supplied by the caller, separate from consent."""

    scope: QualificationScope
    manufacturer: int
    device_id: str
    profile: str
    model: str
    software_raw_hex: str
    selector: dict[str, str | int]
    evidence_reference: str
    native_qualified: bool


@dataclass(frozen=True, slots=True)
class B524WriteAvailability:
    operation: WriteOperationName
    opcode: int
    state: Literal["qualification_required", "schema_unqualified"]
    live_write_available: bool
    reason: str


@dataclass(frozen=True, slots=True)
class B524OperationWriteRequest:
    """Offline-prepared write with explicit baseline and expected readback."""

    operation: WriteOperationName
    opcode: int
    selector: dict[str, str | int]
    write_payload: bytes
    read_requests: tuple[B524OperationReadRequest, ...]
    expected_before: tuple[bytes, ...]
    expected_after: tuple[bytes, ...]


class B524WriteRetryBlocked(RuntimeError):
    """Raised before a transport can admit a second native write attempt."""


def _strict_object(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{context} field names must be strings")
    return cast(Mapping[str, object], value)


def _exact_keys(value: Mapping[str, object], *, expected: set[str], context: str) -> None:
    unknown = sorted(str(key) for key in value if key not in expected)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")
    missing = sorted(key for key in expected if key not in value)
    if missing:
        raise ValueError(f"{context} is missing field(s): {', '.join(missing)}")


def _nonempty_string(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value.strip()


def _u8(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be an integer in range 0-255")
    return value


def _selector_from_document(value: object) -> dict[str, str | int]:
    selector = _strict_object(value, context="qualification.selector")
    result: dict[str, str | int] = {}
    for key, raw in selector.items():
        if isinstance(raw, bool) or not isinstance(raw, (str, int)):
            raise ValueError(f"qualification.selector.{key} must be a string or integer")
        result[key] = raw
    if not result:
        raise ValueError("qualification.selector must not be empty")
    return result


def parse_native_write_qualification(document: object) -> B524NativeWriteQualification:
    """Parse evidence metadata; this does not confirm or authorize a write."""

    value = _strict_object(document, context="qualification")
    expected = {
        "schema_version",
        "scope",
        "manufacturer",
        "device_id",
        "profile",
        "model",
        "software_raw_hex",
        "selector",
        "evidence_reference",
        "native_qualified",
    }
    _exact_keys(value, expected=expected, context="qualification")
    schema_version = value["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("qualification.schema_version must be integer 1")
    scope = value["scope"]
    valid_scopes = {"timer_write_op04", "event_write_op0a", "event_setpoint_write_op0c"}
    if not isinstance(scope, str) or scope not in valid_scopes:
        raise ValueError("qualification.scope is unsupported")
    native_qualified = value["native_qualified"]
    if native_qualified is not True:
        raise ValueError("qualification.native_qualified must be boolean true")
    return B524NativeWriteQualification(
        scope=cast(QualificationScope, scope),
        manufacturer=_u8(value["manufacturer"], name="qualification.manufacturer"),
        device_id=_nonempty_string(value["device_id"], name="qualification.device_id").upper(),
        profile=_nonempty_string(value["profile"], name="qualification.profile"),
        model=_nonempty_string(value["model"], name="qualification.model"),
        software_raw_hex=_software_raw_hex(value["software_raw_hex"]),
        selector=_selector_from_document(value["selector"]),
        evidence_reference=_nonempty_string(
            value["evidence_reference"], name="qualification.evidence_reference"
        ),
        native_qualified=True,
    )


def operation_write_availability(operation: WriteOperationName) -> B524WriteAvailability:
    """Return the current native qualification boundary for a writer."""

    if operation == "WriteTimer":
        return B524WriteAvailability(
            operation=operation,
            opcode=0x04,
            state="qualification_required",
            live_write_available=False,
            reason="OP04 requires external selector-specific VRC700 native qualification",
        )
    if operation == "SetEvent":
        opcode = 0x0A
    elif operation == "SetEventSetPoint":
        opcode = 0x0C
    else:  # pragma: no cover - protected by the public Literal type
        raise ValueError(f"unsupported B524 write operation: {operation}")
    return B524WriteAvailability(
        operation=operation,
        opcode=opcode,
        state="schema_unqualified",
        live_write_available=False,
        reason=(
            "Events/EventSetPoint has a candidate codec but no supported native write qualification"
        ),
    )


def _software_raw_hex(value: object) -> str:
    raw = _compact_hex(
        value,
        name="qualification.software_raw_hex",
        length=2,
    )
    return raw.hex()


def _compact_hex(value: object, *, name: str, length: int) -> bytes:
    if (
        not isinstance(value, str)
        or len(value) != length * 2
        or re.fullmatch(r"[0-9A-Fa-f]+", value) is None
    ):
        raise ValueError(f"{name} must contain exactly {length} compact hexadecimal bytes")
    return bytes.fromhex(value)


def prepare_timer_write(
    *,
    channel: TimerChannelName,
    instance: int,
    weekday: int,
    slots: tuple[
        tuple[int, int] | None,
        tuple[int, int] | None,
        tuple[int, int] | None,
    ],
    expected_before_raw_hex: str,
) -> B524OperationWriteRequest:
    """Build an offline OP04 plan and validate its expected OP03 baseline."""

    write_payload = build_timer_write_payload(
        channel, instance=instance, weekday=weekday, slots=slots
    )
    read_payload = build_timer_read_payload(channel, instance=instance, weekday=weekday)
    before = _compact_hex(expected_before_raw_hex, name="expected_before_raw_hex", length=7)
    parse_timer_response(before)
    selector: dict[str, str | int] = {
        "channel": channel,
        "instance": instance,
        "weekday": weekday,
    }
    read_request = B524OperationReadRequest(
        operation="ReadTimer",
        opcode=0x03,
        selector=dict(selector),
        payload=read_payload,
        requires_vrc700=True,
    )
    return B524OperationWriteRequest(
        operation="WriteTimer",
        opcode=0x04,
        selector=selector,
        write_payload=write_payload,
        read_requests=(read_request,),
        expected_before=(before,),
        expected_after=(bytes((before[0],)) + write_payload[5:],),
    )


def prepare_event_write(
    *,
    setpoint: bool,
    profile: EventProfileName,
    instance: int,
    address: int,
    weekday_code: int,
    values: tuple[int, int, int, int, int, int, int],
    expected_event_raw_hex: str,
    expected_setpoint_raw_hex: str,
) -> B524OperationWriteRequest:
    """Build a complete offline event-pair preview without enabling live writes."""

    before_event = _compact_hex(expected_event_raw_hex, name="expected_event_raw_hex", length=8)
    before_setpoint = _compact_hex(
        expected_setpoint_raw_hex, name="expected_setpoint_raw_hex", length=8
    )
    parse_event_response(before_event)
    parse_event_setpoint_response(before_setpoint, profile)
    selector: dict[str, str | int] = {
        "profile": profile,
        "instance": instance,
        "address": address,
        "weekday_code": weekday_code,
    }
    event_read = B524OperationReadRequest(
        operation="GetEvent",
        opcode=0x09,
        selector=dict(selector),
        payload=build_event_read_payload(
            profile, instance=instance, address=address, weekday_code=weekday_code
        ),
        requires_vrc700=False,
    )
    setpoint_read = B524OperationReadRequest(
        operation="GetEventSetPoint",
        opcode=0x0B,
        selector=dict(selector),
        payload=build_event_setpoint_read_payload(
            profile, instance=instance, address=address, weekday_code=weekday_code
        ),
        requires_vrc700=False,
    )
    if setpoint:
        operation: WriteOperationName = "SetEventSetPoint"
        opcode = 0x0C
        write_payload = build_event_setpoint_write_payload(
            profile,
            instance=instance,
            address=address,
            weekday_code=weekday_code,
            values=values,
        )
        after = (before_event, bytes((before_setpoint[0], *values)))
    else:
        operation = "SetEvent"
        opcode = 0x0A
        write_payload = build_event_write_payload(
            profile,
            instance=instance,
            address=address,
            weekday_code=weekday_code,
            values=values,
        )
        after = (bytes((before_event[0], *values)), before_setpoint)
    return B524OperationWriteRequest(
        operation=operation,
        opcode=opcode,
        selector=selector,
        write_payload=write_payload,
        read_requests=(event_read, setpoint_read),
        expected_before=(before_event, before_setpoint),
        expected_after=after,
    )


def concrete_confirmation_text(request: B524OperationWriteRequest, *, dst: int) -> str:
    """Render the exact concrete payload confirmation required at action time."""

    if isinstance(dst, bool) or not isinstance(dst, int) or not 0 <= dst <= 0xFF:
        raise ValueError("dst must be an integer in range 0-255")
    selector = ",".join(f"{key}={request.selector[key]}" for key in sorted(request.selector))
    baseline = "/".join(value.hex() for value in request.expected_before)
    expected = "/".join(value.hex() for value in request.expected_after)
    return (
        f"CONFIRM {request.operation} dst=0x{dst:02X} selector={selector} "
        f"payload={request.write_payload.hex()} baseline={baseline} expected={expected}"
    )


def _qualification_scope(operation: WriteOperationName) -> QualificationScope:
    if operation == "WriteTimer":
        return "timer_write_op04"
    if operation == "SetEvent":
        return "event_write_op0a"
    return "event_setpoint_write_op0c"


def validate_operation_write_qualification(
    request: B524OperationWriteRequest,
    qualification: B524NativeWriteQualification,
) -> None:
    """Validate native evidence against a prepared request before transport opens."""

    if request.operation in _EVENT_OPERATIONS:
        raise ValueError(operation_write_availability(request.operation).reason)
    if not qualification.native_qualified:
        raise ValueError("native write qualification is required")
    if qualification.scope != _qualification_scope(request.operation):
        raise ValueError("qualification scope does not match the write operation")
    if qualification.manufacturer != 0xB5:
        raise ValueError("write qualification must identify manufacturer B5")
    if qualification.device_id.upper() not in _VRC700_DEVICE_IDS:
        raise ValueError("OP04 qualification requires VRC700 identity 70000 or B7S00")
    if qualification.selector != request.selector:
        raise ValueError("qualification selector does not match the concrete write selector")
    if not qualification.profile or not qualification.model or not qualification.software_raw_hex:
        raise ValueError("qualification must name profile, model, and raw software bytes")
    if not qualification.evidence_reference:
        raise ValueError("qualification must include a concrete evidence reference")


def _verify_connected_identity(
    transport: TransportInterface,
    *,
    dst: int,
    qualification: B524NativeWriteQualification,
) -> dict[str, str]:
    send_proto = getattr(transport, "send_proto", None)
    if not callable(send_proto):
        raise ValueError("transport cannot read standard 07/04 identity for a live write")
    try:
        payload = send_proto(dst, 0x07, 0x04, b"")
        identity = parse_scan_identification(payload)
    except (TransportError, TypeError, ValueError) as exc:
        raise ValueError("connected target identity could not be verified") from exc
    if (
        identity.manufacturer != qualification.manufacturer
        or identity.device_id.strip().upper() != qualification.device_id.strip().upper()
        or identity.sw.lower() != qualification.software_raw_hex.lower()
    ):
        raise ValueError(
            "connected target manufacturer, EID, or raw software bytes do not match qualification"
        )
    return {
        "manufacturer": f"0x{identity.manufacturer:02X}",
        "device_id": identity.device_id,
        "software_raw_hex": identity.sw,
        "hardware_raw_hex": identity.hw,
    }


def _read_snapshot(
    transport: TransportInterface,
    *,
    dst: int,
    requests: tuple[B524OperationReadRequest, ...],
) -> tuple[tuple[bytes | None, ...], list[dict[str, Any]]]:
    values: list[bytes | None] = []
    evidence: list[dict[str, Any]] = []
    for request in requests:
        attempts = 0

        def count_attempt() -> None:
            nonlocal attempts
            attempts += 1

        item: dict[str, Any] = {
            "operation": request.operation,
            "selector": dict(request.selector),
            "request_payload_hex": request.payload.hex(),
            "selector_correlation": "request_context",
            "request_attempts": 0,
            "response_raw_hex": None,
            "response_state": "unknown",
        }
        try:
            response = transport.send_with_attempt_hook(dst, request.payload, count_attempt)
        except TransportError as exc:
            item["response_state"] = "transport_error"
            item["error"] = type(exc).__name__
            values.append(None)
        else:
            item["response_raw_hex"] = response.hex()
            if not response:
                item["response_state"] = "empty"
                values.append(None)
            else:
                try:
                    if request.operation == "ReadTimer":
                        parse_timer_response(response)
                    elif request.operation == "GetEvent":
                        parse_event_response(response)
                    else:
                        profile = cast(EventProfileName, request.selector["profile"])
                        parse_event_setpoint_response(response, profile)
                except (TypeError, ValueError):
                    item["response_state"] = "malformed"
                    values.append(None)
                else:
                    item["response_state"] = "value"
                    values.append(response)
        item["request_attempts"] = attempts
        evidence.append(item)
    return tuple(values), evidence


def _classify_readback(
    request: B524OperationWriteRequest,
    readback: tuple[bytes | None, ...],
) -> WriteOutcome:
    if any(value is None for value in readback):
        return "ambiguous"
    complete = cast(tuple[bytes, ...], readback)
    if complete == request.expected_after:
        return "verified"
    if complete == request.expected_before:
        return "not_applied"
    changed = tuple(
        value != before for value, before in zip(complete, request.expected_before, strict=True)
    )
    expected_changed = tuple(
        after != before
        for after, before in zip(request.expected_after, request.expected_before, strict=True)
    )
    if len(changed) > 1 and any(changed) and changed != expected_changed:
        return "partial"
    return "unexpected"


def execute_controlled_write(
    transport: TransportInterface,
    *,
    dst: int,
    request: B524OperationWriteRequest,
    qualification: B524NativeWriteQualification,
    concrete_confirmation: str,
) -> dict[str, Any]:
    """Execute one qualified write, one time, then read back without rollback."""

    if isinstance(dst, bool) or not isinstance(dst, int) or not 0 <= dst <= 0xFF:
        raise ValueError("dst must be an integer in range 0-255")
    validate_operation_write_qualification(request, qualification)
    expected_confirmation = concrete_confirmation_text(request, dst=dst)
    if concrete_confirmation != expected_confirmation:
        raise ValueError("concrete confirmation does not match this exact B524 write")

    result: dict[str, Any] = {
        "operation": request.operation,
        "opcode_hex": f"0x{request.opcode:02X}",
        "selector": dict(request.selector),
        "request_payload_hex": request.write_payload.hex(),
        "qualification": {
            "scope": qualification.scope,
            "manufacturer": f"0x{qualification.manufacturer:02X}",
            "device_id": qualification.device_id,
            "profile": qualification.profile,
            "model": qualification.model,
            "software_raw_hex": qualification.software_raw_hex,
            "evidence_reference": qualification.evidence_reference,
        },
        "expected_before_raw_hex": [value.hex() for value in request.expected_before],
        "expected_after_raw_hex": [value.hex() for value in request.expected_after],
        "write_attempts": 0,
        "write_feedback_raw_hex": None,
        "write_feedback_interpretation": "unknown",
        "automatic_rollback": False,
    }

    result["connected_identity"] = _verify_connected_identity(
        transport, dst=dst, qualification=qualification
    )

    before, before_evidence = _read_snapshot(transport, dst=dst, requests=request.read_requests)
    result["pre_read"] = before_evidence
    if any(value is None for value in before):
        result["outcome"] = "pre_read_failed"
        return result
    if cast(tuple[bytes, ...], before) != request.expected_before:
        result["outcome"] = "baseline_mismatch"
        result["observed_before_raw_hex"] = [cast(bytes, value).hex() for value in before]
        return result

    write_attempts = 0

    def admit_one_write() -> None:
        nonlocal write_attempts
        if write_attempts >= 1:
            raise B524WriteRetryBlocked(
                "automatic B524 write retry blocked before native transmission"
            )
        write_attempts += 1

    try:
        feedback = transport.send_with_attempt_hook(dst, request.write_payload, admit_one_write)
    except (B524WriteRetryBlocked, TransportError) as exc:
        result["write_error"] = type(exc).__name__
    else:
        result["write_feedback_raw_hex"] = feedback.hex()
    result["write_attempts"] = write_attempts

    readback, readback_evidence = _read_snapshot(transport, dst=dst, requests=request.read_requests)
    result["readback"] = readback_evidence
    result["observed_after_raw_hex"] = [
        value.hex() if isinstance(value, bytes) else None for value in readback
    ]
    result["outcome"] = _classify_readback(request, readback)
    return result
