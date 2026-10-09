"""Bounded, explicit read-only B524 schedule and event acquisition."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast

from ..protocol.b524_schedules import (
    EVENT_PROFILES,
    TIMER_CHANNELS,
    EventProfileName,
    TimerChannelName,
    build_event_read_payload,
    build_event_setpoint_read_payload,
    build_timer_read_payload,
    build_vr91_read_payload,
    parse_event_response,
    parse_event_setpoint_response,
    parse_timer_response,
    parse_vr91_response,
)
from ..transport.base import (
    TransportError,
    TransportInterface,
    TransportNack,
    TransportProtocolFailure,
    TransportRecoveryExhausted,
    TransportTimeout,
)
from ..transport.instrumented import ScanRequestBudgetExceeded
from .observer import ScanObserver

MAX_EXPLICIT_OPERATION_READS = 100_000
_VRC700_DEVICE_IDS = frozenset({"70000", "B7S00"})
_UNKNOWN_DEVICE_IDS = frozenset({"?", "UNKNOWN", "UNAVAILABLE", "NONE", "N/A"})
type OperationName = Literal["ReadTimer", "ReadVR91", "GetEvent", "GetEventSetPoint"]


@dataclass(frozen=True, slots=True)
class B524OperationReadRequest:
    """One finite request whose selector is correlated from request context."""

    operation: OperationName
    opcode: int
    selector: dict[str, str | int]
    payload: bytes
    requires_vrc700: bool


def _u8(value: object, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a JSON integer")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} out of range: {value} (allowed 0-255)")
    return value


def _object(value: object, *, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{context} field names must be strings")
    return cast(Mapping[str, object], value)


def _exact_keys(value: Mapping[str, object], *, expected: set[str], context: str) -> None:
    unknown = sorted(key for key in value if key not in expected)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")
    missing = sorted(key for key in expected if key not in value)
    if missing:
        raise ValueError(f"{context} is missing field(s): {', '.join(missing)}")


def _request_from_json(value: object, *, index: int) -> B524OperationReadRequest:
    request = _object(value, context=f"requests[{index}]")
    operation = request.get("operation")
    if operation == "ReadTimer":
        _exact_keys(
            request,
            expected={"operation", "channel", "instance", "weekday"},
            context=f"requests[{index}]",
        )
        channel = request["channel"]
        if not isinstance(channel, str) or channel not in TIMER_CHANNELS:
            raise ValueError(f"requests[{index}].channel must be a known timer channel")
        instance = _u8(request["instance"], name=f"requests[{index}].instance")
        weekday = _u8(request["weekday"], name=f"requests[{index}].weekday")
        payload = build_timer_read_payload(
            cast(TimerChannelName, channel), instance=instance, weekday=weekday
        )
        return B524OperationReadRequest(
            operation="ReadTimer",
            opcode=0x03,
            selector={"channel": channel, "instance": instance, "weekday": weekday},
            payload=payload,
            requires_vrc700=True,
        )
    if operation == "ReadVR91":
        _exact_keys(request, expected={"operation"}, context=f"requests[{index}]")
        return B524OperationReadRequest(
            operation="ReadVR91",
            opcode=0x08,
            selector={},
            payload=build_vr91_read_payload(),
            requires_vrc700=True,
        )
    if operation in {"GetEvent", "GetEventSetPoint"}:
        _exact_keys(
            request,
            expected={"operation", "profile", "instance", "address", "weekday_code"},
            context=f"requests[{index}]",
        )
        profile = request["profile"]
        if not isinstance(profile, str) or profile not in EVENT_PROFILES:
            raise ValueError(f"requests[{index}].profile must be a known event profile")
        instance = _u8(request["instance"], name=f"requests[{index}].instance")
        address = _u8(request["address"], name=f"requests[{index}].address")
        weekday_code = _u8(request["weekday_code"], name=f"requests[{index}].weekday_code")
        typed_profile = cast(EventProfileName, profile)
        if operation == "GetEvent":
            payload = build_event_read_payload(
                typed_profile,
                instance=instance,
                address=address,
                weekday_code=weekday_code,
            )
            opcode = 0x09
        else:
            payload = build_event_setpoint_read_payload(
                typed_profile,
                instance=instance,
                address=address,
                weekday_code=weekday_code,
            )
            opcode = 0x0B
        return B524OperationReadRequest(
            operation=cast(Literal["GetEvent", "GetEventSetPoint"], operation),
            opcode=opcode,
            selector={
                "profile": profile,
                "instance": instance,
                "address": address,
                "weekday_code": weekday_code,
            },
            payload=payload,
            requires_vrc700=False,
        )
    raise ValueError(f"requests[{index}].operation is unsupported")


def parse_operation_read_plan(document: object) -> tuple[B524OperationReadRequest, ...]:
    """Validate schema v1 and preserve first occurrence order for unique payloads."""

    plan = _object(document, context="plan")
    _exact_keys(plan, expected={"schema_version", "requests"}, context="plan")
    schema_version = plan["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("plan.schema_version must be integer 1")
    raw_requests = plan["requests"]
    if not isinstance(raw_requests, list):
        raise ValueError("plan.requests must be an array")
    if not raw_requests:
        raise ValueError("plan.requests must contain at least one explicit request")
    if len(raw_requests) > MAX_EXPLICIT_OPERATION_READS:
        raise ValueError("operation read plan exceeds the 100000 request safety limit")
    requests: list[B524OperationReadRequest] = []
    payloads: set[bytes] = set()
    for index, value in enumerate(raw_requests):
        request = _request_from_json(value, index=index)
        if request.payload in payloads:
            continue
        payloads.add(request.payload)
        requests.append(request)
    return tuple(requests)


def load_operation_read_plan(path: Path) -> tuple[B524OperationReadRequest, ...]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"operation read plan cannot be loaded: {exc}") from exc
    return parse_operation_read_plan(document)


def _decode(request: B524OperationReadRequest, response: bytes) -> tuple[dict[str, Any], str]:
    if request.operation == "ReadTimer":
        return asdict(parse_timer_response(response)), "profile_vrc700"
    if request.operation == "ReadVR91":
        return asdict(parse_vr91_response(response)), "profile_vrc700"
    profile = cast(EventProfileName, request.selector["profile"])
    if request.operation == "GetEvent":
        return asdict(parse_event_response(response)), "schema_unqualified"
    return asdict(parse_event_setpoint_response(response, profile)), "schema_unqualified"


def decode_operation_read_observation(
    request: B524OperationReadRequest, response: bytes
) -> tuple[dict[str, Any] | None, str, str]:
    """Decode one reply without assuming that its bytes echo the selector."""

    if not response:
        return None, "schema_unqualified", "empty"
    try:
        decoded, qualification = _decode(request, response)
    except (TypeError, ValueError):
        return None, "schema_unqualified", "malformed"
    return decoded, qualification, "value"


def _pair_context(request: B524OperationReadRequest) -> dict[str, str | int] | None:
    if request.operation not in {"GetEvent", "GetEventSetPoint"}:
        return None
    keys = ("profile", "instance", "address", "weekday_code")
    if not all(key in request.selector for key in keys):
        return None
    return {key: request.selector[key] for key in keys}


def record_operation_read_observation(request: B524OperationReadRequest) -> dict[str, Any]:
    record: dict[str, Any] = {
        "operation": request.operation,
        "opcode_hex": f"0x{request.opcode:02X}",
        "selector": dict(request.selector),
        "request_payload_hex": request.payload.hex(),
        "response_raw_hex": None,
        "response_state": "unknown",
        "decoded": None,
        "decode_qualification": "schema_unqualified",
        "selector_correlation": "request_context",
        "request_attempts": 0,
    }
    pair_context = _pair_context(request)
    if pair_context is not None:
        record["pair_context"] = pair_context
    return record


def validate_operation_read_identity(
    requests: Sequence[B524OperationReadRequest],
    *,
    device_id: str | None,
    manufacturer: int | None,
) -> None:
    normalized_device_id = device_id.strip().upper() if isinstance(device_id, str) else ""
    if (
        manufacturer != 0xB5
        or not normalized_device_id
        or normalized_device_id in _UNKNOWN_DEVICE_IDS
    ):
        raise ValueError("B524 operation reads require a known Vaillant target identity")
    if (
        any(request.requires_vrc700 for request in requests)
        and normalized_device_id not in _VRC700_DEVICE_IDS
    ):
        raise ValueError("ReadTimer and ReadVR91 require VRC700 identity 70000 or B7S00")


def _mark_unattempted(
    records: list[dict[str, Any]],
    result: list[dict[str, Any]],
    requests: Sequence[B524OperationReadRequest],
    *,
    reason: str,
) -> None:
    for request in requests:
        record = record_operation_read_observation(request)
        record["response_state"] = "unattempted"
        record["error"] = reason
        records.append(record)
        result.append(record)


def acquire_operation_reads(
    transport: TransportInterface,
    *,
    dst: int,
    artifact: dict[str, Any],
    requests: Sequence[B524OperationReadRequest],
    device_id: str | None,
    manufacturer: int | None,
    observer: ScanObserver | None = None,
) -> list[dict[str, Any]]:
    """Append explicit observations, using transport hooks for actual attempt counts.

    A :class:`CountingTransport` supplied by orchestration remains the sole owner
    of the shared request budget. If that budget or terminal recovery interrupts
    acquisition, the current selector retains its actual attempt state and all
    remaining selectors are retained as unattempted before re-raising.
    """

    if isinstance(dst, bool) or not isinstance(dst, int) or not 0 <= dst <= 0xFF:
        raise ValueError("dst must be an integer in range 0-255")
    if not requests:
        raise ValueError("requests must contain at least one explicit request")
    validate_operation_read_identity(requests, device_id=device_id, manufacturer=manufacturer)
    records = artifact.setdefault("b524_operation_reads", [])
    if not isinstance(records, list):
        raise ValueError("artifact.b524_operation_reads must be a list")
    artifact["b524_operation_reads_schema_version"] = 1
    result: list[dict[str, Any]] = []
    progress_total = len(requests)
    completed = False
    if observer is not None:
        observer.phase_start("b524_operation_reads", total=progress_total)
    try:
        for index, request in enumerate(requests):
            record = record_operation_read_observation(request)
            attempts = 0

            def count_attempt() -> None:
                nonlocal attempts, progress_total
                attempts += 1
                if attempts > 1 and observer is not None:
                    progress_total += 1
                    observer.phase_set_total("b524_operation_reads", total=progress_total)

            if observer is not None:
                observer.status(f"{request.operation} payload={request.payload.hex()}")
            try:
                response = transport.send_with_attempt_hook(dst, request.payload, count_attempt)
            except ScanRequestBudgetExceeded:
                record["response_state"] = "transport_error" if attempts > 0 else "unattempted"
                record["error"] = "request_budget_exhausted"
                record["request_attempts"] = attempts
                records.append(record)
                result.append(record)
                _mark_unattempted(
                    records,
                    result,
                    requests[index + 1 :],
                    reason="request_budget_exhausted",
                )
                if observer is not None:
                    if attempts:
                        observer.phase_advance("b524_operation_reads", advance=attempts)
                    observer.status("B524 operation reads stopped: request budget exhausted")
                raise
            except KeyboardInterrupt:
                record["response_state"] = "transport_error" if attempts > 0 else "unattempted"
                record["error"] = "user_interrupt"
                record["request_attempts"] = attempts
                records.append(record)
                result.append(record)
                _mark_unattempted(
                    records,
                    result,
                    requests[index + 1 :],
                    reason="user_interrupt",
                )
                if observer is not None:
                    if attempts:
                        observer.phase_advance("b524_operation_reads", advance=attempts)
                    observer.status("B524 operation reads interrupted by user")
                raise
            except TransportNack:
                record["response_state"] = "nack"
                record["error"] = "nack"
            except TransportTimeout:
                record["response_state"] = "timeout"
                record["error"] = "timeout"
            except TransportRecoveryExhausted as exc:
                exc.selector = {
                    "operation": request.operation,
                    "opcode": f"0x{request.opcode:02X}",
                    "request_payload_hex": request.payload.hex(),
                    **{key: str(value) for key, value in request.selector.items()},
                }
                record["response_state"] = "transport_error"
                record["error"] = "transport_recovery_exhausted"
                record["request_attempts"] = attempts
                records.append(record)
                result.append(record)
                _mark_unattempted(
                    records,
                    result,
                    requests[index + 1 :],
                    reason="transport_recovery_exhausted",
                )
                if observer is not None:
                    if attempts:
                        observer.phase_advance("b524_operation_reads", advance=attempts)
                    observer.status("B524 operation reads stopped: transport recovery exhausted")
                raise
            except TransportProtocolFailure as exc:
                record["response_state"] = "transport_error"
                record["error"] = str(exc)
            except TransportError:
                record["response_state"] = "transport_error"
                record["error"] = "transport_error"
            else:
                record["response_raw_hex"] = response.hex()
                decoded, qualification, state = decode_operation_read_observation(request, response)
                record["decoded"] = decoded
                record["decode_qualification"] = qualification
                record["response_state"] = state
                if state == "malformed":
                    record["error"] = "malformed_response"
            record["request_attempts"] = attempts
            records.append(record)
            result.append(record)
            if observer is not None:
                observer.phase_advance("b524_operation_reads", advance=max(1, attempts))
        completed = True
    finally:
        if observer is not None and completed:
            observer.phase_finish("b524_operation_reads")
    return result
