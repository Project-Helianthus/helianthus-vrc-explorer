from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from .artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from .protocol.b524_metadata import SYSTEM_INFORMATION_NAMES, decode_parameter_description
from .protocol.b524_schedules import EVENT_PROFILES, TIMER_CHANNELS
from .protocol.parser import ValueParseError, parse_typed_value
from .scanner.b524_operation_reads import (
    B524OperationReadRequest,
    decode_operation_read_observation,
    parse_operation_read_plan,
    record_operation_read_observation,
)
from .scanner.director import (
    GROUP_CONFIG,
    NamespaceProfile,
    group_name_for_opcode,
    group_namespace_profiles,
)
from .scanner.identity import operation_label
from .scanner.register import (
    _interpret_flags,
    _parse_inferred_value,
    _reply_kind,
    _sentinel_value_display,
    _strip_echo_header,
)
from .schema.b524_register_names import b524_register_name
from .schema.myvaillant_map import MyvaillantRegisterMap

_TRACE_LINE_RE = re.compile(r"^(?P<timestamp>\S+)\s+(?P<body>.*)$")
_SEND_PROTO_RE = re.compile(
    r"^#(?P<seq>\d+)\s+SEND_PROTO\s+src=0x(?P<src>[0-9a-fA-F]{2})\s+"
    r"dst=0x(?P<dst>[0-9a-fA-F]{2})\s+primary=0x(?P<primary>[0-9a-fA-F]{2})\s+"
    r"secondary=0x(?P<secondary>[0-9a-fA-F]{2})\s+payload=(?P<payload>[0-9a-fA-F.]*)$"
)
_PARSED_PROTO_RE = re.compile(
    r"^#(?P<seq>\d+)\s+PARSED_PROTO\s+len=(?P<length>\d+)\s+hex=(?P<hex>[0-9a-fA-F.]*)$"
)
_RECV_NO_RESPONSE_RE = re.compile(
    r"^#(?P<seq>\d+)\s+RECV_PROTO\s+(broadcast_or_no_response|initiator_initiator=no_response)$"
)
_RETRY_RE = re.compile(r"^#(?P<seq>\d+)\s+RETRY\s+type=(?P<kind>[a-zA-Z0-9_]+)(?:\s+|$)")
_LOCAL_NACK_RETRY_RE = re.compile(
    r"^#(?P<seq>\d+)\s+LOCAL_NACK_RETRY\s+attempt=(?P<attempt>\d+)(?:\s+|$)"
)
_RECOVERY_RE = re.compile(
    r"^#(?P<seq>\d+)\s+RECOVERY\s+cause=(?P<cause>[a-zA-Z0-9_]+)\s+"
    r"phase=(?P<phase>[a-zA-Z0-9_]+)\s+request_attempt=(?P<request_attempts>\d+)\s+"
    r"reconnects_used=(?P<reconnect_attempts>\d+)/(?P<reconnect_max>\d+)$"
)
_REQUEST_FAILED_RE = re.compile(
    r"^#(?P<seq>\d+)\s+REQUEST_FAILED\s+"
    r"(?:(?:read protocol recovery exhausted|transport recovery exhausted):\s+)?"
    r"cause=(?P<cause>[a-zA-Z0-9_]+)\s+phase=(?P<phase>[a-zA-Z0-9_]+)\s+"
    r"request_attempts=(?P<request_attempts>\d+)\s+"
    r"(?:retry_count=(?P<retry_count>\d+)\s+)?"
    r"reconnect_attempts=(?P<reconnect_attempts>\d+)"
    r"(?:\s+unexpected_symbol=(?P<unexpected_symbol>\S+))?$"
)
_OP_LABEL_RE = re.compile(r"^OP\s+(?P<label>.+)$")
_SUPPORTED_ENH_MARKERS: tuple[str, ...] = ("INIT ",)


class TraceReplayError(ValueError):
    """Raised when trace replay cannot continue."""


class UnsupportedTraceFormatError(TraceReplayError):
    """Raised when the provided trace format is unsupported for replay."""


@dataclass(slots=True)
class _TraceExchange:
    seq: int
    timestamp: datetime
    src: int
    dst: int
    primary: int
    secondary: int
    payload: bytes
    response: bytes | None = None
    op_label: str | None = None
    retry_kind: str | None = None
    failure_cause: str | None = None
    failure_phase: str | None = None
    request_attempts: int = 1
    retry_count: int = 0
    reconnect_attempts: int = 0
    unexpected_symbol: str | None = None


@dataclass(frozen=True, slots=True)
class TraceReplayMetadata:
    source_path: str
    first_timestamp: datetime
    last_timestamp: datetime
    total_lines: int
    parsed_exchanges: int
    truncated_hex_frames: int


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _parse_timestamp(raw: str) -> datetime:
    normalized = raw.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _parse_hex(raw: str, *, line_no: int, field_name: str) -> tuple[bytes, bool]:
    text = raw.strip()
    truncated = "..." in text
    if truncated:
        # Current ENH trace logs can truncate long hex payloads with "...".
        # Replay keeps the deterministic prefix and marks metadata accordingly.
        text = text.replace("...", "")
    if text == "":
        return b"", truncated
    if len(text) % 2 != 0 and truncated:
        text = text[:-1]
    if len(text) % 2 != 0:
        raise TraceReplayError(
            f"Invalid odd-length hex in {field_name} at line {line_no}: {text!r}"
        )
    try:
        return bytes.fromhex(text), truncated
    except ValueError as exc:
        raise TraceReplayError(f"Invalid hex in {field_name} at line {line_no}: {text!r}") from exc


def _parse_enhanced_trace_lines(
    lines: list[str], *, source_path: str
) -> tuple[list[_TraceExchange], TraceReplayMetadata]:
    exchange_by_seq: dict[int, _TraceExchange] = {}
    exchanges_in_order: list[_TraceExchange] = []
    pending_labels: list[str] = []
    saw_enh_marker = False
    session_recovery_pending = False
    truncated_hex_frames = 0
    # Offset to make seq numbers unique across multiple INIT sessions
    # in concatenated traces.
    _seq_offset = 0
    _prev_seq = 0

    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        match = _TRACE_LINE_RE.match(stripped)
        if match is None:
            continue
        timestamp = _parse_timestamp(match.group("timestamp"))
        body = match.group("body").strip()

        if first_ts is None:
            first_ts = timestamp
        last_ts = timestamp

        if body.startswith(_SUPPORTED_ENH_MARKERS):
            saw_enh_marker = True
            if session_recovery_pending:
                # EnhancedTcpTransport keeps its logical request sequence when
                # reconnecting. Keep the next SEND attached to that request.
                session_recovery_pending = False
            else:
                # An independent concatenated trace restarts its sequence.
                _seq_offset = _prev_seq + _seq_offset
            continue

        op_match = _OP_LABEL_RE.match(body)
        if op_match is not None:
            label = op_match.group("label").strip()
            if label:
                pending_labels.append(label)
            continue

        send_match = _SEND_PROTO_RE.match(body)
        if send_match is not None:
            raw_seq = int(send_match.group("seq"), 10)
            seq = raw_seq + _seq_offset
            _prev_seq = raw_seq
            payload, payload_truncated = _parse_hex(
                send_match.group("payload"),
                line_no=line_no,
                field_name="payload",
            )
            if payload_truncated:
                truncated_hex_frames += 1
            src = int(send_match.group("src"), 16)
            dst = int(send_match.group("dst"), 16)
            primary = int(send_match.group("primary"), 16)
            secondary = int(send_match.group("secondary"), 16)
            existing = exchange_by_seq.get(seq)
            if (
                existing is not None
                and existing.response is None
                and (
                    existing.src,
                    existing.dst,
                    existing.primary,
                    existing.secondary,
                    existing.payload,
                )
                == (src, dst, primary, secondary, payload)
            ):
                existing.request_attempts += 1
                existing.retry_count = max(existing.retry_count, existing.request_attempts - 1)
                if existing.op_label is None and pending_labels:
                    existing.op_label = pending_labels.pop(0)
                continue
            exchange = _TraceExchange(
                seq=seq,
                timestamp=timestamp,
                src=src,
                dst=dst,
                primary=primary,
                secondary=secondary,
                payload=payload,
                op_label=pending_labels.pop(0) if pending_labels else None,
            )
            exchange_by_seq[seq] = exchange
            exchanges_in_order.append(exchange)
            continue

        parsed_match = _PARSED_PROTO_RE.match(body)
        if parsed_match is not None:
            seq = int(parsed_match.group("seq"), 10) + _seq_offset
            parsed, parsed_truncated = _parse_hex(
                parsed_match.group("hex"),
                line_no=line_no,
                field_name="response",
            )
            if parsed_truncated:
                truncated_hex_frames += 1
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None:
                matched_exchange.response = parsed
            continue

        recv_match = _RECV_NO_RESPONSE_RE.match(body)
        if recv_match is not None:
            seq = int(recv_match.group("seq"), 10) + _seq_offset
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None and matched_exchange.response is None:
                matched_exchange.response = b""
            continue

        retry_match = _RETRY_RE.match(body)
        if retry_match is not None:
            seq = int(retry_match.group("seq"), 10) + _seq_offset
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None:
                matched_exchange.retry_kind = retry_match.group("kind").strip().lower()
            continue

        local_nack_retry_match = _LOCAL_NACK_RETRY_RE.match(body)
        if local_nack_retry_match is not None:
            seq = int(local_nack_retry_match.group("seq"), 10) + _seq_offset
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None:
                # This marker starts another local attempt; it is not terminal
                # NACK evidence. A later response, recovery, or REQUEST_FAILED
                # marker remains authoritative.
                matched_exchange.retry_kind = "local_nack_retry"
                local_attempts = int(local_nack_retry_match.group("attempt"), 10) + 1
                matched_exchange.request_attempts = max(
                    matched_exchange.request_attempts, local_attempts
                )
                matched_exchange.retry_count = max(matched_exchange.retry_count, local_attempts - 1)
            continue

        recovery_match = _RECOVERY_RE.match(body)
        if recovery_match is not None:
            session_recovery_pending = True
            seq = int(recovery_match.group("seq"), 10) + _seq_offset
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None:
                request_attempts = int(recovery_match.group("request_attempts"), 10)
                matched_exchange.retry_kind = recovery_match.group("cause").strip().lower()
                matched_exchange.failure_cause = matched_exchange.retry_kind
                matched_exchange.failure_phase = recovery_match.group("phase").strip().lower()
                matched_exchange.request_attempts = request_attempts
                matched_exchange.retry_count = max(0, request_attempts - 1)
                matched_exchange.reconnect_attempts = int(
                    recovery_match.group("reconnect_attempts"), 10
                )
            continue

        request_failed_match = _REQUEST_FAILED_RE.match(body)
        if request_failed_match is not None:
            seq = int(request_failed_match.group("seq"), 10) + _seq_offset
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None:
                matched_exchange.retry_kind = request_failed_match.group("cause").strip().lower()
                matched_exchange.failure_cause = matched_exchange.retry_kind
                matched_exchange.failure_phase = request_failed_match.group("phase").strip().lower()
                matched_exchange.request_attempts = int(
                    request_failed_match.group("request_attempts"), 10
                )
                raw_retry_count = request_failed_match.group("retry_count")
                matched_exchange.retry_count = (
                    int(raw_retry_count, 10)
                    if raw_retry_count is not None
                    else max(0, matched_exchange.request_attempts - 1)
                )
                matched_exchange.reconnect_attempts = int(
                    request_failed_match.group("reconnect_attempts"), 10
                )
                matched_exchange.unexpected_symbol = request_failed_match.group("unexpected_symbol")
            session_recovery_pending = False
            continue

        if body.startswith("#") and ("SEND " in body or "PARSED " in body):
            raise UnsupportedTraceFormatError(
                "Unsupported trace format. replay-trace currently supports ENH/ENS traces only."
            )

    if not saw_enh_marker:
        raise UnsupportedTraceFormatError(
            "Unsupported trace format: ENH/ENS markers (INIT/START) not found."
        )
    if first_ts is None or last_ts is None:
        raise UnsupportedTraceFormatError("Trace file does not contain timestamped entries.")

    exchanges = exchanges_in_order
    if not exchanges:
        raise UnsupportedTraceFormatError("No ENH/ENS SEND_PROTO exchanges found in trace.")

    metadata = TraceReplayMetadata(
        source_path=source_path,
        first_timestamp=first_ts,
        last_timestamp=last_ts,
        total_lines=len(lines),
        parsed_exchanges=len(exchanges),
        truncated_hex_frames=truncated_hex_frames,
    )
    return exchanges, metadata


def _response_state_implies_present(response_state: object) -> bool:
    return isinstance(response_state, str) and response_state in {"active", "empty_reply"}


def _transport_diagnostic(exchange: _TraceExchange) -> dict[str, str | int] | None:
    if exchange.failure_cause is None or exchange.failure_phase is None:
        return None
    diagnostic: dict[str, str | int] = {
        "cause": exchange.failure_cause,
        "phase": exchange.failure_phase,
        "request_attempts": exchange.request_attempts,
        "retry_count": exchange.retry_count,
        "reconnect_attempts": exchange.reconnect_attempts,
    }
    if exchange.unexpected_symbol is not None:
        diagnostic["unexpected_symbol"] = exchange.unexpected_symbol
    return diagnostic


def _opcode_from_payload(payload: bytes) -> int | None:
    if len(payload) < 1:
        return None
    return int(payload[0])


def _group_name_for_opcode(group: int, opcode: int) -> str:
    try:
        return group_name_for_opcode(group, opcode)
    except Exception:
        return f"Unknown {_hex_u8(group)}"


def _namespace_profile(group: int, opcode: int) -> NamespaceProfile | None:
    return group_namespace_profiles(group).get(opcode)


def _strip_transport_length_prefix(response: bytes) -> bytes:
    """Return the B524 payload after an optional transport length prefix."""
    if len(response) >= 2 and response[0] == len(response) - 1:
        return response[1:]
    return response


def _system_information_name(identifier: int) -> str:
    if 0 <= identifier < len(SYSTEM_INFORMATION_NAMES):
        return SYSTEM_INFORMATION_NAMES[identifier]
    return f"unknown_0x{identifier:04x}"


def _ensure_operation_group(
    operations: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    """Ensure operations[op_hex].groups[group_key] exists and return the group object."""
    op_key = _hex_u8(opcode)
    group_key = _hex_u8(group)
    config = GROUP_CONFIG.get(group)
    profile = _namespace_profile(group, opcode)
    default_name = _group_name_for_opcode(group, opcode)
    descriptor = config.get("desc") if isinstance(config, dict) else None
    op_obj = operations.setdefault(op_key, {})
    op_groups = op_obj.setdefault("groups", {})
    group_obj = op_groups.setdefault(
        group_key,
        {
            "name": default_name,
            "descriptor_observed": float(descriptor)
            if isinstance(descriptor, (int, float)) and not isinstance(descriptor, bool)
            else 0.0,
            "instances": {},
        },
    )
    group_obj.setdefault("instances", {})
    if profile is not None:
        group_obj["ii_max"] = _hex_u8(profile.ii_max)
        group_obj["rr_max"] = _hex_u16(profile.rr_max)
    return group_obj


def _decode_register_read_entry(
    *,
    opcode: Literal[0x02, 0x06],
    payload: bytes,
    response: bytes | None,
    retry_kind: str | None = None,
    transport_diagnostic: dict[str, str | int] | None = None,
) -> dict[str, Any]:
    read_opcode = _hex_u8(opcode)
    entry: dict[str, Any] = {
        "read_opcode": read_opcode,
        "read_opcode_label": operation_label(opcode=opcode, optype=0x00),
        "reply_hex": response.hex() if isinstance(response, bytes) else None,
        "flags": None,
        "reply_kind": None,
        "flags_access": None,
        "response_state": None,
        "ebusd_name": None,
        "myvaillant_name": None,
        "raw_hex": None,
        "type": None,
        "value": None,
        "error": None,
    }

    if response is None:
        if retry_kind == "nack":
            entry["response_state"] = "nack"
            entry["error"] = "nack"
        elif retry_kind == "nack_or_crc":
            # Transport traces emit "nack_or_crc" for both NACK and CRC errors;
            # preserve the ambiguity instead of misclassifying as pure NACK.
            entry["response_state"] = "nack_or_crc"
            entry["error"] = "nack_or_crc"
        elif retry_kind in {None, "timeout"}:
            entry["response_state"] = "timeout"
            entry["error"] = "timeout"
        else:
            entry["response_state"] = "transport_error"
            entry["error"] = retry_kind
        if transport_diagnostic is not None:
            entry["transport_diagnostic"] = transport_diagnostic
        return entry
    if len(response) == 0:
        entry["response_state"] = "empty_reply"
        entry["reply_hex"] = ""
        return entry

    flags = int(response[0])
    entry["flags"] = flags
    entry["flags_access"] = _interpret_flags(flags, response_len=len(response), opcode=opcode)
    entry["reply_kind"] = _reply_kind(flags, response_len=len(response), opcode=opcode)
    entry["response_state"] = "active"

    if len(response) == 1:
        return entry

    try:
        value_bytes = _strip_echo_header(payload, response)
    except ValueError as exc:
        entry["error"] = f"decode_error: {exc}"
        return entry

    raw_hex = value_bytes.hex()
    entry["raw_hex"] = raw_hex
    inferred_type, inferred_value, _ = _parse_inferred_value(value_bytes)
    entry["type"] = inferred_type
    entry["value"] = inferred_value
    sentinel_display = _sentinel_value_display(
        value=inferred_value,
        raw_hex=raw_hex,
        value_type=inferred_type,
    )
    if sentinel_display is not None:
        entry["value_display"] = sentinel_display
    elif inferred_type == "EXP" and inferred_value is None:
        entry["value_display"] = "NaN"
    return entry


def _operation_read_request(payload: bytes) -> B524OperationReadRequest | None:
    opcode = _opcode_from_payload(payload)
    if opcode == 0x08 and len(payload) == 1:
        return B524OperationReadRequest("ReadVR91", opcode, {}, payload, True)
    if opcode not in {0x03, 0x09, 0x0B} or len(payload) != 5:
        return None
    if opcode == 0x03:
        channel_by_selector = {
            (system_type, address): channel
            for channel, (system_type, address) in TIMER_CHANNELS.items()
        }
        channel = channel_by_selector.get((payload[1], payload[3]))
        selector: dict[str, str | int] = (
            {"channel": channel, "instance": payload[2], "weekday": payload[4]}
            if channel is not None
            else {}
        )
        return B524OperationReadRequest("ReadTimer", opcode, selector, payload, True)
    profile_by_system_type = {profile.system_type: name for name, profile in EVENT_PROFILES.items()}
    profile = profile_by_system_type.get(payload[1])
    selector = (
        {
            "profile": profile,
            "instance": payload[2],
            "address": payload[3],
            "weekday_code": payload[4],
        }
        if profile is not None
        else {}
    )
    operation: Literal["GetEvent", "GetEventSetPoint"] = (
        "GetEvent" if opcode == 0x09 else "GetEventSetPoint"
    )
    return B524OperationReadRequest(operation, opcode, selector, payload, False)


def _unknown_operation_raw_selector(payload: bytes) -> dict[str, int] | None:
    opcode = _opcode_from_payload(payload)
    if opcode not in {0x03, 0x09, 0x0B} or len(payload) != 5:
        return None
    return {
        "system_type": payload[1],
        "instance": payload[2],
        "address": payload[3],
        "weekday_code" if opcode in {0x09, 0x0B} else "weekday": payload[4],
    }


def _replay_operation_read(exchange: _TraceExchange) -> dict[str, Any] | None:
    """Translate one trace exchange without assuming a selector echo."""

    request = _operation_read_request(exchange.payload)
    if request is None:
        return None
    if request.selector:
        try:
            canonical = parse_operation_read_plan(
                {
                    "schema_version": 1,
                    "requests": [{"operation": request.operation, **request.selector}],
                }
            )[0]
            if canonical.payload != request.payload:
                raise ValueError("selector does not round-trip to the recorded payload")
        except (TypeError, ValueError):
            request = replace(request, selector={})
        else:
            request = canonical
    record = record_operation_read_observation(request)
    record["trace_seq"] = exchange.seq
    record["request_attempts"] = exchange.request_attempts
    if not request.selector:
        raw_selector = _unknown_operation_raw_selector(exchange.payload)
        if raw_selector is not None:
            record["raw_selector"] = raw_selector
    response = exchange.response
    record["response_raw_hex"] = response.hex() if isinstance(response, bytes) else None
    if response is None:
        if exchange.retry_kind == "nack":
            record["response_state"] = "nack"
            record["error"] = "nack"
        elif exchange.retry_kind == "nack_or_crc":
            record["response_state"] = "transport_error"
            record["error"] = "nack_or_crc"
        elif exchange.retry_kind not in {None, "timeout"}:
            record["response_state"] = "transport_error"
            record["error"] = exchange.retry_kind
        else:
            record["response_state"] = "timeout"
            record["error"] = "timeout"
        transport_diagnostic = _transport_diagnostic(exchange)
        if transport_diagnostic is not None:
            record["transport_diagnostic"] = transport_diagnostic
        return record
    unknown_timer_channel = request.operation == "ReadTimer" and "channel" not in request.selector
    unknown_event_profile = (
        request.operation in {"GetEvent", "GetEventSetPoint"} and "profile" not in request.selector
    )
    if unknown_timer_channel or unknown_event_profile:
        record["response_state"] = "empty" if not response else "value"
        if response:
            if unknown_timer_channel:
                known = (exchange.payload[1], exchange.payload[3]) in TIMER_CHANNELS.values()
                record["error"] = "unsupported_timer_selector" if known else "unknown_timer_channel"
            else:
                known = any(
                    profile.system_type == exchange.payload[1]
                    for profile in EVENT_PROFILES.values()
                )
                record["error"] = "unsupported_event_selector" if known else "unknown_event_profile"
        return record
    decoded, _qualification, state = decode_operation_read_observation(request, response)
    record["response_state"] = state
    record["decoded"] = decoded
    record["decode_qualification"] = "schema_unqualified"
    if state == "malformed":
        record["error"] = "malformed_response"
    return record


def _raw_operation_history(exchange: _TraceExchange) -> dict[str, Any]:
    payload = exchange.payload
    opcode = payload[0]
    selector: dict[str, int] = {}
    if opcode in {0x04, 0x0A, 0x0C} and len(payload) >= 5:
        selector = {
            "system_type": payload[1],
            "instance": payload[2],
            "address": payload[3],
            "weekday_code" if opcode in {0x0A, 0x0C} else "weekday": payload[4],
        }
    if exchange.response is None:
        response_state = "transport_error" if exchange.retry_kind else "timeout"
    elif exchange.response:
        response_state = "value"
    else:
        response_state = "empty"
    return {
        "trace_seq": exchange.seq,
        "operation": operation_label(opcode=opcode, optype=0x00),
        "opcode_hex": _hex_u8(opcode),
        "selector": selector,
        "selector_correlation": "request_context",
        "request_payload_hex": payload.hex(),
        "response_raw_hex": (
            exchange.response.hex() if isinstance(exchange.response, bytes) else None
        ),
        "response_state": response_state,
        "feedback_interpretation": "unknown",
        "mutative": opcode in {0x04, 0x0A, 0x0C},
    }


def replay_trace_to_artifact(trace_path: Path) -> dict[str, Any]:
    """Replay an ENH/ENS trace into a deterministic scan artifact (schema 2.2).

    The replay is intentionally deterministic and conservative:
    - only ENH/ENS trace lines emitted by current `EnhancedTcpTransport` are supported
    - register values are reconstructed from captured request/response payloads
    - metadata that cannot be reconstructed from trace is filled with stable minimal defaults
    """

    lines = trace_path.read_text(encoding="utf-8").splitlines()
    exchanges, meta = _parse_enhanced_trace_lines(lines, source_path=str(trace_path))

    b524_exchanges = [ex for ex in exchanges if ex.primary == 0xB5 and ex.secondary == 0x24]
    if not b524_exchanges:
        raise UnsupportedTraceFormatError("Trace contains no B524 SEND_PROTO exchanges.")

    dst = b524_exchanges[0].dst
    ignored_targets = sum(exchange.dst != dst for exchange in b524_exchanges)
    b524_exchanges = [exchange for exchange in b524_exchanges if exchange.dst == dst]
    scan_timestamp = meta.first_timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    duration = round((meta.last_timestamp - meta.first_timestamp).total_seconds(), 4)

    artifact: dict[str, Any] = {
        "schema_version": CURRENT_ARTIFACT_SCHEMA_VERSION,
        "meta": {
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": max(0.0, duration),
            "destination_address": _hex_u8(dst),
            "schema_sources": ["replay_trace:enhanced_v1"],
            "incomplete": False,
            "replay_trace": {
                "source_path": str(trace_path),
                "format": "enhanced_v1",
                "lines": meta.total_lines,
                "exchanges": meta.parsed_exchanges,
                "limitations": [
                    "ENH/ENS trace format only",
                    "Only deterministically derivable payloads are reconstructed",
                    "No live identity probing is performed during replay",
                ],
            },
        },
        "operations": {},
    }
    limitations = cast(list[str], artifact["meta"]["replay_trace"]["limitations"])
    artifact["meta"]["replay_trace"]["ignored_b524_exchanges"] = ignored_targets
    if ignored_targets:
        limitations.append(
            f"Selected first B524 target {_hex_u8(dst)}; ignored {ignored_targets} "
            "exchanges belonging to other targets"
        )
    if meta.truncated_hex_frames > 0:
        limitations.append(
            "Some trace hex frames were truncated ('...'); replay used deterministic prefixes only"
        )

    system_information: dict[int, dict[str, Any]] = {}
    description_exchanges: list[_TraceExchange] = []
    legacy_constraint_dedup: dict[str, dict[str, Any]] = {}
    b524_operations: dict[str, list[dict[str, Any]]] = {
        # Retain this compatibility shape for old artifact consumers.  New OP00
        # evidence is system information, never a qualified group directory.
        "group_directory": [],
        "register_constraints": [],
        "parameter_descriptions": [],
        "timer_programs": [],
        "events": [],
        "event_setpoints": [],
        "raw_write_history": [],
        "register_tables": [],
    }
    operation_reads: list[dict[str, Any]] = []

    for exchange in b524_exchanges:
        opcode = _opcode_from_payload(exchange.payload)
        if opcode is None:
            continue

        payload = exchange.payload
        response = exchange.response

        if opcode in {0x02, 0x06} and len(payload) >= 6 and payload[1] == 0x00:
            group = int(payload[2])
            instance = int(payload[3])
            register = int.from_bytes(payload[4:6], byteorder="little", signed=False)
            # Replay preserves recorded OP02/OP06 observations independently
            # of current scheduling profiles.  Unknown groups and selectors
            # outside current II/RR bounds remain raw evidence; new scans keep
            # their separate profile limits.
            group_obj = _ensure_operation_group(artifact["operations"], group=group, opcode=opcode)
            instances = group_obj.setdefault("instances", {})
            instance_key = _hex_u8(instance)
            instance_obj = instances.setdefault(instance_key, {"present": False, "registers": {}})
            registers = instance_obj.setdefault("registers", {})
            register_key = _hex_u16(register)
            entry = _decode_register_read_entry(
                opcode=cast(Literal[0x02, 0x06], opcode),
                payload=payload,
                response=response,
                retry_kind=exchange.retry_kind,
                transport_diagnostic=_transport_diagnostic(exchange),
            )
            entry["trace_seq"] = exchange.seq
            if exchange.op_label:
                entry["trace_label"] = exchange.op_label
            # Keep the entry with the best response (active > empty > timeout)
            existing = registers.get(register_key)
            if (
                existing is None
                or entry.get("response_state") == "active"
                or existing.get("response_state") in {None, "timeout", "nack", "nack_or_crc"}
            ):
                registers[register_key] = entry
            if (
                _response_state_implies_present(entry.get("response_state"))
                and entry.get("flags_access") != "absent"
            ):
                instance_obj["present"] = True
            continue

        if opcode == 0x00 and len(payload) == 3:
            identifier = int.from_bytes(payload[1:3], byteorder="little", signed=False)
            normalized_response = (
                _strip_transport_length_prefix(response) if isinstance(response, bytes) else None
            )
            value: float | None = None
            if isinstance(normalized_response, bytes) and len(normalized_response) == 4:
                decoded = struct.unpack("<f", normalized_response)[0]
                if math.isfinite(decoded):
                    value = decoded
            system_information[identifier] = {
                "identifier": _hex_u16(identifier),
                "name": _system_information_name(identifier),
                "value": value,
                # Keep the trace byte sequence, including any transport prefix.
                "raw_hex": response.hex() if isinstance(response, bytes) else None,
                "trace_seq": exchange.seq,
            }
            continue

        if opcode in {0x01, 0x07}:
            if len(payload) == 5:
                description_exchanges.append(exchange)
                continue
            if opcode == 0x01 and len(payload) == 3:
                # The historic selector is GG/RR8 only.  It cannot be bound to
                # a full parameter identity, so preserve raw evidence without
                # inventing a constraint lookup target.
                entry = {
                    "trace_seq": exchange.seq,
                    "request_hex": payload.hex(),
                    "reply_hex": response.hex() if isinstance(response, bytes) else None,
                    "qualification": "legacy_incomplete",
                    "reason": "OP01 selector has no instance or RR16 identity",
                }
                legacy_constraint_dedup[payload.hex()] = entry
            continue

        if opcode in {0x03, 0x04} and len(payload) >= 5:
            b524_operations["timer_programs"].append(
                {
                    "trace_seq": exchange.seq,
                    "operation": operation_label(opcode=opcode, optype=0x00),
                    "selector": [_hex_u8(payload[1]), _hex_u8(payload[2]), _hex_u8(payload[3])],
                    "weekday": int(payload[4]),
                    "reply_hex": response.hex() if isinstance(response, bytes) else None,
                }
            )
            if opcode == 0x03:
                operation_read = _replay_operation_read(exchange)
                if operation_read is not None:
                    operation_reads.append(operation_read)
            else:
                b524_operations["raw_write_history"].append(_raw_operation_history(exchange))
            continue

        if opcode == 0x08:
            operation_read = _replay_operation_read(exchange)
            if operation_read is not None:
                operation_reads.append(operation_read)
            continue

        if opcode in {0x09, 0x0A, 0x0B, 0x0C} and len(payload) >= 5:
            bucket = "events" if opcode in {0x09, 0x0A} else "event_setpoints"
            history = _raw_operation_history(exchange)
            b524_operations[bucket].append(history)
            if opcode in {0x0A, 0x0C}:
                b524_operations["raw_write_history"].append(history)
            else:
                operation_read = _replay_operation_read(exchange)
                if operation_read is not None:
                    operation_reads.append(operation_read)
            if opcode == 0x0B:
                b524_operations["register_tables"].append(
                    {
                        "trace_seq": exchange.seq,
                        "operation": operation_label(opcode=opcode, optype=0x00),
                        "payload_hex": payload.hex(),
                        "reply_hex": response.hex() if isinstance(response, bytes) else None,
                    }
                )
            continue

    artifact["meta"]["system_information"] = [
        system_information[identifier] for identifier in sorted(system_information)
    ]

    for exchange in description_exchanges:
        payload = exchange.payload
        response = exchange.response
        description_opcode = int(payload[0])
        read_opcode = 0x02 if description_opcode == 0x01 else 0x06
        group, instance = int(payload[1]), int(payload[2])
        register = int.from_bytes(payload[3:5], byteorder="little", signed=False)
        observation: dict[str, Any] = {
            "trace_seq": exchange.seq,
            "request_hex": payload.hex(),
            "reply_hex": response.hex() if isinstance(response, bytes) else None,
            "description_opcode": _hex_u8(description_opcode),
            "read_opcode": _hex_u8(read_opcode),
            "group": _hex_u8(group),
            "instance": _hex_u8(instance),
            "register": _hex_u16(register),
            "qualification": "unqualified",
        }
        target = (
            artifact["operations"]
            .get(_hex_u8(read_opcode), {})
            .get("groups", {})
            .get(_hex_u8(group), {})
            .get("instances", {})
            .get(_hex_u8(instance), {})
            .get("registers", {})
            .get(_hex_u16(register))
        )
        if not isinstance(target, dict):
            observation["reason"] = "matching register observation is unavailable"
            b524_operations["parameter_descriptions"].append(observation)
            continue
        type_spec = target.get("type")
        if not isinstance(type_spec, str):
            observation["reason"] = "matching register has no known scalar codec"
            b524_operations["parameter_descriptions"].append(observation)
            continue
        if not isinstance(response, bytes):
            observation["reason"] = "description response is unavailable"
            b524_operations["parameter_descriptions"].append(observation)
            continue
        normalized_response = _strip_transport_length_prefix(response)
        try:
            description = decode_parameter_description(
                normalized_response,
                opcode=description_opcode,
                group=group,
                instance=instance,
                register=register,
                type_spec=type_spec,
            )
        except ValueError as exc:
            observation["reason"] = str(exc)
            b524_operations["parameter_descriptions"].append(observation)
            continue
        description["trace_seq"] = exchange.seq
        description["trace_reply_hex"] = response.hex()
        target["parameter_description"] = description
        observation["qualification"] = "matched"
        observation["type"] = description["type"]
        b524_operations["parameter_descriptions"].append(observation)

    b524_operations["register_constraints"] = sorted(
        legacy_constraint_dedup.values(),
        key=lambda e: e["request_hex"],
    )
    artifact["b524_operations"] = b524_operations
    if operation_reads:
        artifact["b524_operation_reads_schema_version"] = 1
        artifact["b524_operation_reads"] = operation_reads

    # Enrich register entries with myvaillant register names.
    _enrich_register_names(artifact["operations"])

    # Derive rr_max / ii_max from observed trace data so that metadata
    # reflects the actual scan range, not the GROUP_CONFIG profile defaults.
    _update_namespace_bounds_from_observed(artifact["operations"])

    return artifact


def _update_namespace_bounds_from_observed(operations: dict[str, Any]) -> None:
    """Override rr_max / ii_max with observed trace bounds.

    The replay initially sets these from GROUP_CONFIG profiles, but the
    trace is the source of truth -- the user may have scanned well beyond
    the profile defaults.
    """
    for _op_key, op_obj in operations.items():
        if not isinstance(op_obj, dict):
            continue
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        for _group_key, group_obj in op_groups.items():
            instances = group_obj.get("instances")
            if not isinstance(instances, dict) or not instances:
                continue
            observed_ii_max = max(int(ii_key, 16) for ii_key in instances)
            observed_rr_max = 0
            for inst_obj in instances.values():
                registers = inst_obj.get("registers")
                if isinstance(registers, dict):
                    for rr_key in registers:
                        rr = int(rr_key, 16)
                        if rr > observed_rr_max:
                            observed_rr_max = rr
            group_obj["rr_max"] = _hex_u16(observed_rr_max)
            group_obj["ii_max"] = _hex_u8(observed_ii_max)


def _enrich_register_names(operations: dict[str, Any]) -> None:
    """Apply myvaillant_register_map labels to all register entries."""
    csv_path = Path(__file__).parent / "data" / "myvaillant_register_map.csv"
    if not csv_path.exists():
        return
    mv_map = MyvaillantRegisterMap.from_path(csv_path)

    for op_key, op_obj in operations.items():
        if not isinstance(op_obj, dict):
            continue
        opcode = int(op_key, 16)
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        for group_key, group_obj in op_groups.items():
            group = int(group_key, 16)
            instances = group_obj.get("instances")
            if not isinstance(instances, dict):
                continue
            for ii_key, inst_obj in instances.items():
                instance = int(ii_key, 16)
                registers = inst_obj.get("registers")
                if not isinstance(registers, dict):
                    continue
                for rr_key, entry in registers.items():
                    if not isinstance(entry, dict):
                        continue
                    register = int(rr_key, 16)
                    if entry.get("myvaillant_name") is None:
                        mv = mv_map.lookup(
                            group=group,
                            instance=instance,
                            register=register,
                            opcode=opcode,
                        )
                        if mv is not None:
                            entry["myvaillant_name"] = mv.leaf
                            if mv.register_class is not None:
                                entry.setdefault("register_class", mv.register_class)
                            if entry.get("ebusd_name") is None:
                                resolved = mv.resolved_ebusd_name(
                                    group=group,
                                    instance=instance,
                                    register=register,
                                )
                                if resolved:
                                    entry["ebusd_name"] = resolved
                            if mv.type_hint and entry.get("raw_hex"):
                                try:
                                    raw = bytes.fromhex(entry["raw_hex"])
                                    value = parse_typed_value(mv.type_hint, raw)
                                    entry["type"] = mv.type_hint
                                    entry["value"] = value
                                    if mv.type_hint == "EXP" and value is None:
                                        entry["value_display"] = "NaN"
                                except (ValueParseError, ValueError):
                                    pass

                    canonical_name = b524_register_name(
                        opcode=opcode,
                        group=group,
                        register=register,
                    )
                    if canonical_name is not None:
                        entry["myvaillant_name"] = canonical_name
