from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from .artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from .scanner.director import GROUP_CONFIG, group_name_for_opcode
from .scanner.identity import opcode_label, operation_label
from .scanner.register import (
    _interpret_flags,
    _parse_inferred_value,
    _reply_kind,
    _sentinel_value_display,
    _strip_echo_header,
)

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
_OP_LABEL_RE = re.compile(r"^OP\s+(?P<label>.+)$")
_SUPPORTED_ENH_MARKERS: tuple[str, ...] = ("INIT ", "START ")


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
    sequence_order: list[int] = []
    pending_labels: list[str] = []
    saw_enh_marker = False
    truncated_hex_frames = 0

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
            continue

        op_match = _OP_LABEL_RE.match(body)
        if op_match is not None:
            label = op_match.group("label").strip()
            if label:
                pending_labels.append(label)
            continue

        send_match = _SEND_PROTO_RE.match(body)
        if send_match is not None:
            seq = int(send_match.group("seq"), 10)
            payload, payload_truncated = _parse_hex(
                send_match.group("payload"),
                line_no=line_no,
                field_name="payload",
            )
            if payload_truncated:
                truncated_hex_frames += 1
            exchange = _TraceExchange(
                seq=seq,
                timestamp=timestamp,
                src=int(send_match.group("src"), 16),
                dst=int(send_match.group("dst"), 16),
                primary=int(send_match.group("primary"), 16),
                secondary=int(send_match.group("secondary"), 16),
                payload=payload,
                op_label=pending_labels.pop(0) if pending_labels else None,
            )
            exchange_by_seq[seq] = exchange
            if seq not in sequence_order:
                sequence_order.append(seq)
            continue

        parsed_match = _PARSED_PROTO_RE.match(body)
        if parsed_match is not None:
            seq = int(parsed_match.group("seq"), 10)
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
            seq = int(recv_match.group("seq"), 10)
            matched_exchange = exchange_by_seq.get(seq)
            if matched_exchange is not None and matched_exchange.response is None:
                matched_exchange.response = b""
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

    exchanges = [exchange_by_seq[seq] for seq in sequence_order if seq in exchange_by_seq]
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


def _opcode_from_payload(payload: bytes) -> int | None:
    if len(payload) < 1:
        return None
    return int(payload[0])


def _group_name_for_opcode(group: int, opcode: int) -> str:
    try:
        return group_name_for_opcode(group, opcode)
    except Exception:
        return f"Unknown {_hex_u8(group)}"


def _ensure_group_namespace(
    groups: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    group_key = _hex_u8(group)
    config = GROUP_CONFIG.get(group)
    default_name = str(config.get("name")) if isinstance(config, dict) else f"Unknown {group_key}"
    descriptor = config.get("desc") if isinstance(config, dict) else None
    group_obj = groups.setdefault(
        group_key,
        {
            "name": default_name,
            "descriptor_observed": float(descriptor)
            if isinstance(descriptor, (int, float)) and not isinstance(descriptor, bool)
            else 0.0,
            "dual_namespace": True,
            "namespaces": {},
        },
    )
    namespaces = group_obj.setdefault("namespaces", {})
    namespace_key = _hex_u8(opcode)
    namespace_obj = namespaces.setdefault(
        namespace_key,
        {
            "label": opcode_label(opcode),
            "operation_label": operation_label(opcode=opcode, optype=0x00),
            "group_name": _group_name_for_opcode(group, opcode),
            "instances": {},
        },
    )
    return group_obj, namespace_obj


def _decode_register_read_entry(
    *,
    opcode: Literal[0x02, 0x06],
    payload: bytes,
    response: bytes | None,
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
        entry["response_state"] = "timeout"
        return entry
    if len(response) == 0:
        entry["response_state"] = "empty_reply"
        entry["reply_hex"] = ""
        return entry

    flags = int(response[0])
    entry["flags"] = flags
    entry["flags_access"] = _interpret_flags(flags, response_len=len(response))
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
    return entry


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
        "groups": {},
    }
    limitations = cast(list[str], artifact["meta"]["replay_trace"]["limitations"])
    if meta.truncated_hex_frames > 0:
        limitations.append(
            "Some trace hex frames were truncated ('...'); replay used deterministic prefixes only"
        )

    b524_operations: dict[str, list[dict[str, Any]]] = {
        "group_directory": [],
        "register_constraints": [],
        "timer_programs": [],
        "register_tables": [],
    }

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
            _group_obj, namespace_obj = _ensure_group_namespace(
                artifact["groups"], group=group, opcode=opcode
            )
            instances = namespace_obj.setdefault("instances", {})
            instance_key = _hex_u8(instance)
            instance_obj = instances.setdefault(instance_key, {"present": False, "registers": {}})
            registers = instance_obj.setdefault("registers", {})
            register_key = _hex_u16(register)
            entry = _decode_register_read_entry(
                opcode=cast(Literal[0x02, 0x06], opcode),
                payload=payload,
                response=response,
            )
            entry["trace_seq"] = exchange.seq
            if exchange.op_label:
                entry["trace_label"] = exchange.op_label
            registers[register_key] = entry
            if _response_state_implies_present(entry.get("response_state")):
                instance_obj["present"] = True
            continue

        if opcode == 0x00 and len(payload) >= 3:
            descriptor = None
            if isinstance(response, bytes) and len(response) >= 4:
                parsed = struct.unpack("<f", response[:4])[0]
                descriptor = None if math.isnan(parsed) else parsed
            b524_operations["group_directory"].append(
                {
                    "trace_seq": exchange.seq,
                    "group": _hex_u8(payload[1]),
                    "descriptor": descriptor,
                    "reply_hex": response.hex() if isinstance(response, bytes) else None,
                }
            )
            continue

        if opcode == 0x01 and len(payload) >= 3:
            b524_operations["register_constraints"].append(
                {
                    "trace_seq": exchange.seq,
                    "group": _hex_u8(payload[1]),
                    "register_selector": _hex_u8(payload[2]),
                    "reply_hex": response.hex() if isinstance(response, bytes) else None,
                }
            )
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
            continue

        if opcode == 0x0B:
            b524_operations["register_tables"].append(
                {
                    "trace_seq": exchange.seq,
                    "operation": operation_label(opcode=opcode, optype=0x00),
                    "payload_hex": payload.hex(),
                    "reply_hex": response.hex() if isinstance(response, bytes) else None,
                }
            )

    artifact["b524_operations"] = b524_operations
    return artifact
