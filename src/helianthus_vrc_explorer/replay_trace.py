from __future__ import annotations

import contextlib
import math
import re
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from .artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from .protocol.parser import ValueParseError, parse_typed_value
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
            # Detect session restart: bump seq offset so seqs stay unique
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


def _namespace_profile(group: int, opcode: int) -> NamespaceProfile | None:
    return group_namespace_profiles(group).get(opcode)


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
        if retry_kind == "nack_or_crc":
            # Transport traces emit "nack_or_crc" for both NACK and CRC errors;
            # preserve the ambiguity instead of misclassifying as pure NACK.
            entry["response_state"] = "nack_or_crc"
            entry["error"] = "nack_or_crc"
        else:
            entry["response_state"] = "timeout"
            entry["error"] = "timeout"
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


def _decode_constraint_date(value: bytes) -> str:
    """Decode a 3-byte date triplet (DD MM YY) into ISO date string."""
    if len(value) != 3:
        raise ValueError(f"Date triplet expects 3 bytes, got {len(value)}")
    day = value[0]
    month = value[1]
    year = 2000 + value[2]
    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise ValueError(f"Invalid date triplet: {value.hex()}")
    return f"{year:04d}-{month:02d}-{day:02d}"


def _decode_constraint_response(response: bytes, entry: dict[str, Any]) -> None:
    """Decode OP=0x01 constraint response using TT-based dispatch.

    Wire layout (matching the live scanner's _parse_constraint_entry):
        byte 0: TT (type tag)
        byte 1: GG echo
        byte 2: RR echo
        byte 3: reserved
        byte 4+: body (shape depends on TT)

    TT values:
        0x06 -> u8_range:  3 body bytes (min_u8, max_u8, step_u8)
        0x09 -> u16_range: 6 body bytes (min_u16, max_u16, step_u16) LE
        0x0F -> f32_range: 12 body bytes (min_f32, max_f32, step_f32) LE
        0x0C -> date_range: 9 body bytes (min_date[3], max_date[3], step_u16, pad)
    """
    tt = response[0]
    entry["tt"] = tt
    body = response[4:]

    if tt == 0x06:
        if len(body) < 3:
            return
        entry["kind"] = "u8_range"
        entry["min_value"] = body[0]
        entry["max_value"] = body[1]
        entry["step_value"] = body[2]
    elif tt == 0x09:
        if len(body) < 6:
            return
        entry["kind"] = "u16_range"
        entry["min_value"] = int.from_bytes(body[0:2], byteorder="little", signed=False)
        entry["max_value"] = int.from_bytes(body[2:4], byteorder="little", signed=False)
        entry["step_value"] = int.from_bytes(body[4:6], byteorder="little", signed=False)
    elif tt == 0x0F:
        if len(body) < 12:
            return
        min_f32 = struct.unpack("<f", body[0:4])[0]
        max_f32 = struct.unpack("<f", body[4:8])[0]
        step_f32 = struct.unpack("<f", body[8:12])[0]
        entry["kind"] = "f32_range"
        if not math.isnan(min_f32):
            entry["min_value"] = min_f32
        if not math.isnan(max_f32):
            entry["max_value"] = max_f32
        if not math.isnan(step_f32):
            entry["step_value"] = step_f32
    elif tt == 0x0C:
        if len(body) < 9:
            return
        entry["kind"] = "date_range"
        entry["min_value"] = _decode_constraint_date(body[0:3])
        entry["max_value"] = _decode_constraint_date(body[3:6])
        entry["step_value"] = int.from_bytes(body[6:8], byteorder="little", signed=False)
    # Unknown TT values are silently skipped — the entry retains reply_hex
    # for manual inspection.


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
        "operations": {},
    }
    limitations = cast(list[str], artifact["meta"]["replay_trace"]["limitations"])
    if meta.truncated_hex_frames > 0:
        limitations.append(
            "Some trace hex frames were truncated ('...'); replay used deterministic prefixes only"
        )

    _group_directory_dedup: dict[str, dict[str, Any]] = {}
    _constraint_dedup: dict[tuple[str, str], dict[str, Any]] = {}
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
            # Filter by namespace profile: skip entries where the opcode is
            # not valid for this group, or where instance/register exceed the
            # configured bounds.  This replicates the guardrails the live
            # scanner applies and prevents _update_namespace_bounds_from_observed
            # from widening metadata beyond profile limits.
            profile = _namespace_profile(group, opcode)
            if profile is None:
                # Opcode not in the active namespace profile for this group.
                continue
            if instance > profile.ii_max:
                continue
            if register > profile.rr_max:
                continue
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

        if opcode == 0x00 and len(payload) >= 3:
            descriptor = None
            if isinstance(response, bytes) and len(response) >= 4:
                parsed = struct.unpack("<f", response[:4])[0]
                descriptor = None if math.isnan(parsed) else parsed
            group_key = _hex_u8(payload[1])
            gd_entry = {
                "trace_seq": exchange.seq,
                "group": group_key,
                "descriptor": descriptor,
                "reply_hex": response.hex() if isinstance(response, bytes) else None,
            }
            existing = _group_directory_dedup.get(group_key)
            if existing is None or descriptor is not None:
                _group_directory_dedup[group_key] = gd_entry
            continue

        if opcode == 0x01 and len(payload) >= 3:
            group_key = _hex_u8(payload[1])
            reg_sel = _hex_u8(payload[2])
            constraint_entry: dict[str, Any] = {
                "trace_seq": exchange.seq,
                "group": group_key,
                "register_selector": reg_sel,
                "reply_hex": response.hex() if isinstance(response, bytes) else None,
            }
            if isinstance(response, bytes) and len(response) >= 4:
                # TT-based dispatch matching the live scanner's
                # _parse_constraint_entry layout:
                #   byte 0: TT (type tag)
                #   byte 1: GG echo
                #   byte 2: RR echo
                #   byte 3: reserved
                #   byte 4+: body (shape depends on TT)
                with contextlib.suppress(struct.error, IndexError, ValueError):
                    _decode_constraint_response(response, constraint_entry)
            dedup_key = (group_key, reg_sel)
            # Keep the entry with actual parsed data; don't overwrite with empty
            existing = _constraint_dedup.get(dedup_key)
            if existing is None or "kind" in constraint_entry or "kind" not in existing:
                _constraint_dedup[dedup_key] = constraint_entry
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

    b524_operations["group_directory"] = sorted(
        _group_directory_dedup.values(),
        key=lambda e: int(e["group"], 16),
    )
    b524_operations["register_constraints"] = sorted(
        _constraint_dedup.values(),
        key=lambda e: (int(e["group"], 16), int(e["register_selector"], 16)),
    )
    artifact["b524_operations"] = b524_operations

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
                    if entry.get("myvaillant_name") is not None:
                        continue
                    register = int(rr_key, 16)
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
