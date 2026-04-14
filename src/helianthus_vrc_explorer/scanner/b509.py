from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, Protocol, TypedDict

from ..protocol.b509 import build_b509_register_read_payload
from ..protocol.parser import ValueParseError, parse_typed_value
from ..schema.ebusd_csv import EbusdCsvSchema
from ..transport.base import TransportCommandNotEnabled, TransportError, TransportTimeout
from .observer import ScanObserver
from .plan import parse_int_token


class _B509Transport(Protocol):
    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes: ...


class B509RegisterEntry(TypedDict):
    addr: str
    op: str
    reply_hex: str | None
    raw_hex: str | None
    type: str | None
    value: object | None
    error: str | None
    ebusd_name: str | None
    myvaillant_name: str | None


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _emit_trace_label(transport: _B509Transport, label: str) -> None:
    trace_fn = getattr(transport, "trace_label", None)
    if callable(trace_fn):
        trace_fn(label)


def _parse_b509_value(type_hint: str, response: bytes) -> tuple[object | None, str | None]:
    """Decode a B509 value using the schema type hint.

    Some B509 replies carry a leading status byte. We first try decoding the whole payload,
    then (if applicable) decoding without the first status-like byte.
    """

    decode_candidates: list[bytes] = [response]
    if len(response) > 1 and response[0] in {0x00, 0x01, 0x02, 0x03}:
        decode_candidates.append(response[1:])

    first_error: ValueParseError | None = None
    for candidate in decode_candidates:
        try:
            return parse_typed_value(type_hint, candidate), None
        except ValueParseError as exc:
            if first_error is None:
                first_error = exc

    assert first_error is not None
    return None, f"parse_error: {first_error}"


def parse_b509_range(spec: str) -> tuple[int, int]:
    raw = spec.strip()
    if not raw:
        raise ValueError("empty range")
    if ".." not in raw:
        raise ValueError("range must use '..' (example: 0x2700..0x27FF)")
    start_s, end_s = raw.split("..", 1)
    start = parse_int_token(start_s)
    end = parse_int_token(end_s)
    if not (0x0000 <= start <= 0xFFFF):
        raise ValueError(f"range start out of bounds: {start_s!r}")
    if not (0x0000 <= end <= 0xFFFF):
        raise ValueError(f"range end out of bounds: {end_s!r}")
    if start > end:
        start, end = end, start
    # VE16-R2: Cap maximum range to prevent accidental full-address-space scans.
    span = end - start + 1
    if span > 4096:
        raise ValueError(f"B509 range too large: {span} addresses (max 4096)")
    return start, end


def merge_b509_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []
    ordered = sorted(ranges, key=lambda r: (r[0], r[1]))
    merged: list[tuple[int, int]] = []
    cur_start, cur_end = ordered[0]
    for start, end in ordered[1:]:
        if start <= cur_end + 1:
            cur_end = max(cur_end, end)
            continue
        merged.append((cur_start, cur_end))
        cur_start, cur_end = start, end
    merged.append((cur_start, cur_end))
    return merged


def scan_b509(
    transport: _B509Transport,
    *,
    dst: int,
    ranges: list[tuple[int, int]],
    ebusd_schema: EbusdCsvSchema | None = None,
    observer: ScanObserver | None = None,
) -> dict[str, Any]:
    start_perf = time.perf_counter()
    read_count = 0
    error_count = 0
    incomplete = False
    incomplete_reason: str | None = None

    merged_ranges = merge_b509_ranges(ranges)
    total_reads = sum((end - start + 1) for start, end in merged_ranges)
    artifact: dict[str, Any] = {
        "meta": {
            "scan_timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_duration_seconds": 0.0,
            "ranges": [f"{_hex_u16(start)}..{_hex_u16(end)}" for start, end in merged_ranges],
            "read_count": 0,
            "error_count": 0,
            "incomplete": False,
        },
        "devices": {f"0x{dst:02x}": {"registers": {}}},
    }

    registers = artifact["devices"][f"0x{dst:02x}"]["registers"]

    try:
        if observer is not None:
            observer.phase_start("b509_dump", total=total_reads or 1)
        _emit_trace_label(transport, "B509 Register Dump")

        for start, end in merged_ranges:
            _emit_trace_label(transport, f"B509 range {_hex_u16(start)}..{_hex_u16(end)}")
            for register in range(start, end + 1):
                if observer is not None:
                    observer.status(f"B509 read RR={_hex_u16(register)}")
                    observer.phase_advance("b509_dump", advance=1)

                reply_hex: str | None = None
                raw_hex: str | None = None
                value: object | None = None
                value_type: str | None = None
                error: str | None = None
                ebusd_name: str | None = None
                myvaillant_name: str | None = None

                payload = build_b509_register_read_payload(register)
                try:
                    response = transport.send_proto(dst, 0xB5, 0x09, payload)
                    reply_hex = response.hex()
                    raw_hex = reply_hex

                    schema_entry = (
                        ebusd_schema.lookup_b509(register=register)
                        if ebusd_schema is not None
                        else None
                    )
                    if schema_entry is not None:
                        ebusd_name = schema_entry.name
                        if schema_entry.type_spec:
                            value_type = schema_entry.type_spec
                            value, error = _parse_b509_value(value_type, response)
                except TransportTimeout:
                    error = "timeout"
                except TransportError as exc:
                    if isinstance(exc, TransportCommandNotEnabled):
                        raise
                    error = f"transport_error: {exc}"

                read_count += 1
                if error is not None:
                    error_count += 1

                registers[_hex_u16(register)] = B509RegisterEntry(
                    addr=_hex_u16(register),
                    op="0x09",
                    reply_hex=reply_hex,
                    raw_hex=raw_hex,
                    type=value_type,
                    value=value,
                    error=error,
                    ebusd_name=ebusd_name,
                    myvaillant_name=myvaillant_name,
                )

    except KeyboardInterrupt:
        incomplete = True
        incomplete_reason = "user_interrupt"
    finally:
        if observer is not None:
            observer.phase_finish("b509_dump")

    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    artifact["meta"]["read_count"] = read_count
    artifact["meta"]["error_count"] = error_count
    artifact["meta"]["incomplete"] = incomplete
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason
    return artifact
