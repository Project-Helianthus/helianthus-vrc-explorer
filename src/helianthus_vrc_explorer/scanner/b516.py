from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from ..protocol.b516 import (
    B516Response,
    build_b516_system_payload,
    build_b516_year_payload,
    parse_b516_response,
)
from ..transport.base import TransportCommandNotEnabled, TransportError, TransportTimeout
from .observer import ScanObserver

_B516_PRIMARY = 0xB5
_B516_SECONDARY = 0x16


class _B516Transport(Protocol):
    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes: ...


@dataclass(frozen=True, slots=True)
class B516SelectorSpec:
    key: str
    label: str
    period: str
    source: str
    usage: str
    payload: bytes


DEFAULT_B516_SELECTORS: tuple[B516SelectorSpec, ...] = (
    B516SelectorSpec(
        "system.gas.heating",
        "System Gas Heating",
        "system",
        "gas",
        "heating",
        build_b516_system_payload(source=0x4, usage=0x3),
    ),
    B516SelectorSpec(
        "system.gas.hot_water",
        "System Gas Hot Water",
        "system",
        "gas",
        "hot_water",
        build_b516_system_payload(source=0x4, usage=0x4),
    ),
    B516SelectorSpec(
        "system.electricity.heating",
        "System Electricity Heating",
        "system",
        "electricity",
        "heating",
        build_b516_system_payload(source=0x3, usage=0x3),
    ),
    B516SelectorSpec(
        "system.electricity.hot_water",
        "System Electricity Hot Water",
        "system",
        "electricity",
        "hot_water",
        build_b516_system_payload(source=0x3, usage=0x4),
    ),
    B516SelectorSpec(
        "year.current.gas.heating",
        "Current Year Gas Heating",
        "year_current",
        "gas",
        "heating",
        build_b516_year_payload(source=0x4, usage=0x3, current=True),
    ),
    B516SelectorSpec(
        "year.current.gas.hot_water",
        "Current Year Gas Hot Water",
        "year_current",
        "gas",
        "hot_water",
        build_b516_year_payload(source=0x4, usage=0x4, current=True),
    ),
    B516SelectorSpec(
        "year.current.electricity.heating",
        "Current Year Electricity Heating",
        "year_current",
        "electricity",
        "heating",
        build_b516_year_payload(source=0x3, usage=0x3, current=True),
    ),
    B516SelectorSpec(
        "year.current.electricity.hot_water",
        "Current Year Electricity Hot Water",
        "year_current",
        "electricity",
        "hot_water",
        build_b516_year_payload(source=0x3, usage=0x4, current=True),
    ),
    B516SelectorSpec(
        "year.previous.gas.heating",
        "Previous Year Gas Heating",
        "year_previous",
        "gas",
        "heating",
        build_b516_year_payload(source=0x4, usage=0x3, current=False),
    ),
    B516SelectorSpec(
        "year.previous.gas.hot_water",
        "Previous Year Gas Hot Water",
        "year_previous",
        "gas",
        "hot_water",
        build_b516_year_payload(source=0x4, usage=0x4, current=False),
    ),
    B516SelectorSpec(
        "year.previous.electricity.heating",
        "Previous Year Electricity Heating",
        "year_previous",
        "electricity",
        "heating",
        build_b516_year_payload(source=0x3, usage=0x3, current=False),
    ),
    B516SelectorSpec(
        "year.previous.electricity.hot_water",
        "Previous Year Electricity Hot Water",
        "year_previous",
        "electricity",
        "hot_water",
        build_b516_year_payload(source=0x3, usage=0x4, current=False),
    ),
)


def _emit_trace_label(transport: _B516Transport, label: str) -> None:
    trace_fn = getattr(transport, "trace_label", None)
    if callable(trace_fn):
        trace_fn(label)


def _entry_from_result(
    spec: B516SelectorSpec,
    *,
    response: bytes | None,
    parsed: B516Response | None,
    error: str | None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "label": spec.label,
        "period": spec.period,
        "source": spec.source,
        "usage": spec.usage,
        "request_hex": spec.payload.hex(),
        "reply_hex": response.hex() if response is not None else None,
        "error": error,
    }
    if parsed is None:
        return entry
    entry.update(
        {
            "echo_period": f"0x{parsed.period:01x}",
            "echo_source": f"0x{parsed.source:01x}",
            "echo_usage": f"0x{parsed.usage:01x}",
            "echo_window": f"0x{parsed.packed_window:02x}",
            "echo_qualifier": f"0x{parsed.qualifier:01x}",
            "value_wh": parsed.value_wh,
            "value_kwh": parsed.value_kwh,
        }
    )
    return entry


def scan_b516(
    transport: _B516Transport,
    *,
    dst: int,
    observer: ScanObserver | None = None,
) -> dict[str, Any]:
    start_perf = time.perf_counter()
    read_count = 0
    error_count = 0
    incomplete = False
    incomplete_reason: str | None = None

    artifact: dict[str, Any] = {
        "meta": {
            "scan_timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_duration_seconds": 0.0,
            "destination_address": f"0x{dst:02x}",
            "read_count": 0,
            "error_count": 0,
            "selector_count": len(DEFAULT_B516_SELECTORS),
            "incomplete": False,
        },
        "entries": {},
    }
    entries = artifact["entries"]

    try:
        if observer is not None:
            observer.phase_start("b516_dump", total=len(DEFAULT_B516_SELECTORS) or 1)
        _emit_trace_label(transport, "B516 Energy Dump")

        for spec in DEFAULT_B516_SELECTORS:
            if observer is not None:
                observer.status(f"B516 {spec.label}")
            response: bytes | None = None
            parsed: B516Response | None = None
            error: str | None = None
            try:
                response = transport.send_proto(dst, _B516_PRIMARY, _B516_SECONDARY, spec.payload)
                parsed = parse_b516_response(response)
            except TransportTimeout:
                error = "timeout"
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                error = f"transport_error: {exc}"
            except Exception as exc:
                error = f"parse_error: {exc}"

            read_count += 1
            if error is not None:
                error_count += 1

            entries[spec.key] = _entry_from_result(
                spec,
                response=response,
                parsed=parsed,
                error=error,
            )
            if observer is not None:
                observer.phase_advance("b516_dump", advance=1)

    except KeyboardInterrupt:
        incomplete = True
        incomplete_reason = "user_interrupt"
    finally:
        if observer is not None:
            observer.phase_finish("b516_dump")

    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    artifact["meta"]["read_count"] = read_count
    artifact["meta"]["error_count"] = error_count
    artifact["meta"]["incomplete"] = incomplete
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason
    return artifact
