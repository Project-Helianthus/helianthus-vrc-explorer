from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any, Protocol

from ..protocol.b516 import (
    B516Date,
    B516Response,
    build_b516_system_payload,
    build_b516_year_payload,
    parse_b516_response,
)
from ..transport.base import TransportCommandNotEnabled, TransportError, TransportTimeout
from .observer import ScanObserver

_B516_PRIMARY = 0xB5
_B516_SECONDARY = 0x16

# Observed Vaillant energy-type (source) and operation-mode (usage) codes.
_SOURCE_CODES: dict[str, int] = {"gas": 0x4, "electricity": 0x3}
_USAGE_CODES: dict[str, int] = {"heating": 0x3, "hot_water": 0x4}
_SOURCE_TITLES: dict[str, str] = {"gas": "Gas", "electricity": "Electricity"}
_USAGE_TITLES: dict[str, str] = {"heating": "Heating", "hot_water": "Hot Water"}

#: Default clock used to derive the "host clock" fallback reference year.
Clock = Callable[[], date]


def _default_clock() -> date:
    # Local calendar date: the fallback stands in for the regulator's own
    # date, which follows local time rather than UTC.
    return datetime.now(UTC).astimezone().date()


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
    year: int | None = None


def _system_selectors() -> tuple[B516SelectorSpec, ...]:
    specs: list[B516SelectorSpec] = []
    for source_key in ("gas", "electricity"):
        for usage_key in ("heating", "hot_water"):
            specs.append(
                B516SelectorSpec(
                    key=f"system.{source_key}.{usage_key}",
                    label=f"System {_SOURCE_TITLES[source_key]} {_USAGE_TITLES[usage_key]}",
                    period="system",
                    source=source_key,
                    usage=usage_key,
                    payload=build_b516_system_payload(
                        source=_SOURCE_CODES[source_key], usage=_USAGE_CODES[usage_key]
                    ),
                )
            )
    return tuple(specs)


#: The four total (time base 0) selectors. These are static: the date field
#: is ignored for totals, so the request payload never depends on the
#: scan-time reference year.
DEFAULT_B516_SELECTORS: tuple[B516SelectorSpec, ...] = _system_selectors()


def _year_selectors(reference_year: int) -> tuple[B516SelectorSpec, ...]:
    """Build the yearly selectors for a real reference year.

    "Current year" uses `reference_year`; "previous year" uses
    `reference_year - 1`. Built at scan time (rather than once at import
    time) so the request always carries the real calendar year.
    """
    specs: list[B516SelectorSpec] = []
    for period_key, label_prefix, year in (
        ("year_current", "Current Year", reference_year),
        ("year_previous", "Previous Year", reference_year - 1),
    ):
        entry_key_period = "current" if period_key == "year_current" else "previous"
        for source_key in ("gas", "electricity"):
            for usage_key in ("heating", "hot_water"):
                specs.append(
                    B516SelectorSpec(
                        key=f"year.{entry_key_period}.{source_key}.{usage_key}",
                        label=(
                            f"{label_prefix} {_SOURCE_TITLES[source_key]} "
                            f"{_USAGE_TITLES[usage_key]}"
                        ),
                        period=period_key,
                        source=source_key,
                        usage=usage_key,
                        payload=build_b516_year_payload(
                            source=_SOURCE_CODES[source_key],
                            usage=_USAGE_CODES[usage_key],
                            year=year,
                        ),
                        year=year,
                    )
                )
    return tuple(specs)


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
        "year": spec.year,
        # The date field is ignored by the device for total requests, so
        # only yearly entries carry a request_date (set by the caller).
        "request_date": None,
        "request_hex": spec.payload.hex(),
        "reply_hex": response.hex() if response is not None else None,
        "error": error,
    }
    if parsed is None:
        entry["status"] = None
        entry["return_code"] = None
        entry["reply_date"] = None
        entry["value_wh"] = None
        entry["value_kwh"] = None
        return entry
    entry.update(
        {
            "echo_period": f"0x{parsed.time_base:01x}",
            "echo_source": f"0x{parsed.source:01x}",
            "echo_usage": f"0x{parsed.usage:01x}",
            "return_code": f"0x{parsed.return_code:01x}",
            "status": "ok" if parsed.ok else "not_ok",
            "reply_date": parsed.date.as_dict(),
            # A non-zero return code is a valid device answer meaning "no
            # value", never a transport error -- the value fields stay
            # null rather than surfacing the raw (misleading) zero bytes.
            "value_wh": parsed.value_wh,
            "value_kwh": parsed.value_kwh,
        }
    )
    return entry


def _read_selector(
    transport: _B516Transport,
    spec: B516SelectorSpec,
    *,
    dst: int,
) -> tuple[bytes | None, B516Response | None, str | None]:
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
    except Exception as exc:  # noqa: BLE001 - surfaced as a decoded entry error
        error = f"parse_error: {exc}"
    return response, parsed, error


def _reference_date_from_totals(
    total_results: list[tuple[B516SelectorSpec, B516Response | None]],
) -> B516Date | None:
    """Pick the first plausible echoed date among the total replies."""
    for _spec, parsed in total_results:
        if parsed is not None and parsed.date.plausible:
            return parsed.date
    return None


def scan_b516(
    transport: _B516Transport,
    *,
    dst: int,
    observer: ScanObserver | None = None,
    clock: Clock = _default_clock,
) -> dict[str, Any]:
    start_perf = time.perf_counter()
    read_count = 0
    error_count = 0
    incomplete = False
    incomplete_reason: str | None = None

    system_selectors = DEFAULT_B516_SELECTORS
    selector_count = len(system_selectors) + 8  # 4 totals + 8 yearly (2 periods x 4 combos)

    artifact: dict[str, Any] = {
        "meta": {
            "scan_timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "scan_duration_seconds": 0.0,
            "destination_address": f"0x{dst:02x}",
            "read_count": 0,
            "error_count": 0,
            "selector_count": selector_count,
            "incomplete": False,
        },
        "entries": {},
    }
    entries = artifact["entries"]

    try:
        if observer is not None:
            observer.phase_start("b516_dump", total=selector_count or 1)
        _emit_trace_label(transport, "B516 Energy Dump")

        total_results: list[tuple[B516SelectorSpec, B516Response | None]] = []
        for spec in system_selectors:
            if observer is not None:
                observer.status(f"B516 {spec.label}")
            response, parsed, error = _read_selector(transport, spec, dst=dst)
            total_results.append((spec, parsed))

            read_count += 1
            if error is not None:
                error_count += 1

            entries[spec.key] = _entry_from_result(
                spec, response=response, parsed=parsed, error=error
            )
            if observer is not None:
                observer.phase_advance("b516_dump", advance=1)

        reference_date = _reference_date_from_totals(total_results)
        if reference_date is not None:
            reference_year = reference_date.year
            reference_source = "regulator_echo"
        else:
            host_today = clock()
            reference_year = host_today.year
            reference_source = "host_clock"
            reference_date = B516Date(
                day=host_today.day, month=host_today.month, year=host_today.year
            )

        artifact["meta"]["reference_date"] = reference_date.as_dict()
        artifact["meta"]["reference_date_source"] = reference_source

        for spec in _year_selectors(reference_year):
            if observer is not None:
                observer.status(f"B516 {spec.label}")
            response, parsed, error = _read_selector(transport, spec, dst=dst)

            read_count += 1
            if error is not None:
                error_count += 1

            entry = _entry_from_result(spec, response=response, parsed=parsed, error=error)
            entry["request_date"] = {"day": 0, "month": 0, "year": spec.year}
            entries[spec.key] = entry
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
