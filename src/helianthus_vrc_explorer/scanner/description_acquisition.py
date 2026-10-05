"""Acquire a bounded fair description schedule while retaining partial evidence."""

from __future__ import annotations

from typing import Any

from ..protocol.b524 import build_constraint_probe_payload
from ..transport.base import TransportInterface
from ..transport.instrumented import CountingTransport, ScanRequestBudgetExceeded
from .b524_probe import probe_parameter_description
from .description_scheduler import DescriptionCandidate, schedule_descriptions
from .observer import ScanObserver


def _identity(candidate: DescriptionCandidate) -> tuple[int, int, int, int]:
    return candidate.read_opcode, candidate.group, candidate.instance, candidate.register


def finish_description_coverage(
    candidates: list[DescriptionCandidate],
    entries: dict[tuple[int, int, int, int], dict[str, Any]],
    *,
    budget: int,
    coverage: dict[str, Any],
) -> None:
    effective_budget = int(coverage.get("effective_request_budget", budget))
    schedule = schedule_descriptions(candidates, budget=effective_budget)
    skipped = {_identity(candidate) for candidate in schedule.budget_skipped}
    totals = {
        key: 0
        for key in (
            "eligible",
            "scheduled",
            "attempted",
            "matched",
            "unavailable",
            "unqualified",
            "budget_skipped",
            "not_attempted",
            "request_attempts",
            "retries",
        )
    }
    families: dict[str, dict[str, int]] = {}
    for opcode, counts in schedule.family_counts.items():
        stats = {key: 0 for key in totals}
        stats.update(
            eligible=counts.eligible, scheduled=counts.scheduled, budget_skipped=counts.skipped
        )
        for identity, entry in entries.items():
            if identity[0] != opcode:
                continue
            description = entry.get("parameter_description")
            if identity in skipped:
                entry["parameter_description"] = {
                    "qualification": "unavailable",
                    "reason": (
                        "B524 request budget exhausted"
                        if effective_budget < budget
                        else "description request budget exhausted"
                    ),
                    "request_attempted": False,
                }
            elif isinstance(description, dict) and description.get("request_attempted") is True:
                stats["attempted"] += 1
                attempts = int(description.get("request_attempts", 1))
                stats["request_attempts"] += attempts
                stats["retries"] += max(0, attempts - 1)
                qualification = description.get("qualification")
                stats[
                    qualification if qualification in {"matched", "unqualified"} else "unavailable"
                ] += 1
            else:
                stats["not_attempted"] += 1
                entry["parameter_description"] = {
                    "qualification": "unavailable",
                    "reason": "scan incomplete before description acquisition",
                    "request_attempted": False,
                }
        families[f"0x{opcode:02x}"] = stats
        for key in totals:
            totals[key] += stats[key]
    coverage.clear()
    coverage.update(totals)
    coverage.update(
        request_budget=budget,
        effective_request_budget=effective_budget,
        by_read_operation=families,
    )


def acquire_descriptions(
    transport: TransportInterface,
    *,
    dst: int,
    candidates: list[DescriptionCandidate],
    entries: dict[tuple[int, int, int, int], dict[str, Any]],
    budget: int,
    coverage: dict[str, Any],
    observer: ScanObserver | None = None,
) -> None:
    configured_schedule = schedule_descriptions(candidates, budget=budget)
    effective_budget = budget
    if isinstance(transport, CountingTransport) and transport.request_budget is not None:
        effective_budget = min(
            budget, max(0, transport.request_budget - transport.counters.send_calls)
        )
    coverage["effective_request_budget"] = effective_budget
    schedule = schedule_descriptions(candidates, budget=effective_budget)
    finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
    for candidate in schedule.scheduled:
        if observer is not None:
            observer.status(
                f"Describe OP=0x{candidate.read_opcode:02X} GG=0x{candidate.group:02X} "
                f"II=0x{candidate.instance:02X} RR=0x{candidate.register:04X}"
            )
        entry = entries[_identity(candidate)]
        start_attempts = (
            transport.counters.send_calls if isinstance(transport, CountingTransport) else 0
        )
        try:
            metadata = probe_parameter_description(
                transport,
                dst=dst,
                opcode=candidate.read_opcode,
                group=candidate.group,
                instance=candidate.instance,
                register=candidate.register,
                type_spec=candidate.type_spec,
            )
        except ScanRequestBudgetExceeded:
            selector = {
                "description_opcode": f"0x{candidate.description_opcode:02x}",
                "read_opcode": f"0x{candidate.read_opcode:02x}",
                "group": f"0x{candidate.group:02x}",
                "instance": f"0x{candidate.instance:02x}",
                "register": f"0x{candidate.register:04x}",
            }
            attempts = (
                transport.counters.send_calls - start_attempts
                if isinstance(transport, CountingTransport)
                else 0
            )
            entry["parameter_description"] = {
                **selector,
                "selector": selector,
                "destination_address": f"0x{dst:02x}",
                "profile": "controller_b524",
                "request_hex": build_constraint_probe_payload(
                    candidate.group,
                    candidate.register,
                    instance=candidate.instance,
                    opcode=candidate.description_opcode,
                ).hex(),
                "qualification": "unavailable",
                "reason": "B524 request budget exhausted during description acquisition",
                "request_attempted": attempts > 0,
                "request_attempts": attempts,
            }
            finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
            raise
        metadata["request_attempted"] = True
        metadata["request_attempts"] = (
            transport.counters.send_calls - start_attempts
            if isinstance(transport, CountingTransport)
            else 1
        )
        entry["parameter_description"] = metadata
    finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
    if len(schedule.scheduled) < len(configured_schedule.scheduled):
        raise ScanRequestBudgetExceeded("B524 request budget exhausted during descriptions")
