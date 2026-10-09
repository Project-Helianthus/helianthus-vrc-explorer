"""Acquire a bounded fair description schedule while retaining partial evidence."""

from __future__ import annotations

from typing import Any

from ..protocol.b524 import build_constraint_probe_payload
from ..transport.base import TransportInterface, TransportRecoveryExhausted
from ..transport.instrumented import CountingTransport, ScanRequestBudgetExceeded
from .b524_probe import probe_parameter_description
from .description_scheduler import DescriptionCandidate, schedule_descriptions
from .observer import ScanObserver


class _DescriptionAttemptDeferred(RuntimeError):
    """An attempt was withheld so a reserved first attempt can still run."""


class _FairDescriptionAttemptState:
    def __init__(
        self,
        transport: CountingTransport,
        *,
        capacity: int,
        reserved_firsts: dict[int, int],
    ) -> None:
        self.transport = transport
        self.remaining = capacity
        self.pending_reserved_firsts = sum(reserved_firsts.values())

    def for_candidate(self, *, reserved_first: bool) -> TransportInterface:
        return _FairDescriptionCandidateTransport(self, reserved_first=reserved_first)


class _FairDescriptionCandidateTransport(TransportInterface):
    def __init__(
        self,
        state: _FairDescriptionAttemptState,
        *,
        reserved_first: bool,
    ) -> None:
        self._state = state
        self._reserved_first = reserved_first
        self._first_attempt_admitted = False

    def send(self, dst: int, payload: bytes) -> bytes:
        def _admit_attempt() -> None:
            first_attempt = not self._first_attempt_admitted
            if (
                not (first_attempt and self._reserved_first)
                and self._state.remaining <= self._state.pending_reserved_firsts
            ):
                raise _DescriptionAttemptDeferred(
                    "description attempt deferred to preserve reserved first attempts"
                )
            if self._state.remaining <= 0:
                raise _DescriptionAttemptDeferred("description attempt capacity exhausted")
            self._state.remaining -= 1
            if first_attempt:
                self._first_attempt_admitted = True
                if self._reserved_first:
                    self._state.pending_reserved_firsts -= 1

        return self._state.transport.send_with_attempt_hook(dst, payload, _admit_attempt)


def _identity(candidate: DescriptionCandidate) -> tuple[int, int, int, int]:
    return candidate.read_opcode, candidate.group, candidate.instance, candidate.register


def _unavailable_description(
    candidate: DescriptionCandidate,
    *,
    dst: int,
    reason: str,
    attempts: int,
) -> dict[str, Any]:
    selector = {
        "description_opcode": f"0x{candidate.description_opcode:02x}",
        "read_opcode": f"0x{candidate.read_opcode:02x}",
        "group": f"0x{candidate.group:02x}",
        "instance": f"0x{candidate.instance:02x}",
        "register": f"0x{candidate.register:04x}",
    }
    return {
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
        "reason": reason,
        "request_attempted": attempts > 0,
        "request_attempts": attempts,
    }


def _retain_matched_or_store(
    entry: dict[str, Any],
    description: dict[str, Any],
) -> None:
    existing = entry.get("parameter_description")
    if isinstance(existing, dict) and existing.get("qualification") == "matched":
        return
    entry["parameter_description"] = description


def finish_description_coverage(
    candidates: list[DescriptionCandidate],
    entries: dict[tuple[int, int, int, int], dict[str, Any]],
    *,
    budget: int | None,
    coverage: dict[str, Any],
) -> None:
    configured_count = len(schedule_descriptions(candidates, budget=budget).scheduled)
    effective_budget = int(coverage.get("effective_request_budget", configured_count))
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
            "received",
            "interpreted",
            "planned",
            "omitted",
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
                if not (
                    isinstance(description, dict) and description.get("qualification") == "matched"
                ):
                    entry["parameter_description"] = {
                        "qualification": "unavailable",
                        "reason": (
                            "B524 request budget exhausted"
                            if effective_budget < configured_count
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
                if isinstance(description.get("reply_hex"), str):
                    stats["received"] += 1
            else:
                stats["not_attempted"] += 1
                if not (
                    isinstance(description, dict) and description.get("qualification") == "matched"
                ):
                    entry["parameter_description"] = {
                        "qualification": "unavailable",
                        "reason": "scan incomplete before description acquisition",
                        "request_attempted": False,
                    }
        stats["planned"] = stats["scheduled"]
        stats["interpreted"] = stats["matched"]
        stats["omitted"] = stats["eligible"] - stats["attempted"]
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
    budget: int | None,
    coverage: dict[str, Any],
    observer: ScanObserver | None = None,
) -> None:
    configured_schedule = schedule_descriptions(candidates, budget=budget)
    effective_budget = len(configured_schedule.scheduled)
    attempt_capacity: int | None = None
    if isinstance(transport, CountingTransport) and transport.request_budget is not None:
        attempt_capacity = max(0, transport.request_budget - transport.counters.send_calls)
        effective_budget = min(effective_budget, attempt_capacity)
    coverage["effective_request_budget"] = effective_budget
    schedule = schedule_descriptions(candidates, budget=effective_budget)
    attempt_state: _FairDescriptionAttemptState | None = None
    reserved_firsts = {0x02: 0, 0x06: 0}
    if (
        isinstance(transport, CountingTransport)
        and transport.request_budget is not None
        and attempt_capacity is not None
    ):
        reserved_firsts = {
            0x02: min(schedule.family_counts[0x02].scheduled, (effective_budget + 1) // 2),
            0x06: min(schedule.family_counts[0x06].scheduled, effective_budget // 2),
        }
        attempt_state = _FairDescriptionAttemptState(
            transport,
            capacity=attempt_capacity,
            reserved_firsts=reserved_firsts,
        )
    family_positions = {0x02: 0, 0x06: 0}
    attempt_preempted = False
    finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
    progress_total = len(schedule.scheduled)
    if observer is not None and progress_total:
        observer.phase_start("describe", total=progress_total)
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
        candidate_transport: TransportInterface = transport
        if attempt_state is not None:
            family_position = family_positions[candidate.read_opcode]
            candidate_transport = attempt_state.for_candidate(
                reserved_first=family_position < reserved_firsts[candidate.read_opcode]
            )
            family_positions[candidate.read_opcode] += 1
        try:
            metadata = probe_parameter_description(
                candidate_transport,
                dst=dst,
                opcode=candidate.read_opcode,
                group=candidate.group,
                instance=candidate.instance,
                register=candidate.register,
                type_spec=candidate.type_spec,
            )
        except TransportRecoveryExhausted as exc:
            attempts = (
                transport.counters.send_calls - start_attempts
                if isinstance(transport, CountingTransport)
                else exc.request_attempts
            )
            metadata = exc.parameter_description or _unavailable_description(
                candidate, dst=dst, reason=str(exc), attempts=attempts
            )
            metadata.update(request_attempted=attempts > 0, request_attempts=attempts)
            _retain_matched_or_store(entry, metadata)
            finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
            raise
        except _DescriptionAttemptDeferred as exc:
            attempts = (
                transport.counters.send_calls - start_attempts
                if isinstance(transport, CountingTransport)
                else 0
            )
            if attempts > 0:
                _retain_matched_or_store(
                    entry,
                    _unavailable_description(
                        candidate,
                        dst=dst,
                        reason=str(exc),
                        attempts=attempts,
                    ),
                )
            attempt_preempted = True
            continue
        except ScanRequestBudgetExceeded as exc:
            attempts = (
                transport.counters.send_calls - start_attempts
                if isinstance(transport, CountingTransport)
                else 0
            )
            _retain_matched_or_store(
                entry,
                _unavailable_description(
                    candidate,
                    dst=dst,
                    reason="B524 request budget exhausted during description acquisition",
                    attempts=attempts,
                ),
            )
            finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
            raise ScanRequestBudgetExceeded(
                "B524 request budget exhausted during descriptions"
            ) from exc
        except KeyboardInterrupt:
            attempts = (
                transport.counters.send_calls - start_attempts
                if isinstance(transport, CountingTransport)
                else 0
            )
            if attempts > 0:
                _retain_matched_or_store(
                    entry,
                    _unavailable_description(
                        candidate,
                        dst=dst,
                        reason="description acquisition interrupted",
                        attempts=attempts,
                    ),
                )
            finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
            raise
        finally:
            if observer is not None:
                attempts = (
                    transport.counters.send_calls - start_attempts
                    if isinstance(transport, CountingTransport)
                    else 1
                )
                if attempts > 1:
                    progress_total += attempts - 1
                    observer.phase_set_total("describe", total=progress_total)
                if attempts:
                    observer.phase_advance("describe", advance=attempts)
        metadata["request_attempted"] = True
        metadata["request_attempts"] = (
            transport.counters.send_calls - start_attempts
            if isinstance(transport, CountingTransport)
            else 1
        )
        entry["parameter_description"] = metadata
    finish_description_coverage(candidates, entries, budget=budget, coverage=coverage)
    if attempt_preempted or len(schedule.scheduled) < len(configured_schedule.scheduled):
        raise ScanRequestBudgetExceeded("B524 request budget exhausted during descriptions")
    if observer is not None and progress_total:
        observer.phase_finish("describe")
