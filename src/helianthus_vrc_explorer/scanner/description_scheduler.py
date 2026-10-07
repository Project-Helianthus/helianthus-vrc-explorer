"""Pure, bounded scheduling for B524 parameter-description probes.

The scan destination and target profile are fixed by the caller for one scan.
Candidates therefore carry the complete native parameter identity within that
target: read opcode, group, instance, and 16-bit register selector.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass

_DESCRIPTION_FAMILIES = (0x02, 0x06)


@dataclass(frozen=True, slots=True)
class DescriptionCandidate:
    """One description candidate in a fixed destination/profile scan."""

    read_opcode: int
    group: int
    instance: int
    register: int
    type_spec: str | None

    def __post_init__(self) -> None:
        if self.read_opcode not in _DESCRIPTION_FAMILIES:
            raise ValueError("read_opcode must be 0x02 or 0x06")
        if not 0 <= self.group <= 0xFF:
            raise ValueError("group must be an unsigned 8-bit integer")
        if not 0 <= self.instance <= 0xFF:
            raise ValueError("instance must be an unsigned 8-bit integer")
        if not 0 <= self.register <= 0xFFFF:
            raise ValueError("register must be an unsigned 16-bit integer")
        if self.type_spec is not None and not self.type_spec.strip():
            raise ValueError("type_spec must be a non-empty string or None")

    @property
    def native_identity(self) -> tuple[int, int, int, int]:
        return (self.read_opcode, self.group, self.instance, self.register)

    @property
    def description_opcode(self) -> int:
        return 0x01 if self.read_opcode == 0x02 else 0x07


@dataclass(frozen=True, slots=True)
class DescriptionFamilyCounts:
    eligible: int
    scheduled: int
    skipped: int


@dataclass(frozen=True, slots=True)
class DescriptionSchedule:
    """Deterministic schedule plus candidates omitted only by the budget."""

    scheduled: tuple[DescriptionCandidate, ...]
    budget_skipped: tuple[DescriptionCandidate, ...]
    family_counts: dict[int, DescriptionFamilyCounts]


def _deduplicate_candidates(
    candidates: Iterable[DescriptionCandidate],
) -> dict[int, list[DescriptionCandidate]]:
    by_identity: dict[tuple[int, int, int, int], list[DescriptionCandidate]] = defaultdict(list)
    for candidate in candidates:
        if not isinstance(candidate, DescriptionCandidate):
            raise TypeError("candidates must contain DescriptionCandidate values")
        by_identity[candidate.native_identity].append(candidate)

    families: dict[int, list[DescriptionCandidate]] = {
        opcode: [] for opcode in _DESCRIPTION_FAMILIES
    }
    for identity, duplicates in by_identity.items():
        known_codecs = {
            candidate.type_spec.strip().upper()
            for candidate in duplicates
            if candidate.type_spec is not None
        }
        has_unknown_codec = any(candidate.type_spec is None for candidate in duplicates)
        type_spec = (
            next(iter(known_codecs)) if len(known_codecs) == 1 and not has_unknown_codec else None
        )
        read_opcode, group, instance, register = identity
        families[read_opcode].append(
            DescriptionCandidate(read_opcode, group, instance, register, type_spec)
        )
    return families


def _round_robin_namespaces(
    candidates: Iterable[DescriptionCandidate],
) -> list[DescriptionCandidate]:
    buckets: dict[tuple[int, int], deque[DescriptionCandidate]] = defaultdict(deque)
    for candidate in sorted(
        candidates,
        key=lambda item: (item.group, item.instance, item.register, item.type_spec or ""),
    ):
        buckets[(candidate.group, candidate.instance)].append(candidate)

    ordered: list[DescriptionCandidate] = []
    namespace_keys = sorted(buckets)
    while any(buckets.values()):
        for key in namespace_keys:
            if buckets[key]:
                ordered.append(buckets[key].popleft())
    return ordered


def schedule_descriptions(
    candidates: Iterable[DescriptionCandidate],
    budget: int | None = None,
) -> DescriptionSchedule:
    """Build a finite OP01/OP07 schedule with balanced reservations.

    The local description family receives the extra reservation for an odd
    budget. Either family may borrow capacity that the other family cannot use.
    """
    if budget is not None and (
        isinstance(budget, bool) or not isinstance(budget, int) or budget < 0
    ):
        raise ValueError("budget must be a non-negative integer")

    deduplicated = _deduplicate_candidates(candidates)
    ordered = {
        opcode: _round_robin_namespaces(deduplicated[opcode]) for opcode in _DESCRIPTION_FAMILIES
    }
    if budget is None:
        budget = sum(len(family) for family in ordered.values())
    reservations = {0x02: (budget + 1) // 2, 0x06: budget // 2}
    consumed = {
        opcode: min(len(ordered[opcode]), reservations[opcode]) for opcode in _DESCRIPTION_FAMILIES
    }

    capacity = budget - sum(consumed.values())
    for opcode in _DESCRIPTION_FAMILIES:
        if capacity <= 0:
            break
        available = len(ordered[opcode]) - consumed[opcode]
        borrowed = min(available, capacity)
        consumed[opcode] += borrowed
        capacity -= borrowed

    scheduled = tuple(
        candidate
        for opcode in _DESCRIPTION_FAMILIES
        for candidate in ordered[opcode][: consumed[opcode]]
    )
    budget_skipped = tuple(
        candidate
        for opcode in _DESCRIPTION_FAMILIES
        for candidate in ordered[opcode][consumed[opcode] :]
    )
    family_counts = {
        opcode: DescriptionFamilyCounts(
            eligible=len(ordered[opcode]),
            scheduled=consumed[opcode],
            skipped=len(ordered[opcode]) - consumed[opcode],
        )
        for opcode in _DESCRIPTION_FAMILIES
    }
    return DescriptionSchedule(
        scheduled=scheduled,
        budget_skipped=budget_skipped,
        family_counts=family_counts,
    )
