"""Typed final planner selection shared by both interactive planner surfaces."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from ..scanner.plan import GroupScanPlan, PlanKey

type DescriptionSource = Literal["profile", "live"]
type DescriptionClass = Literal["local", "remote"]
type PlannerPresetName = Literal["recommended", "full", "research", "custom"]


@dataclass(frozen=True, slots=True)
class DescriptionPolicySelection:
    """Description source selected independently for local and remote classes."""

    local: DescriptionSource
    remote: DescriptionSource
    local_override: bool = False
    remote_override: bool = False

    def for_opcode(self, opcode: int) -> DescriptionSource:
        return self.remote if opcode == 0x06 else self.local

    def overridden_for_opcode(self, opcode: int) -> bool:
        return self.remote_override if opcode == 0x06 else self.local_override

    def with_override(
        self, device_class: DescriptionClass, source: DescriptionSource
    ) -> DescriptionPolicySelection:
        if device_class == "local":
            return DescriptionPolicySelection(
                local=source,
                remote=self.remote,
                local_override=True,
                remote_override=self.remote_override,
            )
        return DescriptionPolicySelection(
            local=self.local,
            remote=source,
            local_override=self.local_override,
            remote_override=True,
        )


def default_description_policy(
    preset: PlannerPresetName, *, exact_profile_known: bool
) -> DescriptionPolicySelection:
    """Return the accepted preset policy without imposing a request-count cap."""

    source: DescriptionSource = (
        "live" if preset in {"full", "research"} or not exact_profile_known else "profile"
    )
    return DescriptionPolicySelection(local=source, remote=source)


def description_probe_required(policy: DescriptionPolicySelection, *, opcode: int) -> bool:
    """Return whether a writable row needs a live Describe request."""

    return policy.for_opcode(opcode) == "live"


@dataclass(frozen=True, slots=True, eq=False)
class PlannerSelection(Mapping[PlanKey, GroupScanPlan]):
    """One complete planner result, while remaining mapping-compatible for callers."""

    plan: dict[PlanKey, GroupScanPlan]
    selected_preset: PlannerPresetName
    operation_requests: tuple[object, ...]
    operation_selection: tuple[bool, ...]
    description_policy: DescriptionPolicySelection

    def __getitem__(self, key: PlanKey) -> GroupScanPlan:
        return self.plan[key]

    def __iter__(self) -> Iterator[PlanKey]:
        return iter(self.plan)

    def __len__(self) -> int:
        return len(self.plan)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PlannerSelection):
            return (
                self.plan == other.plan
                and self.selected_preset == other.selected_preset
                and self.operation_requests == other.operation_requests
                and self.operation_selection == other.operation_selection
                and self.description_policy == other.description_policy
            )
        if isinstance(other, Mapping):
            return self.plan == dict(other)
        return False


def make_planner_selection(
    plan: Mapping[PlanKey, GroupScanPlan],
    *,
    selected_preset: PlannerPresetName,
    operation_requests: Sequence[object] = (),
    operation_selection: Sequence[bool] = (),
    description_policy: DescriptionPolicySelection,
) -> PlannerSelection:
    if len(operation_requests) != len(operation_selection):
        raise ValueError("operation_selection must match operation_requests")
    return PlannerSelection(
        plan=dict(plan),
        selected_preset=selected_preset,
        operation_requests=tuple(operation_requests),
        operation_selection=tuple(operation_selection),
        description_policy=description_policy,
    )
