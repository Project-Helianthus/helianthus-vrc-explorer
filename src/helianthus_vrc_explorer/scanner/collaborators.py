"""Typed collaborators injected into the B524 scan run.

The scanner never imports a user interface. Interactive planners are supplied by
the caller (the command layer) as a ``ScanPlanners`` bundle.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Protocol

from rich.console import Console

from ..protocol.b524 import RegisterOpcode
from ..transport.base import TransportInterface
from .director import DiscoveredGroup
from .observer import ScanObserver
from .plan import GroupScanPlan, PlanKey
from .planner_model import PlannerGroup, PlannerPreset
from .planner_selection import DescriptionPolicySelection
from .register import InstanceAvailabilityProbe


class GroupDiscovery(Protocol):
    """Bounded system-information discovery of the regulator's groups."""

    def __call__(
        self,
        transport: TransportInterface,
        /,
        *,
        dst: int,
        observer: ScanObserver | None,
    ) -> list[DiscoveredGroup]: ...


class InstanceAvailabilityProber(Protocol):
    """Probe one instance slot and retain the evidence used for presence."""

    def __call__(
        self,
        transport: TransportInterface,
        /,
        *,
        dst: int,
        group: int,
        instance: int,
        opcode: RegisterOpcode | None = ...,
        presence_profile: str | None = ...,
    ) -> InstanceAvailabilityProbe: ...


class PlannerHotkeys(Protocol):
    """Active hotkey reader polled between register reads."""

    def poll(self) -> bool: ...

    def suspend(self) -> AbstractContextManager[object]: ...


class PlannerHotkeyReaderFactory(Protocol):
    """Create the replanning hotkey reader for one register scan."""

    def __call__(self, *, enabled: bool) -> AbstractContextManager[PlannerHotkeys]: ...


class ClassicScanPlanner(Protocol):
    """Prompt-based planner; returns the selected plan or a ``PlannerSelection``."""

    def __call__(
        self,
        console: Console,
        groups: list[PlannerGroup],
        /,
        *,
        request_rate_rps: float | None,
        default_plan: dict[PlanKey, GroupScanPlan] | None = ...,
        default_preset: PlannerPreset = ...,
        system_information: Sequence[Mapping[str, object]] | None = ...,
        operation_requests: Sequence[object] | None = ...,
        operation_selection: list[bool] | None = ...,
        description_policy: DescriptionPolicySelection | None = ...,
        description_profile_status: str = ...,
    ) -> Mapping[PlanKey, GroupScanPlan]: ...


class TextualScanPlanner(Protocol):
    """Full-screen planner; returns ``None`` when the operator cancels."""

    def __call__(
        self,
        groups: list[PlannerGroup],
        /,
        *,
        request_rate_rps: float | None,
        default_plan: dict[PlanKey, GroupScanPlan] | None = ...,
        default_preset: PlannerPreset = ...,
        system_information: Sequence[Mapping[str, object]] | None = ...,
        operation_requests: Sequence[object] | None = ...,
        operation_selection: list[bool] | None = ...,
        description_policy: DescriptionPolicySelection | None = ...,
        description_profile_status: str = ...,
    ) -> Mapping[PlanKey, GroupScanPlan] | None: ...


class TextualScanPlannerLoader(Protocol):
    """Load the full-screen planner; raising selects the classic fallback."""

    def __call__(self) -> TextualScanPlanner: ...


@dataclass(frozen=True, slots=True)
class ScanPlanners:
    """Interactive planner surfaces offered to the scan run by its caller."""

    prompt_scan_plan: ClassicScanPlanner
    load_textual_scan_plan: TextualScanPlannerLoader
