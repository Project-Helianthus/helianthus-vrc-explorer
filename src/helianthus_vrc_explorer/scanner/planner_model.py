"""Planner group model and preset plan construction shared by scanner and planners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ..protocol.b524 import RegisterOpcode
from .plan import GroupScanPlan, PlanKey, make_plan_key
from .scan_policy import profile_opcodes, research_rr_max


@dataclass(frozen=True, slots=True)
class PlannerGroup:
    group: int
    opcode: RegisterOpcode
    name: str
    descriptor: float
    known: bool
    ii_max: int | None
    rr_max: int | None
    rr_max_full: int | None
    present_instances: tuple[int, ...]
    namespace_label: str | None = None
    recommended: bool = True
    expected_count: int | None = None
    ii_min: int | None = None
    instances_probed: bool = True
    research_rr_max: int | None = None
    native_dhw_admitted: bool = False

    @property
    def key(self) -> PlanKey:
        return make_plan_key(self.group, self.opcode)

    @property
    def display_name(self) -> str:
        if self.namespace_label is None:
            return self.name
        if self.name.lower().endswith(f"({self.namespace_label.lower()})"):
            return self.name
        return f"{self.name} ({self.namespace_label})"

    @property
    def prompt_label(self) -> str:
        if self.namespace_label is None:
            return _hex_u8(self.group)
        return f"{_hex_u8(self.group)} ({self.namespace_label})"


PlannerPreset = Literal[
    "recommended",
    "full",
    "research",
    "custom",
]


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _namespace_opcode_rank(opcode: int) -> tuple[int, int]:
    if opcode == 0x02:
        return (0, opcode)
    if opcode == 0x06:
        return (1, opcode)
    return (2, opcode)


def planner_group_sort_key(group: PlannerGroup) -> tuple[int, int, int]:
    return (*_namespace_opcode_rank(group.opcode), group.group)


def planner_instance_bounds(group: PlannerGroup) -> tuple[int, int]:
    """Return the configured inclusive II bounds shown by planner surfaces."""
    if group.opcode == 0x06:
        ii_min = group.ii_min if group.ii_min is not None else 0x01
        ii_max = min(group.ii_max if group.ii_max is not None else 0x08, 0x08)
    elif group.opcode == 0x02 and group.group == 0x02:
        ii_min = group.ii_min if group.ii_min is not None else 0x01
        ii_max = min(group.ii_max if group.ii_max is not None else 0x09, 0x09)
    elif group.ii_max is None:
        return (0x00, 0x00)
    else:
        ii_min = group.ii_min if group.ii_min is not None else 0x00
        ii_max = group.ii_max
    if ii_min > ii_max:
        raise ValueError(
            f"Invalid II bounds for GG=0x{group.group:02X}/OP=0x{group.opcode:02X}: "
            f"0x{ii_min:02X}..0x{ii_max:02X}"
        )
    return (ii_min, ii_max)


def planner_instance_range(group: PlannerGroup) -> tuple[int, ...]:
    ii_min, ii_max = planner_instance_bounds(group)
    result = tuple(range(ii_min, ii_max + 1))
    if group.opcode == 0x06 or (group.opcode == 0x02 and group.group == 0x02):
        return result
    return result + ((0xFF,) if 0xFF in group.present_instances else ())


def planner_present_instances(group: PlannerGroup) -> tuple[int, ...]:
    allowed = set(planner_instance_range(group))
    return tuple(ii for ii in group.present_instances if ii in allowed)


def _instances_for_preset(group: PlannerGroup, preset: PlannerPreset) -> tuple[int, ...]:
    if group.ii_max is None and group.opcode != 6 and not (group.opcode == 2 and group.group == 2):
        return (0x00,)
    if preset == "recommended":
        return planner_present_instances(group)
    return planner_instance_range(group)


def _has_recommended_availability(group: PlannerGroup) -> bool:
    """Return whether an admitted group has affirmative default-scan evidence.

    The profile policy remains the static admission rule.  OP00 counts guide
    discovery only: a count cannot admit a family without a confirmed instance,
    and a confirmed instance remains usable when it contradicts a zero count.
    System is the mandatory OP=0x02/GG=0x00 singleton.  Native DHW has a
    dedicated, correlated gate; other singleton rows are not admitted by
    static inventory alone.  All other rows require a confirmed present
    instance, so unknown or unprobed results stay manually selectable only.
    """

    if group.opcode == 0x02 and group.group == 0x00:
        return True
    if group.opcode == 0x02 and group.group == 0x01:
        return group.native_dhw_admitted
    if group.ii_max is None:
        return False
    return bool(planner_present_instances(group))


def build_plan_from_preset(
    groups: list[PlannerGroup],
    *,
    preset: PlannerPreset,
) -> dict[PlanKey, GroupScanPlan]:
    selected: dict[PlanKey, GroupScanPlan] = {}
    for group in sorted(groups, key=planner_group_sort_key):
        if group.opcode not in profile_opcodes(group.group, preset):
            continue
        if preset == "recommended" and not _has_recommended_availability(group):
            continue
        if preset in {"recommended", "full"}:
            if group.rr_max is None:
                continue
            selected[group.key] = GroupScanPlan(
                group=group.group,
                opcode=group.opcode,
                rr_max=group.rr_max,
                instances=_instances_for_preset(group, preset),
            )
        elif preset == "research":
            normal_rr_max = group.research_rr_max
            if normal_rr_max is None and group.rr_max is not None:
                normal_rr_max = max(group.rr_max, group.rr_max_full or group.rr_max)
            if normal_rr_max is None:
                continue
            selected[group.key] = GroupScanPlan(
                group=group.group,
                opcode=group.opcode,
                rr_max=research_rr_max(
                    group=group.group,
                    opcode=group.opcode,
                    normal_rr_max=normal_rr_max,
                ),
                instances=_instances_for_preset(group, preset),
            )
    return selected
