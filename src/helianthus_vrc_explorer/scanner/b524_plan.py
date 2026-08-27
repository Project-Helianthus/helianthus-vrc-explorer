"""Private planning helpers for the B524 scanner facade."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Final, Literal, cast

from ..protocol.b524 import RegisterOpcode
from ..ui.planner import PlannerPreset
from .director import GROUP_CONFIG, ClassifiedGroup, group_name_for_opcode, group_namespace_profiles
from .identity import opcode_label, operation_label
from .plan import GroupScanPlan, PlanKey, make_plan_key
from .register import opcodes_for_group

if TYPE_CHECKING:
    from .b524_probe import GroupMetadata


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


_LOCAL_REGISTER_OPCODE: RegisterOpcode = 0x02
_REMOTE_REGISTER_OPCODE: RegisterOpcode = 0x06
_UNKNOWN_GROUP_OPCODE_CANDIDATES: tuple[RegisterOpcode, ...] = (
    _LOCAL_REGISTER_OPCODE,
    _REMOTE_REGISTER_OPCODE,
)
PlannerUiMode = Literal["disabled", "auto", "textual", "classic"]
_KNOWN_DESCRIPTOR_TYPES = frozenset(
    float(desc) for config in GROUP_CONFIG.values() if (desc := config.get("desc")) is not None
)


def _is_instanced_group(ii_max: int | None) -> bool:
    return ii_max is not None and ii_max > 0


def _normalize_planner_preset(preset: str) -> PlannerPreset:
    normalized = preset.strip().lower()
    if normalized == "aggressive":
        normalized = "full"
    if normalized == "exhaustive":
        normalized = "research"
    if normalized == "conservative":
        normalized = "recommended"
    return cast(PlannerPreset, normalized)


def _planner_ii_max(ii_max: int | None) -> int | None:
    return ii_max if _is_instanced_group(ii_max) else None


def _group_opcodes(group: int) -> tuple[RegisterOpcode, ...]:
    return _sorted_namespace_opcodes(opcodes_for_group(group))


def _namespace_opcode_sort_key(opcode: int) -> tuple[int, int]:
    priority = 0 if opcode == 0x02 else 1 if opcode == 0x06 else 2
    return priority, opcode


def _sorted_namespace_opcodes(opcodes: Sequence[int]) -> tuple[RegisterOpcode, ...]:
    unique = {int(opcode): cast(RegisterOpcode, opcode) for opcode in opcodes}
    ordered = sorted(unique, key=_namespace_opcode_sort_key)
    return tuple(unique[opcode] for opcode in ordered)


def _planner_source_opcodes(group: int) -> tuple[RegisterOpcode, ...]:
    """Return broad planner-visible opcode candidates for a group.

    The planner intentionally exposes both local and remote opcode families so
    users can include exploratory rows even when semantic modeling is still
    conservative for that namespace.
    """

    config = GROUP_CONFIG.get(group)
    if config is None:
        return _UNKNOWN_GROUP_OPCODE_CANDIDATES

    profiles = group_namespace_profiles(group)
    candidate_opcodes: set[int] = {int(opcode) for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES}
    if profiles:
        candidate_opcodes.update(int(opcode) for opcode in profiles)
    else:
        candidate_opcodes.update(int(opcode) for opcode in config["opcodes"])
    # BASV2 confirmed: GG=0x00 has no remote (0x06) namespace; keep it out of
    # planner-visible candidates to avoid probing a nonexistent namespace.
    if group == 0x00:
        candidate_opcodes.discard(int(_REMOTE_REGISTER_OPCODE))
    return _sorted_namespace_opcodes(tuple(candidate_opcodes))


def _planner_primary_opcode(
    *,
    group: int,
    planner_opcodes: tuple[RegisterOpcode, ...],
    resolved_opcodes: tuple[RegisterOpcode, ...],
) -> RegisterOpcode:
    # Planner visibility can be broader than scan semantics. Preserve the
    # semantic primary namespace from resolved opcodes when available.
    if resolved_opcodes:
        return resolved_opcodes[0]
    if group in GROUP_CONFIG:
        return _primary_opcode(group)
    return planner_opcodes[0]


def _primary_opcode(group: int) -> RegisterOpcode:
    return _group_opcodes(group)[0]


def _is_multi_operation_group(group: int) -> bool:
    return len(_group_opcodes(group)) > 1


_LOCAL_ALWAYS_ON: Final[frozenset[int]] = frozenset({0x00, 0x01, 0x04, 0x05})
_LOCAL_PRESENT_GATED: Final[frozenset[int]] = frozenset({0x02, 0x03, 0x08, 0x09})


def _planner_group_is_recommended(*, group: int, opcode: RegisterOpcode) -> bool:
    if opcode == _LOCAL_REGISTER_OPCODE:
        return group in _LOCAL_ALWAYS_ON or group in _LOCAL_PRESENT_GATED
    # OP=0x06 (remote): all groups are recommended if they have present instances.
    return True


def _instance_discovery_targets(
    classified: list[ClassifiedGroup],
    metadata_map: Mapping[int, GroupMetadata],
    resolved_group_opcodes: Mapping[int, tuple[RegisterOpcode, ...]],
) -> list[tuple[ClassifiedGroup, GroupMetadata, RegisterOpcode]]:
    targets: list[tuple[ClassifiedGroup, GroupMetadata, RegisterOpcode]] = []
    for opcode in (_LOCAL_REGISTER_OPCODE, _REMOTE_REGISTER_OPCODE):
        for group in classified:
            if opcode not in resolved_group_opcodes.get(group.group, ()):
                continue
            targets.append((group, metadata_map[group.group], opcode))
    for group in classified:
        for opcode in resolved_group_opcodes.get(group.group, ()):
            if opcode in {_LOCAL_REGISTER_OPCODE, _REMOTE_REGISTER_OPCODE}:
                continue
            targets.append((group, metadata_map[group.group], opcode))
    return targets


def _group_name_for_opcode(group: int, opcode: RegisterOpcode) -> str:
    return group_name_for_opcode(group, int(opcode))


def _group_display_name_for_opcodes(
    *, group: int, opcodes: tuple[RegisterOpcode, ...], fallback: str
) -> str:
    if not opcodes:
        return fallback
    names = [_group_name_for_opcode(group, opcode) for opcode in opcodes]
    unique_names: list[str] = []
    for name in names:
        if name not in unique_names:
            unique_names.append(name)
    if not unique_names:
        return fallback
    if len(unique_names) == 1:
        return unique_names[0]
    config = GROUP_CONFIG.get(group)
    if config is not None:
        configured = str(config["name"]).strip()
        if configured:
            return configured
    return unique_names[0]


def _rr_max_full_for_opcode(*, group: int, opcode: int) -> int:
    """Research-mode RR ceiling: 0x01FF for OP=0x02/GG=0x00, 0xFF for everything else."""
    if opcode == _LOCAL_REGISTER_OPCODE and group == 0x00:
        return 0x01FF
    return 0xFF


def _rr_max_for_opcode(*, group: int, default_rr_max: int, opcode: int) -> int:
    config = GROUP_CONFIG.get(group)
    if config is None:
        return default_rr_max
    overrides = config.get("rr_max_by_opcode")
    if overrides is None:
        return default_rr_max
    return int(overrides.get(opcode, default_rr_max))


def _ii_max_for_opcode(*, group: int, default_ii_max: int | None, opcode: int) -> int | None:
    config = GROUP_CONFIG.get(group)
    if config is None:
        return default_ii_max
    overrides = config.get("ii_max_by_opcode")
    if overrides is None:
        return default_ii_max
    value = overrides.get(opcode)
    if value is None:
        return default_ii_max
    return int(value)


def _plan_key(group: int, opcode: int) -> PlanKey:
    return make_plan_key(group, opcode)


def _instance_discovery_decision(*, group: int, multi_op: bool) -> dict[str, Any]:
    if not multi_op:
        return {
            "strategy": "single_operation",
            "decision": "independent_per_operation",
            "tradeoff": "not_applicable",
        }

    if group in {0x09, 0x0A}:
        return {
            "strategy": "multi_operation",
            "decision": "independent_per_operation",
            "tradeoff": (
                "extra presence probes accepted to avoid cross-operation false-equivalence "
                "assumptions"
            ),
        }

    return {
        "strategy": "multi_operation",
        "decision": "independent_per_operation",
        "tradeoff": "independent probing is authoritative over shared inference",
    }


def _operation_plan_meta(group_plan: GroupScanPlan) -> tuple[str, dict[str, object]]:
    op_key = _hex_u8(group_plan.opcode)
    payload = group_plan.to_meta()
    payload["op_key"] = op_key
    payload["label"] = opcode_label(group_plan.opcode)
    payload["operation_label"] = operation_label(opcode=group_plan.opcode, optype=0x00)
    return op_key, payload


def _scan_plan_meta_groups(plan: dict[PlanKey, GroupScanPlan]) -> dict[str, object]:
    serializable: dict[str, object] = {}
    grouped: dict[int, list[GroupScanPlan]] = {}
    for _key, group_plan in sorted(plan.items()):
        grouped.setdefault(group_plan.group, []).append(group_plan)

    for group in sorted(grouped):
        group_plans = sorted(grouped[group], key=lambda gp: gp.opcode)
        group_key = _hex_u8(group)
        op_meta: dict[str, object] = {}
        for group_plan in group_plans:
            op_key, payload = _operation_plan_meta(group_plan)
            op_meta[op_key] = payload
        if len(group_plans) > 1:
            serializable[group_key] = {
                "multi_op": True,
                "operations": op_meta,
            }
            continue
        _, single_payload = _operation_plan_meta(group_plans[0])
        serializable[group_key] = {
            **single_payload,
            "multi_op": False,
            "operations": op_meta,
        }
    return serializable
