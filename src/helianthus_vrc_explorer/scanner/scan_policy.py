"""Pure B524 scan candidate policy and explicit-plan parser."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal, cast

from ..protocol.b524 import RegisterOpcode
from .plan import (
    GroupScanPlan,
    PlanKey,
    estimate_register_requests,
    make_plan_key,
    parse_int_set,
    parse_int_token,
)

type ScanPreset = Literal["recommended", "full", "research", "custom"]

MAX_EXPLICIT_SCALAR_REQUESTS: Final[int] = 100_000

_PROFILE_GROUPS_BY_OPCODE: Final[dict[RegisterOpcode, frozenset[int]]] = {
    0x02: frozenset({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09}),
    0x06: frozenset({0x01, 0x02, 0x08, 0x09, 0x0A, 0x0C, 0x0E, 0x0F}),
}
_READ_OPCODES: Final[tuple[RegisterOpcode, ...]] = (0x02, 0x06)


def profile_opcodes(group: int, preset: ScanPreset) -> tuple[RegisterOpcode, ...]:
    """Return read opcodes allowed as candidates for one group and preset.

    Recommended and full are limited to pairs characterized by the public B524
    profile. Research exposes both read namespaces except the globally
    unsupported-by-default OP=0x06/GG=0x00 pair. Custom permits any explicit
    read-namespace pair within the wire selector bounds.
    """

    _require_bounded_int("group", group, max_value=0xFF)
    if preset not in {"recommended", "full", "research", "custom"}:
        raise ValueError(f"Unknown scan preset: {preset!r}")
    if preset in {"recommended", "full"}:
        return tuple(
            opcode for opcode in _READ_OPCODES if group in _PROFILE_GROUPS_BY_OPCODE[opcode]
        )
    if preset == "research" and group == 0x00:
        return (0x02,)
    return _READ_OPCODES


def research_rr_max(*, group: int, opcode: int, normal_rr_max: int) -> int:
    """Return the bounded research ceiling without shrinking known normal scope."""

    _require_bounded_int("group", group, max_value=0xFF)
    _require_bounded_int("opcode", opcode, max_value=0xFF)
    _require_bounded_int("normal_rr_max", normal_rr_max, max_value=0xFFFF)
    floor = 0x00FF
    return max(normal_rr_max, floor)


def parse_scan_plan(data: object) -> dict[PlanKey, GroupScanPlan]:
    """Parse schema-version 1 explicit custom-plan data into exact scan selectors."""

    if not isinstance(data, Mapping):
        raise ValueError("scan plan must be an object")
    _reject_unknown_fields(data, {"schema_version", "groups"}, context="scan plan")
    schema_version = data.get("schema_version")
    schema_version_valid = (
        isinstance(schema_version, int)
        and not isinstance(schema_version, bool)
        and schema_version == 1
    ) or (isinstance(schema_version, str) and schema_version == "1")
    if not schema_version_valid:
        raise ValueError("schema_version must be 1 or the string '1'")
    rows = data.get("groups")
    if isinstance(rows, (str, bytes, bool)) or not isinstance(rows, list):
        raise ValueError("groups must be a JSON array")
    if not rows:
        raise ValueError("groups must contain at least one scope row")

    plan: dict[PlanKey, GroupScanPlan] = {}
    total_requests = 0
    for index, row in enumerate(rows):
        context = f"groups[{index}]"
        if not isinstance(row, Mapping):
            raise ValueError(f"{context} must be an object")
        _reject_unknown_fields(
            row,
            {"opcode", "group", "instances", "registers"},
            context=context,
        )
        missing = {
            field for field in ("opcode", "group", "instances", "registers") if field not in row
        }
        if missing:
            raise ValueError(f"{context} missing field(s): {', '.join(sorted(missing))}")

        opcode = _parse_scalar(row["opcode"], name=f"{context}.opcode", max_value=0xFF)
        if opcode not in _READ_OPCODES:
            raise ValueError(f"{context}.opcode must be 0x02 or 0x06")
        group = _parse_scalar(row["group"], name=f"{context}.group", max_value=0xFF)
        instances = _parse_selector_list(
            row["instances"], name=f"{context}.instances", max_value=0xFF
        )
        _validate_profile_instances(
            opcode=opcode, group=group, instances=instances, context=context
        )
        registers = _parse_selector_list(
            row["registers"], name=f"{context}.registers", max_value=0xFFFF
        )
        group_plan = GroupScanPlan(
            group=group,
            opcode=cast(RegisterOpcode, opcode),
            rr_max=max(registers),
            instances=instances,
            registers=registers,
        )
        key = make_plan_key(group, opcode)
        previous = plan.get(key)
        if previous is not None and previous != group_plan:
            raise ValueError(
                f"{context} is a conflicting duplicate for OP=0x{opcode:02X}/GG=0x{group:02X}"
            )
        if previous is None:
            plan[key] = group_plan
            total_requests += len(group_plan.instances) * len(registers)
            _require_request_limit(total_requests)
    return plan


def validate_scalar_request_limit(plan: Mapping[PlanKey, GroupScanPlan]) -> None:
    """Reject plans whose materialized scalar queue would exceed the safe cap."""

    _require_request_limit(estimate_register_requests(dict(plan)))


def _require_request_limit(requests: int) -> None:
    if requests > MAX_EXPLICIT_SCALAR_REQUESTS:
        raise ValueError("scan plan exceeds the 100000 scalar request safety limit")


def _validate_profile_instances(
    *, opcode: int, group: int, instances: tuple[int, ...], context: str
) -> None:
    if opcode == 0x06 and any(not 0x01 <= instance <= 0x08 for instance in instances):
        raise ValueError(f"{context}.instances for OP=0x06 must be within 0x01..0x08")
    if (
        opcode == 0x02
        and group == 0x02
        and any(not 0x01 <= instance <= 0x09 for instance in instances)
    ):
        raise ValueError(f"{context}.instances for OP=0x02/GG=0x02 must be within 0x01..0x09")


def _reject_unknown_fields(
    value: Mapping[object, object], allowed: set[str], *, context: str
) -> None:
    unknown = sorted(str(field) for field in value if field not in allowed)
    if unknown:
        raise ValueError(f"{context} has unknown field(s): {', '.join(unknown)}")


def _parse_selector_list(value: object, *, name: str, max_value: int) -> tuple[int, ...]:
    if isinstance(value, (str, bytes, bool)) or not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array")
    if not value:
        raise ValueError(f"{name} must not be empty")
    parsed: set[int] = set()
    for index, item in enumerate(value):
        item_name = f"{name}[{index}]"
        if isinstance(item, bool) or not isinstance(item, (int, str)):
            raise ValueError(f"{item_name} must be an integer or integer/range string")
        if isinstance(item, int):
            _require_bounded_int(item_name, item, max_value=max_value)
            parsed.add(item)
            continue
        if "," in item:
            raise ValueError(f"{item_name} must contain one integer or range")
        try:
            parsed.update(parse_int_set(item, min_value=0, max_value=max_value))
        except ValueError as exc:
            raise ValueError(f"invalid {item_name}: {exc}") from exc
    if not parsed:
        raise ValueError(f"{name} must select at least one value")
    return tuple(sorted(parsed))


def _parse_scalar(value: object, *, name: str, max_value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{name} must be an integer or integer string")
    if isinstance(value, str):
        try:
            value = parse_int_token(value)
        except ValueError as exc:
            raise ValueError(f"invalid {name}: {exc}") from exc
    _require_bounded_int(name, value, max_value=max_value)
    return value


def _require_bounded_int(name: str, value: object, *, max_value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not (0 <= value <= max_value):
        raise ValueError(f"{name} out of range: {value} (allowed 0-{max_value})")
