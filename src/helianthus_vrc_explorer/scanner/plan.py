from __future__ import annotations

import string
from collections.abc import Sequence
from dataclasses import dataclass

from ..protocol.b524 import RegisterOpcode
from .identity import NamespaceIdentity, make_namespace_identity

_HEX_DIGITS = set(string.hexdigits)
PlanKey = NamespaceIdentity


def parse_int_token(token: str) -> int:
    """Parse an integer token.

    Accepts:
    - decimal digits (e.g. "10")
    - 0x-prefixed hex (e.g. "0x0A")
    - bare hex with A-F (e.g. "0A")
    """

    raw = token.strip()
    if not raw:
        raise ValueError("Empty integer token")

    lowered = raw.lower()
    if lowered.startswith("0x"):
        return int(lowered, 16)
    if raw.isdigit():
        return int(raw, 10)
    if all(ch in _HEX_DIGITS for ch in raw):
        return int(raw, 16)
    raise ValueError(f"Invalid integer token: {token!r}")


def parse_int_set(spec: str, *, min_value: int, max_value: int) -> list[int]:
    """Parse a comma-separated set of ints and ranges.

    Example inputs:
    - "0-10"
    - "0,2,5"
    - "0-3,7,9-10"
    """

    if min_value > max_value:
        raise ValueError("min_value must be <= max_value")

    result: set[int] = set()
    raw = spec.strip()
    if not raw:
        raise ValueError("Empty set specification")

    for part in raw.split(","):
        token = part.strip()
        if not token:
            continue
        # VE23-R3: Support ".." as the primary range separator (unambiguous for hex).
        # Fall back to "-" only when ".." is absent.
        if ".." in token:
            start_s, end_s = token.split("..", 1)
            start = parse_int_token(start_s)
            end = parse_int_token(end_s)
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                if value < min_value or value > max_value:
                    raise ValueError(
                        f"Value out of range: {value} (allowed {min_value}-{max_value})"
                    )
                result.add(value)
            continue
        if "-" in token:
            start_s, end_s = token.split("-", 1)
            start = parse_int_token(start_s)
            end = parse_int_token(end_s)
            if start > end:
                start, end = end, start
            for value in range(start, end + 1):
                if value < min_value or value > max_value:
                    raise ValueError(
                        f"Value out of range: {value} (allowed {min_value}-{max_value})"
                    )
                result.add(value)
            continue

        value = parse_int_token(token)
        if value < min_value or value > max_value:
            raise ValueError(f"Value out of range: {value} (allowed {min_value}-{max_value})")
        result.add(value)

    return sorted(result)


def format_int_set(values: Sequence[int]) -> str:
    """Format an increasing list of ints into a compact range string.

    Example:
        [0, 1, 2, 4, 5] -> "0-2,4-5"
    """

    if not values:
        return ""

    parts: list[str] = []
    start = values[0]
    prev = values[0]
    for v in values[1:]:
        if v == prev + 1:
            prev = v
            continue
        if start == prev:
            parts.append(str(start))
        else:
            parts.append(f"{start}-{prev}")
        start = prev = v

    if start == prev:
        parts.append(str(start))
    else:
        parts.append(f"{start}-{prev}")

    return ",".join(parts)


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def make_plan_key(group: int, opcode: int) -> PlanKey:
    return make_namespace_identity(opcode=opcode, group=group)


def format_plan_key(key: PlanKey) -> str:
    opcode, group = key
    return f"{_hex_u8(group)}/{_hex_u8(opcode)}"


@dataclass(frozen=True, slots=True)
class GroupScanPlan:
    group: int
    opcode: RegisterOpcode
    rr_max: int
    instances: tuple[int, ...]
    registers: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        _validate_selector("group", self.group, max_value=0xFF)
        _validate_selector("opcode", self.opcode, max_value=0xFF)
        if self.opcode not in {0x02, 0x06}:
            raise ValueError("opcode must be 0x02 or 0x06")
        _validate_selector("rr_max", self.rr_max, max_value=0xFFFF)
        _validate_selector_tuple("instances", self.instances, max_value=0xFF, allow_empty=True)
        # The virtual water-circuit slot is independent of ordinary circuit_count.
        # This common plan type also covers CLI, both interactive planners and
        # replanning; adding it here keeps deduplication and estimates consistent.
        if self.opcode == 0x02 and self.group == 0x02:
            instances = set(self.instances)
            instances.add(0x09)
            object.__setattr__(self, "instances", tuple(sorted(instances)))
        if self.registers is not None:
            _validate_selector_tuple(
                "registers", self.registers, max_value=0xFFFF, allow_empty=False
            )
            if max(self.registers) > self.rr_max:
                raise ValueError("explicit registers exceed rr_max")

    def to_meta(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "opcode": _hex_u8(self.opcode),
            "rr_max": _hex_u16(self.rr_max),
            "instances": [_hex_u8(ii) for ii in self.instances],
        }
        if self.registers is not None:
            payload["registers"] = [_hex_u16(rr) for rr in self.registers]
        if self.opcode == 0x02 and self.group == 0x02:
            payload["mandatory_instances"] = ["0x09"]
        return payload


def _validate_selector(name: str, value: object, *, max_value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not (0 <= value <= max_value):
        raise ValueError(f"{name} out of range: {value} (allowed 0-{max_value})")


def _validate_selector_tuple(
    name: str,
    values: object,
    *,
    max_value: int,
    allow_empty: bool,
) -> None:
    if not isinstance(values, tuple):
        raise ValueError(f"{name} must be a tuple")
    if not values and not allow_empty:
        raise ValueError(f"{name} must not be empty")
    for value in values:
        _validate_selector(name.removesuffix("s"), value, max_value=max_value)
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must not contain duplicates")


@dataclass(frozen=True, slots=True, order=True)
class RegisterTask:
    group: int
    opcode: RegisterOpcode
    instance: int
    register: int


def build_work_queue(
    plan: dict[PlanKey, GroupScanPlan],
    *,
    done: set[RegisterTask],
) -> list[RegisterTask]:
    """Build the remaining register-scan task list in deterministic order."""

    tasks: list[RegisterTask] = []
    for key in sorted(plan.keys()):
        group_plan = plan[key]
        if key != make_plan_key(group_plan.group, group_plan.opcode):
            raise ValueError(
                f"Plan key mismatch: key={key!r} entry={(group_plan.group, group_plan.opcode)!r}"
            )
        registers: Sequence[int]
        if group_plan.registers is None:
            registers = range(0x0000, group_plan.rr_max + 1)
        else:
            registers = group_plan.registers
        for ii in group_plan.instances:
            for rr in registers:
                task = RegisterTask(
                    group=group_plan.group,
                    opcode=group_plan.opcode,
                    instance=ii,
                    register=rr,
                )
                if task in done:
                    continue
                tasks.append(task)
    return tasks


def estimate_register_requests(plan: dict[PlanKey, GroupScanPlan]) -> int:
    total = 0
    for group_plan in plan.values():
        register_count = (
            group_plan.rr_max + 1 if group_plan.registers is None else len(group_plan.registers)
        )
        total += len(group_plan.instances) * register_count
    return total


def estimate_eta_seconds(*, requests: int, request_rate_rps: float | None) -> float | None:
    if request_rate_rps is None:
        return None
    if request_rate_rps <= 0:
        return None
    return requests / request_rate_rps
