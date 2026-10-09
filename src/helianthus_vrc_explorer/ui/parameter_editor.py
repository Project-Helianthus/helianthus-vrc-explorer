"""Presentation helpers for local previews and typed scalar editing.

Enum labels and UI gates do not establish native access or write authorization.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ..schema.b524_value_labels import bundled_b524_value_labels


@dataclass(frozen=True, slots=True)
class ParameterEnumChoice:
    value: int
    label: str
    enabled: bool = True
    reason: str = ""
    gate_unknown: bool = False

    @property
    def display(self) -> str:
        suffix = (
            f" — {self.reason}" if self.reason else " — gate unknown" if self.gate_unknown else ""
        )
        return f"{self.label} ({self.value}){suffix}"


def parameter_enum_choices(
    entry: dict[str, Any],
    *,
    read_opcode: int,
    group: int,
    register: int,
    description: dict[str, Any] | None,
) -> list[ParameterEnumChoice]:
    """Keep every named code, including disabled choices and unknown gates."""
    rows = entry.get("enum_options")
    if not isinstance(rows, list):
        rows = [
            {"value": code, "label": item.label}
            for (op, gg, rr, code), item in bundled_b524_value_labels().items()
            if (op, gg, rr) == (read_opcode, group, register)
        ]
    if not rows and entry.get("type") == "BOOL":
        rows = [{"value": 0, "label": "OFF"}, {"value": 1, "label": "ON"}]
    choices = []
    seen: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        code, label = row.get("value"), row.get("label")
        if isinstance(code, bool) or not isinstance(code, int) or code in seen:
            continue
        if not isinstance(label, str) or not label.strip():
            continue
        seen.add(code)
        enabled, reason, unknown = True, "", False
        gate = row.get("gate")
        if isinstance(gate, dict):
            qualified = gate.get("qualification") in {"qualified", "profile_qualified"}
            if qualified and gate.get("state") is False:
                enabled, reason = False, str(gate.get("reason") or "Gate not satisfied")
            elif not qualified or gate.get("state") is not True:
                unknown = True
        if description is not None:
            minimum, maximum, step = (description.get(k) for k in ("min", "max", "step"))
            if (
                isinstance(minimum, (float, int))
                and not isinstance(minimum, bool)
                and isinstance(maximum, (float, int))
                and not isinstance(maximum, bool)
                and math.isfinite(minimum)
                and math.isfinite(maximum)
            ):
                if not minimum <= code <= maximum:
                    enabled, reason = False, "Outside described range"
                elif isinstance(step, (float, int)) and math.isfinite(step) and step > 0:
                    quotient = (code - minimum) / step
                    if abs(quotient - round(quotient)) > 1e-4:
                        enabled, reason = False, "Outside described step"
        choices.append(ParameterEnumChoice(code, label, enabled, reason, unknown))
    return sorted(choices, key=lambda c: c.value)


def record_offline_edit(
    entry: dict[str, Any],
    *,
    value: object,
    raw_hex: str,
    type_spec: str,
) -> None:
    """Record a preview without replacing a bus observation or claiming a write."""
    entry["local_edit_preview"] = {
        "value": value,
        "raw_hex": raw_hex,
        "type": type_spec,
        "device_write": False,
        "edited_at": datetime.now(UTC).isoformat(),
    }


def parameter_value_display(
    entry: dict[str, Any], *, opcode: int, group: int, register: int
) -> str:
    value = entry.get("value")
    resolved = entry.get("enum_resolved_name")
    if isinstance(resolved, str) and resolved:
        return f"{resolved} ({value})"
    choices = parameter_enum_choices(
        entry,
        read_opcode=opcode,
        group=group,
        register=register,
        description=None,
    )
    for choice in choices:
        if value == choice.value:
            return f"{choice.label} ({choice.value})"
    if choices:
        return f"UNKNOWN ({value})"
    return str(entry.get("value_display", value))
