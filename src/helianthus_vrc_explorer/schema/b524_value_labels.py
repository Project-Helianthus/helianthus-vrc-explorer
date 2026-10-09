"""Bundled, namespace-aware candidate labels for B524 scalar values."""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from functools import cache
from importlib import resources
from typing import Any

from ..artifact_schema import iter_register_entries

_EXPECTED_FIELDS = ("opcode", "group", "register", "value", "label", "qualification")
_LABEL = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_QUALIFICATION = "candidate_unqualified"


@dataclass(frozen=True, slots=True)
class B524ValueLabel:
    """Presentation annotation that carries no write or native-qualification authority."""

    label: str
    qualification: str


@cache
def bundled_b524_value_labels() -> dict[tuple[int, int, int, int], B524ValueLabel]:
    """Return candidate labels keyed by ``(opcode, group, register, value)``."""

    mapping: dict[tuple[int, int, int, int], B524ValueLabel] = {}
    resource = resources.files("helianthus_vrc_explorer.data").joinpath("b524_value_labels.csv")
    with resource.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != _EXPECTED_FIELDS:
            raise ValueError("B524 value-label catalog has an unexpected header")
        for row in reader:
            opcode = int((row.get("opcode") or "").strip(), 0)
            group = int((row.get("group") or "").strip(), 0)
            register = int((row.get("register") or "").strip(), 0)
            value = int((row.get("value") or "").strip(), 0)
            label = (row.get("label") or "").strip()
            qualification = (row.get("qualification") or "").strip()
            if not (0 <= opcode <= 0xFF and 0 <= group <= 0xFF):
                raise ValueError(f"B524 value-label namespace out of range: {row!r}")
            if not (0 <= register <= 0xFFFF and 0 <= value <= 0xFFFFFFFF):
                raise ValueError(f"B524 value-label scalar out of range: {row!r}")
            if _LABEL.fullmatch(label) is None:
                raise ValueError(f"B524 value label must be uppercase snake case: {label!r}")
            if qualification != _QUALIFICATION:
                raise ValueError("B524 value labels must remain explicitly candidate_unqualified")
            key = (opcode, group, register, value)
            if key in mapping:
                raise ValueError(f"Duplicate B524 value-label identity: {key!r}")
            mapping[key] = B524ValueLabel(label=label, qualification=qualification)
    return mapping


def b524_value_label(
    *, opcode: int, group: int, register: int, value: int
) -> B524ValueLabel | None:
    """Resolve one operation-scoped candidate label without inferring unknown codes."""

    return bundled_b524_value_labels().get((opcode, group, register, value))


def apply_b524_value_labels(artifact: dict[str, Any]) -> None:
    """Attach presentation-only labels while preserving numeric and raw evidence."""

    for opcode_key, group_key, _instance_key, register_key, entry in iter_register_entries(
        artifact
    ):
        if opcode_key is None:
            continue
        value = entry.get("value")
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        try:
            annotation = b524_value_label(
                opcode=int(opcode_key, 0),
                group=int(group_key, 0),
                register=int(register_key, 0),
                value=value,
            )
        except ValueError:
            continue
        if annotation is None:
            continue
        entry["enum_resolved_name"] = annotation.label
        entry["value_label_qualification"] = annotation.qualification
        entry["value_display"] = f"{value} ({annotation.label})"
