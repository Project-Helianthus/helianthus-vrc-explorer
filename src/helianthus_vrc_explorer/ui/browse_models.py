from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

BrowseTab = Literal["config", "state"]
ProtocolKey = Literal["b524", "b555", "b516", "b509"]


def _compact_hex_label(raw: str) -> str:
    try:
        return f"0x{int(raw, 0):x}"
    except ValueError:
        return raw


@dataclass(frozen=True, slots=True)
class RegisterAddress:
    protocol: ProtocolKey
    group_key: str | None
    namespace_key: str | None
    namespace_label: str | None
    instance_key: str | None
    register_key: str
    read_opcode: str | None
    selector_label: str | None = None

    @property
    def label(self) -> str:
        if self.selector_label is not None:
            return self.selector_label
        suffix = f" {self.read_opcode}" if self.read_opcode else ""
        if self.protocol == "b509":
            return f"B509 RR={self.register_key}{suffix}"
        if self.protocol == "b555":
            group_key = self.group_key or "program"
            return f"B555 {group_key} {self.register_key}{suffix}".strip()
        if self.protocol == "b516":
            return f"B516 {self.register_key}{suffix}".strip()
        gg = f"GG={_compact_hex_label(self.group_key)}" if self.group_key else ""
        rr = f"RR={_compact_hex_label(self.register_key)}"
        parts = [p for p in ("B524", gg, rr) if p]
        return " ".join(parts) + suffix


@dataclass(frozen=True, slots=True)
class RegisterRow:
    row_id: str
    protocol: ProtocolKey
    group_key: str | None
    namespace_key: str | None
    namespace_label: str | None
    section_key: str | None
    group_name: str
    instance_key: str | None
    register_key: str
    name: str
    myvaillant_name: str
    ebusd_name: str
    path: str
    tab: BrowseTab
    address: RegisterAddress
    value_text: str
    raw_hex: str
    unit: str
    access_flags: str
    last_update_text: str
    age_text: str
    change_indicator: str
    search_blob: str
    parameter_description: dict[str, object] | None = None
    bundled_parameter_description: dict[str, object] | None = None
    candidate_name: str = ""
    candidate_evidence: str = ""
    value_label_qualification: str = ""

    @property
    def display_label(self) -> str:
        """Compact user-facing register label while retaining native address metadata."""

        if self.section_key and self.section_key.startswith("operation_"):
            return self.name
        try:
            register = int(self.register_key, 0)
            rr_label = f"0x{register:04x}"
        except ValueError:
            rr_label = self.register_key
        semantic_name = self.myvaillant_name or self.name
        compact_register = f"0x{register:x}" if "register" in locals() else self.register_key
        if not semantic_name or semantic_name in {self.register_key, compact_register}:
            return rr_label
        return f"{semantic_name} ({rr_label})"

    @property
    def description_text(self) -> str:
        parts: list[str] = []
        if self.value_label_qualification:
            parts.append("Value label (candidate, unqualified presentation; no write authority)")
        for label, desc in (
            ("Verified", self.parameter_description),
            ("Bundled", self.bundled_parameter_description),
        ):
            if desc is None:
                continue
            state = desc.get("verification", desc.get("qualification", "unknown"))
            if desc.get("qualification") in {"matched", "bundled"}:
                parts.append(
                    f"{label} ({state}): {desc.get('type', 'unknown')} "
                    f"{desc.get('min', '?')}..{desc.get('max', '?')} "
                    f"step={desc.get('step', '?')}"
                )
            else:
                parts.append(f"Description {state}")
        return " | ".join(parts) or "Unknown"


TreeNodeLevel = Literal[
    "root",
    "protocol",
    "section",
    "group",
    "namespace",
    "instance",
    "register",
    "range",
]


@dataclass(frozen=True, slots=True)
class TreeNodeRef:
    node_id: str
    label: str
    level: TreeNodeLevel
    protocol: ProtocolKey | None = None
    section_key: str | None = None
    group_key: str | None = None
    namespace_key: str | None = None
    namespace_label: str | None = None
    instance_key: str | None = None
    register_key: str | None = None
    range_key: str | None = None
