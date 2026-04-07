from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

BrowseTab = Literal["config", "config_limits", "state"]
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

    @property
    def label(self) -> str:
        suffix = f" {self.read_opcode}" if self.read_opcode else ""
        if self.protocol == "b509":
            return f"B509 RR={self.register_key}{suffix}"
        if self.protocol == "b555":
            group_key = self.group_key or "program"
            return f"B555 {group_key} {self.register_key}{suffix}".strip()
        if self.protocol == "b516":
            return f"B516 {self.register_key}{suffix}".strip()
        return _compact_hex_label(self.register_key)


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
