from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

BrowseTab = Literal["config", "config_limits", "state"]
ProtocolKey = Literal["b524", "b555", "b509"]


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
        group_key = self.group_key or "0x??"
        instance_key = self.instance_key or "0x??"
        return f"GG={group_key} II={instance_key} RR={self.register_key}{suffix}"


@dataclass(frozen=True, slots=True)
class RegisterRow:
    row_id: str
    protocol: ProtocolKey
    group_key: str | None
    namespace_key: str | None
    namespace_label: str | None
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


TreeNodeLevel = Literal["root", "protocol", "group", "namespace", "instance", "range"]


@dataclass(frozen=True, slots=True)
class TreeNodeRef:
    node_id: str
    label: str
    level: TreeNodeLevel
    protocol: ProtocolKey | None = None
    group_key: str | None = None
    namespace_key: str | None = None
    namespace_label: str | None = None
    instance_key: str | None = None
    range_key: str | None = None
