"""Bundled, opcode-scoped semantic names for B524 registers.

This is deliberately separate from the optional myVaillant/ebusd mappings:
it carries only the VRC Explorer display name and cannot change a register's
codec, class, or ebusd alias.
"""

from __future__ import annotations

import csv
import re
from functools import cache
from importlib import resources
from typing import Any

_SNAKE_CASE_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
_OP06_DEVICE_HEADER_NAMES: dict[int, str] = {
    0x0001: "device_connected",
    0x0002: "device_class_address",
    0x0003: "device_error_code",
    0x0004: "device_firmware_version",
}


@cache
def bundled_b524_register_names() -> dict[tuple[int, int, int], str]:
    """Return bundled semantic names keyed by ``(opcode, group, register)``."""

    mapping: dict[tuple[int, int, int], str] = {}
    resource = resources.files("helianthus_vrc_explorer.data").joinpath("b524_register_names.csv")
    with resource.open("r", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            opcode = int((row.get("opcode") or "").strip(), 0)
            group = int((row.get("group") or "").strip(), 0)
            register = int((row.get("register") or "").strip(), 0)
            name = (row.get("name") or "").strip()
            if not (0 <= opcode <= 0xFF and 0 <= group <= 0xFF and 0 <= register <= 0xFFFF):
                raise ValueError(f"B524 register-name identity out of range: {row!r}")
            if not _SNAKE_CASE_NAME.fullmatch(name):
                raise ValueError(f"B524 register name must be snake_case: {name!r}")
            key = (opcode, group, register)
            if key in mapping:
                raise ValueError(f"Duplicate B524 register-name identity: {key!r}")
            mapping[key] = name
    return mapping


def b524_register_name(*, opcode: int, group: int, register: int) -> str | None:
    """Return the opcode-scoped bundled name, if the catalog has one."""

    if opcode == 0x06:
        if group == 0x0D and register == 0x0001:
            return "device_present"
        return _OP06_DEVICE_HEADER_NAMES.get(register)
    return bundled_b524_register_names().get((opcode, group, register))


def apply_b524_canonical_register_names(operations: dict[str, Any]) -> None:
    """Apply bundled names to an artifact operation tree in place.

    Callers that need artifact immutability must pass their working copy. Only
    ``myvaillant_name`` changes; reply data and existing metadata stay intact.
    """

    for opcode_key, operation in operations.items():
        if not isinstance(operation, dict):
            continue
        try:
            opcode = int(opcode_key, 0)
        except ValueError:
            continue
        groups = operation.get("groups")
        if not isinstance(groups, dict):
            continue
        for group_key, group_obj in groups.items():
            if not isinstance(group_obj, dict):
                continue
            try:
                group = int(group_key, 0)
            except ValueError:
                continue
            instances = group_obj.get("instances")
            if not isinstance(instances, dict):
                continue
            for instance_obj in instances.values():
                if not isinstance(instance_obj, dict):
                    continue
                registers = instance_obj.get("registers")
                if not isinstance(registers, dict):
                    continue
                for register_key, entry in registers.items():
                    if not isinstance(entry, dict):
                        continue
                    try:
                        register = int(register_key, 0)
                    except ValueError:
                        continue
                    name = b524_register_name(
                        opcode=opcode,
                        group=group,
                        register=register,
                    )
                    if name is not None:
                        entry["myvaillant_name"] = name
