"""Bundled, opcode-scoped register-name correspondence for B524 registers.

This is a purely presentational cross-reference between the canonical
Explorer name and the observed Vaillant and eBUSd names for the same
register. It never changes a register's codec, class, write authority, or
the canonical Explorer name used everywhere else -- it is secondary
information, resolved at render time, never written into scan artifacts.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import cache
from importlib import resources

_EXPECTED_FIELDS = (
    "opcode",
    "group",
    "register",
    "name",
    "vaillant_friendly_name",
    "vaillant_name_vrc720",
    "vaillant_name_vrc700",
    "myvaillant_name_vrc720",
    "myvaillant_name_vrc700",
    "ebusd_name",
)


def _split_multi(value: str) -> tuple[str, ...]:
    """Split a ` | `-separated cell into its individual values."""
    if not value:
        return ()
    return tuple(part.strip() for part in value.split(" | ") if part.strip())


@dataclass(frozen=True, slots=True)
class B524RegisterNameCorrespondence:
    """One register's observed Vaillant/eBUSd name cross-reference."""

    name: str
    vaillant_friendly_name: tuple[str, ...]
    vaillant_name_vrc720: tuple[str, ...]
    vaillant_name_vrc700: tuple[str, ...]
    myvaillant_name_vrc720: tuple[str, ...]
    myvaillant_name_vrc700: tuple[str, ...]
    ebusd_name: tuple[str, ...]


@cache
def bundled_b524_register_name_correspondence() -> dict[
    tuple[int, int, int], B524RegisterNameCorrespondence
]:
    """Return the bundled correspondence keyed by ``(opcode, group, register)``."""

    mapping: dict[tuple[int, int, int], B524RegisterNameCorrespondence] = {}
    resource = resources.files("helianthus_vrc_explorer.data").joinpath(
        "b524_register_name_correspondence.csv"
    )
    with resource.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != _EXPECTED_FIELDS:
            raise ValueError("B524 register-name correspondence catalog has an unexpected header")
        for row in reader:
            opcode = int((row.get("opcode") or "").strip(), 0)
            group = int((row.get("group") or "").strip(), 0)
            register = int((row.get("register") or "").strip(), 0)
            name = (row.get("name") or "").strip()
            if not (0 <= opcode <= 0xFF and 0 <= group <= 0xFF and 0 <= register <= 0xFFFF):
                raise ValueError(
                    f"B524 register-name correspondence identity out of range: {row!r}"
                )
            key = (opcode, group, register)
            if key in mapping:
                raise ValueError(f"Duplicate B524 register-name correspondence identity: {key!r}")

            def _cell(column: str, *, _row: dict[str, str] = row) -> tuple[str, ...]:
                return _split_multi((_row.get(column) or "").strip())

            mapping[key] = B524RegisterNameCorrespondence(
                name=name,
                vaillant_friendly_name=_cell("vaillant_friendly_name"),
                vaillant_name_vrc720=_cell("vaillant_name_vrc720"),
                vaillant_name_vrc700=_cell("vaillant_name_vrc700"),
                myvaillant_name_vrc720=_cell("myvaillant_name_vrc720"),
                myvaillant_name_vrc700=_cell("myvaillant_name_vrc700"),
                ebusd_name=_cell("ebusd_name"),
            )
    return mapping


def b524_register_name_correspondence(
    *, opcode: int, group: int, register: int
) -> B524RegisterNameCorrespondence | None:
    """Resolve one register's observed name cross-reference, if the catalog has one."""

    return bundled_b524_register_name_correspondence().get((opcode, group, register))
