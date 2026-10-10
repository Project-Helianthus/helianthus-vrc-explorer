from __future__ import annotations

import csv
from pathlib import Path

from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
    B524RegisterNameCorrespondence,
    b524_register_name_correspondence,
    bundled_b524_register_name_correspondence,
)
from helianthus_vrc_explorer.schema.b524_register_names import bundled_b524_register_names

_CSV_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "helianthus_vrc_explorer"
    / "data"
    / "b524_register_name_correspondence.csv"
)


def _rows() -> list[dict[str, str]]:
    with _CSV_PATH.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_loader_resolves_a_known_entry_with_split_multi_values() -> None:
    entry = b524_register_name_correspondence(opcode=0x02, group=0x00, register=0x0016)
    assert entry is not None
    assert entry.name == "system_ventilation_operating_mode"
    assert entry.vaillant_name_vrc700 == (
        "system_vrc700_operating_mode_for_air_ventilation",
        "ventilations_are_active",
    )


def test_loader_returns_none_for_unknown_identity() -> None:
    assert b524_register_name_correspondence(opcode=0x02, group=0xFF, register=0xFFFF) is None


def test_no_duplicate_identity_keys() -> None:
    keys = [
        (
            int(row["opcode"], 0),
            int(row["group"], 0),
            int(row["register"], 0),
        )
        for row in _rows()
    ]
    assert len(keys) == len(set(keys))


def test_every_op02_row_name_matches_register_names_catalog_both_ways() -> None:
    register_names = bundled_b524_register_names()
    correspondence = bundled_b524_register_name_correspondence()

    op02_names_by_key = {key: entry.name for key, entry in correspondence.items() if key[0] == 0x02}
    assert op02_names_by_key == register_names

    for key, name in op02_names_by_key.items():
        assert name == register_names[key]


def test_values_are_stripped_ascii() -> None:
    for row in _rows():
        for column, value in row.items():
            if value is None:
                continue
            assert value == value.strip(), f"{column}={value!r} is not stripped"
            assert value.isascii() or value == "", f"{column}={value!r} is not ASCII"


def test_dataclass_fields_are_tuples_of_stripped_values() -> None:
    entry = b524_register_name_correspondence(opcode=0x02, group=0x00, register=0x0001)
    assert entry is not None
    assert isinstance(entry, B524RegisterNameCorrespondence)
    for field_values in (
        entry.vaillant_friendly_name,
        entry.vaillant_name_vrc720,
        entry.vaillant_name_vrc700,
        entry.myvaillant_name_vrc720,
        entry.myvaillant_name_vrc700,
        entry.ebusd_name,
    ):
        assert isinstance(field_values, tuple)
        for value in field_values:
            assert value == value.strip()
            assert value != ""


def test_ebusd_names_are_unique_per_opcode() -> None:
    """One literal eBUSd name must not be attached to two different registers.

    HwcParallelLoading (GG00 RR000A) and Hc{hc}CircuitType (GG02 RR0002) were
    each found duplicated onto a second, unrelated register.
    """
    seen: dict[tuple[int, str], tuple[int, int]] = {}
    for row in _rows():
        opcode = int(row["opcode"], 0)
        group = int(row["group"], 0)
        register = int(row["register"], 0)
        for name in (row.get("ebusd_name") or "").split(" | "):
            name = name.strip()
            if not name:
                continue
            key = (opcode, name)
            here = (group, register)
            if key in seen and seen[key] != here:
                raise AssertionError(
                    f"eBUSd name {name!r} (opcode 0x{opcode:02X}) is attached to both "
                    f"{seen[key]} and {here}"
                )
            seen[key] = here
