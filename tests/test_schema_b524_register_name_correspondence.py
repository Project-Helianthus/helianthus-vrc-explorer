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
    entry = b524_register_name_correspondence(opcode=0x02, group=0x02, register=0x0002)
    assert entry is not None
    assert entry.name == "circuit_mixer_type_external"
    assert entry.vaillant_name_vrc720 == (
        "circuit_type",
        "circuit_type_of_mixed_circuit_external",
    )
    assert entry.vaillant_name_vrc700 == entry.vaillant_name_vrc720


def test_loader_resolves_a_single_name_as_a_one_element_tuple() -> None:
    entry = b524_register_name_correspondence(opcode=0x02, group=0x02, register=0x0001)
    assert entry is not None
    assert entry.name == "circuit_circuit_type"
    assert entry.vaillant_name_vrc720 == ("circuit_circuit_type",)
    assert entry.vaillant_name_vrc700 == ("circuit_circuit_type",)


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


_ANNOTATION_COLUMNS = (
    "vaillant_friendly_name",
    "vaillant_name_vrc720",
    "vaillant_name_vrc700",
    "myvaillant_name_vrc720",
    "myvaillant_name_vrc700",
    "ebusd_name",
)

# A cell lists more than one value only when each value is an observed name
# of that same register for that column. Every such cell is pinned here, so a
# regenerated catalog cannot quietly attach the name of a derived value, an
# aggregate or a composite field to a register again.
_MULTI_VALUED_CELLS = {
    (0x02, 0x00, 0x008B, "vaillant_friendly_name"): (
        "Max Flow Set Point Heat Pump",
        "Max Flow Set Point Heat Pump CH",
    ),
    (0x02, 0x01, 0x0008, "vaillant_friendly_name"): (
        "Current target flow temperature",
        "Current target flow temperature heating",
    ),
    (0x02, 0x02, 0x0002, "vaillant_name_vrc720"): (
        "circuit_type",
        "circuit_type_of_mixed_circuit_external",
    ),
    (0x02, 0x02, 0x0002, "vaillant_name_vrc700"): (
        "circuit_type",
        "circuit_type_of_mixed_circuit_external",
    ),
}


def _cell_values(row: dict[str, str], column: str) -> tuple[str, ...]:
    cell = row.get(column) or ""
    return tuple(cell.split(" | ")) if cell else ()


def test_cells_use_only_the_canonical_separator() -> None:
    """Values are separated by exactly " | ", the only form the loader splits.

    Any other use of the pipe character would make a multi-valued cell load as
    one value and slip past the checks below, so it is rejected outright.
    """
    for row in _rows():
        for column in _ANNOTATION_COLUMNS:
            for value in _cell_values(row, column):
                where = f"{row['opcode']}/{row['group']}/{row['register']} {column}"
                assert "|" not in value, f"{where}: non-canonical separator in {row[column]!r}"
                assert value and value == value.strip(), f"{where}: malformed value"


def test_multi_valued_cells_are_exactly_the_pinned_set() -> None:
    found: dict[tuple[int, int, int, str], tuple[str, ...]] = {}
    for row in _rows():
        key = (int(row["opcode"], 0), int(row["group"], 0), int(row["register"], 0))
        for column in _ANNOTATION_COLUMNS:
            values = _cell_values(row, column)
            if len(values) > 1:
                found[(*key, column)] = values
    assert found == _MULTI_VALUED_CELLS


def test_values_are_not_repeated_within_a_cell() -> None:
    """Each name is recorded once, in one spelling.

    Values that differ only in letter case, spacing or punctuation are the
    same name, not separate values.
    """
    for row in _rows():
        for column in _ANNOTATION_COLUMNS:
            values = _cell_values(row, column)
            folded = ["".join(ch for ch in value.lower() if ch.isalnum()) for value in values]
            assert len(set(folded)) == len(folded), (
                f"{row['opcode']}/{row['group']}/{row['register']} {column}: {values}"
            )


def test_vaillant_names_are_attached_to_one_register_per_family() -> None:
    for column in ("vaillant_name_vrc720", "vaillant_name_vrc700"):
        # Partitioned by opcode: OP02 and OP06 are independent namespaces, so
        # the same name may be recorded once in each.
        seen: dict[tuple[str, str], tuple[str, str]] = {}
        for row in _rows():
            here = (row["group"], row["register"])
            for value in _cell_values(row, column):
                key = (row["opcode"], value)
                assert seen.setdefault(key, here) == here, (
                    f"{column}: {value!r} (opcode {row['opcode']}) is attached to both "
                    f"{seen[key]} and {here}"
                )
