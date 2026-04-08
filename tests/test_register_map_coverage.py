from __future__ import annotations

import csv
from pathlib import Path

_CSV_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "helianthus_vrc_explorer"
    / "data"
    / "myvaillant_register_map.csv"
)


def _register_map_rows() -> list[dict[str, str]]:
    csv_path = _CSV_PATH
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_register_map_contains_current_opcode_namespace_rows() -> None:
    rows = _register_map_rows()
    coverage = {
        (row["group"].strip().lower(), (row.get("opcode") or "").strip().lower())
        for row in rows
        if row.get("group") and row.get("opcode")
    }

    assert {
        ("0x08", "0x02"),
        ("0x09", "0x02"),
        ("0x09", "0x06"),
        ("0x0a", "0x02"),
        ("0x0a", "0x06"),
        ("0x0c", "0x06"),
    } <= coverage


def test_register_map_firmware_rows_cover_radio_and_remote_accessories() -> None:
    rows = _register_map_rows()
    fw_rows = {
        (row["group"].strip().lower(), (row.get("opcode") or "").strip().lower())
        for row in rows
        if (row.get("type_hint") or "").strip().upper() == "FW"
    }

    # The wildcard (*,*) firmware row covers all groups at opcode 0x06.
    assert ("*", "0x06") in fw_rows
