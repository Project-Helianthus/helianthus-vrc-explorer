from __future__ import annotations

import csv
from pathlib import Path

import pytest

from helianthus_vrc_explorer.scanner.director import GROUP_CONFIG
from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap


def test_default_zone_desired_room_setpoint_mapping_uses_rr_0x0022() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    desired = schema.lookup(group=0x03, instance=0x00, register=0x0022)
    assert desired is not None
    assert desired.leaf == "heating_desired_setpoint"

    # RR=0x0014 is a distinct manual setpoint register and must not reuse RR=0x0022 semantics.
    legacy = schema.lookup(group=0x03, instance=0x00, register=0x0014)
    assert legacy is not None
    assert legacy.leaf == "heating_manual_mode_setpoint"


def test_default_heating_circuit_curve_mapping_uses_wildcard_instances() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    curve_ii0 = schema.lookup(group=0x02, instance=0x00, register=0x000F)
    curve_ii2 = schema.lookup(group=0x02, instance=0x02, register=0x000F)
    assert curve_ii0 is not None
    assert curve_ii2 is not None
    assert curve_ii0.leaf == "heating_curve"
    assert curve_ii2.leaf == "heating_curve"


def test_default_heating_circuit_mapping_resolves_ebusd_name_templates() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    flow = schema.lookup(group=0x02, instance=0x01, register=0x0007)
    zone = schema.lookup(group=0x03, instance=0x02, register=0x0016)
    assert flow is not None
    assert zone is not None
    assert flow.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0007) == (
        "Hc2FlowTempDesired"
    )
    assert zone.resolved_ebusd_name(group=0x03, instance=0x02, register=0x0016) == "Zone3Name"


def test_default_heating_circuit_type_mapping_uses_rr_0x0001() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    circuit_type = schema.lookup(group=0x02, instance=0x00, register=0x0001)
    assert circuit_type is not None
    assert circuit_type.leaf == "heating_circuit_type"
    assert circuit_type.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0001) == (
        "Hc2CircuitType"
    )


def test_default_mixer_circuit_type_external_mapping_uses_rr_0x0002() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    mixer_type = schema.lookup(group=0x02, instance=0x00, register=0x0002)
    assert mixer_type is not None
    assert mixer_type.leaf == "mixer_circuit_type_external"
    assert mixer_type.resolved_ebusd_name(group=0x02, instance=0x02, register=0x0002) == (
        "Hc3CircuitType"
    )


def test_default_room_influence_type_mapping_uses_rr_0x0003() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    room_influence = schema.lookup(group=0x02, instance=0x00, register=0x0003)
    assert room_influence is not None
    assert room_influence.leaf == "room_influence_type"
    assert room_influence.register_class == "config"
    assert room_influence.resolved_ebusd_name(group=0x02, instance=0x01, register=0x0003) == (
        "Hc2RoomInfluenceType"
    )


def test_default_hc_new_register_mappings_include_class_hints() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    frost = schema.lookup(group=0x02, instance=0x00, register=0x001D)
    mixer_pos = schema.lookup(group=0x02, instance=0x00, register=0x0021)
    pump_starts = schema.lookup(group=0x02, instance=0x00, register=0x0025)
    assert frost is not None
    assert mixer_pos is not None
    assert pump_starts is not None
    assert frost.leaf == "frost_protection_threshold"
    assert frost.register_class == "config_limits"
    assert mixer_pos.leaf == "mixer_position_percentage"
    assert mixer_pos.register_class == "state"
    assert pump_starts.leaf == "pump_starts_count"
    assert pump_starts.register_class == "state"
    assert pump_starts.type_hint == "U32"


def test_loader_accepts_legacy_six_column_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "legacy.csv"
    csv_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class",
                "0x03,*,0x0016,name,Zone{zone}Name,config",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    schema = MyvaillantRegisterMap.from_path(csv_path)
    entry = schema.lookup(group=0x03, instance=0x02, register=0x0016)

    assert entry is not None
    assert entry.leaf == "name"
    assert entry.type_hint is None
    assert entry.opcode is None


def test_loader_accepts_seven_column_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "seven-column.csv"
    csv_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class,type_hint",
                "0x00,0x00,0x0034,system_date,,state,HDA:3",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    schema = MyvaillantRegisterMap.from_path(csv_path)
    entry = schema.lookup(group=0x00, instance=0x00, register=0x0034)

    assert entry is not None
    assert entry.leaf == "system_date"
    assert entry.type_hint == "HDA:3"
    assert entry.opcode is None


def test_loader_prefers_opcode_specific_rows_and_exposes_type_hint(tmp_path: Path) -> None:
    csv_path = tmp_path / "opcode-aware.csv"
    csv_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class,type_hint,opcode",
                "0x09,*,0x0004,radio_device_firmware_local,,state,FW,0x02",
                "0x09,*,0x0004,radio_device_firmware_remote,,state,FW,0x06",
                "0x09,*,0x000F,radio_room_temperature,,state,,",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    schema = MyvaillantRegisterMap.from_path(csv_path)
    local = schema.lookup(group=0x09, instance=0x01, register=0x0004, opcode=0x02)
    remote = schema.lookup(group=0x09, instance=0x01, register=0x0004, opcode=0x06)
    fallback = schema.lookup(group=0x09, instance=0x01, register=0x000F, opcode=0x06)

    assert local is not None
    assert remote is not None
    assert fallback is not None
    assert local.leaf == "radio_device_firmware_local"
    assert local.type_hint == "FW"
    assert local.opcode == 0x02
    assert remote.leaf == "radio_device_firmware_remote"
    assert remote.type_hint == "FW"
    assert remote.opcode == 0x06
    assert fallback.leaf == "radio_room_temperature"
    assert fallback.opcode is None


def test_loader_rejects_duplicate_group_instance_register_opcode_rows(tmp_path: Path) -> None:
    csv_path = tmp_path / "duplicates.csv"
    csv_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class,type_hint,opcode",
                "0x09,*,0x0004,first,,state,FW,0x06",
                "0x09,*,0x0004,second,,state,FW,0x06",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"Duplicate wildcard mapping"):
        MyvaillantRegisterMap.from_path(csv_path)


def test_radio_firmware_entry_exposes_type_hint_and_opcode() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    entry = schema.lookup(group=0x09, instance=0x01, register=0x0004, opcode=0x06)

    assert entry is not None
    assert entry.leaf == "radio_device_firmware"
    assert entry.type_hint == "FW"
    assert entry.opcode == 0x06


def test_zone_name_suffix_entry_exposes_string_type_hint() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    suffix = schema.lookup(group=0x03, instance=0x00, register=0x0018)
    prefix = schema.lookup(group=0x03, instance=0x00, register=0x0017)

    assert suffix is not None
    assert prefix is not None
    assert suffix.type_hint == "STR:*"
    assert prefix.type_hint == "STR:*"


def test_register_map_minimum_entry_count_and_no_duplicates() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"

    rows: list[tuple[int, str, int, int | None]] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            gg_raw = (row.get("group") or "").strip()
            ii_raw = (row.get("instance") or "").strip()
            rr_raw = (row.get("register") or "").strip()
            leaf = (row.get("leaf") or "").strip()
            if not (gg_raw and ii_raw and rr_raw and leaf):
                continue
            opcode_raw = (row.get("opcode") or "").strip()
            rows.append(
                (int(gg_raw, 0), ii_raw, int(rr_raw, 0), int(opcode_raw, 0) if opcode_raw else None)
            )

    assert len(rows) >= 150
    assert len(rows) == len(set(rows))


def test_register_map_all_groups_represented() -> None:
    csv_path = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    schema = MyvaillantRegisterMap.from_path(csv_path)

    groups_in_csv = {group for (group, _instance, _register, _opcode) in schema._exact} | {
        group for (group, _register, _opcode) in schema._wildcard_instance
    }

    assert groups_in_csv == set(GROUP_CONFIG)


def test_packaged_myvaillant_map_stays_in_sync_with_repo_copy() -> None:
    repo_csv = Path(__file__).resolve().parents[1] / "data" / "myvaillant_register_map.csv"
    packaged_csv = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "helianthus_vrc_explorer"
        / "data"
        / "myvaillant_register_map.csv"
    )
    assert packaged_csv.read_text(encoding="utf-8") == repo_csv.read_text(encoding="utf-8")
