from __future__ import annotations

from copy import deepcopy

from helianthus_vrc_explorer.schema.parameter_descriptions import (
    attach_bundled_descriptions,
    export_description_baseline,
)
from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _artifact() -> dict:
    return {
        "schema_version": "2.3",
        "meta": {
            "identity": {"model": "test_controller", "firmware": "SW 0100 / HW 0200"},
            "profile_context": {"profile": "controller_b524", "api_version": 1.0},
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x02": {
                        "instances": {
                            "0x01": {
                                "registers": {
                                    "0x0009": {
                                        "type": "EXP",
                                        "parameter_description": {
                                            "qualification": "matched",
                                            "description_opcode": "0x01",
                                            "read_opcode": "0x02",
                                            "group": "0x02",
                                            "instance": "0x01",
                                            "register": "0x0009",
                                            "type": "EXP",
                                            "width": 4,
                                            "min": 20.0,
                                            "max": 70.0,
                                            "step": 0.5,
                                            "reply_hex": "0209000000a04100008c420000003f",
                                        },
                                    }
                                }
                            },
                        }
                    }
                }
            }
        },
    }


def test_baseline_export_omits_private_identity_and_raw_capture() -> None:
    a = _artifact()
    a["meta"]["identity"]["serial"] = "private-serial"
    bundle = export_description_baseline(a)
    assert len(bundle["descriptions"]) == 1
    assert "serial" not in str(bundle)
    assert "reply_hex" not in str(bundle)
    assert "destination_address" not in str(bundle)
    assert bundle["descriptions"][0]["instance"] == "0x01"


def test_offline_bundle_is_available_but_not_current_target_verification() -> None:
    a = _artifact()
    bundle = export_description_baseline(a)
    entry = a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"]["0x0009"]
    del entry["parameter_description"]
    attach_bundled_descriptions(a, bundle=bundle)
    cached = entry["bundled_parameter_description"]
    assert cached["qualification"] == "bundled"
    assert cached["verification"] == "not_verified"
    assert cached["max"] == 70.0
    assert "parameter_description" not in entry


def test_live_match_difference_and_unavailable_are_distinct() -> None:
    a = _artifact()
    bundle = export_description_baseline(a)
    entry = a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"]["0x0009"]
    attach_bundled_descriptions(a, bundle=bundle)
    assert entry["bundled_parameter_description"]["verification"] == "matches"
    entry["parameter_description"]["max"] = 60.0
    attach_bundled_descriptions(a, bundle=bundle)
    assert entry["bundled_parameter_description"]["verification"] == "differs"
    assert entry["parameter_description"]["max"] == 60.0
    entry["parameter_description"] = {"qualification": "unavailable"}
    attach_bundled_descriptions(a, bundle=bundle)
    assert entry["bundled_parameter_description"]["verification"] == "unavailable"


def test_profile_firmware_and_namespace_instance_do_not_leak_constraints() -> None:
    a = _artifact()
    bundle = export_description_baseline(a)
    entry = a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"]["0x0009"]
    attach_bundled_descriptions(a, bundle=bundle)
    a["meta"]["identity"]["firmware"] = "SW 0200 / HW 0200"
    attach_bundled_descriptions(a, bundle=bundle)
    assert entry["bundled_parameter_description"]["verification"] == "profile_mismatch"
    assert entry["parameter_description"]["target_profile_match"] is False
    assert export_description_baseline(a)["descriptions"] == []
    a["operations"]["0x06"] = deepcopy(a["operations"]["0x02"])
    a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x02"] = deepcopy(
        a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]
    )
    attach_bundled_descriptions(a, bundle=bundle)
    for op, ii in (("0x06", "0x01"), ("0x02", "0x02")):
        other = a["operations"][op]["groups"]["0x02"]["instances"][ii]["registers"]["0x0009"]
        assert "bundled_parameter_description" not in other


def test_incomplete_scan_export_retains_only_valid_matched_metadata() -> None:
    a = _artifact()
    a["meta"]["incomplete"] = True
    bundle = export_description_baseline(a)
    assert bundle["coverage"]["complete_scan"] is False
    entry = a["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"]["0x0009"]
    entry["parameter_description"]["register"] = "0x0008"
    assert export_description_baseline(a)["descriptions"] == []


def test_remote_slot_firmware_change_invalidates_prior_description() -> None:
    a = _artifact()
    a["operations"]["0x06"] = deepcopy(a["operations"].pop("0x02"))
    regs = a["operations"]["0x06"]["groups"]["0x02"]["instances"]["0x01"]["registers"]
    desc = regs["0x0009"]["parameter_description"]
    desc.update(read_opcode="0x06", description_opcode="0x07")
    regs["0x0002"] = {"type": "HEX:1", "raw_hex": "15", "value": "0x15"}
    regs["0x0004"] = {"type": "FW", "raw_hex": "080500", "value": "08.05.00"}
    bundle = export_description_baseline(a)
    assert len(bundle["descriptions"]) == 1
    assert bundle["descriptions"][0]["profile"]["device_firmware_raw"] == "080500"
    attach_bundled_descriptions(a, bundle=bundle)
    assert regs["0x0009"]["bundled_parameter_description"]["verification"] == "matches"
    regs["0x0004"]["raw_hex"] = "090500"
    attach_bundled_descriptions(a, bundle=bundle)
    assert regs["0x0009"]["bundled_parameter_description"]["verification"] == "profile_mismatch"
    assert desc["target_profile_match"] is False
    assert export_description_baseline(a)["descriptions"] == []


def test_remote_slot_with_unknown_firmware_cannot_qualify_baseline() -> None:
    a = _artifact()
    a["operations"]["0x06"] = deepcopy(a["operations"].pop("0x02"))
    regs = a["operations"]["0x06"]["groups"]["0x02"]["instances"]["0x01"]["registers"]
    regs["0x0009"]["parameter_description"].update(read_opcode="0x06", description_opcode="0x07")
    regs["0x0002"] = {"type": "HEX:1", "raw_hex": "15", "value": "0x15"}
    assert export_description_baseline(a)["descriptions"] == []


def test_offline_html_and_browse_display_baseline_without_live_description(monkeypatch) -> None:
    artifact = _artifact()
    bundle = export_description_baseline(artifact)
    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    monkeypatch.setattr(
        "helianthus_vrc_explorer.schema.parameter_descriptions.load_description_baseline",
        lambda: bundle,
    )
    html = render_html_report(artifact)
    assert "Bundled baseline" in html
    assert '"verification":"not_verified"' in html
    store = BrowseStore.from_artifact(artifact)
    row = next(row for row in store.rows if row.register_key == "0x0009")
    assert row.parameter_description is None
    assert "Bundled (not_verified)" in row.description_text
    assert "20.0..70.0" in row.description_text
