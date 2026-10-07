from __future__ import annotations

from copy import deepcopy

import pytest

from helianthus_vrc_explorer.scanner.director import (
    group_name_for_opcode,
    group_namespace_profiles,
)
from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report
from helianthus_vrc_explorer.ui.summary import _compute_summary_rows
from helianthus_vrc_explorer.ui.viewer import _build_sheets


@pytest.mark.parametrize(
    "group,name",
    [
        (1, "Boiler"),
        (2, "Heat Pump"),
        (3, "Air Recovery (VAR) recoVair"),
        (4, "unused"),
        (5, "Wärmepumpe Zubehör Appliance Interface (VWZ-AI)"),
        (6, "Pumpen Module - Solar (VPM-S) auroFLOW"),
        (7, "Pumpen Module - Wasser (VPM-W) aguaFLOW"),
        (8, "Modul Solar (VMS) auroSTEP"),
        (9, "Remote Control Regulators (VRC7xx, VRT38x)"),
        (10, "Remote Control Thermostats (VR9x)"),
        (11, "Functional Modules (VR70) FM3"),
        (12, "Functional Modules (VR71) FM5"),
        (13, "Relay Module (VR41)"),
        (14, "Clock Module"),
        (15, "Base Station"),
    ],
)
def test_saved_artifacts_use_current_remote_names_without_rewriting_evidence(group, name):
    group_key = f"0x{group:02x}"
    artifact = {
        "meta": {},
        "operations": {
            "0x02": {"groups": {group_key: {"name": "preserved local label", "instances": {}}}},
            "0x06": {
                "groups": {
                    group_key: {
                        "name": "obsolete remote label",
                        "instances": {
                            "0x01": {
                                "present": True,
                                "registers": {
                                    "0x0001": {
                                        "read_opcode": "0x06",
                                        "raw_hex": "01",
                                        "value": True,
                                        "type": "BOOL",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    }
                }
            },
        },
    }
    original = deepcopy(artifact)
    assert group_name_for_opcode(group, 6) == name
    assert group_namespace_profiles(group)[6].name == name
    rows = _compute_summary_rows(artifact)
    assert next(row for row in rows if row.namespace_key == "0x06").name == name
    assert next(row for row in rows if row.namespace_key == "0x02").name == "preserved local label"
    sheets = _build_sheets(artifact)
    assert next(sheet for sheet in sheets if sheet.op_key == "0x06").name == name
    assert next(sheet for sheet in sheets if sheet.op_key == "0x02").name == "preserved local label"
    store = BrowseStore.from_artifact(artifact)
    assert any(node.label == f"{name} ({group_key})" for node in store.tree_nodes)
    assert name in render_html_report(artifact)
    assert artifact == original
