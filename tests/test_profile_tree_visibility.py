from copy import deepcopy

import pytest

from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _instance(present):
    return {
        "present": present,
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


def test_tree_shows_only_present_remote_slots_in_profile_range():
    instances = {f"0x{ii:02x}": _instance(ii in {0, 1, 9, 10}) for ii in range(11)}
    instances["0x02"] = _instance(None)
    artifact = {
        "operations": {"0x06": {"groups": {"0x0f": {"name": "old", "instances": instances}}}}
    }
    original = deepcopy(artifact)
    store = BrowseStore.from_artifact(artifact)
    nodes = [n for n in store.tree_nodes if n.level == "instance"]
    assert [n.instance_key for n in nodes] == ["0x01"]
    assert nodes[0].label == "Remote Slot 1 (0x01)"
    # Hidden probes remain available as raw diagnostic rows, not tree instances.
    assert len(store.rows) == len(instances)
    assert artifact == original


def test_circuit_tree_uses_one_to_nine_and_virtual_water_nine():
    instances = {f"0x{ii:02x}": _instance(ii in {0, 1, 3, 9, 10}) for ii in range(11)}
    for inst in instances.values():
        inst["registers"]["0x0001"]["read_opcode"] = "0x02"
    artifact = {
        "operations": {"0x02": {"groups": {"0x02": {"name": "old", "instances": instances}}}}
    }
    store = BrowseStore.from_artifact(artifact)
    nodes = [n for n in store.tree_nodes if n.level == "instance"]
    assert [n.instance_key for n in nodes] == ["0x01", "0x03", "0x09"]
    assert nodes[0].label == "Heating Circuit 1 (0x01)"
    assert nodes[-1].label == "Virtual DHW Slot (0x09)"


@pytest.mark.parametrize(
    "gg,name",
    [
        (0, "System"),
        (1, "Native Domestic Hot Water"),
        (2, "Circuits"),
        (3, "Zones"),
        (4, "Solar Circuit"),
        (5, "Solar Loaded Cylinder"),
        (6, "Device"),
        (7, "Generator"),
        (8, "DeltaT"),
        (9, "Ventilation"),
    ],
)
def test_saved_local_group_names_are_canonical_in_browser_and_html(gg, name):
    ii = "0x01" if gg == 2 else "0x00"
    inst = _instance(True)
    inst["registers"]["0x0001"]["read_opcode"] = "0x02"
    artifact = {
        "operations": {
            "0x02": {"groups": {f"0x{gg:02x}": {"name": "obsolete", "instances": {ii: inst}}}}
        }
    }
    original = deepcopy(artifact)
    store = BrowseStore.from_artifact(artifact)
    assert any(n.level == "group" and n.label == f"{name} (0x{gg:02x})" for n in store.tree_nodes)
    assert name in render_html_report(artifact)
    assert artifact == original


def test_all_missing_device_slots_do_not_turn_parent_into_a_register_leaf():
    artifact = {
        "operations": {"0x06": {"groups": {"0x0f": {"instances": {"0x01": _instance(False)}}}}}
    }
    store = BrowseStore.from_artifact(artifact)
    group = next(n for n in store.tree_nodes if n.level == "group")
    assert not any(n.level == "instance" for n in store.tree_nodes)
    assert store.rows_for_selection(group, tab="state") == []
    assert store.rows  # Raw probes remain available to diagnostic searches.
