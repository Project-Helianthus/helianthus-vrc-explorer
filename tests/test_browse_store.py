from __future__ import annotations

from helianthus_vrc_explorer.ui.browse_store import BrowseStore


def _sample_artifact() -> dict[str, object]:
    return {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
        },
        "groups": {
            "0x00": {
                "name": "Regulator Parameters",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {
                                "value": 1.0,
                                "raw_hex": "00",
                                "flags_access": "user_rw",
                                "read_opcode": "0x02",
                                "ebusd_name": "regulator_param_1",
                            },
                            "0x0002": {
                                "value": 2.0,
                                "value_display": "HEATING_OR_COOLING (HEATING)",
                                "raw_hex": "0102",
                                "flags_access": "technical_rw",
                                "read_opcode": "0x06",
                                "myvaillant_name": "limit_value",
                            },
                            "0x0003": {
                                "value": 3.0,
                                "raw_hex": "03",
                                "flags_access": "stable_ro",
                                "read_opcode": "0x02",
                            },
                        }
                    }
                },
            }
        },
    }


def test_browse_store_builds_rows_and_left_tree_uses_only_myvaillant_name() -> None:
    store = BrowseStore.from_artifact(_sample_artifact())
    assert store.device_label == "Device 0x15"
    assert len(store.rows) == 3

    by_register = {row.register_key: row for row in store.rows}
    assert by_register["0x0001"].tab == "config"
    assert by_register["0x0002"].tab == "config_limits"
    assert by_register["0x0003"].tab == "state"
    assert by_register["0x0001"].name == "0x0001"
    assert by_register["0x0002"].name == "limit_value"
    assert by_register["0x0002"].value_text == "HEATING_OR_COOLING (HEATING)"
    assert by_register["0x0003"].name == "0x0003"
    assert by_register["0x0001"].myvaillant_name == ""
    assert by_register["0x0001"].ebusd_name == "regulator_param_1"
    assert by_register["0x0002"].myvaillant_name == "limit_value"
    assert by_register["0x0002"].ebusd_name == ""

    by_node_id = {node.node_id: node for node in store.tree_nodes}
    assert by_node_id["proto:b524"].label == "B524"
    assert by_node_id["b524:group:0x00"].label == "Regulator Parameters (0x00)"
    assert not any(node.level == "register" for node in store.tree_nodes)


def test_browse_store_filters_rows_for_tree_selection() -> None:
    store = BrowseStore.from_artifact(_sample_artifact())
    protocol_node = next(node for node in store.tree_nodes if node.level == "protocol")
    group_node = next(
        node for node in store.tree_nodes if node.level == "group" and node.group_key == "0x00"
    )

    assert len(store.rows_for_selection(None, tab="state")) == 1
    assert len(store.rows_for_selection(protocol_node, tab="config")) == 1
    assert len(store.rows_for_selection(group_node, tab="config_limits")) == 1
    assert len(store.rows_for_selection(group_node, tab="state")) == 1


def test_browse_store_prefers_register_class_over_flags_access_for_tab() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T12:00:00Z"},
        "groups": {
            "0x02": {
                "name": "Heating Circuits",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0021": {
                                "value": 37,
                                "raw_hex": "25",
                                "flags_access": "technical_rw",
                                "register_class": "state",
                            }
                        }
                    }
                },
            }
        },
    }
    store = BrowseStore.from_artifact(artifact)
    row = store.rows[0]
    assert row.register_key == "0x0021"
    assert row.tab == "state"


def test_browse_store_hides_b524_protocol_when_no_groups_present() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T12:00:00Z"},
        "groups": {},
        "b509_dump": {
            "meta": {"ranges": ["0x2700..0x2700"]},
            "devices": {
                "0x15": {
                    "registers": {
                        "0x2700": {
                            "addr": "0x2700",
                            "reply_hex": "00",
                            "raw_hex": "",
                            "value": None,
                            "error": None,
                        }
                    }
                }
            },
        },
    }

    store = BrowseStore.from_artifact(artifact)
    node_ids = {node.node_id for node in store.tree_nodes}
    assert "proto:b524" not in node_ids
    assert "proto:b509" in node_ids


def test_browse_store_treats_unknown_singleton_group_as_singleton() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T12:00:00Z"},
        "groups": {
            "0x69": {
                "name": "Unknown",
                "descriptor_observed": 1.0,
                "instances": {
                    "0x00": {
                        "present": True,
                        "registers": {
                            "0x0000": {
                                "value": 0.0,
                                "raw_hex": "00",
                                "flags_access": "stable_ro",
                                "read_opcode": "0x02",
                            }
                        },
                    }
                },
            }
        },
    }

    store = BrowseStore.from_artifact(artifact)
    assert not any(node.level == "instance" for node in store.tree_nodes)
