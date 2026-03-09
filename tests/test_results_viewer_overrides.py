from __future__ import annotations

import io

from rich.console import Console

from helianthus_vrc_explorer.ui.viewer import (
    apply_row_type_override,
    candidate_type_specs_for_length,
    cycle_type_spec,
    get_row_type_override,
    run_results_viewer,
)


def test_candidate_type_specs_and_cycle() -> None:
    c4 = candidate_type_specs_for_length(4)
    c3 = candidate_type_specs_for_length(3)
    assert c3 == ("HDA:3", "HTI", "FW", "HEX:3")
    assert c4 == ("EXP", "U32", "I32", "HEX:4")
    assert cycle_type_spec(None, c4) == "EXP"
    assert cycle_type_spec("EXP", c4) == "U32"
    assert cycle_type_spec("U32", c4) == "I32"
    assert cycle_type_spec("I32", c4) == "HEX:4"
    assert cycle_type_spec("HEX:4", c4) == "EXP"


def test_apply_row_type_override_persists_and_reparses_values() -> None:
    artifact: dict[str, object] = {
        "meta": {},
        "groups": {
            "0x01": {
                "name": "Test",
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "present": True,
                        "registers": {
                            "0x0005": {
                                "raw_hex": "01000000",
                                "type": "EXP",
                                "value": 0.0,
                                "error": None,
                            }
                        },
                    },
                    "0x01": {
                        "present": True,
                        "registers": {
                            "0x0005": {
                                "raw_hex": "02000000",
                                "type": "EXP",
                                "value": 0.0,
                                "error": None,
                            }
                        },
                    },
                },
            }
        },
    }

    apply_row_type_override(artifact, group_key="0x01", rr_key="0x0005", type_spec="U32")

    assert get_row_type_override(artifact, group_key="0x01", rr_key="0x0005") == "U32"

    groups = artifact["groups"]
    assert isinstance(groups, dict)
    group = groups["0x01"]
    assert isinstance(group, dict)
    instances = group["instances"]
    assert isinstance(instances, dict)
    for ii_key, expected in {"0x00": 1, "0x01": 2}.items():
        instance = instances[ii_key]
        assert isinstance(instance, dict)
        registers = instance["registers"]
        assert isinstance(registers, dict)
        entry = registers["0x0005"]
        assert isinstance(entry, dict)
        assert entry["type"] == "U32"
        assert entry["value"] == expected
        assert entry["error"] is None


def test_apply_row_type_override_can_target_one_namespace_only() -> None:
    artifact: dict[str, object] = {
        "meta": {},
        "groups": {
            "0x09": {
                "name": "Regulators",
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0004": {
                                        "raw_hex": "051226",
                                        "type": "HDA:3",
                                        "value": "2026-12-05",
                                        "error": None,
                                    }
                                }
                            }
                        },
                    },
                    "0x06": {
                        "label": "remote",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0004": {
                                        "raw_hex": "051226",
                                        "type": "HDA:3",
                                        "value": "2026-12-05",
                                        "error": None,
                                    }
                                }
                            }
                        },
                    },
                },
            }
        },
    }

    apply_row_type_override(
        artifact,
        group_key="0x09",
        rr_key="0x0004",
        type_spec="HEX:3",
        namespace_key="0x06",
    )

    assert (
        get_row_type_override(
            artifact,
            group_key="0x09",
            rr_key="0x0004",
            namespace_key="0x06",
        )
        == "HEX:3"
    )

    groups = artifact["groups"]
    assert isinstance(groups, dict)
    group = groups["0x09"]
    assert isinstance(group, dict)
    namespaces = group["namespaces"]
    assert isinstance(namespaces, dict)

    local_entry = namespaces["0x02"]["instances"]["0x00"]["registers"]["0x0004"]
    remote_entry = namespaces["0x06"]["instances"]["0x00"]["registers"]["0x0004"]
    assert local_entry["type"] == "HDA:3"
    assert local_entry["value"] == "2026-12-05"
    assert remote_entry["type"] == "HEX:3"
    assert remote_entry["value"] == "0x051226"


def test_run_results_viewer_requires_stdout_tty(monkeypatch) -> None:
    artifact = {"meta": {}, "groups": {"0x00": {"instances": {}}}}
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    monkeypatch.setattr("sys.stdout", io.StringIO())

    changed = run_results_viewer(Console(force_terminal=True), artifact)

    assert changed is False
