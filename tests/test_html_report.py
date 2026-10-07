from __future__ import annotations

import json
import re
import shutil
import subprocess

import pytest

from helianthus_vrc_explorer.ui.html_report import render_html_report


def test_generated_html_hti_override_decodes_numeric_bytes() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML decoder smoke test")
    html = render_html_report({})
    start = html.index("function parseTypedValue(")
    end = html.index("function formatValue(", start)
    cases = [[0, 0, 0], [15, 5, 37], [16, 16, 32], [23, 59, 58]]
    invalid = [[24, 0, 0], [0, 60, 0], [0, 0, 60], [255, 255, 255], [0, 0]]
    script = html[start:end] + (
        "console.log(JSON.stringify("
        + json.dumps(cases + invalid)
        + '.map(bytes => parseTypedValue("HTI", bytes))));'
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    parsed = json.loads(result.stdout)
    assert [row["value"] for row in parsed[:4]] == [
        "00:00:00",
        "15:05:37",
        "16:16:32",
        "23:59:58",
    ]
    assert all(row["error"] is None for row in parsed[:4])
    assert all(row["value"] is None and row["error"] for row in parsed[4:])


def test_generated_html_fwu_override_preserves_numeric_triplets() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML decoder smoke test")
    html = render_html_report({})
    start = html.index("function parseTypedValue(")
    end = html.index("function formatValue(", start)
    cases = [[2, 17, 0], [12, 1, 0], [1, 15, 0], [255, 255, 255]]
    script = html[start:end] + (
        "console.log(JSON.stringify("
        + json.dumps(cases)
        + '.map(bytes => parseTypedValue("FWU", bytes))));'
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    parsed = json.loads(result.stdout)
    assert [row["value"] for row in parsed[:3]] == ["02.17.00", "12.01.00", "01.15.00"]
    assert all(row["error"] is None for row in parsed[:3])
    assert parsed[3]["value"] is None and parsed[3]["error"]


def test_html_report_preserves_partial_scan_coverage_and_escapes_group_evidence() -> None:
    scan_coverage = {
        "preset": "research",
        "scope": "declared_profile",
        "request_budget": 5,
        "actual_requests": 5,
        "completed": False,
        "unknown_groups": ["</script><script>alert(1)</script>"],
    }
    descriptions = {
        "eligible": 10,
        "scheduled": 5,
        "attempted": 3,
        "matched": 1,
        "unavailable": 1,
        "unqualified": 1,
        "budget_skipped": 5,
        "not_attempted": 2,
        "request_budget": 256,
        "effective_request_budget": 5,
        "by_read_operation": {"0x06": {"eligible": 5, "not_attempted": 2}},
    }
    html = render_html_report(
        {"meta": {"scan_coverage": scan_coverage, "parameter_description_coverage": descriptions}}
    )
    match = re.search(
        r'<script id="artifact-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match is not None
    embedded = json.loads(match.group(1))
    assert embedded["meta"]["scan_coverage"] == scan_coverage
    assert embedded["meta"]["parameter_description_coverage"] == descriptions
    assert "</script><script>alert(1)</script>" not in html
    assert 'key: "scan_coverage"' in html
    assert '"Descriptions not attempted", descriptions.not_attempted' in html
    assert '"scheduled", "attempted"' in html


def test_html_report_supports_b509_tab_and_dual_naming() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x02": {
                "name": "Heating Circuits",
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "present": True,
                        "registers": {
                            "0x0007": {
                                "raw_hex": "00000000",
                                "type": "EXP",
                                "value": 0.0,
                                "error": None,
                                "myvaillant_name": "heating_circuit_flow_setpoint",
                                "ebusd_name": "Hc1FlowTempDesired",
                            }
                        },
                    }
                },
            }
        },
        "b509_dump": {
            "meta": {"ranges": ["0x2700..0x2701"], "read_count": 2, "error_count": 0},
            "devices": {"0x15": {"registers": {"0x2700": {"addr": "0x2700", "reply_hex": "00"}}}},
        },
    }

    html = render_html_report(artifact, title="test")

    assert "PB=B5 SB=09" in html
    assert "Hide timeouts" in html
    assert "hideAbsent" in html
    assert "ebusd: " in html
    assert "Legacy unqualified group-directory artifacts" in html
    assert "OP=02h GetParameter" in html
    assert "OP=06h GetDeviceParameter" in html


def test_html_report_renders_modern_system_information_and_embedded_descriptions() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-10-05T00:00:00Z",
            "system_information": [
                {
                    "identifier": "0x0000",
                    "name": "circuit_count",
                    "value": 2.0,
                    "raw_hex": "00000040",
                    "state": "available",
                },
                {
                    "identifier": "0x0001",
                    "name": "zone_count",
                    "value": None,
                    "raw_hex": "7fc00000",
                    "state": "unavailable",
                },
            ],
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "System",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0002": {
                                        "value": 1,
                                        "raw_hex": "01",
                                        "flags": 2,
                                        "response_state": "active",
                                        "read_opcode": "0x02",
                                        "parameter_description": {
                                            "qualification": "matched",
                                            "description_opcode": "0x01",
                                            "read_opcode": "0x02",
                                            "group": "0x09",
                                            "instance": "0x00",
                                            "register": "0x0002",
                                            "type": "UCH",
                                            "width": 1,
                                            "min": 0,
                                            "max": 4,
                                            "step": 1,
                                            "reply_hex": "090200000401",
                                        },
                                    },
                                    "0x0004": {
                                        "value": 0,
                                        "raw_hex": "00",
                                        "flags": 0,
                                        "response_state": "active",
                                        "read_opcode": "0x02",
                                        "candidate_name": "status_special_function_ventilation",
                                        "candidate_evidence": (
                                            "profile_scoped_reconstruction_recovair_count_nonzero"
                                        ),
                                    },
                                }
                            }
                        },
                    }
                }
            }
        },
    }

    html = render_html_report(artifact, title="test")

    assert "OP=00h ReadSystemInformation" in html
    assert "circuit_count" in html
    assert "raw_hex" in html
    assert "Describe: min=${formatValue(description.min)}" in html
    assert "description_opcode" in html
    assert "Candidate annotation:" in html
    assert "candidate_name=" in html


def test_html_report_supports_b555_tab() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {},
        "b555_dump": {
            "meta": {"read_count": 3, "error_count": 0, "incomplete": False},
            "programs": {
                "z1_heating": {
                    "label": "Z1 Heating",
                    "selector": {"zone": "0x00", "hc": "0x00"},
                    "config": {
                        "request_hex": "a30000",
                        "reply_hex": "000c0a05010c051e00",
                        "status": "0x00",
                        "status_label": "available",
                        "max_slots": 12,
                        "temp_slots": 12,
                        "time_resolution_min": 10,
                    },
                    "slots_per_weekday": {
                        "request_hex": "a40000",
                        "reply_hex": "000100000000000000",
                        "status": "0x00",
                        "status_label": "available",
                        "days": {"monday": 1},
                    },
                    "weekdays": {
                        "monday": {
                            "slots": {
                                "0x00": {
                                    "op": "0xa5",
                                    "request_hex": "a500000000",
                                    "reply_hex": "0000001800e100",
                                    "status": "0x00",
                                    "status_label": "available",
                                    "start_text": "00:00",
                                    "end_text": "24:00",
                                    "temperature_c": 22.5,
                                }
                            }
                        }
                    },
                }
            },
        },
    }

    html = render_html_report(artifact, title="test")

    assert "PB=B5 SB=55" in html
    assert "No B555 dump in artifact." in html
    assert "request_hex=" in html
    assert '"zone":"0x00"' in html
    assert '"hc":"0x00"' in html


def test_html_report_includes_dormant_status_rendering_logic() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x00": {
                "name": "Regulator Parameters",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0006": {
                                "raw_hex": None,
                                "type": None,
                                "value": None,
                                "error": None,
                                "flags_access": "dormant",
                                "reply_hex": "",
                                "read_opcode": "0x02",
                            }
                        }
                    }
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")

    assert "status-dormant" in html
    assert 'if (access === "dormant") return "dormant";' in html
    assert "Dormant (feature inactive)" in html


def test_html_report_register_constraints_has_replay_fallback_path() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {},
        "b524_operations": {
            "register_constraints": [
                {"group": "0x02", "register_selector": "0x01", "reply_hex": "09020100000100020001"}
            ]
        },
    }

    html = render_html_report(artifact, title="test")

    assert "Array.isArray(operations.register_constraints)" in html
    expected = 'register: typeof row.register_selector === "string" ? row.register_selector : "n/a"'
    assert expected in html


def test_html_report_supports_b516_tab() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {},
        "b516_dump": {
            "meta": {"read_count": 1, "error_count": 0, "incomplete": False},
            "entries": {
                "system.gas.heating": {
                    "label": "System Gas Heating",
                    "period": "system",
                    "source": "gas",
                    "usage": "heating",
                    "request_hex": "1000ffff04030030",
                    "reply_hex": "00aabb0403003000004842",
                    "echo_period": "0x0",
                    "echo_source": "0x4",
                    "echo_usage": "0x3",
                    "echo_window": "0x00",
                    "echo_qualifier": "0x0",
                    "value_wh": 50.0,
                    "value_kwh": 0.05,
                    "error": None,
                }
            },
        },
    }

    html = render_html_report(artifact, title="test")

    assert "PB=B5 SB=16" in html
    assert "No B516 dump in artifact." in html
    assert "System Gas Heating" in html
    assert '"period":"system"' in html
    assert '"source":"gas"' in html
    assert '"usage":"heating"' in html
    assert "1000ffff04030030" in html
    assert "00aabb0403003000004842" in html
    assert '"echo_period":"0x0"' in html


def test_html_report_supports_b516_tab_with_raw_evidence() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {},
        "b516_dump": {
            "meta": {"read_count": 2, "error_count": 1, "incomplete": False},
            "entries": {
                "system.gas.heating": {
                    "label": "System Gas Heating",
                    "period": "system",
                    "source": "gas",
                    "usage": "heating",
                    "request_hex": "1000ffff04030030",
                    "reply_hex": "00aabb040300300000c842",
                    "echo_period": "0x0",
                    "echo_source": "0x4",
                    "echo_usage": "0x3",
                    "echo_window": "0x00",
                    "echo_qualifier": "0x0",
                    "value_wh": 100.0,
                    "value_kwh": 0.1,
                    "error": None,
                },
                "year.previous.electricity.hot_water": {
                    "label": "Previous Year Electricity Hot Water",
                    "period": "year_previous",
                    "source": "electricity",
                    "usage": "hot_water",
                    "request_hex": "1030ffff03043131",
                    "reply_hex": "03aabb030400",
                    "error": "parse_error: B516 response must be at least 11 bytes",
                },
            },
        },
    }

    html = render_html_report(artifact, title="test")

    assert "PB=B5 SB=16" in html
    assert "No B516 dump in artifact." in html
    assert "No B516 entries in artifact." in html
    assert '"system.gas.heating"' in html
    assert '"request_hex":"1000ffff04030030"' in html
    assert '"reply_hex":"00aabb040300300000c842"' in html
    assert '"value_kwh":0.1' in html
    assert '"value_wh":100.0' in html
    assert '"echo_period":"0x0"' in html


def test_html_report_renders_flags_access_for_multi_operation_groups() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "System",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {
                                        "raw_hex": "0000a441",
                                        "type": "EXP",
                                        "value": 20.5,
                                        "error": None,
                                        "flags_access": "state_stable",
                                        "read_opcode": "0x02",
                                        "read_opcode_label": "local",
                                        "myvaillant_name": "temperature_local",
                                    }
                                }
                            }
                        },
                    }
                }
            },
            "0x06": {
                "groups": {
                    "0x09": {
                        "name": "Regulators",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {
                                        "raw_hex": "0000a841",
                                        "type": "EXP",
                                        "value": 21.0,
                                        "error": None,
                                        "flags_access": "config_user",
                                        "read_opcode": "0x06",
                                        "read_opcode_label": "remote",
                                        "myvaillant_name": "temperature_remote",
                                    }
                                }
                            }
                        },
                    }
                }
            },
        },
    }

    html = render_html_report(artifact, title="test")

    assert "Namespace Totals" not in html
    assert "cell-flags" in html
    assert "Regulators" in html
    assert "activeNamespaceByGroup" in html
    # v2.3: operations-first, operations are serialized with op_key as key
    assert '"0x02"' in html
    assert '"0x06"' in html


def test_html_report_renders_identity_card_with_star_bold_markers() -> None:
    artifact = {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T00:00:00Z",
            "identity": {
                "device": (
                    "Wireless 720-series Regulator *BA*se *S*tation "
                    "*V*aillant-branded Revision *2* (BASV2)"
                ),
                "model": "Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148",
                "serial": "21213400202621480000000001N7",
                "firmware": "SW 0507 / HW 1704",
            },
        },
        "groups": {},
    }

    html = render_html_report(artifact, title="test")

    assert "Scan Identity" in html
    assert "<strong>BA</strong>se" in html
    assert "<strong>S</strong>tation" in html
    assert "<strong>V</strong>aillant-branded Revision <strong>2</strong>" in html


def test_html_report_does_not_use_single_namespace_identity_sentinel() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x00": {
                "name": "Regulator Parameters",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {
                                "raw_hex": "00",
                                "value": 1,
                                "error": None,
                                "flags_access": "state_stable",
                                "read_opcode": "0x02",
                            }
                        }
                    }
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")
    assert 'namespaceKey || "single"' not in html
    assert '|| "single"' not in html
    assert 'namespaceKey || "0x00"' not in html
    assert ': "0x00"' not in html


def test_html_report_namespace_helpers_are_opcode_key_authoritative() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x09": {
                "name": "Regulators",
                "dual_namespace": True,
                "namespaces": {
                    "0x06": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {
                                        "raw_hex": "0000a841",
                                        "type": "EXP",
                                        "value": 21.0,
                                        "read_opcode": "0x06",
                                        "read_opcode_label": "local",
                                    }
                                }
                            }
                        },
                    }
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")

    assert "function canonicalNamespaceLabel(namespaceKey)" in html
    assert 'if (trimmed === "local") return "0x02";' in html
    assert 'if (trimmed === "remote") return "0x06";' in html
    assert "if (canonical) {" in html
    assert "(${namespaceKey})" in html


def test_html_report_operations_first_direct_lookup_and_scopes_overrides() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x02": {
                "name": "Heating Circuits",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {"raw_hex": "01", "read_opcode": "0x02"},
                            "0x0002": {"raw_hex": "02", "read_opcode": "0x06"},
                        }
                    }
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")

    # Operations-first: JS uses direct operation group lookup, not merging
    assert "function getOperationGroup(opKey, groupKey)" in html
    assert "function groupKeysForOp(opKey)" in html
    assert "function buildGroupTable(instancesObj" in html
    # Deleted merge/split functions must NOT be present
    assert "buildGroupsFromOperations" not in html
    assert "splitInstancesByNamespace" not in html


def test_html_report_legacy_entries_without_read_opcode_present_after_migration() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x02": {
                "name": "Heating Circuits",
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {"raw_hex": "01", "read_opcode": "0x02"},
                            "0x0002": {"raw_hex": "02", "read_opcode": "0x06"},
                            "0x0003": {"raw_hex": "03"},
                        }
                    }
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")

    # Migration adds response_state to entries; check the entry is present
    assert '"0x0003":{' in html
    assert '"raw_hex":"03"' in html
    # Operations-first: direct lookup, no merging
    assert "function getOperationGroup(opKey, groupKey)" in html
    assert "buildGroupsFromOperations" not in html


def test_html_report_browser_presentation_keeps_html_only_corrections() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML status smoke test")
    artifact = {
        "schema_version": "2.3",
        "operations": {
            "0x02": {
                "groups": {
                    "0x00": {"name": "stale", "instances": {}},
                    "0x01": {"name": "stale", "instances": {}},
                }
            }
        },
    }

    html = render_html_report(artifact)

    assert '"0x00":{"0x02":{"name":"Regulator Parameters","rr_max":"0x00FF"}' in html
    assert '"0x01":{"0x02":{"name":"Native Drinkable Hot Water"}' in html
    assert "declared RR_max" in html
    assert (
        "Describe: min=${formatValue(description.min)}, max=${formatValue(description.max)}, "
        "step=${step}, ${codec}"
    ) in html
    assert (
        'case "read_only_visible": return [{text:"read-only",cls:"flag-state"},'
        '{text:"visible",cls:"flag-other"}];'
    ) in html
    assert "read-only hint" not in html
    assert "writable hint" not in html
    assert "transport_failure" in html
    assert 'statusKind !== "transport_failure" && errTxt' in html
    assert 'selectedType.startsWith("STR:")' in html
    assert 'verification === "differs" || verification === "profile_mismatch"' in html

    status_start = html.index("function entryStatusKind(")
    status_end = html.index("function rowHasExplicitName(", status_start)
    flags_start = html.index("function flagBadges(")
    flags_end = html.index("function appendAccessBadges(", flags_start)
    script = (
        html[status_start:status_end]
        + html[flags_start:flags_end]
        + (
            'const transport = entryStatusLabel({error: "transport_error: TransportError"});'
            "console.log(JSON.stringify([transport, "
            'flagBadges("read_only_visible").map((badge) => badge.text)]));'
        )
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    assert json.loads(result.stdout) == ["Transport failure", ["read-only", "visible"]]
