from __future__ import annotations

from helianthus_vrc_explorer.ui.html_report import render_html_report


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

    assert "B509 Dump" in html
    assert "Hide timeouts" in html
    assert "ebusd: " in html


def test_html_report_renders_namespace_totals_and_flags_access_for_dual_namespace_groups() -> None:
    artifact = {
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-02-11T00:00:00Z"},
        "groups": {
            "0x09": {
                "name": "Radio Sensors VRC7xx",
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {
                                        "raw_hex": "0000a441",
                                        "type": "EXP",
                                        "value": 20.5,
                                        "error": None,
                                        "flags_access": "stable_ro",
                                        "read_opcode": "0x02",
                                        "read_opcode_label": "local",
                                        "myvaillant_name": "temperature_local",
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
                                    "0x0001": {
                                        "raw_hex": "0000a841",
                                        "type": "EXP",
                                        "value": 21.0,
                                        "error": None,
                                        "flags_access": "user_rw",
                                        "read_opcode": "0x06",
                                        "read_opcode_label": "remote",
                                        "myvaillant_name": "temperature_remote",
                                    }
                                }
                            }
                        },
                    },
                },
            }
        },
    }

    html = render_html_report(artifact, title="test")

    assert "Namespace Totals" in html
    assert "FLAGS Access" in html
    assert "Radio Sensors VRC7xx" in html
    assert '"label":"local"' in html
    assert '"label":"remote"' in html
