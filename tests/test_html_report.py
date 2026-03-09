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
    assert "hideAbsent" in html
    assert "ebusd: " in html


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

    assert "B555 Dump" in html
    assert "No B555 dump in artifact." in html
    assert "request_hex=" in html
    assert '"zone":"0x00"' in html
    assert '"hc":"0x00"' in html


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

    assert "B516 Dump" in html
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

    assert "B516 Dump" in html
    assert "No B516 dump in artifact." in html
    assert "No B516 entries in artifact." in html
    assert '"system.gas.heating"' in html
    assert '"request_hex":"1000ffff04030030"' in html
    assert '"reply_hex":"00aabb040300300000c842"' in html
    assert '"value_kwh":0.1' in html
    assert '"value_wh":100.0' in html
    assert '"echo_period":"0x0"' in html


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
    assert "activeNamespaceByGroup" in html
    assert '"label":"local"' in html
    assert '"label":"remote"' in html


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
