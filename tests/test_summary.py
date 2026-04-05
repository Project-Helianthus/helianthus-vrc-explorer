from __future__ import annotations

from pathlib import Path

from rich.console import Console

from helianthus_vrc_explorer.ui.summary import render_summary


def test_render_summary_shows_namespace_totals_and_flags_distribution(tmp_path: Path) -> None:
    artifact = {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
            "scan_duration_seconds": 1.25,
        },
        "groups": {
            "0x00": {
                "name": "Regulator Parameters",
                "descriptor_observed": 3.0,
                "instances": {
                    "0x00": {
                        "present": True,
                        "registers": {
                            "0x0001": {
                                "read_opcode": "0x02",
                                "read_opcode_label": "local",
                                "flags_access": "stable_ro",
                                "error": None,
                            }
                        },
                    }
                },
            },
            "0x09": {
                "name": "Regulators",
                "descriptor_observed": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "local",
                        "group_name": "Unknown 0x09 (local)",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0001": {
                                        "read_opcode": "0x02",
                                        "read_opcode_label": "local",
                                        "flags_access": "stable_ro",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    },
                    "0x06": {
                        "label": "remote",
                        "group_name": "Regulators",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0001": {
                                        "read_opcode": "0x06",
                                        "read_opcode_label": "remote",
                                        "flags_access": "user_rw",
                                        "error": "timeout",
                                    }
                                },
                            }
                        },
                    },
                },
            },
        },
        "b555_dump": {
            "meta": {"read_count": 4, "error_count": 1, "incomplete": False},
            "programs": {"z1_heating": {}, "dhw": {}},
        },
    }

    console = Console(record=True, width=140)

    render_summary(console, artifact, output_path=tmp_path / "artifact.json")

    text = console.export_text()
    assert "namespaces local (0x02)=2, remote (0x06)=1" in text
    assert "flags_access volatile_ro=0, stable_ro=2, technical_rw=0, user_rw=1" in text
    assert "b555 reads=4 errors=1 programs=2" in text
    assert "local (0x02)=1, remote (0x06)=1" in text
    assert "Unknown 0x09 (local) / Regulators" in text
    assert "2/2" not in text


def test_render_summary_shows_b516_stats(tmp_path: Path) -> None:
    artifact = {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
            "scan_duration_seconds": 0.75,
        },
        "groups": {},
        "b516_dump": {
            "meta": {"read_count": 12, "error_count": 2, "incomplete": True},
            "entries": {
                "system.gas.heating": {
                    "label": "System Gas Heating",
                    "period": "system",
                    "source": "gas",
                    "usage": "heating",
                    "request_hex": "1000ffff04030030",
                    "reply_hex": "00",
                    "value_wh": 100.0,
                    "value_kwh": 0.1,
                    "error": None,
                },
                "year.previous.electricity.hot_water": {
                    "label": "Previous Year Electricity Hot Water",
                    "period": "year_previous",
                    "source": "electricity",
                    "usage": "hot_water",
                    "request_hex": "1030ffff03043231",
                    "reply_hex": None,
                    "error": "timeout",
                },
            },
        },
    }

    console = Console(record=True, width=140)

    render_summary(console, artifact, output_path=tmp_path / "artifact.json")

    text = console.export_text()
    assert "b516 reads=12 errors=2 entries=2 incomplete=true" in text


def test_render_summary_namespace_totals_ignore_stale_namespace_labels(tmp_path: Path) -> None:
    artifact = {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
            "scan_duration_seconds": 1.0,
        },
        "groups": {
            "0x02": {
                "name": "Heating Circuits",
                "descriptor_observed": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "remote",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0001": {
                                        "read_opcode": "0x02",
                                        "read_opcode_label": "remote",
                                        "flags_access": "stable_ro",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    },
                    "0x06": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0002": {
                                        "read_opcode": "0x06",
                                        "read_opcode_label": "local",
                                        "flags_access": "stable_ro",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    },
                },
            }
        },
    }

    console = Console(record=True, width=140)
    render_summary(console, artifact, output_path=tmp_path / "artifact.json")
    text = console.export_text()
    assert "namespaces local (0x02)=1, remote (0x06)=1" in text
    assert "remote (0x02)" not in text
    assert "local (0x06)" not in text


def test_render_summary_namespace_totals_use_namespace_container_when_opcode_missing(
    tmp_path: Path,
) -> None:
    artifact = {
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-02-11T12:00:00Z",
            "scan_duration_seconds": 1.0,
        },
        "groups": {
            "0x09": {
                "name": "Regulators",
                "descriptor_observed": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "remote",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0001": {
                                        "read_opcode_label": "remote",
                                        "flags_access": "stable_ro",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    },
                    "0x06": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0002": {
                                        "read_opcode_label": "local",
                                        "flags_access": "stable_ro",
                                        "error": None,
                                    }
                                },
                            }
                        },
                    },
                },
            }
        },
    }

    console = Console(record=True, width=140)
    render_summary(console, artifact, output_path=tmp_path / "artifact.json")
    text = console.export_text()
    assert "namespaces local (0x02)=1, remote (0x06)=1" in text
    assert "remote (0x02)" not in text
    assert "local (0x06)" not in text
