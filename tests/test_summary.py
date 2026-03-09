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
                "name": "Radio Sensors VRC7xx",
                "descriptor_observed": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "local",
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
    assert "namespaces local=2, remote=1" in text
    assert "flags_access volatile_ro=0, stable_ro=2, technical_rw=0, user_rw=1" in text
    assert "b555 reads=4 errors=1 programs=2" in text
    assert "local=1, remote=1" in text
    assert "Radio Sensors VRC7xx" in text
    assert "2/2" not in text
