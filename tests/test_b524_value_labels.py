from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.replay_trace import replay_trace_to_artifact
from helianthus_vrc_explorer.scanner.scan import _apply_contextual_enum_annotations
from helianthus_vrc_explorer.schema.b524_value_labels import b524_value_label
from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _entry(value: int) -> dict[str, object]:
    return {
        "value": value,
        "raw_hex": f"{value:02x}",
        "response_state": "active",
        "flags_access": "state_stable",
    }


def _artifact() -> dict[str, Any]:
    return {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15"},
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "Ventilation",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0002": _entry(2),
                                    "0x0004": _entry(10),
                                },
                            },
                            "0x01": {
                                "present": True,
                                "registers": {
                                    "0x0002": _entry(99),
                                    "0x0004": _entry(7),
                                },
                            },
                        },
                    },
                    "0x02": {
                        "name": "Heating Circuits",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {"0x0002": _entry(2)},
                            }
                        },
                    },
                }
            },
            "0x06": {
                "groups": {
                    "0x09": {
                        "name": "Remote Slot",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {
                                    "0x0002": _entry(2),
                                    "0x0004": _entry(1),
                                },
                            }
                        },
                    }
                }
            },
        },
    }


def _registers(
    artifact: dict[str, Any], *, opcode: str, group: str, instance: str
) -> dict[str, dict[str, Any]]:
    return artifact["operations"][opcode]["groups"][group]["instances"][instance]["registers"]


def test_value_label_catalog_is_exact_and_operation_scoped() -> None:
    expected = {
        (0x0002, 1): "TIME_CONTROLLED",
        (0x0002, 2): "NORMAL",
        (0x0002, 3): "REDUCED",
        (0x0004, 0): "REGULAR",
        (0x0004, 1): "BOOST",
        (0x0004, 7): "HOLIDAY",
        (0x0004, 10): "SYSTEM_OFF",
    }
    for (register, value), label in expected.items():
        annotation = b524_value_label(opcode=0x02, group=0x09, register=register, value=value)
        assert annotation is not None
        assert annotation.label == label
        assert annotation.qualification == "candidate_unqualified"

    assert b524_value_label(opcode=0x02, group=0x09, register=0x0002, value=99) is None
    assert b524_value_label(opcode=0x06, group=0x09, register=0x0002, value=2) is None
    assert b524_value_label(opcode=0x02, group=0x02, register=0x0002, value=2) is None


def test_scan_annotations_are_scoped_and_preserve_raw_unknown_values() -> None:
    artifact = _artifact()

    _apply_contextual_enum_annotations(artifact)

    local = _registers(artifact, opcode="0x02", group="0x09", instance="0x00")
    assert local["0x0002"]["value"] == 2
    assert local["0x0002"]["raw_hex"] == "02"
    assert local["0x0002"]["enum_resolved_name"] == "NORMAL"
    assert local["0x0002"]["value_display"] == "2 (NORMAL)"
    assert local["0x0002"]["value_label_qualification"] == "candidate_unqualified"
    assert local["0x0004"]["enum_resolved_name"] == "SYSTEM_OFF"
    assert local["0x0004"]["value_display"] == "10 (SYSTEM_OFF)"

    unknown = _registers(artifact, opcode="0x02", group="0x09", instance="0x01")
    assert unknown["0x0002"]["value"] == 99
    assert unknown["0x0002"]["raw_hex"] == "63"
    assert "enum_resolved_name" not in unknown["0x0002"]
    assert "value_display" not in unknown["0x0002"]
    assert unknown["0x0004"]["value_display"] == "7 (HOLIDAY)"

    remote = _registers(artifact, opcode="0x06", group="0x09", instance="0x00")
    unrelated = _registers(artifact, opcode="0x02", group="0x02", instance="0x00")
    assert "value_display" not in remote["0x0002"]
    assert "value_display" not in remote["0x0004"]
    assert unrelated["0x0002"]["enum_resolved_name"] == "FIXED_VALUE"
    assert "value_label_qualification" not in unrelated["0x0002"]


def test_replay_artifact_applies_only_the_local_ventilation_label(tmp_path: Path) -> None:
    trace_path = tmp_path / "ventilation.trace"
    trace_path.write_text(
        "\n".join(
            [
                "2026-10-09T10:00:00.000000Z INIT features=0x01",
                "2026-10-09T10:00:00.050000Z START initiator=0xF7",
                "2026-10-09T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=020009000200",
                "2026-10-09T10:00:00.150000Z #1 PARSED_PROTO len=5 hex=0109020002",
                "2026-10-09T10:00:00.200000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=060009000200",
                "2026-10-09T10:00:00.250000Z #2 PARSED_PROTO len=5 hex=0109020002",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    artifact = replay_trace_to_artifact(trace_path)
    local = _registers(artifact, opcode="0x02", group="0x09", instance="0x00")
    remote = _registers(artifact, opcode="0x06", group="0x09", instance="0x00")
    assert local["0x0002"]["value"] == 2
    assert local["0x0002"]["raw_hex"] == "02"
    assert local["0x0002"]["value_display"] == "2 (NORMAL)"
    assert "value_display" not in remote["0x0002"]


def test_browser_hydrates_ventilation_labels_without_namespace_bleed() -> None:
    store = BrowseStore.from_artifact(_artifact())
    rows = {
        (row.namespace_key, row.group_key, row.instance_key, row.register_key): row
        for row in store.rows
    }

    assert rows[("0x02", "0x09", "0x00", "0x0002")].value_text == "2 (NORMAL)"
    assert (
        rows[("0x02", "0x09", "0x00", "0x0002")].value_label_qualification
        == "candidate_unqualified"
    )
    assert "no write authority" in rows[("0x02", "0x09", "0x00", "0x0002")].description_text
    assert rows[("0x02", "0x09", "0x00", "0x0004")].value_text == "10 (SYSTEM_OFF)"
    assert rows[("0x02", "0x09", "0x01", "0x0002")].value_text == "99"
    assert rows[("0x06", "0x09", "0x00", "0x0002")].value_text == "2"
    assert rows[("0x02", "0x02", "0x00", "0x0002")].value_text == "2"


def test_html_embeds_ventilation_labels_without_namespace_bleed() -> None:
    html = render_html_report(_artifact())
    match = re.search(
        r'<script id="artifact-data" type="application/json">(.*?)</script>', html, re.S
    )
    assert match is not None
    embedded = json.loads(match.group(1))

    local = _registers(embedded, opcode="0x02", group="0x09", instance="0x00")
    remote = _registers(embedded, opcode="0x06", group="0x09", instance="0x00")
    unrelated = _registers(embedded, opcode="0x02", group="0x02", instance="0x00")
    assert local["0x0002"]["value_display"] == "2 (NORMAL)"
    assert local["0x0004"]["value_display"] == "10 (SYSTEM_OFF)"
    assert "value_label_qualification=${entry.value_label_qualification}" in html
    assert "value_display" not in remote["0x0002"]
    assert "value_display" not in unrelated["0x0002"]
