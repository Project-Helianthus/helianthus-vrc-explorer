from __future__ import annotations

from helianthus_vrc_explorer.ui.register_semantics import (
    entry_display_value_text,
    entry_status_kind,
    entry_status_label,
    visible_rr_keys,
)


def test_entry_status_kind_distinguishes_absent_dormant_transport_and_decode() -> None:
    assert (
        entry_status_kind({"reply_hex": "00", "flags_access": "absent", "error": None}) == "absent"
    )
    assert (
        entry_status_kind({"reply_hex": "", "flags_access": "dormant", "error": None}) == "dormant"
    )
    assert entry_status_kind({"error": "timeout"}) == "transport_failure"
    assert (
        entry_status_kind({"error": "transport_error: ERR: arbitration lost"})
        == "transport_failure"
    )
    assert entry_status_kind({"error": "parse_error: bad thing"}) == "decode_error"


def test_entry_display_value_text_uses_semantic_labels_for_absent_and_transport() -> None:
    assert (
        entry_display_value_text({"reply_hex": "00", "flags_access": "absent", "error": None})
        == "absent"
    )
    assert (
        entry_display_value_text({"error": "transport_error: ERR: arbitration lost"})
        == "transport failure"
    )
    assert (
        entry_display_value_text({"reply_hex": "", "flags_access": "dormant", "error": None})
        == "dormant"
    )
    assert entry_display_value_text({"value": 38.0, "raw_hex": "00001842", "error": None}) == "38"
    assert (
        entry_status_label({"reply_hex": "00", "flags_access": "absent", "error": None})
        == "Absent / no data"
    )
    assert (
        entry_status_label({"reply_hex": "", "flags_access": "dormant", "error": None})
        == "Dormant (feature inactive)"
    )


def test_visible_rr_keys_trims_rr_zero_and_final_unnamed_absent_tail() -> None:
    instances = {
        "0x00": {
            "registers": {
                "0x0000": {"reply_hex": "00", "flags_access": "absent", "error": None},
                "0x0001": {"value": 1, "raw_hex": "01", "flags_access": "stable_ro", "error": None},
                "0x0002": {"reply_hex": "00", "flags_access": "absent", "error": None},
                "0x0003": {"reply_hex": "00", "flags_access": "absent", "error": None},
            }
        }
    }

    assert visible_rr_keys(instances) == ["0x0001"]


def test_visible_rr_keys_keeps_named_absent_rows_and_trims_per_namespace() -> None:
    local_instances = {
        "0x01": {
            "registers": {
                "0x0035": {"value": 1, "raw_hex": "01", "flags_access": "stable_ro", "error": None},
                "0x0036": {"value": 2, "raw_hex": "02", "flags_access": "stable_ro", "error": None},
            }
        }
    }
    remote_instances = {
        "0x01": {
            "registers": {
                "0x0035": {
                    "myvaillant_name": "named_absent_remote",
                    "reply_hex": "00",
                    "flags_access": "absent",
                    "error": None,
                },
                "0x0036": {"reply_hex": "00", "flags_access": "absent", "error": None},
                "0x0037": {"reply_hex": "00", "flags_access": "absent", "error": None},
            }
        }
    }

    assert visible_rr_keys(local_instances) == ["0x0035", "0x0036"]
    assert visible_rr_keys(remote_instances) == ["0x0035"]
