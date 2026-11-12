from __future__ import annotations

import copy

import pytest

from helianthus_vrc_explorer.ui.register_semantics import (
    entry_display_value_text,
    entry_status_kind,
    entry_status_label,
    entry_status_raw_byte,
    visible_rr_keys,
)


def test_entry_status_kind_distinguishes_absent_dormant_transport_and_decode() -> None:
    assert entry_status_kind({"flags_access": "absent", "error": None}) == "absent"
    assert (
        entry_status_kind({"reply_hex": "", "flags_access": "dormant", "error": None}) == "dormant"
    )
    assert entry_status_kind({"response_state": "empty_reply", "error": None}) == "dormant"
    assert entry_status_kind({"response_state": "timeout", "error": None}) == "transport_failure"
    assert entry_status_kind({"response_state": "nack", "error": None}) == "transport_failure"
    assert entry_status_kind({"error": "timeout"}) == "transport_failure"
    assert (
        entry_status_kind({"error": "transport_error: ERR: arbitration lost"})
        == "transport_failure"
    )
    assert entry_status_kind({"error": "parse_error: bad thing"}) == "decode_error"


def test_entry_display_value_text_uses_semantic_labels_for_absent_and_transport() -> None:
    assert entry_display_value_text({"flags_access": "absent", "error": None}) == "absent"
    assert (
        entry_display_value_text({"error": "transport_error: ERR: arbitration lost"})
        == "transport failure"
    )
    assert (
        entry_display_value_text({"reply_hex": "", "flags_access": "dormant", "error": None})
        == "dormant"
    )
    assert entry_display_value_text({"value": 38.0, "raw_hex": "00001842", "error": None}) == "38"
    assert entry_status_label({"flags_access": "absent", "error": None}) == "Absent / no data"
    assert (
        entry_status_label({"reply_hex": "", "flags_access": "dormant", "error": None})
        == "Dormant (feature inactive)"
    )


def test_visible_rr_keys_trims_rr_zero_and_final_unnamed_absent_tail() -> None:
    instances = {
        "0x00": {
            "registers": {
                "0x0000": {"flags_access": "absent", "error": None},
                "0x0001": {
                    "value": 1,
                    "raw_hex": "01",
                    "flags_access": "state_stable",
                    "error": None,
                },
                "0x0002": {"flags_access": "absent", "error": None},
                "0x0003": {"flags_access": "absent", "error": None},
            }
        }
    }

    assert visible_rr_keys(instances) == ["0x0001"]


def test_visible_rr_keys_keeps_named_absent_rows_and_trims_per_namespace() -> None:
    local_instances = {
        "0x01": {
            "registers": {
                "0x0035": {
                    "value": 1,
                    "raw_hex": "01",
                    "flags_access": "state_stable",
                    "error": None,
                },
                "0x0036": {
                    "value": 2,
                    "raw_hex": "02",
                    "flags_access": "state_stable",
                    "error": None,
                },
            }
        }
    }
    remote_instances = {
        "0x01": {
            "registers": {
                "0x0035": {
                    "register_name": "named_absent_remote",
                    "flags_access": "absent",
                    "error": None,
                },
                "0x0036": {"flags_access": "absent", "error": None},
                "0x0037": {"flags_access": "absent", "error": None},
            }
        }
    }

    assert visible_rr_keys(local_instances) == ["0x0035", "0x0036"]
    assert visible_rr_keys(remote_instances) == ["0x0035"]


_STATUS_ONLY_RECORDS = {
    "explicit_00": {"response_state": "status_only", "reply_hex": "00", "error": None},
    "explicit_ff": {"response_state": "status_only", "reply_hex": "ff", "error": None},
    "explicit_without_reply": {"response_state": "status_only", "error": None},
    "legacy_active_00": {
        "response_state": "active",
        "reply_hex": "00",
        "flags": 0,
        "flags_access": "absent",
        "error": None,
    },
    "legacy_active_ff": {"response_state": "active", "reply_hex": "ff", "error": None},
    "legacy_without_state_00": {"reply_hex": "00", "flags_access": "absent", "error": None},
    "legacy_uppercase_padded_ff": {"reply_hex": " FF ", "error": None},
}


@pytest.mark.parametrize("name", sorted(_STATUS_ONLY_RECORDS))
def test_one_byte_status_is_neutral_and_makes_no_absence_claim(name: str) -> None:
    entry = _STATUS_ONLY_RECORDS[name]
    before = copy.deepcopy(entry)

    assert entry_status_kind(entry) == "status_only"
    assert entry_status_label(entry) == "Status only"
    assert entry_status_label(entry) != "Absent / no data"
    assert entry_display_value_text(entry) != "absent"
    assert entry == before


@pytest.mark.parametrize(
    ("entry", "raw_byte", "display"),
    [
        ({"response_state": "status_only", "reply_hex": "00"}, "00", "status only (00)"),
        ({"response_state": "status_only", "reply_hex": "ff"}, "ff", "status only (ff)"),
        ({"response_state": "active", "reply_hex": "00", "flags_access": "absent"}, "00", None),
        ({"reply_hex": "FF"}, "ff", "status only (ff)"),
        ({"response_state": "status_only"}, None, "status only"),
    ],
)
def test_status_only_display_keeps_the_raw_status_byte(
    entry: dict[str, object], raw_byte: str | None, display: str | None
) -> None:
    assert entry_status_raw_byte(entry) == raw_byte
    expected = display if display is not None else f"status only ({raw_byte})"
    assert entry_display_value_text(entry) == expected


@pytest.mark.parametrize(
    ("entry", "kind", "label"),
    [
        (
            {"response_state": "empty_reply", "reply_hex": ""},
            "dormant",
            "Dormant (feature inactive)",
        ),
        (
            {"response_state": "timeout", "error": "timeout"},
            "transport_failure",
            "Transport failure",
        ),
        ({"response_state": "nack", "error": None}, "transport_failure", "Transport failure"),
        (
            {"response_state": "timeout", "reply_hex": "00", "error": "timeout"},
            "transport_failure",
            "Transport failure",
        ),
        ({"reply_hex": "00", "error": "parse_error: bad"}, "decode_error", "Decode error"),
        ({"flags_access": "absent", "error": None}, "absent", "Absent / no data"),
        (
            {
                "response_state": "active",
                "reply_hex": "0001e3",
                "raw_hex": "e3",
                "value": 227,
                "error": None,
            },
            "ok",
            "OK",
        ),
        (
            {"response_state": "active", "reply_hex": "00", "raw_hex": "0000", "value": 0},
            "ok",
            "OK",
        ),
    ],
)
def test_controls_around_status_only_keep_their_own_classification(
    entry: dict[str, object], kind: str, label: str
) -> None:
    assert entry_status_kind(entry) == kind
    assert entry_status_label(entry) == label
    assert entry_status_raw_byte(entry) is None


def test_status_only_flows_into_unchanged_grade_and_metadata() -> None:
    entry = {
        "response_state": "status_only",
        "reply_hex": "00",
        "evidence_grade": "Hypothesis",
        "acquisition_state": "completed",
        "read_opcode": "0x06",
        "register_name": "synthetic_name",
    }
    before = copy.deepcopy(entry)

    assert entry_status_label(entry) == "Status only"
    assert entry_display_value_text(entry) == "status only (00)"
    assert entry == before


def _ns_instances(first: str, second: str, tail: str) -> dict[str, object]:
    # Synthetic namespace: one instance per selector value, status bytes given per cell.
    def status(raw: str) -> dict[str, object]:
        return {"response_state": "status_only", "reply_hex": raw, "error": None}

    return {
        "0x00": {
            "registers": {
                "0x0001": {"value": 1, "raw_hex": "01", "flags_access": "state_stable"},
                "0x0002": status(first),
                "0x0003": status(second),
                "0x0004": {"flags_access": "absent", "error": None},
                "0x0005": status(tail),
            }
        },
        "0x01": {
            "registers": {
                "0x0002": {"flags_access": "absent", "error": None},
                "0x0003": status(second),
            }
        },
    }


@pytest.mark.parametrize("raw", ["00", "ff"])
def test_status_only_rows_stay_visible_when_the_trailing_policy_would_trim_absent_rows(
    raw: str,
) -> None:
    instances = _ns_instances("00", "ff", raw)

    assert visible_rr_keys(instances) == ["0x0001", "0x0002", "0x0003", "0x0004", "0x0005"]


def test_equal_selector_values_in_two_namespaces_keep_independent_statuses() -> None:
    op02 = _ns_instances("00", "00", "00")
    op06 = _ns_instances("ff", "ff", "ff")

    assert entry_status_raw_byte(op02["0x00"]["registers"]["0x0005"]) == "00"  # type: ignore[index]
    assert entry_status_raw_byte(op06["0x00"]["registers"]["0x0005"]) == "ff"  # type: ignore[index]

    # Changing a status byte in one namespace leaves the other namespace's result untouched.
    op06_snapshot = copy.deepcopy(op06)
    op02["0x00"]["registers"]["0x0005"]["reply_hex"] = "ff"  # type: ignore[index]
    assert entry_status_raw_byte(op02["0x00"]["registers"]["0x0005"]) == "ff"  # type: ignore[index]
    assert op06 == op06_snapshot
    assert entry_status_raw_byte(op06["0x00"]["registers"]["0x0005"]) == "ff"  # type: ignore[index]
    assert entry_status_raw_byte(op06["0x00"]["registers"]["0x0003"]) == "ff"  # type: ignore[index]

    # Absence evidence on a different register or instance does not hide a status-only row.
    only_absent_tail = {
        "0x00": {
            "registers": {
                "0x0001": {"value": 1, "raw_hex": "01"},
                "0x0002": {"flags_access": "absent", "error": None},
            }
        }
    }
    assert visible_rr_keys(only_absent_tail) == ["0x0001"]
    only_absent_tail["0x01"] = {
        "registers": {"0x0002": {"response_state": "status_only", "reply_hex": "00"}}
    }
    assert visible_rr_keys(only_absent_tail) == ["0x0001", "0x0002"]
