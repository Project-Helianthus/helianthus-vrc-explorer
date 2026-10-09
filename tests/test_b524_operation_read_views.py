from helianthus_vrc_explorer.ui.b524_operation_reads import operation_edit_document
from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _artifact() -> dict:
    return {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15", "scan_timestamp": "2026-01-01T00:00:00Z"},
        "operations": {},
        "b524_operation_reads_schema_version": 1,
        "b524_operation_reads": [
            {
                "operation": "GetEvent",
                "opcode_hex": "0x09",
                "selector": {"profile": "zone", "instance": 0, "address": 1, "weekday_code": 129},
                "request_payload_hex": "0903000181",
                "response_raw_hex": "03ff242a30363c42",
                "response_state": "value",
                "decode_qualification": "schema_unqualified",
                "selector_correlation": "request_context",
                "request_attempts": 1,
                "decoded": {
                    "parameter_config": 3,
                    "start1_raw": 255,
                    "starts": [{"raw": 36, "minutes": 360}],
                },
            },
            {
                "operation": "GetEventSetPoint",
                "opcode_hex": "0x0b",
                "selector": {"profile": "zone", "instance": 0, "address": 1, "weekday_code": 129},
                "request_payload_hex": "0b03000181",
                "response_raw_hex": "",
                "response_state": "empty",
                "decode_qualification": "schema_unqualified",
                "selector_correlation": "request_context",
                "decoded": None,
            },
        ],
    }


def test_operation_selector_is_leaf_and_empty_half_is_preserved() -> None:
    store = BrowseStore.from_artifact(_artifact())
    sections = {node.label for node in store.tree_nodes if node.level == "section"}
    assert {"OP09 GetEvent", "OP0B GetEventSetPoint"} <= sections
    event_section = next(
        node
        for node in store.tree_nodes
        if node.section_key == "operation_09" and node.level == "section"
    )
    assert store.rows_for_selection(event_section, tab="state") == []
    selector = next(
        node
        for node in store.tree_nodes
        if node.section_key == "operation_09" and node.level == "group"
    )
    rows = store.rows_for_selection(selector, tab="state")
    assert rows and all(row.tab == "state" and row.access_flags == "read-only" for row in rows)
    first_value = next(row for row in rows if row.name == "event_value_1")
    assert "0xff (raw)" in first_value.value_text
    assert "00:00" not in first_value.value_text
    assert any(row.value_text == "schema_unqualified" for row in rows)
    empty = [row for row in store.rows if row.section_key == "operation_0b"]
    assert any(row.value_text == "empty" for row in empty)


def test_html_renders_operation_evidence_without_network_actions() -> None:
    html = render_html_report(_artifact())
    assert "OP09 GetEvent" in html
    assert "Qualification" in html
    assert "selector_correlation" in html
    assert "cannot send a native write" in html
    assert "Export offline edit document" in html


def test_event_preview_document_preserves_both_raw_baselines() -> None:
    records = _artifact()["b524_operation_reads"]
    records[1]["response_raw_hex"] = "0300010203040506"
    records[1]["decoded"] = {"parameter_config": 3, "values": [{"raw": 1}]}
    records[1]["response_state"] = "value"
    document = operation_edit_document(records, operation="SetEvent", values=[255] * 7)
    assert document["expected_before_raw_hex"] == [
        "03ff242a30363c42",
        "0300010203040506",
    ]
    assert document["values"][0] == 255


def test_setpoint_preview_baselines_are_always_event_then_setpoint() -> None:
    records = _artifact()["b524_operation_reads"]
    records[1]["response_raw_hex"] = "0300010203040506"
    records[1]["decoded"] = {"parameter_config": 3, "values": [{"raw": 1}]}
    records[1]["response_state"] = "value"
    document = operation_edit_document(records, operation="SetEventSetPoint", values=[1] * 7)
    assert document["expected_before_raw_hex"] == [
        "03ff242a30363c42",
        "0300010203040506",
    ]


def test_pairing_rejects_a_baseline_from_another_selector() -> None:
    records = _artifact()["b524_operation_reads"]
    records[1]["selector"] = {"profile": "zone", "instance": 1, "address": 1, "weekday_code": 129}
    try:
        operation_edit_document(records, operation="SetEvent", values=[255] * 7)
    except ValueError as exc:
        assert "both OP09 and OP0B" in str(exc)
    else:  # pragma: no cover - explicit failure message for the selector invariant
        raise AssertionError("mismatched operation baselines must fail closed")
