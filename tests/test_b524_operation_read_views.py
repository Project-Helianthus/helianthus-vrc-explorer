from helianthus_vrc_explorer.protocol.b524_schedules import parse_timer_response
from helianthus_vrc_explorer.scanner.b524_operation_edit import parse_operation_edit
from helianthus_vrc_explorer.ui.b524_operation_reads import (
    operation_edit_document,
    operation_read_views,
)
from helianthus_vrc_explorer.ui.browse_store import BrowseStore
from helianthus_vrc_explorer.ui.html_report import render_html_report


def _stored_timer_read(*, stored_channel: str, request_address: int, raw_hex: str) -> dict:
    """A 0.6.0-shaped ReadTimer observation: selector.channel is the pre-0.6.1 label."""

    weekday = 0
    return {
        "operation": "ReadTimer",
        "opcode_hex": "0x03",
        "selector": {"channel": stored_channel, "instance": 0, "weekday": weekday},
        "request_payload_hex": bytes((0x03, 0x00, 0, request_address, weekday)).hex(),
        "response_raw_hex": raw_hex,
        "response_state": "value",
        "decode_qualification": "profile_vrc700",
        "selector_correlation": "request_context",
        "request_attempts": 1,
        "decoded": {
            "parameter_config": int(raw_hex[0:2], 16),
            "slots": [
                {"start_raw": int(raw_hex[2:4], 16), "stop_raw": int(raw_hex[4:6], 16)},
                {"start_raw": int(raw_hex[6:8], 16), "stop_raw": int(raw_hex[8:10], 16)},
                {"start_raw": int(raw_hex[10:12], 16), "stop_raw": int(raw_hex[12:14], 16)},
            ],
        },
    }


def test_0_6_0_ventilation_artifact_is_presented_as_noise_reduction() -> None:
    """0.6.0 wrote 'ventilation' for address 0x01, which 0.6.1 calls noise-reduction."""

    raw_hex = "00002490909090"
    record = _stored_timer_read(stored_channel="ventilation", request_address=0x01, raw_hex=raw_hex)
    parse_timer_response(bytes.fromhex(raw_hex))  # sanity: baseline is a valid OP03 response

    views = operation_read_views({"b524_operation_reads": [record]})
    assert len(views) == 1
    assert "channel=noise-reduction" in views[0].selector_label
    assert "channel=ventilation" not in views[0].selector_label
    fields = dict(views[0].fields)
    assert fields.get("channel_source") == "request_bytes"
    assert fields.get("stored_channel") == "ventilation"

    document = operation_edit_document(
        [record],
        operation="WriteTimer",
        values=[[1, 36], None, None],
        destination_address=0x15,
    )
    assert document["selector"]["channel"] == "noise-reduction"
    assert document["expected_before_raw_hex"] == [raw_hex]
    request = parse_operation_edit(document)
    assert request.write_payload[1] == 0x00  # system_type: system timer row
    assert request.write_payload[3] == 0x01  # address: the byte the baseline was actually read at


def test_0_6_0_noise_reduction_artifact_is_presented_as_ventilation() -> None:
    """Mirror case: 0.6.0 wrote 'noise-reduction' for address 0x02, now called ventilation."""

    raw_hex = "00003090909090"
    record = _stored_timer_read(
        stored_channel="noise-reduction", request_address=0x02, raw_hex=raw_hex
    )
    parse_timer_response(bytes.fromhex(raw_hex))

    views = operation_read_views({"b524_operation_reads": [record]})
    assert "channel=ventilation" in views[0].selector_label
    fields = dict(views[0].fields)
    assert fields.get("channel_source") == "request_bytes"
    assert fields.get("stored_channel") == "noise-reduction"

    document = operation_edit_document(
        [record],
        operation="WriteTimer",
        values=[[1, 48], None, None],
        destination_address=0x15,
    )
    assert document["selector"]["channel"] == "ventilation"
    request = parse_operation_edit(document)
    assert request.write_payload[3] == 0x02


def test_unaffected_timer_channel_is_unchanged_control_case() -> None:
    """dhw's mapping never moved; request bytes should agree with the stored name."""

    raw_hex = "00002490909090"
    record = _stored_timer_read(stored_channel="dhw", request_address=0x01, raw_hex=raw_hex)
    record["selector"] = {"channel": "dhw", "instance": 0, "weekday": 0}
    record["request_payload_hex"] = bytes((0x03, 0x01, 0, 0x01, 0)).hex()

    views = operation_read_views({"b524_operation_reads": [record]})
    assert "channel=dhw" in views[0].selector_label
    fields = dict(views[0].fields)
    assert fields.get("channel_source") == "request_bytes"
    assert "stored_channel" not in fields

    document = operation_edit_document(
        [record], operation="WriteTimer", values=[[1, 36], None, None], destination_address=0x15
    )
    assert document["selector"]["channel"] == "dhw"


def test_timer_channel_without_decodable_request_bytes_keeps_stored_name() -> None:
    record = _stored_timer_read(
        stored_channel="ventilation", request_address=0x01, raw_hex="00002490909090"
    )
    record["request_payload_hex"] = ""  # absent/undecodable, as a 0.6.0 artifact might lack it

    views = operation_read_views({"b524_operation_reads": [record]})
    assert "channel=ventilation" in views[0].selector_label
    fields = dict(views[0].fields)
    assert fields.get("channel_source") == "stored_selector_unverified"
    assert "stored_channel" not in fields


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
    document = operation_edit_document(
        records, operation="SetEvent", values=[255] * 7, destination_address=0x26
    )
    assert document["destination_address"] == 0x26
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
    document = operation_edit_document(
        records, operation="SetEventSetPoint", values=[1] * 7, destination_address=0x26
    )
    assert document["destination_address"] == 0x26
    assert document["expected_before_raw_hex"] == [
        "03ff242a30363c42",
        "0300010203040506",
    ]


def test_pairing_rejects_a_baseline_from_another_selector() -> None:
    records = _artifact()["b524_operation_reads"]
    records[1]["selector"] = {"profile": "zone", "instance": 1, "address": 1, "weekday_code": 129}
    try:
        operation_edit_document(
            records, operation="SetEvent", values=[255] * 7, destination_address=0x26
        )
    except ValueError as exc:
        assert "both OP09 and OP0B" in str(exc)
    else:  # pragma: no cover - explicit failure message for the selector invariant
        raise AssertionError("mismatched operation baselines must fail closed")
