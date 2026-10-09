import asyncio
import copy
import json

import pytest
from textual.widgets import DataTable, Input, Static, Tabs, Tree

from helianthus_vrc_explorer.protocol.b524_schedules import (
    parse_event_response,
    parse_event_setpoint_response,
)
from helianthus_vrc_explorer.ui import browse_textual
from helianthus_vrc_explorer.ui.b524_operation_reads import (
    operation_edit_export,
    operation_read_views,
)


def _records(instance=2):
    from dataclasses import asdict

    selector = {"profile": "zone", "instance": instance, "address": 1, "weekday_code": 255}
    return [
        {
            "operation": "GetEvent",
            "opcode_hex": "0x09",
            "selector": selector,
            "request_payload_hex": f"0903{instance:02x}01ff",
            "response_raw_hex": "03ff000648908fff",
            "response_state": "value",
            "decode_qualification": "schema_unqualified",
            "decoded": asdict(parse_event_response(bytes.fromhex("03ff000648908fff"))),
        },
        {
            "operation": "GetEventSetPoint",
            "opcode_hex": "0x0B",
            "selector": selector,
            "request_payload_hex": f"0b03{instance:02x}01ff",
            "response_raw_hex": "0020212223242526",
            "response_state": "value",
            "decode_qualification": "schema_unqualified",
            "decoded": asdict(
                parse_event_setpoint_response(bytes.fromhex("0020212223242526"), "zone")
            ),
        },
    ]


def test_export_uses_selected_setpoint_values_and_exact_pair():
    records = _records(1) + _records(2)
    document = operation_edit_export(
        records, selector=records[-1]["selector"], operation="SetEventSetPoint"
    )
    assert document["values"] == [32, 33, 34, 35, 36, 37, 38]
    assert document["selector"]["instance"] == 2
    assert document["expected_before_raw_hex"] == ["03ff000648908fff", "0020212223242526"]
    records.append(copy.deepcopy(records[-1]))
    with pytest.raises(ValueError, match="exactly one"):
        operation_edit_export(
            records, selector=records[-1]["selector"], operation="SetEventSetPoint"
        )


def test_duplicate_replay_observations_remain_distinct_in_view():
    records = _records()
    artifact = {"b524_operation_reads": records + copy.deepcopy(records)}
    views = operation_read_views(artifact)
    assert len({(view.request_payload_hex, view.selector_key) for view in views}) == 4


def test_in_memory_decoded_tuples_show_all_event_times_and_timer_slots():
    from dataclasses import asdict

    from helianthus_vrc_explorer.protocol.b524_schedules import parse_timer_response

    records = _records()
    records.append(
        {
            "opcode_hex": "0x03",
            "selector": {"channel": "dhw", "instance": 0, "weekday": 0},
            "request_payload_hex": "0301000100",
            "response_state": "value",
            "decoded": asdict(parse_timer_response(bytes.fromhex("00000612909090"))),
        }
    )
    views = operation_read_views({"b524_operation_reads": records})
    assert len([name for name, _ in views[0].fields if name.startswith("event_value_")]) == 7
    assert ("slot_1", "00:00–01:00") in views[-1].fields
    assert ("slot_3", "unused (0x90/0x90)") in views[-1].fields


@pytest.mark.parametrize("destination", ["0x75", 0x26])
def test_browser_edits_previews_and_exports_without_native_write(tmp_path, destination):
    records = _records()
    artifact = {
        "schema_version": "2.3",
        "meta": {"destination_address": destination},
        "operations": {},
        "b524_operation_reads": records,
    }
    output = tmp_path / "edit.json"

    async def exercise():
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            leaf = next(
                node
                for node in app._store.tree_nodes
                if node.section_key == "operation_0b" and node.level == "group"
            )
            app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[leaf.node_id])
            await pilot.pause()
            assert app.query_one("#browse-tabs", Tabs).display is False
            app.query_one("#browse-table", DataTable).focus()
            await pilot.press("e")
            await pilot.pause()
            dialog = app.screen
            assert isinstance(dialog, browse_textual._OperationEditDialog)
            values = dialog.query_one("#operation-values", Input)
            values.value = "[40,33,34,35,36,37,38]"
            dialog.query_one("#operation-export-path", Input).value = str(output)
            await pilot.click("#operation-preview-button")
            preview = str(dialog.query_one("#operation-preview-content", Static).render())
            assert "0c030201ff28212223242526" in preview
            target = int(destination, 0) if isinstance(destination, str) else destination
            assert f"0x{target:02X}" in preview
            await pilot.click("#operation-export-button")
            document = json.loads(output.read_text())
            assert document["values"][0] == 40
            assert document["expected_before_raw_hex"] == ["03ff000648908fff", "0020212223242526"]
            values.value = "[256,33,34,35,36,37,38]"
            await pilot.click("#operation-preview-button")
            assert "Invalid edit" in str(
                dialog.query_one("#operation-edit-status", Static).render()
            )
            assert json.loads(output.read_text())["values"][0] == 40

    asyncio.run(exercise())


def test_browser_timer_with_unused_slots_opens_editor_and_exports_null(tmp_path):
    from dataclasses import asdict

    from helianthus_vrc_explorer.protocol.b524_schedules import parse_timer_response

    raw = "00002490909090"
    artifact = {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15"},
        "operations": {},
        "b524_operation_reads": [
            {
                "operation": "ReadTimer",
                "opcode_hex": "0x03",
                "selector": {"channel": "dhw", "instance": 0, "weekday": 0},
                "request_payload_hex": "0301000100",
                "response_raw_hex": raw,
                "response_state": "value",
                "decode_qualification": "profile_vrc700",
                "decoded": asdict(parse_timer_response(bytes.fromhex(raw))),
            }
        ],
    }
    output = tmp_path / "timer.json"

    async def exercise():
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            leaf = next(
                node
                for node in app._store.tree_nodes
                if node.section_key == "operation_03" and node.level == "group"
            )
            app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[leaf.node_id])
            await pilot.pause()
            app.query_one("#browse-table", DataTable).focus()
            await pilot.press("e")
            await pilot.pause()
            dialog = app.screen
            assert isinstance(dialog, browse_textual._OperationEditDialog)
            assert json.loads(dialog.query_one("#operation-values", Input).value) == [
                [0, 36],
                None,
                None,
            ]
            dialog.query_one("#operation-export-path", Input).value = str(output)
            await pilot.click("#operation-export-button")
            document = json.loads(output.read_text())
            assert document["values"] == [[0, 36], None, None]
            assert document["expected_before_raw_hex"] == [raw]

    asyncio.run(exercise())
