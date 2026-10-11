from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

from rich.console import Console
from textual.widgets import DataTable, Static, Tree

from helianthus_vrc_explorer.ui import browse_textual

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def _detail_text(app) -> str:
    content = app.query_one("#detail-content", Static).content
    console = Console(file=io.StringIO(), width=160, legacy_windows=False)
    console.print(content)
    return console.file.getvalue()


def test_system_information_row_shows_value_and_evidence_with_applicability_note() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "system_information": [
                {
                    "identifier": "0x0000",
                    "name": "circuit_count",
                    "value": 2,
                    "raw_hex": "00000040",
                }
            ],
        },
        "operations": {},
    }

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            tree = app.query_one("#browse-tree", Tree)
            tree.select_node(app._tree_node_by_ref["b524:section:system_information"])
            await pilot.pause()
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            text = _detail_text(app)
            assert "circuit_count" in text
            assert "No artifact entry for this row." in text

    asyncio.run(exercise())


def test_operation_read_row_shows_decode_qualification_section_in_the_running_app() -> None:
    from dataclasses import asdict

    from helianthus_vrc_explorer.protocol.b524_schedules import parse_event_response

    selector = {"profile": "zone", "instance": 2, "address": 1, "weekday_code": 255}
    records = [
        {
            "operation": "GetEvent",
            "opcode_hex": "0x09",
            "selector": selector,
            "request_payload_hex": "09030201ff",
            "response_raw_hex": "03ff000648908fff",
            "response_state": "value",
            "decode_qualification": "schema_unqualified",
            "decoded": asdict(parse_event_response(bytes.fromhex("03ff000648908fff"))),
        }
    ]
    artifact = {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x26"},
        "operations": {},
        "b524_operation_reads": records,
    }

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            section_node = next(
                node
                for node in app._store.tree_nodes
                if node.level == "section" and node.section_key == "operation_09"
            )
            tree = app.query_one("#browse-tree", Tree)
            tree.select_node(app._tree_node_by_ref[section_node.node_id])
            await pilot.pause()
            app._selected_node_id = section_node.node_id
            app._refresh_table()
            await pilot.pause()
            assert app._table_rows, "expected operation-read field rows"
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            text = _detail_text(app)
            assert "DECODE QUALIFICATION" in text
            assert "schema_unqualified" in text
            assert "LIMITS" not in text
            assert "NAMES" not in text
            assert "ENUMERATION" not in text

    asyncio.run(exercise())


def test_op06_remote_row_renders_full_panel_with_remote_opcode() -> None:
    # Uses the repository's dual-namespace fixture: a device_slots group
    # with a direct register child is a navigation-only node in
    # browse_query._has_navigation_children, so the row-bearing selection is
    # the instance node one level down (b524:inst:device_slots:...).
    artifact = json.loads((FIXTURES / "dual_namespace_scan.json").read_text(encoding="utf-8"))

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            node = next(
                item
                for item in app._store.tree_nodes
                if item.level == "instance"
                and item.section_key == "device_slots"
                and item.namespace_key == "0x06"
            )
            tree = app.query_one("#browse-tree", Tree)
            tree.select_node(app._tree_node_by_ref[node.node_id])
            await pilot.pause()
            app._selected_node_id = node.node_id
            app._refresh_table()
            await pilot.pause()
            assert app._table_rows, "expected OP06 remote register rows"
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            text = _detail_text(app)
            assert "0x06" in text
            assert "GATES" in text

    asyncio.run(exercise())


def test_b516_row_shows_real_unit_and_no_limits_or_names() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15"},
        "operations": {},
        "b516_dump": {
            "entries": {
                "system:total:heating": {
                    "period": "system",
                    "source": "total",
                    "usage": "heating",
                    "label": "Total heating energy",
                    "value": 1234,
                    "value_kwh": 1234,
                    "request_hex": "aa",
                    "reply_hex": "bb",
                }
            }
        },
    }

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            node = next(
                item
                for item in app._store.tree_nodes
                if item.protocol == "b516" and item.level == "group"
            )
            tree = app.query_one("#browse-tree", Tree)
            tree.select_node(app._tree_node_by_ref[node.node_id])
            await pilot.pause()
            app._selected_node_id = node.node_id
            app._refresh_table()
            await pilot.pause()
            assert app._table_rows
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            text = _detail_text(app)
            assert "kWh" in text
            assert "LIMITS" not in text
            assert "NAMES" not in text

    asyncio.run(exercise())


def test_006_artifact_fixture_opens_with_the_panel_without_crashing() -> None:
    artifact = json.loads((FIXTURES / "vrc720_full_scan.json").read_text(encoding="utf-8"))

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            if app._table_rows:
                table.move_cursor(row=0)
                await pilot.pause()
                # Must render without raising, regardless of content.
                _detail_text(app)

    asyncio.run(exercise())
