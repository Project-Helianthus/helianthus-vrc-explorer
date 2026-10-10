from __future__ import annotations

import asyncio

from textual.widgets import DataTable, Static, Tree

from helianthus_vrc_explorer.ui import browse_textual


def test_browse_table_columns_constant_is_register_and_value() -> None:
    assert browse_textual.BROWSE_TABLE_COLUMNS == ("Register", "Value")


def _artifact() -> dict[str, object]:
    return {
        "schema_version": "2.3",
        "meta": {"destination_address": "0x15"},
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "Controller",
                        "instances": {
                            "0x01": {
                                "present": True,
                                "registers": {
                                    "0x0002": {
                                        "read_opcode": "0x02",
                                        "type": "UCH",
                                        "value": 2,
                                        "raw_hex": "02",
                                        "value_display": "NORMAL (2)",
                                        "flags": 3,
                                        "flags_access": "writable_visible",
                                        "register_class": "config",
                                        "response_state": "active",
                                        "ebusd_name": "Hc1OperatingMode",
                                    },
                                    "0x0003": {
                                        "read_opcode": "0x02",
                                        "type": "UCH",
                                        "value": 1,
                                        "raw_hex": "7f",
                                        "flags": 1,
                                        "flags_access": "read_only_visible",
                                        "register_class": "config",
                                        "response_state": "active",
                                        "ebusd_name": "Hc1OtherSwitch",
                                    },
                                },
                            }
                        },
                    }
                }
            }
        },
    }


async def _select_local_instance(app, pilot) -> None:
    node = next(
        item
        for item in app._store.tree_nodes
        if item.level == "instance"
        and item.namespace_key == "0x02"
        and item.group_key == "0x09"
        and item.instance_key == "0x01"
    )
    app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[node.node_id])
    await pilot.pause()
    app._selected_node_id = node.node_id
    app.action_tab_config()
    await pilot.pause()
    app._refresh_table()


def test_refresh_table_writes_exactly_two_cells_per_row_with_folded_marker() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            assert tuple(str(col.label) for col in table.columns.values()) == (
                "Register",
                "Value",
            )
            assert len(app._table_rows) == 2
            for row_index in range(len(app._table_rows)):
                cells = table.get_row_at(row_index)
                assert len(cells) == len(browse_textual.BROWSE_TABLE_COLUMNS)

    asyncio.run(exercise())


def test_search_matches_ebusd_name_access_flags_and_raw_hex_before_and_after_column_shrink() -> (
    None
):
    """Pinned against 0.6.0 columns and must keep passing after Step 1's shrink.

    ``search_blob`` already carries ``ebusd_name``, ``access_flags`` and
    ``raw_hex`` independently of the rendered columns (``browse_hydration.py``),
    so removing table columns must not break ``/`` search, even though search
    was never exercised by a test before this one.
    """
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()

            # Match on ebusd_name ("Hc1OtherSwitch").
            app._search.target = "table"
            app._on_search_entered("hc1otherswitch")
            await pilot.pause()
            row = app._table_rows[table.cursor_row]
            assert row.register_key == "0x0003"
            assert "Match 1/1" in str(app.query_one("#status", Static).render())

            # Match on access_flags ("writable_visible").
            app._on_search_entered("writable_visible")
            await pilot.pause()
            row = app._table_rows[table.cursor_row]
            assert row.register_key == "0x0002"

            # Match on raw_hex ("ab").
            app._on_search_entered("7f")
            await pilot.pause()
            row = app._table_rows[table.cursor_row]
            assert row.register_key == "0x0003"

    asyncio.run(exercise())
