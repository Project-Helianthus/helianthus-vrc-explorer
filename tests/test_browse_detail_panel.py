from __future__ import annotations

import asyncio
import io

from rich.console import Console
from textual.widgets import DataTable, Static, Tree

from helianthus_vrc_explorer.protocol.b524_metadata import decode_parameter_description
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    attach_bundled_descriptions,
    export_description_baseline,
)
from helianthus_vrc_explorer.ui import browse_textual


def _detail_text(app) -> str:
    """Render the #detail-content Static's current Rich renderable to plain text.

    Static.render() returns an opaque Visual wrapper once the content is a
    Rich renderable (rather than a markup string), so tests read the
    original renderable via the `.content` property and render it through a
    plain Console instead of relying on str(widget.render()).
    """
    content = app.query_one("#detail-content", Static).content
    console = Console(file=io.StringIO(), width=160, legacy_windows=False)
    console.print(content)
    return console.file.getvalue()


def _artifact() -> dict[str, object]:
    artifact: dict[str, object] = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "identity": {"eid": "BASV2", "sw": "0507", "hw": "1704"},
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
            },
        },
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
                                        # Built below via decode_parameter_description plus
                                        # export/attach, exactly as a live Describe reply
                                        # would be captured and then rebundled -- not
                                        # hand-crafted limits.
                                        "parameter_description": decode_parameter_description(
                                            bytes.fromhex("090200000501"),
                                            opcode=0x01,
                                            group=0x09,
                                            instance=0x01,
                                            register=0x0002,
                                            type_spec="UCH",
                                        ),
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
    # Round-trip through the export/attach baseline so the 0x0002 register
    # ends up with a profile-qualified bundled_parameter_description (the
    # effective_parameter_description() fallback path), matching what a
    # real artifact carries once scanned, rather than hand-crafted limits.
    baseline = export_description_baseline(artifact)
    attach_bundled_descriptions(artifact, bundle=baseline)
    del artifact["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"][  # type: ignore[index]
        "0x0002"
    ]["parameter_description"]
    return artifact


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
    await pilot.pause()


def test_detail_pane_shows_canonical_name_raw_limits_and_ebusd_name() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            row_index = next(
                index for index, row in enumerate(app._table_rows) if row.register_key == "0x0002"
            )
            table.move_cursor(row=row_index)
            await pilot.pause()

            detail_pane = app.query_one("#detail-pane")
            assert detail_pane.display is True
            text = _detail_text(app)
            assert "0x2" in text or "0x0002" in text
            assert "02" in text
            assert "min=0" in text
            assert "max=5" in text
            assert "Hc1OperatingMode" in text

    asyncio.run(exercise())


def test_moving_cursor_one_row_changes_detail_content() -> None:
    """Pins the new DataTable.RowHighlighted wiring: nothing recomputed the
    panel on cursor movement before this feature."""
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            first_text = _detail_text(app)
            table.move_cursor(row=1)
            await pilot.pause()
            second_text = _detail_text(app)
            assert first_text != second_text

    asyncio.run(exercise())


def test_selecting_navigation_node_empties_table_and_shows_select_hint() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            group_node = next(
                item
                for item in app._store.tree_nodes
                if item.level == "group" and item.group_key == "0x09"
            )
            app.query_one("#browse-tree", Tree).select_node(
                app._tree_node_by_ref[group_node.node_id]
            )
            await pilot.pause()
            text = _detail_text(app)
            assert "Select a register to see its details." in text

    asyncio.run(exercise())


def test_d_toggles_detail_pane_at_wide_width() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            detail_pane = app.query_one("#detail-pane")
            assert detail_pane.display is True
            await pilot.press("d")
            assert detail_pane.display is False
            await pilot.press("d")
            assert detail_pane.display is True

    asyncio.run(exercise())


def test_narrow_width_hides_detail_by_default_and_d_swaps_tree_and_detail() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(100, 40)) as pilot:
            detail_pane = app.query_one("#detail-pane")
            tree_pane = app.query_one("#tree-pane")
            assert app._narrow is True
            assert detail_pane.display is False
            assert tree_pane.display is True

            await pilot.press("d")
            assert detail_pane.display is True
            assert tree_pane.display is False

            await pilot.press("d")
            assert detail_pane.display is False
            assert tree_pane.display is True

    asyncio.run(exercise())


def test_detail_min_width_threshold_is_pinned_at_109_110_111() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)):
            app._apply_layout_mode(109)
            assert app._narrow is True
            app._apply_layout_mode(110)
            assert app._narrow is False
            app._apply_layout_mode(111)
            assert app._narrow is False

    asyncio.run(exercise())


def test_apply_layout_mode_restores_wide_arrangement() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)):
            app._apply_layout_mode(140)
            app._apply_layout_mode(100)
            app._detail_visible = True
            app._apply_layout_mode(140)
            detail_pane = app.query_one("#detail-pane")
            tree_pane = app.query_one("#tree-pane")
            assert app._narrow is False
            assert detail_pane.display is True
            assert tree_pane.display is True

    asyncio.run(exercise())


def test_detail_pane_is_in_focus_cycle_and_pagedown_scrolls_without_moving_cursor() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            # Cycle focus until the detail pane's scroll view is focused.
            found = False
            for _ in range(len(app._focus_order)):
                app.action_focus_next_section()
                await pilot.pause()
                if app._focus_order[app._focus_idx] == "detail":
                    found = True
                    break
            assert found
            cursor_before = table.cursor_row
            await pilot.press("pagedown")
            await pilot.pause()
            assert table.cursor_row == cursor_before

    asyncio.run(exercise())


def test_names_are_presented_under_the_fixed_name_labels() -> None:
    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(row=0)
            await pilot.pause()
            text = _detail_text(app)
            assert "NAMES" in text
            assert "Explorer" in text

    asyncio.run(exercise())


def test_help_dialog_mentions_detail_binding() -> None:
    bindings = {(binding.key, binding.action) for binding in browse_textual._BrowseApp.BINDINGS}
    assert ("d", "toggle_detail") in bindings


def test_panel_shows_editable_row_and_fresh_live_edit_context_entry() -> None:
    """Step 7: the EDIT row states yes/no with the real reason, and once a live
    edit context has been read for the selected row, the panel renders its
    fresh entry (access/baseline) instead of the stale artifact entry --
    without touching the confirmation/write flow itself."""
    from helianthus_vrc_explorer.scanner.b524_parameter_writes import (
        B524NativeIdentity,
        B524ParameterEditContext,
        B524ParameterTarget,
    )

    artifact = _artifact()

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            row_index = next(
                index for index, row in enumerate(app._table_rows) if row.register_key == "0x0002"
            )
            table.move_cursor(row=row_index)
            await pilot.pause()

            text_before = _detail_text(app)
            assert "Editable" in text_before
            assert "yes" in text_before

            row = app._table_rows[row_index]
            fresh_entry = {
                "read_opcode": "0x02",
                "type": "UCH",
                "value": 4,
                "raw_hex": "04",
                "value_display": "SOMETHING_ELSE (4)",
                "flags": 3,
                "flags_access": "writable_visible",
                "response_state": "active",
            }
            app._editing_row_id = row.row_id
            app._live_edit_context = B524ParameterEditContext(
                target=B524ParameterTarget(
                    destination=0x15, opcode=0x02, group=0x09, instance=0x01, register=0x0002
                ),
                entry=fresh_entry,
                profile={},
                identity=B524NativeIdentity(
                    manufacturer=0xB5,
                    eid="BASV2",
                    software_raw_hex="0507",
                    hardware_raw_hex="1704",
                ),
            )
            app._refresh_detail()
            await pilot.pause()
            text_after = _detail_text(app)
            # RAW comes straight from the entry (parameter_value_display may
            # still fall back to "UNKNOWN (n)" for a value outside the
            # bundled catalog's named codes, which is correct, unrelated
            # behaviour); the fresh raw byte is what proves the panel is
            # reading context.entry rather than the stale artifact entry.
            assert "04" in text_after
            assert "RAW" in text_after
            assert text_after != text_before

    asyncio.run(exercise())
