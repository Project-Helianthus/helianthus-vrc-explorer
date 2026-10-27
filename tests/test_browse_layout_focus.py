"""Browser layout, focus cue, scrollbar, wrapping and tree-glyph regressions (issue 320).

The pilot tests run the real Textual app headlessly with the scan identity header
present and a register list that is taller than the right pane. They assert the
laid-out geometry, the computed styles and the text that actually reaches the screen.
"""

from __future__ import annotations

import asyncio
import html
import io
import re
from typing import Any

import pytest
from rich.console import Console
from textual.color import Color
from textual.geometry import Region
from textual.widgets import DataTable, Static, Tree

from helianthus_vrc_explorer.ui import browse_textual
from helianthus_vrc_explorer.ui.browse_detail import DetailRow, DetailSection
from tests.test_browse_detail_panel import _artifact, _select_local_instance

FOCUS = Color.parse("#fce94f")
FOCUS_TABS_BACKGROUND = Color.parse("#204a87")
DIM_BORDER = Color.parse("#555753")
DIM_TITLE = Color.parse("#888a85")
SCROLL_TRACK = Color.parse("#3a4042")
SCROLL_THUMB = Color.parse("#729fcf")
FIRST_EXTRA = 0x20
LAST_EXTRA_COUNT = 40


def _registers(artifact: dict[str, Any]) -> dict[str, Any]:
    return artifact["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"]


def _tall_artifact(*, long_value: bool = False) -> dict[str, Any]:
    """An artifact with the scan identity header and 42 rows in the local instance."""

    artifact = _artifact()
    artifact["meta"]["identity"].update(
        device="Synthetic Controller", model="Synthetic VRC", firmware="0507"
    )
    registers = _registers(artifact)
    for index in range(LAST_EXTRA_COUNT):
        registers[f"0x{FIRST_EXTRA + index:04x}"] = {
            "read_opcode": "0x02",
            "type": "UCH",
            "value": index,
            "raw_hex": f"{index:02x}",
            "flags": 1,
            "flags_access": "read_only_visible",
            "register_class": "config",
            "response_state": "active",
        }
    if long_value:
        # Wider than the right pane, so the table needs its horizontal scrollbar.
        registers[f"0x{FIRST_EXTRA:04x}"]["value_display"] = "a-very-long-value-" * 8
    return artifact


def _screen_text(app: Any) -> str:
    """Plain text of everything painted on the screen (public screenshot export)."""

    svg = app.export_screenshot()
    runs = re.findall(r"<text[^>]*>(.*?)</text>", svg)
    text = html.unescape("".join(runs)).replace("\xa0", " ")
    assert text.strip()
    return text


def _last_label() -> str:
    return f"0x{FIRST_EXTRA + LAST_EXTRA_COUNT - 1:04x}"


# --- 5. childless tree nodes are leaves ---------------------------------------------------


def _tree_artifact() -> dict[str, Any]:
    artifact = _artifact()
    operations = artifact["operations"]
    operations["0x02"]["groups"]["0x00"] = {"name": "System", "instances": {}}
    operations["0x02"]["groups"]["0x01"] = {"name": "Native Domestic Hot Water", "instances": {}}
    operations["0x06"] = {"groups": {"0x00": {"name": "System", "instances": {}}}}
    return artifact


def test_tree_nodes_without_children_are_leaves_and_parents_keep_the_glyph() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tree_artifact(), allow_write=False)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            nodes = [app._tree_node_by_ref[ref.node_id] for ref in app._store.tree_nodes]
            leaves = [node for node in nodes if not node.children]
            parents = [node for node in nodes if node.children]
            assert leaves and parents  # the fixture exercises both kinds
            for node in nodes:
                assert node.allow_expand is bool(node.children), node.label
            labels = {str(node.label) for node in leaves}
            assert {"System (0x00)", "Native Domestic Hot Water (0x01)"} <= labels
            assert "OP02 GetParameter" in {str(node.label) for node in parents}

    asyncio.run(exercise())


def test_leaf_tree_node_renders_no_glyph_and_selecting_it_does_not_toggle() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tree_artifact(), allow_write=False)
        async with app.run_test(size=(200, 50)) as pilot:
            tree = app.query_one("#browse-tree", Tree)
            section = next(
                app._tree_node_by_ref[ref.node_id]
                for ref in app._store.tree_nodes
                if ref.level == "section" and ref.label.startswith("OP02")
            )
            section.expand()
            await pilot.pause()
            lines = [
                strip.text
                for strip in tree.render_lines(Region(0, 0, tree.size.width, tree.size.height))
            ]
            leaf_line = next(line for line in lines if "Native Domestic Hot Water" in line)
            parent_line = next(line for line in lines if "OP02 GetParameter" in line)
            assert "▶" not in leaf_line and "▼" not in leaf_line
            assert "▼" in parent_line  # expanded parent keeps its triangle

            leaf = next(
                app._tree_node_by_ref[ref.node_id]
                for ref in app._store.tree_nodes
                if ref.label.startswith("Native Domestic Hot Water")
            )
            tree.select_node(leaf)
            await pilot.pause()
            assert leaf.is_expanded is False
            assert app._selected_node_id == leaf.data  # the selection itself still works

    asyncio.run(exercise())


# --- 1. the last table row is visible -----------------------------------------------------


@pytest.mark.parametrize("size", [(120, 40), (160, 30)])
@pytest.mark.parametrize("long_value", [False, True], ids=["fits-width", "needs-hscroll"])
def test_last_table_row_is_visible_when_the_table_does_not_fit(
    size: tuple[int, int], long_value: bool
) -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tall_artifact(long_value=long_value), allow_write=False)
        async with app.run_test(size=size) as pilot:
            await _select_local_instance(app, pilot)
            assert app.query_one("#identity-header").display is True
            table = app.query_one("#browse-table", DataTable)
            right = app.query_one("#right-pane")
            assert table.row_count == LAST_EXTRA_COUNT + 2
            # The table really is taller than its viewport, so scrolling is required.
            assert table.virtual_size.height > table.scrollable_content_region.height

            # Tabs row + table + (optional horizontal scrollbar) fit the pane's content area.
            assert table.region.bottom <= right.content_region.bottom
            assert table.region.right <= right.content_region.right
            assert app.query_one("#browse-tabs").region.bottom <= table.region.y

            table.focus()
            table.move_cursor(row=table.row_count - 1)
            await pilot.pause()
            assert table.show_horizontal_scrollbar is long_value
            assert table.cursor_row == table.row_count - 1
            # The cursor row is the last scroll position and lies inside the clipped pane.
            assert table.scroll_y == table.max_scroll_y
            text = _screen_text(app)
            assert _last_label() in text
            assert f"0x{FIRST_EXTRA + LAST_EXTRA_COUNT - 2:04x}" in text

    asyncio.run(exercise())


# --- 2. themed scrollbars, no horizontal bar when the content fits ------------------------


def test_scrollbars_follow_the_palette_and_horizontal_bar_hides_when_content_fits() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tall_artifact(), allow_write=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            detail = app.query_one("#detail-pane")
            tree = app.query_one("#browse-tree", Tree)
            for widget in (table, detail, tree, app.screen):
                styles = widget.styles
                assert styles.scrollbar_size_vertical == 1
                assert styles.scrollbar_size_horizontal == 1
                assert styles.scrollbar_color.hex == SCROLL_THUMB.hex
                assert styles.scrollbar_background.hex == SCROLL_TRACK.hex
                assert styles.scrollbar_corner_color.hex == SCROLL_TRACK.hex
                assert styles.scrollbar_color_hover.hex == FOCUS.hex
                assert styles.scrollbar_color_active.hex == FOCUS.hex

            # Both scrollable panes have more rows than fit, so the vertical bar is there ...
            assert table.show_vertical_scrollbar is True
            assert detail.show_vertical_scrollbar is True
            assert table.vertical_scrollbar.thickness == 1
            # ... and nothing needs the horizontal bar, so no grey block along the bottom.
            assert table.show_horizontal_scrollbar is False
            assert detail.show_horizontal_scrollbar is False

    asyncio.run(exercise())


def test_horizontal_scrollbar_is_thin_and_inside_the_table_when_content_is_wider() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tall_artifact(long_value=True), allow_write=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            assert table.virtual_size.width > table.size.width
            assert table.show_horizontal_scrollbar is True
            assert table.horizontal_scrollbar.thickness == 1
            assert (
                table.horizontal_scrollbar.region.bottom
                <= app.query_one("#right-pane").content_region.bottom
            )

    asyncio.run(exercise())


# --- 3. focus cue when cycling Tab --------------------------------------------------------

_PANES = ("tree-pane", "right-pane", "detail-pane", "watch-dock")


def _is_focused_look(app: Any, pane_id: str) -> bool:
    styles = app.query_one(f"#{pane_id}").styles
    return (
        styles.border_top == ("heavy", FOCUS)
        and styles.border_title_color.hex == FOCUS.hex
        and "bold" in str(styles.border_title_style)
    )


def _is_dim_look(app: Any, pane_id: str) -> bool:
    styles = app.query_one(f"#{pane_id}").styles
    return (
        styles.border_top == ("round", DIM_BORDER)
        and styles.border_title_color.hex == DIM_TITLE.hex
        and "bold" not in str(styles.border_title_style)
    )


def _tabs_row_is_highlighted(app: Any) -> bool:
    return app.query_one("#browse-tabs").styles.background.hex == FOCUS_TABS_BACKGROUND.hex


def _table_cursor_is_bright(app: Any) -> bool:
    table = app.query_one("#browse-table", DataTable)
    return table.get_component_styles("datatable--cursor").background.hex == FOCUS.hex


# (focused widget id, pane that owns the bright border, tabs row lit, table cursor lit)
_TAB_CYCLE = (
    ("browse-tabs", "right-pane", True, False),
    ("browse-table", "right-pane", False, True),
    ("detail-pane", "detail-pane", False, False),
    ("watch-dock", "watch-dock", False, False),
    ("browse-tree", "tree-pane", False, False),
)


def _assert_only_focused(app: Any, widget_id: str, pane: str, tabs_lit: bool, cursor: bool) -> None:
    assert app.focused is not None and app.focused.id == widget_id
    for pane_id in _PANES:
        if pane_id == pane:
            assert _is_focused_look(app, pane_id), f"{pane_id} lacks the focused look"
            assert not _is_dim_look(app, pane_id)
        else:
            assert _is_dim_look(app, pane_id), f"{pane_id} is not dimmed while unfocused"
            assert not _is_focused_look(app, pane_id)
    assert _tabs_row_is_highlighted(app) is tabs_lit
    assert _table_cursor_is_bright(app) is cursor


def test_every_section_gets_a_focused_look_while_the_others_are_dimmed() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tall_artifact(), allow_write=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _select_local_instance(app, pilot)
            app._focus_tree()
            await pilot.pause()
            _assert_only_focused(app, "browse-tree", "tree-pane", False, False)
            # The panes are titled, so the border title colour has something to colour.
            assert [str(app.query_one(f"#{pane}").border_title) for pane in _PANES] == [
                "Navigation",
                "Registers",
                "Detail",
                "Watchlist",
            ]
            for widget_id, pane, tabs_lit, cursor in _TAB_CYCLE:
                await pilot.press("tab")
                await pilot.pause()
                _assert_only_focused(app, widget_id, pane, tabs_lit, cursor)
            for widget_id, pane, tabs_lit, cursor in reversed(_TAB_CYCLE[:-1]):
                await pilot.press("shift+tab")
                await pilot.pause()
                # Walking back lands on the previous section of the cycle.
                _assert_only_focused(app, widget_id, pane, tabs_lit, cursor)

    asyncio.run(exercise())


# --- 4. detail values wrap instead of ending in an ellipsis -------------------------------


def _render(renderable: Any, width: int) -> str:
    console = Console(file=io.StringIO(), width=width, legacy_windows=False, color_system=None)
    console.print(renderable)
    return console.file.getvalue()  # type: ignore[attr-defined]


def test_long_detail_values_wrap_at_the_pane_width_without_an_ellipsis() -> None:
    long_name = "heatpump_max_flow_dhw_setpoint_extra_nam"
    assert len(long_name) == 40
    long_address = "b524/0x02/0x00fc/" + "0123456789abcdef" * 3
    sections = (
        DetailSection(
            title="",
            rows=(
                DetailRow("Name", long_name),
                DetailRow("Address", long_address),
                DetailRow("Interpreted", "value " + "x" * 45),
                DetailRow("Validated readback", "k=" + "v" * 30, note="n" * 40),
            ),
        ),
    )
    rendered = _render(browse_textual._render_detail_sections(sections), width=38)
    assert "…" not in rendered
    lines = rendered.splitlines()
    assert all(len(line) <= 38 for line in lines)
    # The value column starts where the name starts; read it back top to bottom.
    column = lines[0].index("heatpump")
    values = "".join(line[column:].strip() for line in lines)
    assert values == (
        long_name + long_address + "value" + "x" * 45 + "k=" + "v" * 30 + "(" + "n" * 40 + ")"
    )
    # The 40-character name takes two lines inside the 38-cell pane instead of one cut line.
    first, second = (line[column:].strip() for line in lines[:2])
    assert first and second and first + second == long_name


def test_detail_pane_shows_the_full_register_name_on_screen() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_tall_artifact(), allow_write=False)
        async with app.run_test(size=(120, 40)) as pilot:
            await _select_local_instance(app, pilot)
            table = app.query_one("#browse-table", DataTable)
            table.focus()
            table.move_cursor(
                row=next(i for i, row in enumerate(app._table_rows) if row.register_key == "0x0002")
            )
            await pilot.pause()
            row = app._selected_table_row()
            assert row is not None
            name = row.myvaillant_name or row.name or row.register_key
            content = app.query_one("#detail-content", Static)
            # The name is longer than the value column of the 38-cell pane.
            assert len(name) > content.size.width * 3 // 5
            strips = content.render_lines(Region(0, 0, content.size.width, content.size.height))
            lines = [strip.text for strip in strips]
            assert not any("…" in line for line in lines)
            assert name in "".join("".join(lines).split())
            assert sum(1 for line in lines if name[:6] in line or name[-4:] in line) >= 2

    asyncio.run(exercise())
