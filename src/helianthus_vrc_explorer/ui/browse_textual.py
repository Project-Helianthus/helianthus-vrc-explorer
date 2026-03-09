from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from time import monotonic
from typing import Any

from rich.console import Group
from rich.table import Table
from rich.text import Text

from .browse_models import BrowseTab, RegisterRow, TreeNodeRef
from .browse_store import BrowseStore
from .emphasis import rich_star_bold_text

_ALLOWED_WATCH_INTERVALS: tuple[float, ...] = (0.25, 0.5, 1.0, 2.0, 5.0)
_WRITE_MARK = "✎"


def _fmt_value_text(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def format_watch_interval(seconds: float) -> str:
    if seconds < 1.0:
        return f"{int(seconds * 1000)}ms"
    if seconds.is_integer():
        return f"{int(seconds)}s"
    return f"{seconds:.2f}s"


def parse_watch_interval(raw: str) -> float | None:
    text = raw.strip().lower()
    if not text:
        return None
    if text.endswith("ms"):
        try:
            value = float(text[:-2].strip()) / 1000.0
        except ValueError:
            return None
    elif text.endswith("s"):
        try:
            value = float(text[:-1].strip())
        except ValueError:
            return None
    else:
        try:
            value = float(text)
        except ValueError:
            return None
    for allowed in _ALLOWED_WATCH_INTERVALS:
        if abs(value - allowed) < 1e-9:
            return allowed
    return None


def compute_change_indicator(previous: str, current: str) -> str:
    if previous == current:
        return "-"
    try:
        prev_n = float(previous)
        curr_n = float(current)
    except ValueError:
        return "Δ"
    if curr_n > prev_n:
        return "▲"
    if curr_n < prev_n:
        return "▼"
    return "Δ"


def parse_bool_input(raw: str) -> bool | None:
    text = raw.strip().lower()
    if not text:
        return None
    if text in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "f", "no", "n", "off"}:
        return False
    return None


def _build_identity_header_renderable(artifact: dict[str, object]) -> Group | None:
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        return None
    identity = meta.get("identity")
    if not isinstance(identity, dict):
        identity = meta.get("resolved_identity")
    if not isinstance(identity, dict):
        return None

    rows: list[tuple[str, str]] = []
    for label, key in (
        ("Device", "device"),
        ("Model", "model"),
        ("Serial", "serial"),
        ("Firmware", "firmware"),
    ):
        value = identity.get(key)
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text == "n/a":
            continue
        rows.append((label, text))

    if not rows:
        return None

    table = Table.grid(expand=True)
    table.add_column(style="bold cyan", ratio=1)
    table.add_column(ratio=6)
    for label, value in rows:
        table.add_row(f"{label}:", rich_star_bold_text(value))
    return Group(Text("Scan Identity", style="bold"), table)


@dataclass(slots=True)
class _SearchState:
    query: str = ""
    matches: list[str | int] | None = None
    index: int = -1
    target: str = ""

    def __post_init__(self) -> None:
        if self.matches is None:
            self.matches = []


@dataclass(slots=True)
class _WatchEntry:
    row_id: str
    pinned: bool
    poll_interval_s: float
    next_poll_at: float
    last_poll_at: float
    last_poll_text: str
    current_value: str
    current_raw: str
    previous_value: str
    previous_raw: str
    change_indicator: str


@dataclass(slots=True)
class _PendingWrite:
    row_id: str
    type_spec: str
    old_value_text: str
    old_raw_hex: str
    new_value_text: str
    new_raw_hex: str
    new_value: object


def _tab_id(tab: BrowseTab) -> str:
    return {
        "config": "tab-config",
        "config_limits": "tab-config-limits",
        "state": "tab-state",
    }[tab]


def _tab_from_id(tab_id: str) -> BrowseTab:
    if tab_id == "tab-config":
        return "config"
    if tab_id == "tab-config-limits":
        return "config_limits"
    return "state"


def run_browse_from_artifact(
    artifact: dict[str, object],
    *,
    allow_write: bool,
) -> None:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.events import Key
    from textual.screen import ModalScreen
    from textual.widgets import DataTable, Footer, Header, Input, Label, Static, Tab, Tabs, Tree

    from ..protocol.parser import (
        ValueEncodeError,
        ValueParseError,
        encode_typed_value,
        parse_typed_value,
    )

    class _FocusableStatic(Static):
        can_focus = True

    class _InputDialog(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
            Binding("enter", "submit", "Search"),
        ]
        CSS = """
        _InputDialog {
            align: center middle;
        }
        _InputDialog > Vertical {
            width: 70;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def __init__(self, *, title: str, value: str, hint: str | None = None) -> None:
            super().__init__()
            self._title = title
            self._value = value
            self._hint = hint

        def compose(self) -> ComposeResult:
            children: list[Any] = [Label(self._title), Input(value=self._value, id="value")]
            if self._hint:
                children.append(Static(self._hint, classes="dim"))
            yield Vertical(*children)

        def on_mount(self) -> None:
            field = self.query_one(Input)
            field.focus()
            # Make edits overwrite the default value without requiring manual delete.
            field.select_all()

        def action_cancel(self) -> None:
            self.dismiss(None)

        def action_submit(self) -> None:
            self.dismiss(self.query_one(Input).value.strip())

        def on_input_submitted(self, event: Input.Submitted) -> None:
            self.dismiss(event.value.strip())

    class _HelpDialog(ModalScreen[None]):
        BINDINGS = [Binding("escape", "close", "Close"), Binding("q", "close", "Close")]
        CSS = """
        _HelpDialog {
            align: center middle;
        }
        _HelpDialog > Vertical {
            width: 86;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def compose(self) -> ComposeResult:
            yield Vertical(
                Label("Browse Help"),
                Static(
                    "Tab/Shift+Tab focus | 1/2/3 tabs | Arrow keys navigate\n"
                    "/ search (focused widget) | n/N next/prev match\n"
                    "W watch/unwatch | P pin/unpin | R poll rate\n"
                    "? help | q quit | E write (P2)."
                ),
            )

        def action_close(self) -> None:
            self.dismiss(None)

    class _ConfirmDialog(ModalScreen[bool]):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
            Binding("q", "cancel", "Cancel"),
            Binding("enter", "confirm", "Write"),
            Binding("y", "confirm", "Write"),
        ]
        CSS = """
        _ConfirmDialog {
            align: center middle;
        }
        _ConfirmDialog > Vertical {
            width: 90;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def __init__(
            self,
            *,
            title: str,
            summary_lines: list[str],
        ) -> None:
            super().__init__()
            self._title = title
            self._lines = summary_lines

        def compose(self) -> ComposeResult:
            body = "\n".join(self._lines)
            yield Vertical(Label(self._title), Static(body), Static("Enter/Y=write  Esc/Q=cancel"))

        def action_cancel(self) -> None:
            self.dismiss(False)

        def action_confirm(self) -> None:
            self.dismiss(True)

    class _BrowseApp(App[None]):
        BINDINGS = [
            Binding("tab", "focus_next_section", "Next Focus"),
            Binding("shift+tab", "focus_prev_section", "Prev Focus"),
            Binding("1", "tab_config", "Config"),
            Binding("2", "tab_config_limits", "Config-Limits"),
            Binding("3", "tab_state", "State"),
            Binding("/", "search", "Search"),
            Binding("n", "search_next", "Next Match"),
            Binding("N", "search_prev", "Prev Match"),
            Binding("question_mark", "help", "Help"),
            Binding("w", "toggle_watch", "Watch"),
            Binding("p", "toggle_pin", "Pin"),
            Binding("r", "set_watch_rate", "Rate"),
            Binding("e", "edit_selected", "Edit"),
            Binding("q", "quit", "Quit"),
            Binding("escape", "close_dialog", "Back"),
        ]

        CSS = """
        Screen {
            background: #2e3436;
            color: #eeeeec;
        }
        #identity-header {
            height: auto;
            min-height: 5;
            padding: 0 1;
            border: round #729fcf;
            margin-bottom: 1;
        }
        #main {
            height: 1fr;
        }
        #tree-pane {
            width: 35%;
            border: round #729fcf;
        }
        #right-pane {
            width: 65%;
            border: round #729fcf;
        }
        #watch-dock {
            height: 5;
            border: round #888a85;
        }
        #status {
            height: 1;
            padding: 0 1;
            color: #fce94f;
            background: #555753;
        }
        """

        def __init__(self) -> None:
            super().__init__()
            self._store = BrowseStore.from_artifact(artifact)
            self._node_by_id = {node.node_id: node for node in self._store.tree_nodes}
            self._tree_node_by_ref: dict[str, Any] = {}
            self._focus_order = ["tree", "tabs", "table", "watch"]
            self._focus_idx = 0
            self._selected_node_id = "root"
            self._active_tab: BrowseTab = "config"
            self._table_rows: list[RegisterRow] = []
            self._search = _SearchState()
            self._write_enabled = allow_write
            self._watch: dict[str, _WatchEntry] = {}
            self._editing_watch_row_id: str | None = None
            self._artifact = artifact
            self._editing_row_id: str | None = None
            self._pending_write: _PendingWrite | None = None
            self._written_at: dict[str, str] = {}
            self._identity_header = _build_identity_header_renderable(artifact)

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            if self._identity_header is not None:
                yield Static(self._identity_header, id="identity-header")
            with Horizontal(id="main"):
                with Vertical(id="tree-pane"):
                    yield Tree(self._store.device_label, id="browse-tree")
                with Vertical(id="right-pane"):
                    yield Tabs(
                        Tab("Config", id="tab-config"),
                        Tab("Config-Limits", id="tab-config-limits"),
                        Tab("State", id="tab-state"),
                        id="browse-tabs",
                    )
                    yield DataTable(id="browse-table")
            yield _FocusableStatic("Watchlist: reserved for P1 (watch/pin)", id="watch-dock")
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#browse-table", DataTable)
            table.cursor_type = "row"
            table.add_columns(
                "myVaillant",
                "eBUSd",
                "Address",
                "Value",
                "Raw",
                "Unit",
                "FLAGS Access",
                "Last Update",
                "Age",
                "Δ",
            )
            self._build_tree()
            self._refresh_table()
            self._render_watch_dock()
            self.set_interval(0.2, self._on_watch_tick)
            self._set_status("Ready")
            self._focus_tree()

        def on_key(self, event: Key) -> None:
            if event.key not in {"enter", "ctrl+j", "ctrl+m"}:
                return
            if len(self.screen_stack) > 1:
                return
            if isinstance(self.focused, DataTable) and self.focused.id == "browse-table":
                event.stop()
                self.action_edit_selected()

        def _set_status(self, text: str) -> None:
            self.query_one("#status", Static).update(text)

        def _build_tree(self) -> None:
            tree = self.query_one("#browse-tree", Tree)
            tree.clear()
            root = tree.root
            root.data = "root"
            self._tree_node_by_ref = {"root": root}
            protocols: dict[str, Any] = {}
            groups: dict[tuple[str, str], Any] = {}
            namespaces: dict[tuple[str, str, str], Any] = {}
            for node in self._store.tree_nodes:
                if node.level == "root":
                    continue
                if node.level == "protocol" and node.protocol is not None:
                    proto_node = root.add(node.label, data=node.node_id)
                    protocols[node.protocol] = proto_node
                    self._tree_node_by_ref[node.node_id] = proto_node
                    continue
                if (
                    node.level == "group"
                    and node.protocol is not None
                    and node.group_key is not None
                ):
                    parent = protocols.get(node.protocol)
                    if parent is None:
                        continue
                    group_node = parent.add(node.label, data=node.node_id)
                    groups[(node.protocol, node.group_key)] = group_node
                    self._tree_node_by_ref[node.node_id] = group_node
                    continue
                if (
                    node.level == "namespace"
                    and node.protocol is not None
                    and node.group_key is not None
                    and node.namespace_key is not None
                ):
                    parent = groups.get((node.protocol, node.group_key))
                    if parent is None:
                        continue
                    namespace_node = parent.add(node.label, data=node.node_id)
                    namespaces[(node.protocol, node.group_key, node.namespace_key)] = namespace_node
                    self._tree_node_by_ref[node.node_id] = namespace_node
                    continue
                if (
                    node.level == "instance"
                    and node.group_key is not None
                    and node.protocol is not None
                ):
                    parent = (
                        namespaces.get((node.protocol, node.group_key, node.namespace_key))
                        if node.namespace_key is not None
                        else groups.get((node.protocol, node.group_key))
                    )
                    if parent is None:
                        continue
                    instance_node = parent.add(node.label, data=node.node_id)
                    self._tree_node_by_ref[node.node_id] = instance_node
                    continue
                if node.level == "range" and node.protocol is not None:
                    parent = protocols.get(node.protocol)
                    if parent is None:
                        continue
                    range_node = parent.add(node.label, data=node.node_id)
                    self._tree_node_by_ref[node.node_id] = range_node
            root.expand()
            for node in protocols.values():
                node.expand()

        def _current_node(self) -> TreeNodeRef | None:
            return self._node_by_id.get(self._selected_node_id)

        def _selection_label(self, node: TreeNodeRef | None) -> str:
            if node is None:
                return "root"
            return node.label

        def _selection_namespace_label(self, node: TreeNodeRef | None) -> str:
            if node is None:
                return "all"
            if node.namespace_label:
                return node.namespace_label
            return "all"

        def _refresh_table(self) -> None:
            table = self.query_one("#browse-table", DataTable)
            selected = self._current_node()
            self._table_rows = self._store.rows_for_selection(selected, tab=self._active_tab)
            cursor = max(0, table.cursor_row)
            table.clear(columns=False)
            now = monotonic()
            for row in self._table_rows:
                watch = self._watch.get(row.row_id)
                value_text = watch.current_value if watch else row.value_text
                raw_hex = watch.current_raw if watch else row.raw_hex
                last_update_text = watch.last_poll_text if watch else row.last_update_text
                age_text = f"{max(0.0, now - watch.last_poll_at):.1f}s" if watch else row.age_text
                change_indicator = watch.change_indicator if watch else row.change_indicator
                if row.row_id in self._written_at:
                    if change_indicator.startswith(_WRITE_MARK):
                        pass
                    elif change_indicator == "-":
                        change_indicator = _WRITE_MARK
                    else:
                        change_indicator = f"{_WRITE_MARK}{change_indicator}"
                table.add_row(
                    row.myvaillant_name or row.name,
                    row.ebusd_name or "—",
                    row.address.label,
                    value_text,
                    raw_hex,
                    row.unit,
                    row.access_flags,
                    last_update_text,
                    age_text,
                    change_indicator,
                    key=row.row_id,
                )
            if self._table_rows:
                table.move_cursor(row=min(cursor, len(self._table_rows) - 1))
            status_text = (
                f"Rows: {len(self._table_rows)} | Selection: {self._selection_label(selected)} | "
                f"Namespace: {self._selection_namespace_label(selected)} | Tab: {self._active_tab}"
            )
            self._set_status(status_text)

        def _selected_table_row(self) -> RegisterRow | None:
            if not self._table_rows:
                return None
            table = self.query_one("#browse-table", DataTable)
            idx = table.cursor_row
            if idx < 0 or idx >= len(self._table_rows):
                return None
            return self._table_rows[idx]

        def _render_watch_dock(self) -> None:
            dock = self.query_one("#watch-dock", Static)
            if not self._watch:
                dock.update("Watchlist: empty (W add/remove, P pin, R rate)")
                return
            entries = sorted(
                self._watch.values(),
                key=lambda item: (not item.pinned, item.row_id),
            )
            lines = [f"Watchlist ({len(entries)}):"]
            for item in entries[:5]:
                row = self._store.row_by_id(item.row_id)
                label = row.address.label if row is not None else item.row_id
                pin = "[p]" if item.pinned else "   "
                mark = _WRITE_MARK if item.row_id in self._written_at else " "
                lines.append(
                    f"{pin} {mark}{label} = {item.current_value} Δ={item.change_indicator} "
                    f"@ {format_watch_interval(item.poll_interval_s)}"
                )
            if len(entries) > 5:
                lines.append(f"... +{len(entries) - 5} more")
            dock.update("\n".join(lines))

        def _on_watch_tick(self) -> None:
            if not self._watch:
                return
            now = monotonic()
            changed = False
            for item in self._watch.values():
                if now < item.next_poll_at:
                    continue
                row = self._store.row_by_id(item.row_id)
                item.next_poll_at = now + item.poll_interval_s
                item.last_poll_at = now
                item.last_poll_text = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
                if row is None:
                    continue
                current_value = row.value_text
                current_raw = row.raw_hex
                item.previous_value = item.current_value
                item.previous_raw = item.current_raw
                item.current_value = current_value
                item.current_raw = current_raw
                item.change_indicator = compute_change_indicator(
                    item.previous_value, item.current_value
                )
                changed = True
            if changed:
                self._refresh_table()
                self._render_watch_dock()

        def _focus_tree(self) -> None:
            self.query_one("#browse-tree", Tree).focus()
            self._focus_idx = 0

        def _focus_tabs(self) -> None:
            self.query_one("#browse-tabs", Tabs).focus()
            self._focus_idx = 1

        def _focus_table(self) -> None:
            self.query_one("#browse-table", DataTable).focus()
            self._focus_idx = 2

        def _focus_watch(self) -> None:
            self.query_one("#watch-dock", Static).focus()
            self._focus_idx = 3

        def _focus_by_index(self) -> None:
            match self._focus_order[self._focus_idx]:
                case "tree":
                    self._focus_tree()
                case "tabs":
                    self._focus_tabs()
                case "table":
                    self._focus_table()
                case _:
                    self._focus_watch()

        def action_focus_next_section(self) -> None:
            self._focus_idx = (self._focus_idx + 1) % len(self._focus_order)
            self._focus_by_index()

        def action_focus_prev_section(self) -> None:
            self._focus_idx = (self._focus_idx - 1) % len(self._focus_order)
            self._focus_by_index()

        def action_tab_config(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("config")

        def action_tab_config_limits(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("config_limits")

        def action_tab_state(self) -> None:
            self.query_one("#browse-tabs", Tabs).active = _tab_id("state")

        def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
            if event.tabs.id != "browse-tabs":
                return
            self._active_tab = _tab_from_id(event.tab.id or "tab-state")
            self._refresh_table()

        def on_tree_node_selected(self, event: Tree.NodeSelected[str]) -> None:
            data = event.node.data
            if isinstance(data, str):
                self._selected_node_id = data
                self._refresh_table()

        def action_search(self) -> None:
            # Prefer the actual focused widget over internal focus bookkeeping so search
            # remains correct even if focus was moved by Textual's default Tab handling.
            focused = self.focused
            if isinstance(focused, Tree) and focused.id == "browse-tree":
                target = "tree"
            else:
                target = "table"
            self._search.target = target
            self.push_screen(
                _InputDialog(title=f"Search in {target}", value=self._search.query),
                self._on_search_entered,
            )

        def _on_search_entered(self, query: str | None) -> None:
            if query is None:
                return
            q = query.strip().lower()
            self._search.query = q
            self._search.matches = []
            self._search.index = -1
            if not q:
                self._set_status("Search cleared")
                return

            if self._search.target == "tree":
                self._search.matches = [
                    node.node_id for node in self._store.tree_nodes if q in node.label.lower()
                ]
            else:
                self._search.matches = [
                    idx for idx, row in enumerate(self._table_rows) if q in row.search_blob
                ]
            if not self._search.matches:
                self._set_status(f"No matches for '{query}'")
                return
            self._search.index = 0
            self._apply_search_current()

        def _apply_search_current(self) -> None:
            if not self._search.matches or self._search.index < 0:
                return
            current = self._search.matches[self._search.index]
            if self._search.target == "tree":
                tree = self.query_one("#browse-tree", Tree)
                node = self._tree_node_by_ref.get(str(current))
                if node is not None:
                    parent = node.parent
                    while parent is not None:
                        parent.expand()
                        parent = parent.parent
                    tree.select_node(node)
                    self._focus_tree()
            else:
                table = self.query_one("#browse-table", DataTable)
                row = int(current)
                if 0 <= row < len(self._table_rows):
                    table.move_cursor(row=row)
                    self._focus_table()
            match_status = (
                f"Match {self._search.index + 1}/{len(self._search.matches)} "
                f"for '{self._search.query}'"
            )
            self._set_status(match_status)

        def action_search_next(self) -> None:
            if not self._search.matches:
                return
            self._search.index = (self._search.index + 1) % len(self._search.matches)
            self._apply_search_current()

        def action_search_prev(self) -> None:
            if not self._search.matches:
                return
            self._search.index = (self._search.index - 1) % len(self._search.matches)
            self._apply_search_current()

        def action_help(self) -> None:
            self.push_screen(_HelpDialog())

        def action_toggle_watch(self) -> None:
            row = self._selected_table_row()
            if row is None:
                self._set_status("Select a table row first.")
                return
            if row.row_id in self._watch:
                del self._watch[row.row_id]
                self._render_watch_dock()
                self._refresh_table()
                self._set_status(f"Watch removed: {row.address.label}")
                return
            now = monotonic()
            self._watch[row.row_id] = _WatchEntry(
                row_id=row.row_id,
                pinned=False,
                poll_interval_s=1.0,
                next_poll_at=now,
                last_poll_at=now,
                last_poll_text=datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ"),
                current_value=row.value_text,
                current_raw=row.raw_hex,
                previous_value=row.value_text,
                previous_raw=row.raw_hex,
                change_indicator="-",
            )
            self._render_watch_dock()
            self._refresh_table()
            self._set_status(f"Watch added: {row.address.label}")

        def action_toggle_pin(self) -> None:
            row = self._selected_table_row()
            if row is None:
                self._set_status("Select a watched row to pin/unpin.")
                return
            item = self._watch.get(row.row_id)
            if item is None:
                self._set_status("Row is not watched. Press W first.")
                return
            item.pinned = not item.pinned
            self._render_watch_dock()
            self._set_status(f"{'Pinned' if item.pinned else 'Unpinned'}: {row.address.label}")

        def _on_watch_rate_entered(self, value: str | None) -> None:
            row_id = self._editing_watch_row_id
            self._editing_watch_row_id = None
            if value is None or row_id is None:
                self._set_status("Watch rate edit cancelled")
                return
            interval = parse_watch_interval(value)
            if interval is None:
                self._set_status("Invalid rate. Use 250ms/500ms/1s/2s/5s.")
                return
            item = self._watch.get(row_id)
            if item is None:
                self._set_status("Watch row no longer exists.")
                return
            item.poll_interval_s = interval
            item.next_poll_at = monotonic() + interval
            self._render_watch_dock()
            self._set_status(f"Watch rate set to {format_watch_interval(interval)}")

        def action_set_watch_rate(self) -> None:
            row = self._selected_table_row()
            if row is None:
                self._set_status("Select a watched row to set rate.")
                return
            item = self._watch.get(row.row_id)
            if item is None:
                self._set_status("Row is not watched. Press W first.")
                return
            self._editing_watch_row_id = row.row_id
            self.push_screen(
                _InputDialog(
                    title=f"Poll rate for {row.address.label}",
                    value=format_watch_interval(item.poll_interval_s),
                    hint="Allowed: 250ms, 500ms, 1s, 2s, 5s",
                ),
                self._on_watch_rate_entered,
            )

        def _entry_for_row(self, row: RegisterRow) -> dict[str, Any] | None:
            if row.protocol != "b524" or row.group_key is None or row.instance_key is None:
                return None
            groups = self._artifact.get("groups")
            if not isinstance(groups, dict):
                return None
            group_obj = groups.get(row.group_key)
            if not isinstance(group_obj, dict):
                return None
            if row.namespace_key is not None and bool(group_obj.get("dual_namespace")):
                namespaces = group_obj.get("namespaces")
                if not isinstance(namespaces, dict):
                    return None
                namespace_obj = namespaces.get(row.namespace_key)
                if not isinstance(namespace_obj, dict):
                    return None
                instances = namespace_obj.get("instances")
            else:
                instances = group_obj.get("instances")
            if not isinstance(instances, dict):
                return None
            instance_obj = instances.get(row.instance_key)
            if not isinstance(instance_obj, dict):
                return None
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                return None
            entry = registers.get(row.register_key)
            return entry if isinstance(entry, dict) else None

        def _parse_new_value(self, *, type_spec: str, raw: str) -> tuple[object, bytes] | None:
            normalized = type_spec.strip().upper()
            if normalized == "BOOL":
                parsed_bool = parse_bool_input(raw)
                if parsed_bool is None:
                    self._set_status("Invalid BOOL. Use true/false or 1/0.")
                    return None
                try:
                    data = encode_typed_value("BOOL", parsed_bool)
                except ValueEncodeError as exc:
                    self._set_status(f"Encode error: {exc}")
                    return None
                return (parsed_bool, data)
            if normalized in {"UIN", "UCH", "I8", "I16", "U32", "I32"}:
                try:
                    parsed_int = int(raw.strip(), 0)
                except ValueError:
                    self._set_status("Invalid integer. Use hex (0x..) or decimal.")
                    return None
                try:
                    data = encode_typed_value(normalized, parsed_int)
                except ValueEncodeError as exc:
                    self._set_status(f"Encode error: {exc}")
                    return None
                return (parsed_int, data)
            if normalized == "EXP":
                try:
                    parsed_float = float(raw.strip())
                except ValueError:
                    self._set_status("Invalid float.")
                    return None
                try:
                    data = encode_typed_value("EXP", parsed_float)
                except ValueEncodeError as exc:
                    self._set_status(f"Encode error: {exc}")
                    return None
                return (parsed_float, data)
            if normalized.startswith("STR:"):
                try:
                    data = encode_typed_value(normalized, raw)
                except ValueEncodeError as exc:
                    self._set_status(f"Encode error: {exc}")
                    return None
                return (raw, data)
            if (
                normalized == "HDA:3"
                or normalized == "HTI"
                or normalized == "FW"
                or normalized.startswith("HEX:")
            ):
                try:
                    data = encode_typed_value(normalized, raw)
                except ValueEncodeError as exc:
                    self._set_status(f"Encode error: {exc}")
                    return None
                return (raw, data)
            self._set_status(f"Unsupported type for write: {type_spec}")
            return None

        def _update_store_row(
            self,
            *,
            row_id: str,
            value_text: str,
            raw_hex: str,
            last_update_text: str,
            age_text: str,
        ) -> None:
            from dataclasses import replace

            current = self._store.row_by_id(row_id)
            if current is None:
                return
            updated = replace(
                current,
                value_text=value_text,
                raw_hex=raw_hex,
                last_update_text=last_update_text,
                age_text=age_text,
            )
            self._store._row_by_id[row_id] = updated
            for idx, existing in enumerate(self._store.rows):
                if existing.row_id == row_id:
                    self._store.rows[idx] = updated
                    break

        def _apply_write(self, pending: _PendingWrite) -> None:
            row = self._store.row_by_id(pending.row_id)
            if row is None:
                self._set_status("Selected row no longer exists.")
                return
            entry = self._entry_for_row(row)
            if entry is None:
                self._set_status("Artifact entry not found.")
                return

            entry["type"] = pending.type_spec
            entry["value"] = pending.new_value
            entry["raw_hex"] = pending.new_raw_hex
            entry["error"] = None
            entry["written"] = True
            entry["written_at"] = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")

            now_txt = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
            self._written_at[pending.row_id] = now_txt

            self._update_store_row(
                row_id=pending.row_id,
                value_text=pending.new_value_text,
                raw_hex=pending.new_raw_hex,
                last_update_text=now_txt,
                age_text="0.0s",
            )

            watch = self._watch.get(pending.row_id)
            if watch is not None:
                now_mono = monotonic()
                watch.previous_value = watch.current_value
                watch.previous_raw = watch.current_raw
                watch.current_value = pending.new_value_text
                watch.current_raw = pending.new_raw_hex
                watch.change_indicator = _WRITE_MARK
                watch.last_poll_at = now_mono
                watch.last_poll_text = now_txt
                watch.next_poll_at = now_mono + watch.poll_interval_s

            self._render_watch_dock()
            self._refresh_table()
            self._set_status(f"Wrote {row.address.label}")

        def _on_confirm_write(self, confirmed: bool | None) -> None:
            pending = self._pending_write
            self._pending_write = None
            if not confirmed or pending is None:
                self._set_status("Write cancelled")
                return
            self._apply_write(pending)

        def _on_edit_value_entered(self, value: str | None) -> None:
            row_id = self._editing_row_id
            self._editing_row_id = None
            if value is None or row_id is None:
                self._set_status("Edit cancelled")
                return
            row = self._store.row_by_id(row_id)
            if row is None:
                self._set_status("Row no longer exists.")
                return
            entry = self._entry_for_row(row)
            if entry is None:
                self._set_status("Artifact entry not found.")
                return
            type_spec_obj = entry.get("type")
            type_spec = (
                type_spec_obj if isinstance(type_spec_obj, str) and type_spec_obj else "HEX:0"
            )
            if type_spec == "HEX:0":
                self._set_status("Missing type; edit raw_hex is not supported yet.")
                return

            parsed = self._parse_new_value(type_spec=type_spec, raw=value)
            if parsed is None:
                return
            new_value_obj, new_bytes = parsed
            try:
                canonical_value = parse_typed_value(type_spec, new_bytes)
            except ValueParseError:
                canonical_value = new_value_obj
            new_value_text = _fmt_value_text(canonical_value)
            new_raw_hex = new_bytes.hex()

            old_raw_hex_obj = entry.get("raw_hex")
            old_raw_hex = old_raw_hex_obj if isinstance(old_raw_hex_obj, str) else ""
            old_value_text = row.value_text

            self._pending_write = _PendingWrite(
                row_id=row_id,
                type_spec=type_spec,
                old_value_text=old_value_text,
                old_raw_hex=old_raw_hex,
                new_value_text=new_value_text,
                new_raw_hex=new_raw_hex,
                new_value=canonical_value,
            )
            self.push_screen(
                _ConfirmDialog(
                    title="Confirm write",
                    summary_lines=[
                        f"Target: {row.address.label}",
                        f"Type:   {type_spec}",
                        "",
                        f"Old: {old_value_text}  raw={old_raw_hex}",
                        f"New: {new_value_text}  raw={new_raw_hex}",
                    ],
                ),
                self._on_confirm_write,
            )

        def action_edit_selected(self) -> None:
            if not self._write_enabled:
                self._set_status("Write disabled: run with --allow-write")
                return
            row = self._selected_table_row()
            if row is None:
                self._set_status("Select a table row to edit.")
                return
            if row.tab == "state":
                self._set_status("State tab is read-only.")
                return
            entry = self._entry_for_row(row)
            type_spec_obj = entry.get("type") if entry is not None else None
            type_spec = type_spec_obj if isinstance(type_spec_obj, str) and type_spec_obj else None
            if type_spec is None:
                self._set_status("No type for this row; cannot edit safely.")
                return
            self._editing_row_id = row.row_id
            self.push_screen(
                _InputDialog(
                    title=f"Write {row.address.label} ({type_spec})",
                    value=row.value_text if row.value_text != "null" else "",
                    hint="Enter new value. Esc=cancel. (Safe mode: confirmation required.)",
                ),
                self._on_edit_value_entered,
            )

        def action_close_dialog(self) -> None:
            if len(self.screen_stack) > 1:
                self.pop_screen()

    _BrowseApp().run()
