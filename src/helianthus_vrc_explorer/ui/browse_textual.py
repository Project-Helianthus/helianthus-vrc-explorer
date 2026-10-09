from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import get_ident
from time import monotonic
from typing import Any, Literal, cast

from rich.console import Group
from rich.table import Table
from rich.text import Text

from ..protocol.parser import (
    ValueEncodeError,
    ValueParseError,
    encode_typed_value,
    parse_typed_value,
)
from ..scanner.b524_parameter_writes import (
    B524NativeIdentity,
    B524ParameterEditContext,
    B524ParameterTarget,
    B524ParameterWritePreparation,
    B524ParameterWriteResult,
    execute_parameter_write,
    prepare_parameter_write,
    read_browser_identity,
    read_parameter_edit_context,
    recheck_parameter_write,
)
from ..scanner.browser_session import BrowserSession, BrowserTransportConfig
from ..schema.parameter_descriptions import description_profile, effective_parameter_description
from .browse_models import BrowseTab, RegisterRow, TreeNodeRef
from .browse_store import BrowseStore
from .emphasis import rich_star_bold_text
from .parameter_editor import parameter_enum_choices, parameter_value_display, record_offline_edit

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from textual.events import Key
    from textual.screen import ModalScreen
    from textual.widgets import (
        Button,
        DataTable,
        Footer,
        Header,
        Input,
        Label,
        Static,
        Tab,
        Tabs,
        Tree,
    )
except ModuleNotFoundError as exc:
    if exc.name is None or (exc.name != "textual" and not exc.name.startswith("textual.")):
        raise
    _TEXTUAL_IMPORT_ERROR: ModuleNotFoundError | None = exc
else:
    _TEXTUAL_IMPORT_ERROR = None

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
    from .regulator_identity import regulator_profile_label

    profile = regulator_profile_label(identity)
    if profile:
        rows.append(("Profile", profile))
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
    preparation: B524ParameterWritePreparation | None = None
    live: bool = False
    incomplete_limits_confirmed: bool = False


def _artifact_native_identity(artifact: dict[str, object]) -> B524NativeIdentity:
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        raise ValueError("artifact has no recorded native identity")
    identity = meta.get("identity")
    if not isinstance(identity, dict):
        identity = meta.get("resolved_identity")
    if not isinstance(identity, dict):
        raise ValueError("artifact has no recorded native identity")
    manufacturer_raw = identity.get("manufacturer")
    try:
        manufacturer = (
            int(manufacturer_raw, 0) if isinstance(manufacturer_raw, str) else manufacturer_raw
        )
    except ValueError as exc:
        raise ValueError("artifact native manufacturer is invalid") from exc
    eid = identity.get("eid", identity.get("device_id"))
    software = identity.get("sw", identity.get("software_raw_hex"))
    hardware = identity.get("hw", identity.get("hardware_raw_hex"))
    if (
        isinstance(manufacturer, bool)
        or not isinstance(manufacturer, int)
        or not isinstance(eid, str)
        or not isinstance(software, str)
        or not isinstance(hardware, str)
    ):
        raise ValueError("artifact native identity requires manufacturer, EID, SW, and HW")
    return B524NativeIdentity(
        manufacturer=manufacturer,
        eid=eid,
        software_raw_hex=software,
        hardware_raw_hex=hardware,
    )


def _identity_matches(expected: B524NativeIdentity, actual: B524NativeIdentity) -> bool:
    return (
        expected.manufacturer == actual.manufacturer
        and expected.eid.strip().upper() == actual.eid.strip().upper()
        and expected.software_raw_hex.lower() == actual.software_raw_hex.lower()
        and expected.hardware_raw_hex.lower() == actual.hardware_raw_hex.lower()
    )


def _tab_id(tab: BrowseTab) -> str:
    return {
        "config": "tab-config",
        "state": "tab-state",
    }[tab]


def _tab_from_id(tab_id: str) -> BrowseTab:
    if tab_id == "tab-config":
        return "config"
    return "state"


def _validate_browse_artifact(artifact: dict[str, object]) -> dict[str, object]:
    """Keep the programmatic artifact seam explicit without changing validation."""

    return artifact


def _raise_if_textual_unavailable() -> None:
    if _TEXTUAL_IMPORT_ERROR is not None:
        raise _TEXTUAL_IMPORT_ERROR


def _hydrate_browse_store(artifact: dict[str, object]) -> BrowseStore:
    return BrowseStore.from_artifact(artifact)


if _TEXTUAL_IMPORT_ERROR is None:
    from .parameter_edit_dialogs import BrowserConnectionDialog, ParameterEnumDialog

    class _FocusableStatic(Static):
        can_focus = True

    class _InputDialog(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
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

        def on_input_submitted(self, event: Input.Submitted) -> None:
            event.stop()
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
                    "C connect/disconnect | E edit | V read-only write recheck\n"
                    "? help | q quit. Offline edits never send to the regulator."
                ),
            )

        def action_close(self) -> None:
            self.dismiss(None)

    class _OperationEditDialog(ModalScreen[None]):
        BINDINGS = [Binding("escape", "close", "Close")]
        CSS = """
        _OperationEditDialog { align: center middle; }
        _OperationEditDialog > Vertical {
            width: 95%; height: 90%; padding: 1 2;
            border: heavy $accent; background: $surface;
        }
        #operation-preview-scroll { height: 1fr; }
        #operation-edit-buttons { height: 3; }
        """

        def __init__(self, *, document: dict[str, object], destination: int) -> None:
            super().__init__()
            self._document = document
            self._destination = destination

        def compose(self) -> ComposeResult:
            yield Vertical(
                Label(f"Offline {self._document['operation']} editor"),
                Static(
                    "Raw values as JSON: seven byte codes, or three timer [start, stop] pairs/null "
                    "slots. Editing never sends to the bus."
                ),
                Input(value=json.dumps(self._document["values"]), id="operation-values"),
                Input(
                    value="b524-operation-edit.json",
                    placeholder="Export file path",
                    id="operation-export-path",
                ),
                Horizontal(
                    Button("Preview", id="operation-preview-button"),
                    Button("Export JSON", id="operation-export-button"),
                    id="operation-edit-buttons",
                ),
                Static("", id="operation-edit-status"),
                VerticalScroll(
                    Static("", id="operation-preview-content"), id="operation-preview-scroll"
                ),
                Static("Offline only. Esc closes."),
            )

        def on_mount(self) -> None:
            self._refresh_preview()

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id == "operation-values" and self.is_mounted:
                self._refresh_preview()

        def _edited(self) -> tuple[dict[str, object], dict[str, object]]:
            from ..scanner.b524_operation_edit import build_operation_edit_preview

            document = dict(self._document)
            document["values"] = json.loads(self.query_one("#operation-values", Input).value)
            return document, build_operation_edit_preview(document, dst=self._destination)

        def _refresh_preview(self) -> bool:
            try:
                document, preview = self._edited()
            except (TypeError, ValueError) as exc:
                self.query_one("#operation-edit-status", Static).update(f"Invalid edit: {exc}")
                self.query_one("#operation-preview-content", Static).update("")
                return False
            self.query_one("#operation-edit-status", Static).update(
                "Validated offline; no native write."
            )
            self.query_one("#operation-preview-content", Static).update(
                json.dumps({"document": document, "preview": preview}, indent=2)
            )
            return True

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if not self._refresh_preview() or event.button.id != "operation-export-button":
                return
            document, _preview = self._edited()
            path = Path(self.query_one("#operation-export-path", Input).value).expanduser()
            try:
                with path.open("x", encoding="utf-8") as output:
                    output.write(json.dumps(document, indent=2) + "\n")
            except OSError as exc:
                self.query_one("#operation-edit-status", Static).update(f"Could not export: {exc}")
            else:
                self.query_one("#operation-edit-status", Static).update(
                    f"Exported {path}; no native write."
                )

        def action_close(self) -> None:
            self.dismiss(None)

    class _ConfirmDialog(ModalScreen[bool]):
        BINDINGS = [
            Binding("escape", "cancel", "Cancel"),
            Binding("q", "cancel", "Cancel"),
            Binding("enter", "confirm", "Apply locally"),
            Binding("y", "confirm", "Apply locally"),
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
            live: bool = False,
        ) -> None:
            super().__init__()
            self._title = title
            self._lines = summary_lines
            self._live = live

        def compose(self) -> ComposeResult:
            body = "\n".join(self._lines)
            yield Vertical(
                Label(self._title),
                Static(body),
                Static(
                    "Enter/Y=confirm device write  Esc/Q=cancel"
                    if self._live
                    else "Enter/Y=apply locally  Esc/Q=cancel"
                ),
            )

        def action_cancel(self) -> None:
            self.dismiss(False)

        def action_confirm(self) -> None:
            self.dismiss(True)

    class _BrowseApp(App[None]):
        BINDINGS = [
            Binding("tab", "focus_next_section", "Next Focus"),
            Binding("shift+tab", "focus_prev_section", "Prev Focus"),
            Binding("1", "tab_config", "Config"),
            Binding("2", "tab_state", "State"),
            Binding("/", "search", "Search"),
            Binding("n", "search_next", "Next Match"),
            Binding("N", "search_prev", "Prev Match"),
            Binding("question_mark", "help", "Help"),
            Binding("w", "toggle_watch", "Watch"),
            Binding("p", "toggle_pin", "Pin"),
            Binding("r", "set_watch_rate", "Rate"),
            Binding("e", "edit_selected", "Edit"),
            Binding("c", "connect", "Connect/Disconnect"),
            Binding("v", "recheck", "Recheck write"),
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

        def __init__(
            self,
            artifact: dict[str, object],
            *,
            allow_write: bool,
            store: BrowseStore | None = None,
            connection_settings: dict[str, Any] | None = None,
            artifact_path: Path | None = None,
        ) -> None:
            super().__init__()
            self._store = store if store is not None else _hydrate_browse_store(artifact)
            self._node_by_id = {node.node_id: node for node in self._store.tree_nodes}
            self._tree_node_by_ref: dict[str, Any] = {}
            self._focus_order = ["tree", "tabs", "table", "watch"]
            self._focus_idx = 0
            self._selected_node_id = "root"
            self._active_tab: BrowseTab = "config"
            self._table_rows: list[RegisterRow] = []
            self._search = _SearchState()
            self._write_enabled = True
            self._connection_settings = connection_settings
            self._artifact_path = artifact_path
            self._browser_session: Any = None
            self._connected_identity: Any = None
            self._session_dst: int | None = None
            self._live_edit_context: B524ParameterEditContext | None = None
            self._transport_busy = False
            self._pending_preparation: Any = None
            self._last_live_write: tuple[_PendingWrite, Any] | None = None
            self._inflight_future: Any = None
            self._inflight_recorded = True
            self._inflight_teardown_success: Any = None
            self._ui_thread_id = get_ident()
            self._watch: dict[str, _WatchEntry] = {}
            self._editing_watch_row_id: str | None = None
            self._artifact = artifact
            self._editing_row_id: str | None = None
            self._pending_write: _PendingWrite | None = None
            self._written_at: dict[str, str] = {}
            self._identity_header = _build_identity_header_renderable(artifact)

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            yield Static(
                "CONNECTING — verifying scan target"
                if self._connection_settings is not None
                else "OFFLINE — edits are local previews",
                id="connection-state",
            )
            if self._identity_header is not None:
                yield Static(self._identity_header, id="identity-header")
            with Horizontal(id="main"):
                with Vertical(id="tree-pane"):
                    yield Tree(self._store.device_label, id="browse-tree")
                with Vertical(id="right-pane"):
                    yield Tabs(
                        Tab("Config", id="tab-config"),
                        Tab("State", id="tab-state"),
                        id="browse-tabs",
                    )
                    yield DataTable(id="browse-table")
            yield _FocusableStatic("Watchlist: reserved for P1 (watch/pin)", id="watch-dock")
            yield Static("", id="status")
            yield Footer()

        def on_mount(self) -> None:
            self._ui_thread_id = get_ident()
            table = self.query_one("#browse-table", DataTable)
            table.cursor_type = "row"
            table.add_columns(
                "Register",
                "eBUSd",
                "Value",
                "Raw",
                "Unit",
                "FLAGS Access",
                "Descriptions",
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
            if self._connection_settings is not None:
                self._begin_connect(self._connection_settings)

        def on_key(self, event: Key) -> None:
            if event.key not in {"enter", "ctrl+j", "ctrl+m"}:
                return
            if len(self.screen_stack) > 1:
                return
            if isinstance(self.focused, DataTable) and self.focused.id == "browse-table":
                event.stop()
                # Stop App._on_key from resolving the same key against the
                # newly opened modal before its Input has mounted.
                event.prevent_default()
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
            sections: dict[tuple[str, str], Any] = {}
            groups: dict[tuple[str, str, str], Any] = {}
            namespaces: dict[tuple[str, str, str, str], Any] = {}
            for node in self._store.tree_nodes:
                if node.level == "root":
                    continue
                if node.level == "protocol" and node.protocol is not None:
                    proto_node = root.add(node.label, data=node.node_id)
                    protocols[node.protocol] = proto_node
                    self._tree_node_by_ref[node.node_id] = proto_node
                    continue
                if (
                    node.level == "section"
                    and node.protocol is not None
                    and node.section_key is not None
                ):
                    parent = protocols.get(node.protocol)
                    if parent is None:
                        continue
                    section_node = parent.add(node.label, data=node.node_id)
                    sections[(node.protocol, node.section_key)] = section_node
                    self._tree_node_by_ref[node.node_id] = section_node
                    continue
                if (
                    node.level == "group"
                    and node.protocol is not None
                    and node.group_key is not None
                ):
                    section_key = node.section_key or ""
                    parent = sections.get(
                        (node.protocol, section_key), protocols.get(node.protocol)
                    )
                    if parent is None:
                        continue
                    group_node = parent.add(node.label, data=node.node_id)
                    groups[(node.protocol, section_key, node.group_key)] = group_node
                    self._tree_node_by_ref[node.node_id] = group_node
                    continue
                if (
                    node.level == "namespace"
                    and node.protocol is not None
                    and node.group_key is not None
                    and node.namespace_key is not None
                ):
                    section_key = node.section_key or ""
                    parent = groups.get((node.protocol, section_key, node.group_key))
                    if parent is None:
                        continue
                    namespace_node = parent.add(node.label, data=node.node_id)
                    namespaces[(node.protocol, section_key, node.group_key, node.namespace_key)] = (
                        namespace_node
                    )
                    self._tree_node_by_ref[node.node_id] = namespace_node
                    continue
                if (
                    node.level == "instance"
                    and node.group_key is not None
                    and node.protocol is not None
                ):
                    section_key = node.section_key or ""
                    parent = None
                    if node.namespace_key is not None:
                        parent = namespaces.get(
                            (
                                node.protocol,
                                section_key,
                                node.group_key,
                                node.namespace_key,
                            )
                        )
                    if parent is None:
                        parent = groups.get((node.protocol, section_key, node.group_key))
                    if parent is None:
                        continue
                    instance_node = parent.add(node.label, data=node.node_id)
                    self._tree_node_by_ref[node.node_id] = instance_node
                    continue
                if (
                    node.level == "register"
                    and node.group_key is not None
                    and node.instance_key is not None
                    and node.protocol is not None
                ):
                    section_key = node.section_key or ""
                    parts = ["b524", "inst", section_key, node.group_key]
                    if node.namespace_key is not None:
                        parts.append(node.namespace_key)
                    parts.append(node.instance_key)
                    parent = self._tree_node_by_ref.get(":".join(parts))
                    if parent is None:
                        continue
                    register_node = parent.add(node.label, data=node.node_id)
                    self._tree_node_by_ref[node.node_id] = register_node
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
            allowed_tabs = self._sync_tabs_for_selection(selected)
            if not allowed_tabs and selected is not None:
                self._table_rows = [
                    row
                    for row in self._store.rows
                    if row.protocol == "b524" and row.section_key == selected.section_key
                ]
            else:
                self._table_rows = self._store.rows_for_selection(selected, tab=self._active_tab)
            cursor = max(0, table.cursor_row)
            table.clear(columns=False)
            now = monotonic()
            for row in self._table_rows:
                watch = self._watch.get(row.row_id)
                value_text = watch.current_value if watch else row.value_text
                entry = self._entry_for_row(row)
                if (
                    entry is not None
                    and row.protocol == "b524"
                    and row.address.read_opcode in {"0x02", "0x06"}
                ):
                    value_text = parameter_value_display(
                        entry,
                        opcode=int(row.address.read_opcode, 0),
                        group=int(row.group_key or "0", 0),
                        register=int(row.register_key, 0),
                    )
                    preview = entry.get("local_edit_preview")
                    if isinstance(preview, dict):
                        value_text += f" → {preview.get('value')} [offline preview]"
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
                    row.display_label,
                    row.ebusd_name or "—",
                    value_text,
                    raw_hex,
                    row.unit,
                    row.access_flags,
                    row.description_text,
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

        def _allowed_tabs_for_selection(self, node: TreeNodeRef | None) -> tuple[BrowseTab, ...]:
            if node is None:
                return ("config", "state")
            if node.protocol != "b524":
                return ("state",)
            if node.section_key not in {None, "controller_registers", "device_slots"}:
                return ()
            return ("config", "state")

        def _sync_tabs_for_selection(self, node: TreeNodeRef | None) -> tuple[BrowseTab, ...]:
            tabs_widget = self.query_one("#browse-tabs", Tabs)
            allowed_tabs = self._allowed_tabs_for_selection(node)
            allowed = set(allowed_tabs)
            tabs_widget.display = bool(allowed)
            tab_map = {
                "config": self.query_one("#tab-config", Tab),
                "state": self.query_one("#tab-state", Tab),
            }
            for key, tab in tab_map.items():
                tab.disabled = key not in allowed
            if self._active_tab not in allowed:
                self._active_tab = "state"
                tabs_widget.active = _tab_id("state")
            return allowed_tabs

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
            if "config" not in self._allowed_tabs_for_selection(self._current_node()):
                self._set_status("Config tab is not available for this B524 operation.")
                return
            self.query_one("#browse-tabs", Tabs).active = _tab_id("config")

        def action_tab_state(self) -> None:
            if "state" not in self._allowed_tabs_for_selection(self._current_node()):
                self._set_status("Config/State tabs are not available for this B524 operation.")
                return
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

        def _track_transport_future(
            self,
            future: Any,
            *,
            status: str,
            on_success: Any,
            on_error: Any = None,
            on_teardown_success: Any = None,
        ) -> None:
            if self._transport_busy:
                raise RuntimeError("a Browser transport operation is already active")
            self._transport_busy = True
            self._inflight_future = future
            self._inflight_recorded = False
            self._inflight_teardown_success = on_teardown_success
            self._set_status(status)

            def completed(done_future: Any) -> None:
                # ``Future.add_done_callback`` runs inline for an already-complete
                # future. Calling Textual's cross-thread bridge from its own UI
                # thread raises and would otherwise leave the Browser busy forever.
                if get_ident() == self._ui_thread_id:
                    self._finish_transport_future(
                        done_future,
                        on_success,
                        on_error,
                    )
                    return
                try:
                    self.call_from_thread(
                        self._finish_transport_future,
                        done_future,
                        on_success,
                        on_error,
                    )
                except RuntimeError:
                    # The run wrapper still closes the session if the app is
                    # already stopping for an unrelated fatal UI error.
                    return

            future.add_done_callback(completed)

        def _finish_transport_future(
            self,
            future: Any,
            on_success: Any,
            on_error: Any,
        ) -> None:
            if self._inflight_future is future:
                self._transport_busy = False
            recorded = False
            try:
                result = future.result()
            except Exception as exc:
                if callable(on_error):
                    on_error(exc)
                else:
                    self._set_status(f"Transport operation failed: {exc}")
                recorded = True
            else:
                on_success(result)
                recorded = True
            finally:
                if self._inflight_future is future and recorded:
                    self._inflight_recorded = True
                    self._inflight_teardown_success = None

        def _artifact_destination(self, *, default: int | None = None) -> int:
            meta = self._artifact.get("meta")
            raw = meta.get("destination_address") if isinstance(meta, dict) else None
            if raw is None and default is not None:
                return default
            if isinstance(raw, bool) or not isinstance(raw, (str, int)):
                raise ValueError("artifact destination is unavailable")
            try:
                destination = int(raw, 0) if isinstance(raw, str) else raw
            except ValueError as exc:
                raise ValueError("artifact destination is invalid") from exc
            if not 0 <= destination <= 0xFF or destination in {0x00, 0xA9, 0xAA}:
                raise ValueError("artifact destination is not a concrete eBUS address")
            return destination

        def action_connect(self) -> None:
            if self._transport_busy:
                self._set_status("Wait for the current transport operation to finish.")
                return
            if self._browser_session is not None:
                self._disconnect_browser_session()
                return
            destination = self._artifact_destination(default=0x15)
            self.push_screen(
                BrowserConnectionDialog(destination=destination),
                self._on_connection_settings,
            )

        def _on_connection_settings(self, settings: dict[str, Any] | None) -> None:
            if settings is None:
                self._set_status("Connection cancelled")
                return
            self._begin_connect(settings)

        def _begin_connect(self, settings: dict[str, Any]) -> None:
            if self._transport_busy:
                self._set_status("Wait for the current transport operation to finish.")
                return
            try:
                expected = _artifact_native_identity(self._artifact)
                kind_raw = settings.get("protocol", settings.get("kind"))
                host = settings.get("host")
                port = settings.get("port")
                source = settings.get("src", settings.get("source"))
                destination = settings.get("dst", settings.get("destination"))
                trace_path = settings.get("trace_path")
                if kind_raw not in {"tcp", "ens"}:
                    raise ValueError("protocol must be tcp or ens")
                if not isinstance(host, str):
                    raise ValueError("host must be text")
                if not isinstance(port, int) or isinstance(port, bool):
                    raise ValueError("port must be an integer")
                if not (source is None and kind_raw == "tcp") and (
                    not isinstance(source, int) or isinstance(source, bool)
                ):
                    raise ValueError("source must be an integer, or unset for tcp")
                if not isinstance(destination, int) or isinstance(destination, bool):
                    raise ValueError("destination must be an integer")
                if trace_path is not None and not isinstance(trace_path, Path):
                    raise ValueError("trace_path must be a Path")
                config = BrowserTransportConfig(
                    kind=cast(Literal["tcp", "ens"], kind_raw),
                    host=host,
                    port=port,
                    source=source,
                    destination=destination,
                    timeout_s=float(settings.get("timeout_s", 5.0)),
                    trace_path=trace_path,
                )
            except (TypeError, ValueError) as exc:
                self.query_one("#connection-state", Static).update(
                    f"OFFLINE — connection rejected: {exc}; edits are local previews"
                )
                self._set_status(f"Connection rejected: {exc}")
                return
            session = BrowserSession.from_config(config)
            self._browser_session = session
            self._session_dst = config.destination
            self.query_one("#connection-state", Static).update(
                f"CONNECTING {config.kind.upper()} — dst=0x{config.destination:02X} "
                "— verifying native identity"
            )

            def connected(_transport: Any) -> None:
                assert self._browser_session is session
                future = session.submit(read_browser_identity, config.destination)
                self._track_transport_future(
                    future,
                    status="Verifying native EID/SW/HW identity…",
                    on_success=lambda actual: self._finish_connect_identity(
                        expected, actual, config
                    ),
                    on_error=self._connection_failed,
                )

            self._track_transport_future(
                session.connect(),
                status="Connecting…",
                on_success=connected,
                on_error=self._connection_failed,
            )

        def _finish_connect_identity(
            self,
            expected: B524NativeIdentity,
            actual: B524NativeIdentity,
            config: BrowserTransportConfig,
        ) -> None:
            if not _identity_matches(expected, actual):
                self._connection_failed(
                    ValueError("live EID/SW/HW does not match the artifact identity")
                )
                return
            self._connected_identity = actual
            self._session_dst = config.destination
            self.query_one("#connection-state", Static).update(
                f"LIVE {config.kind.upper()} — dst=0x{config.destination:02X} — identity verified"
            )
            self._set_status("Connected; each live write requires fresh checks and confirmation.")

        def _connection_failed(self, exc: Exception) -> None:
            session = self._browser_session
            self._browser_session = None
            self._connected_identity = None
            self._session_dst = None
            if session is not None:
                session.close(wait=False)
            reason = (
                "recorded native identity mismatch"
                if "does not match" in str(exc)
                else "connection failed"
            )
            self.query_one("#connection-state", Static).update(
                f"OFFLINE — {reason}; edits are local previews"
            )
            self._set_status(f"Connection failed: {exc}")

        def _disconnect_browser_session(self) -> None:
            session = self._browser_session
            self._browser_session = None
            self._connected_identity = None
            self._session_dst = None
            self._live_edit_context = None
            if session is not None:
                session.close(wait=False)
            self.query_one("#connection-state", Static).update("OFFLINE — edits are local previews")
            self._set_status("Disconnected; edits are local previews.")

        def close_transport(self, *, wait: bool = True) -> None:
            if wait:
                self._harvest_inflight_result()
            session = self._browser_session
            self._browser_session = None
            if session is not None:
                session.close(wait=wait)
            if wait:
                self._harvest_inflight_result()

        def _harvest_inflight_result(self) -> None:
            future = self._inflight_future
            callback = self._inflight_teardown_success
            if self._inflight_recorded or future is None or not callable(callback):
                return
            try:
                result = future.result()
            except Exception:
                return
            self._inflight_recorded = True
            self._transport_busy = False
            self._inflight_teardown_success = None
            callback(result)

        def _persist_artifact(self) -> str | None:
            path = self._artifact_path
            if path is None:
                return None
            temporary = path.with_name(f".{path.name}.tmp")
            try:
                temporary.write_text(json.dumps(self._artifact, indent=2) + "\n", encoding="utf-8")
                temporary.replace(path)
            except (OSError, TypeError, ValueError) as exc:
                return str(exc)
            return None

        def _entry_for_row(self, row: RegisterRow) -> dict[str, Any] | None:
            if row.protocol != "b524" or row.group_key is None or row.instance_key is None:
                return None
            # Navigate operations-first: operations[op_key].groups[group_key]
            operations = self._artifact.get("operations")
            if not isinstance(operations, dict):
                return None
            group_obj = None
            if row.namespace_key is not None:
                op_obj = operations.get(row.namespace_key)
                if isinstance(op_obj, dict):
                    op_groups = op_obj.get("groups")
                    if isinstance(op_groups, dict):
                        group_obj = op_groups.get(row.group_key)
            if not isinstance(group_obj, dict):
                # Fallback: search all operations for the group
                for op_obj in operations.values():
                    if not isinstance(op_obj, dict):
                        continue
                    op_groups = op_obj.get("groups")
                    if isinstance(op_groups, dict):
                        candidate = op_groups.get(row.group_key)
                        if isinstance(candidate, dict):
                            group_obj = candidate
                            break
            if not isinstance(group_obj, dict):
                return None
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
                or normalized == "FWU"
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

        def _selector_for_row(self, row: RegisterRow) -> dict[str, str]:
            if (
                row.address.read_opcode not in {"0x02", "0x06"}
                or row.group_key is None
                or row.instance_key is None
            ):
                raise ValueError("selected row has no concrete OP02/OP06 selector")
            return {
                "read_opcode": row.address.read_opcode,
                "group": row.group_key,
                "instance": row.instance_key,
                "register": row.register_key,
            }

        def _target_for_row(self, row: RegisterRow, *, destination: int) -> B524ParameterTarget:
            selector = self._selector_for_row(row)
            opcode = int(selector["read_opcode"], 0)
            if opcode not in {0x02, 0x06}:
                raise ValueError("selected row is not an OP02/OP06 parameter")
            return B524ParameterTarget(
                destination=destination,
                opcode=cast(Any, opcode),
                group=int(selector["group"], 0),
                instance=int(selector["instance"], 0),
                register=int(selector["register"], 0),
            )

        def _effective_description(self, row: RegisterRow) -> dict[str, Any] | None:
            return effective_parameter_description(self._artifact, self._selector_for_row(row))

        def _open_parameter_editor(self, row: RegisterRow, entry: dict[str, Any]) -> None:
            type_spec = entry.get("type")
            if not isinstance(type_spec, str) or not type_spec:
                self._set_status("No type for this row; cannot edit safely.")
                return
            description = self._effective_description(row)
            selector = self._selector_for_row(row)
            choices = parameter_enum_choices(
                entry,
                read_opcode=int(selector["read_opcode"], 0),
                group=int(selector["group"], 0),
                register=int(row.register_key, 0),
                description=description,
            )
            self._editing_row_id = row.row_id
            if choices:
                self.push_screen(
                    ParameterEnumDialog(
                        title=f"Edit {row.address.label} ({type_spec})",
                        choices=choices,
                        current=entry.get("value"),
                    ),
                    self._on_edit_value_entered,
                )
                return
            current = entry.get("value")
            self.push_screen(
                _InputDialog(
                    title=f"Edit {row.address.label} ({type_spec})",
                    value="" if current is None else _fmt_value_text(current),
                    hint="Enter the typed value. Esc cancels; confirmation follows.",
                ),
                self._on_edit_value_entered,
            )

        def _prepare_pending_write(
            self,
            *,
            row: RegisterRow,
            entry: dict[str, Any],
            profile: dict[str, Any],
            identity: B524NativeIdentity,
            destination: int,
            value: object,
            type_spec: str,
            encoded: bytes,
            live: bool,
        ) -> _PendingWrite | None:
            description = self._effective_description(row)
            target = self._target_for_row(row, destination=destination)
            try:
                preparation = prepare_parameter_write(
                    target=target,
                    entry=entry,
                    description=description,
                    profile=profile,
                    identity=identity,
                    desired_value=value,
                )
            except ValueError as exc:
                if "explicit exception is required" not in str(exc):
                    self._set_status(f"Edit rejected: {exc}")
                    return None
                try:
                    preparation = prepare_parameter_write(
                        target=target,
                        entry=entry,
                        description=description,
                        profile=profile,
                        identity=identity,
                        desired_value=value,
                        allow_incomplete_limits=True,
                    )
                except ValueError as retry_exc:
                    self._set_status(f"Edit rejected: {retry_exc}")
                    return None
            display_selector = dict(
                opcode=target.opcode, group=target.group, register=target.register
            )
            proposed_entry = {
                key: data
                for key, data in entry.items()
                if key not in {"value_display", "enum_raw_name", "enum_resolved_name"}
            }
            proposed_entry["value"] = value
            return _PendingWrite(
                row_id=row.row_id,
                type_spec=type_spec,
                old_value_text=parameter_value_display(entry, **display_selector),
                old_raw_hex=str(entry.get("raw_hex") or ""),
                new_value_text=parameter_value_display(proposed_entry, **display_selector),
                new_raw_hex=encoded.hex(),
                new_value=value,
                preparation=preparation,
                live=live,
            )

        def _show_write_confirmation(self, pending: _PendingWrite) -> None:
            preparation = pending.preparation
            if preparation is None:
                self._set_status("Prepared edit is unavailable.")
                return
            self._pending_write = pending
            row = self._store.row_by_id(pending.row_id)
            self.push_screen(
                _ConfirmDialog(
                    title="Confirm device write" if pending.live else "Confirm offline preview",
                    summary_lines=[
                        row.display_label if row is not None else pending.row_id,
                        f"{pending.old_value_text} → {pending.new_value_text}",
                        preparation.confirmation_text,
                        "",
                        (
                            "Readback alone will determine the live result."
                            if pending.live
                            else "Observed value and raw evidence will remain unchanged."
                        ),
                    ],
                    live=pending.live,
                ),
                self._on_concrete_write_confirmation,
            )

        def _show_incomplete_limits_confirmation(self, pending: _PendingWrite) -> None:
            preparation = pending.preparation
            if preparation is None or preparation.incomplete_limits_confirmation_text is None:
                self._show_write_confirmation(pending)
                return
            self._pending_write = pending
            self.push_screen(
                _ConfirmDialog(
                    title="Confirm incomplete limits exception",
                    summary_lines=[
                        preparation.incomplete_limits_confirmation_text,
                        "",
                        "Readonly access, unknown codecs, identity mismatch, and ambiguous routes "
                        "remain blocked.",
                    ],
                    live=pending.live,
                ),
                self._on_incomplete_limits_confirmation,
            )

        def _on_incomplete_limits_confirmation(self, confirmed: bool | None) -> None:
            pending = self._pending_write
            self._pending_write = None
            if not confirmed or pending is None:
                self._set_status("Incomplete-limits exception cancelled")
                return
            pending.incomplete_limits_confirmed = True
            self._show_write_confirmation(pending)

        def _apply_offline_preview(self, pending: _PendingWrite) -> None:
            row = self._store.row_by_id(pending.row_id)
            entry = self._entry_for_row(row) if row is not None else None
            if row is None or entry is None:
                self._set_status("Selected artifact row no longer exists.")
                return
            record_offline_edit(
                entry,
                value=pending.new_value,
                raw_hex=pending.new_raw_hex,
                type_spec=pending.type_spec,
            )
            error = self._persist_artifact()
            self._refresh_table()
            if error is None:
                suffix = " and saved" if self._artifact_path is not None else " in memory"
                self._set_status(f"Offline preview recorded{suffix}; observation preserved.")
            else:
                self._set_status(f"Offline preview recorded but could not be saved: {error}")

        def _on_concrete_write_confirmation(self, confirmed: bool | None) -> None:
            pending = self._pending_write
            self._pending_write = None
            if not confirmed or pending is None:
                self._set_status("Edit cancelled")
                return
            if not pending.live:
                self._apply_offline_preview(pending)
                return
            preparation = pending.preparation
            session = self._browser_session
            if preparation is None or session is None:
                self._set_status("Live session or prepared write is unavailable.")
                return
            artifact_snapshot = deepcopy(self._artifact)
            row = self._store.row_by_id(pending.row_id)
            if row is None:
                self._set_status("Selected row no longer exists.")
                return
            selector = self._selector_for_row(row)

            def resolve_description(
                _target: B524ParameterTarget, _live_profile: dict[str, object]
            ) -> dict[str, Any] | None:
                return effective_parameter_description(artifact_snapshot, selector)

            future = session.submit(
                execute_parameter_write,
                preparation,
                concrete_confirmation=preparation.confirmation_text,
                resolve_description=resolve_description,
                incomplete_limits_confirmation=(
                    preparation.incomplete_limits_confirmation_text
                    if pending.incomplete_limits_confirmed
                    else None
                ),
            )
            self._track_transport_future(
                future,
                status="Running final identity, access, baseline, one write, and readback…",
                on_success=lambda result: self._record_live_result(pending, result, kind="write"),
                on_teardown_success=lambda result: self._record_live_result(
                    pending, result, kind="write", render=False
                ),
            )

        def _update_from_validated_readback(
            self,
            pending: _PendingWrite,
            result: B524ParameterWriteResult,
            *,
            kind: str,
        ) -> None:
            if result.outcome not in {"desired", "other"} or result.readback_raw_hex is None:
                return
            row = self._store.row_by_id(pending.row_id)
            entry = self._entry_for_row(row) if row is not None else None
            if row is None or entry is None:
                return
            try:
                raw = bytes.fromhex(result.readback_raw_hex)
                value = parse_typed_value(pending.type_spec, raw)
            except (ValueError, ValueParseError):
                return
            now_txt = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%SZ")
            entry.setdefault(
                "observed_before_live_write",
                {
                    "value": entry.get("value"),
                    "raw_hex": entry.get("raw_hex"),
                    "reply_hex": entry.get("reply_hex"),
                    "response_state": entry.get("response_state"),
                    "last_update": entry.get("last_update"),
                    "source": "artifact_observation",
                },
            )
            # The backend validates selector echo and typed raw data, but it does
            # not return the full FLAGS reply. Keep the old reply as history and
            # remove it from the active observation so raw/reply cannot disagree.
            entry.pop("reply_hex", None)
            for stale_field in ("value_display", "enum_raw_name", "enum_resolved_name"):
                entry.pop(stale_field, None)
            entry.update(
                value=value,
                raw_hex=raw.hex(),
                error=None,
                response_state="active",
                last_update=now_txt,
                last_write_outcome=result.outcome,
                validated_readback={
                    "value": value,
                    "raw_hex": raw.hex(),
                    "source": kind,
                    "outcome": result.outcome,
                    "recorded_at": now_txt,
                    "selector_echo_verified": True,
                },
            )
            if kind == "write" and result.outcome == "desired" and result.write_attempts == 1:
                entry["written"] = True
                entry["written_at"] = now_txt
                self._written_at[pending.row_id] = now_txt
            self._update_store_row(
                row_id=pending.row_id,
                value_text=_fmt_value_text(value),
                raw_hex=raw.hex(),
                last_update_text=now_txt,
                age_text="0.0s",
            )
            watch = self._watch.get(pending.row_id)
            if watch is not None:
                now_mono = monotonic()
                watch.previous_value = watch.current_value
                watch.previous_raw = watch.current_raw
                watch.current_value = _fmt_value_text(value)
                watch.current_raw = raw.hex()
                watch.change_indicator = compute_change_indicator(
                    watch.previous_value, watch.current_value
                )
                watch.last_poll_at = now_mono
                watch.last_poll_text = now_txt
                watch.next_poll_at = now_mono + watch.poll_interval_s

        def _record_live_result(
            self,
            pending: _PendingWrite,
            result: B524ParameterWriteResult,
            *,
            kind: str,
            render: bool = True,
        ) -> None:
            history_obj = self._artifact.setdefault("b524_parameter_write_history", [])
            if not isinstance(history_obj, list):
                history_obj = []
                self._artifact["b524_parameter_write_history"] = history_obj
            history_obj.append(
                {
                    "kind": kind,
                    "recorded_at": datetime.now(UTC).isoformat(),
                    "row_id": pending.row_id,
                    "type": pending.type_spec,
                    "desired_value": pending.new_value,
                    "desired_raw_hex": pending.new_raw_hex,
                    "result": asdict(result),
                }
            )
            self._update_from_validated_readback(pending, result, kind=kind)
            self._last_live_write = (pending, result)
            persistence_error = self._persist_artifact()
            if render:
                self._render_watch_dock()
                self._refresh_table()
            suffix = (
                f" Artifact save failed: {persistence_error}"
                if persistence_error is not None
                else ""
            )
            if not render:
                return
            if kind == "read_only_recheck" and result.outcome == "desired":
                self._set_status(
                    f"Read-only recheck found the desired value; the recheck sent no write.{suffix}"
                )
            elif result.outcome == "desired":
                self._set_status(f"Write confirmed by desired-value readback.{suffix}")
            elif result.outcome == "other":
                self._set_status(f"Write not confirmed; readback returned another value.{suffix}")
            elif result.outcome == "unknown":
                self._set_status(f"Write outcome unknown; press V for read-only recheck.{suffix}")
            elif result.outcome == "reconfirmation_required":
                self._set_status(f"Baseline changed; edit again to reconfirm.{suffix}")
            elif result.outcome == "no_op":
                self._set_status(f"No-op; no native write was sent.{suffix}")
            else:
                self._set_status(f"Write blocked by fresh verification.{suffix}")

        def action_recheck(self) -> None:
            if self._transport_busy:
                self._set_status("Wait for the current transport operation to finish.")
                return
            if self._browser_session is None:
                self._set_status("Connect before rechecking a live write.")
                return
            last = self._last_live_write
            if last is None or last[1].outcome != "unknown":
                self._set_status("There is no unknown live write to recheck.")
                return
            pending, _previous = last
            preparation = pending.preparation
            if preparation is None:
                self._set_status("Prepared write context is unavailable.")
                return
            future = self._browser_session.submit(recheck_parameter_write, preparation)
            self._track_transport_future(
                future,
                status="Running read-only identity and value recheck…",
                on_success=lambda result: self._record_live_result(
                    pending, result, kind="read_only_recheck"
                ),
                on_teardown_success=lambda result: self._record_live_result(
                    pending, result, kind="read_only_recheck", render=False
                ),
            )

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
            context = self._live_edit_context
            live = (
                context is not None
                and context.target.destination == self._session_dst
                and self._browser_session is not None
            )
            entry = context.entry if live and context is not None else self._entry_for_row(row)
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
            choices = parameter_enum_choices(
                entry,
                read_opcode=int(self._selector_for_row(row)["read_opcode"], 0),
                group=int(self._selector_for_row(row)["group"], 0),
                register=int(row.register_key, 0),
                description=self._effective_description(row),
            )
            blocked_choice = next(
                (
                    choice
                    for choice in choices
                    if choice.value == canonical_value and not choice.enabled
                ),
                None,
            )
            if blocked_choice is not None:
                self._set_status(
                    f"Edit rejected: {blocked_choice.label} ({blocked_choice.value}) is disabled — "
                    f"{blocked_choice.reason}"
                )
                return
            try:
                if live and context is not None:
                    profile = context.profile
                    identity = context.identity
                    destination = context.target.destination
                else:
                    profile = description_profile(self._artifact, self._selector_for_row(row))
                    identity = _artifact_native_identity(self._artifact)
                    destination = self._artifact_destination()
            except ValueError as exc:
                self._set_status(f"Edit rejected: {exc}")
                return
            pending = self._prepare_pending_write(
                row=row,
                entry=entry,
                profile=profile,
                identity=identity,
                destination=destination,
                value=canonical_value,
                type_spec=type_spec,
                encoded=new_bytes,
                live=live,
            )
            self._live_edit_context = None
            if pending is not None:
                self._show_incomplete_limits_confirmation(pending)

        def _finish_live_edit_context(self, context: B524ParameterEditContext) -> None:
            row_id = self._editing_row_id
            row = self._store.row_by_id(row_id) if row_id is not None else None
            if row is None:
                self._editing_row_id = None
                self._set_status("Selected row no longer exists.")
                return
            self._live_edit_context = context
            self._open_parameter_editor(row, context.entry)

        def action_edit_selected(self) -> None:
            if len(self.screen_stack) > 1:
                return
            row = self._selected_table_row()
            if row is not None and (row.section_key or "").startswith("operation_"):
                self._preview_operation_export(row)
                return
            if row is None:
                self._set_status("Select a table row to edit.")
                return
            entry = self._entry_for_row(row)
            if entry is None:
                self._set_status("Artifact entry not found.")
                return
            flags = entry.get("flags") if entry else None
            access = entry.get("flags_access") if entry else None
            writable = (
                access in {"writable_not_visible", "writable_visible"}
                if isinstance(access, str)
                else entry.get("writable")
                if entry is not None
                else None
            )
            if writable is None and isinstance(flags, int) and flags in {0, 1, 2, 3}:
                writable = bool(flags & 2)
            if writable is False or (writable is None and row.tab == "state"):
                self._set_status("Parameter is read-only.")
                return
            type_spec_obj = entry.get("type") if entry is not None else None
            type_spec = type_spec_obj if isinstance(type_spec_obj, str) and type_spec_obj else None
            if type_spec is None:
                self._set_status("No type for this row; cannot edit safely.")
                return
            if self._browser_session is None:
                self._live_edit_context = None
                self._open_parameter_editor(row, entry)
                return
            if self._transport_busy:
                self._set_status("Wait for the current transport operation to finish.")
                return
            try:
                destination = self._session_dst
                if destination is None:
                    raise ValueError("live destination is unavailable")
                target = self._target_for_row(row, destination=destination)
                identity = _artifact_native_identity(self._artifact)
                profile = description_profile(self._artifact, self._selector_for_row(row))
            except ValueError as exc:
                self._set_status(f"Live edit unavailable: {exc}")
                return
            self._editing_row_id = row.row_id
            future = self._browser_session.submit(
                read_parameter_edit_context,
                target=target,
                entry=entry,
                profile=profile,
                identity=identity,
            )
            self._track_transport_future(
                future,
                status="Reading fresh identity, profile, access, and baseline…",
                on_success=self._finish_live_edit_context,
            )

        def _preview_operation_export(self, row: RegisterRow) -> None:
            from ..scanner.b524_operation_edit import build_operation_edit_preview
            from .b524_operation_reads import operation_edit_export

            reads = self._artifact.get("b524_operation_reads")
            if not isinstance(reads, list):
                self._set_status("No operation reads available for offline export.")
                return
            records = [record for record in reads if isinstance(record, dict)]
            operation = {
                "operation_03": "WriteTimer",
                "operation_09": "SetEvent",
                "operation_0b": "SetEventSetPoint",
            }.get(row.section_key or "")
            if operation is None:
                self._set_status("OP08 has no editable operation export.")
                return
            matching = next(
                (
                    record
                    for record in records
                    if isinstance(record.get("request_payload_hex"), str)
                    and record["request_payload_hex"] in row.row_id
                ),
                None,
            )
            selector = matching.get("selector") if isinstance(matching, dict) else None
            if not isinstance(selector, dict):
                self._set_status("Selected operation selector is unavailable.")
                return
            try:
                meta = self._artifact.get("meta")
                dst = meta.get("destination_address") if isinstance(meta, dict) else None
                if isinstance(dst, bool) or not isinstance(dst, (str, int)):
                    raise ValueError("artifact destination must be a byte address")
                destination = int(dst, 0) if isinstance(dst, str) else dst
                if not 0 <= destination <= 0xFF:
                    raise ValueError("artifact destination must be in range 0..255")
                document = operation_edit_export(
                    records,
                    selector=selector,
                    operation=operation,
                    destination_address=destination,
                )
                build_operation_edit_preview(document, dst=destination)
            except ValueError as exc:
                self._set_status(f"Offline export unavailable: {exc}")
                return
            self.push_screen(_OperationEditDialog(document=document, destination=destination))

        def action_close_dialog(self) -> None:
            if len(self.screen_stack) > 1:
                self.pop_screen()

        async def action_quit(self) -> None:
            if self._transport_busy or not self._inflight_recorded:
                self._set_status(
                    "A transport result is still in flight; wait for it to be recorded "
                    "before quitting."
                )
                return
            self.close_transport(wait=False)
            self.exit()


def _compose_browse_app(
    artifact: dict[str, object],
    *,
    allow_write: bool,
    store: BrowseStore,
    connection_settings: dict[str, Any] | None = None,
    artifact_path: Path | None = None,
) -> Any:
    kwargs: dict[str, Any] = {"allow_write": allow_write, "store": store}
    # Preserve older FakeApp constructor seams by adding new kwargs only when used.
    if connection_settings is not None:
        kwargs["connection_settings"] = connection_settings
    if artifact_path is not None:
        kwargs["artifact_path"] = artifact_path
    return _BrowseApp(artifact, **kwargs)


def _run_browse_app(app: Any) -> None:
    try:
        app.run()
    finally:
        close = getattr(app, "close_transport", None)
        if callable(close):
            close(wait=True)


def run_browse_from_artifact(
    artifact: dict[str, object],
    *,
    allow_write: bool,
    connection_settings: dict[str, Any] | None = None,
    artifact_path: Path | None = None,
) -> None:
    artifact = _validate_browse_artifact(artifact)
    _raise_if_textual_unavailable()
    store = _hydrate_browse_store(artifact)
    _run_browse_app(
        _compose_browse_app(
            artifact,
            allow_write=allow_write,
            store=store,
            connection_settings=connection_settings,
            artifact_path=artifact_path,
        )
    )
