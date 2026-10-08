from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from ..scanner.plan import (
    GroupScanPlan,
    PlanKey,
    estimate_eta_seconds,
    estimate_register_requests,
    format_int_set,
    parse_int_set,
    parse_int_token,
)
from ..scanner.scan_policy import validate_scalar_request_limit
from .planner import (
    PlannerGroup,
    PlannerPreset,
    _format_seconds,
    build_plan_from_preset,
    format_planner_instance_bounds,
    format_planner_op00_count,
    planner_instance_range,
    planner_namespace_title,
    planner_present_instances,
    planner_unmapped_system_information,
    split_planner_groups_by_namespace,
)
from .system_information import format_system_information_text

PLANNER_TABLE_COLUMNS = (
    "On",
    "GG",
    "Name",
    "OP00 count",
    "II range",
    "Instances",
    "RR_max",
)


@dataclass(slots=True)
class _EditableGroup:
    group: PlannerGroup
    enabled: bool
    rr_max: int
    instances: tuple[int, ...]
    registers: tuple[int, ...] | None = None


def _table_row_values(
    state: _EditableGroup,
    system_information: Sequence[Mapping[str, object]] | None = None,
) -> tuple[str, str, str, str, str, str, str]:
    group = state.group
    mark = "✓" if state.enabled else " "
    name = group.name if group.known else f"{group.name} (experimental)"
    return (
        mark,
        f"0x{group.group:02X}",
        name,
        format_planner_op00_count(group, system_information),
        format_planner_instance_bounds(group),
        _format_instances(group, state.instances, enabled=state.enabled),
        _format_register_scope(state),
    )


def _format_register_scope(state: _EditableGroup) -> str:
    if state.registers is None:
        return f"0x{state.rr_max:04X}"
    return ",".join(f"0x{register:04X}" for register in state.registers)


def _parse_register_scope(spec: str) -> tuple[int, tuple[int, ...] | None]:
    """Parse a legacy RR ceiling or an exact comma/range selector scope."""

    raw = spec.strip()
    if not raw:
        raise ValueError("Empty register scope")
    if not any(marker in raw for marker in (",", "..", "-")):
        rr_max = parse_int_token(raw)
        if not (0x0000 <= rr_max <= 0xFFFF):
            raise ValueError("RR_max must be in 0x0000..0xFFFF")
        return rr_max, None
    registers = tuple(parse_int_set(raw, min_value=0x0000, max_value=0xFFFF))
    if not registers:
        raise ValueError("Register scope must not be empty")
    return max(registers), registers


def _format_instances(group: PlannerGroup, instances: tuple[int, ...], *, enabled: bool) -> str:
    if group.ii_max is None:
        return "singleton"

    full = planner_instance_range(group)
    total = len(full)
    selected = len(instances)
    if instances == full:
        label = f"all {selected}/{total}"
    elif instances == planner_present_instances(group):
        label = f"present {selected}/{total}"
    elif not instances:
        label = f"none 0/{total}"
    else:
        label = f"{format_int_set(list(instances))} ({selected}/{total})"
    if not enabled:
        return f"{label} (off)"
    return label


def _parse_instances_spec(spec: str, *, group: PlannerGroup) -> tuple[int, ...]:
    if group.ii_max is None:
        return (0x00,)
    raw = spec.strip().lower()
    if raw in {"all", "*"}:
        return planner_instance_range(group)
    if raw in {"present", "p"}:
        return planner_present_instances(group)
    if raw in {"none", "no"}:
        return ()
    allowed = planner_instance_range(group)
    parsed = parse_int_set(spec, min_value=min(allowed), max_value=max(allowed))
    if any(ii not in allowed for ii in parsed):
        raise ValueError("instance is outside the operation profile range")
    return tuple(parsed)


def _estimate_footer(
    states: dict[PlanKey, _EditableGroup],
    *,
    request_rate_rps: float | None,
) -> str:
    plan = {
        key: GroupScanPlan(
            group=state.group.group,
            opcode=state.group.opcode,
            rr_max=state.rr_max,
            instances=state.instances,
            registers=state.registers,
        )
        for (key, state) in states.items()
        if state.enabled
    }
    requests = estimate_register_requests(plan)
    eta_s = estimate_eta_seconds(requests=requests, request_rate_rps=request_rate_rps)
    eta_txt = _format_seconds(eta_s) if eta_s is not None else "n/a"
    rate_txt = f"{request_rate_rps:.2f}" if request_rate_rps is not None else "n/a"
    enabled_groups = sum(1 for state in states.values() if state.enabled)
    return (
        f"Plan: {requests} requests | ETA: {eta_txt} @ {rate_txt} req/s | "
        f"{enabled_groups} plan entries selected"
    )


def _planner_pane_id(opcode: int) -> str:
    if opcode == 0x02:
        return "local"
    # Keep the planner bounded to the two B524 namespace panes. Unexpected
    # opcodes are routed to remote instead of being silently dropped.
    return "remote"


_PANE_TABLE_IDS: dict[str, str] = {
    "local": "planner-table-local",
    "remote": "planner-table-remote",
}


def _table_id_to_pane_key(table_id: str | None) -> str | None:
    if table_id is None:
        return None
    for pane_key, pane_table_id in _PANE_TABLE_IDS.items():
        if table_id == pane_table_id:
            return pane_key
    return None


def run_textual_scan_plan(
    groups: list[PlannerGroup],
    *,
    request_rate_rps: float | None,
    default_plan: dict[PlanKey, GroupScanPlan] | None = None,
    default_preset: PlannerPreset = "recommended",
    system_information: Sequence[Mapping[str, object]] | None = None,
) -> dict[PlanKey, GroupScanPlan] | None:
    """Open a Textual planner and return selected plan (None when cancelled).

    This function imports Textual lazily so non-interactive environments remain lightweight.
    """

    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Vertical
    from textual.events import Key
    from textual.screen import ModalScreen
    from textual.widgets import DataTable, Footer, Header, Input, Label, Static

    class _InputDialog(ModalScreen[str | None]):
        BINDINGS = [
            Binding(
                "enter,return,ctrl+j,ctrl+m",
                "submit",
                "Save",
                show=False,
                priority=True,
            ),
            Binding("escape", "cancel", "Cancel"),
        ]
        CSS = """
        _InputDialog {
            align: center middle;
        }
        _InputDialog > Vertical {
            width: 72;
            padding: 1 2;
            border: heavy $accent;
            background: $surface;
        }
        """

        def __init__(self, *, title: str, value: str, hint: str) -> None:
            super().__init__()
            self._title = title
            self._value = value
            self._hint = hint

        def compose(self) -> ComposeResult:
            yield Vertical(
                Label(self._title),
                Input(value=self._value, id="value"),
                Static(self._hint, classes="dim"),
            )

        def on_mount(self) -> None:
            field = self.query_one(Input)
            field.focus()
            # Make edits overwrite the default value without requiring manual delete.
            field.select_all()

        def action_cancel(self) -> None:
            self.dismiss(None)

        def action_submit(self) -> None:
            value = self.query_one(Input).value.strip()
            self.dismiss(value)

    class _PlannerApp(App[dict[PlanKey, GroupScanPlan] | None]):
        BINDINGS = [
            Binding("space", "toggle_enabled", "Toggle"),
            Binding(
                "enter,return,ctrl+j,ctrl+m",
                "edit_rr_max",
                "Edit RR",
                show=False,
            ),
            Binding("tab", "focus_next", "Next"),
            Binding("i", "edit_instances", "Edit II"),
            Binding("1", "preset_recommended", "Preset 1"),
            Binding("2", "preset_full", "Preset 2"),
            Binding("3", "preset_research", "Preset 3"),
            Binding("4", "preset_custom", "Preset 4"),
            Binding("s", "save", "Save"),
            Binding("q", "cancel", "Cancel"),
            Binding("question_mark", "show_help", "Help"),
        ]

        CSS = """
        Screen {
            background: #2e3436;
            color: #eeeeec;
        }
        #planner-pane-local, #planner-pane-remote {
            height: 1fr;
        }
        DataTable {
            height: 1fr;
        }
        #status {
            padding: 0 1;
            color: #729fcf;
            background: #204a87;
        }
        #help {
            padding: 0 1;
            color: #fce94f;
            background: #555753;
        }
        """

        def __init__(self) -> None:
            super().__init__()
            self._system_information = system_information
            namespace_sections = split_planner_groups_by_namespace(groups)
            self._groups = [
                group for (_title, pane_groups) in namespace_sections for group in pane_groups
            ]
            preset_plan = build_plan_from_preset(self._groups, preset=default_preset)
            initial_plan = default_plan if default_plan is not None else preset_plan
            self._states: dict[PlanKey, _EditableGroup] = {}
            self._row_groups: dict[str, list[PlanKey]] = {"local": [], "remote": []}
            self._editing_group: PlanKey | None = None
            self._suppress_next_enter = False
            for group in self._groups:
                group_plan = initial_plan.get(group.key)
                if group_plan is None:
                    instances = (
                        (0x00,) if group.ii_max is None else planner_present_instances(group)
                    )
                    self._states[group.key] = _EditableGroup(
                        group=group,
                        enabled=False,
                        rr_max=group.rr_max,
                        instances=instances,
                        registers=None,
                    )
                else:
                    self._states[group.key] = _EditableGroup(
                        group=group,
                        enabled=True,
                        rr_max=group_plan.rr_max,
                        instances=group_plan.instances,
                        registers=group_plan.registers,
                    )

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            system_information_text = format_system_information_text(
                planner_unmapped_system_information(system_information)
            )
            if system_information_text:
                yield Static(
                    f"System Information: {system_information_text}", id="system-information"
                )
            yield Vertical(
                Vertical(
                    Label(planner_namespace_title(0x02)),
                    DataTable(id="planner-table-local"),
                    id="planner-pane-local",
                ),
                Vertical(
                    Label(planner_namespace_title(0x06)),
                    DataTable(id="planner-table-remote"),
                    id="planner-pane-remote",
                ),
                id="planner-panes",
            )
            yield Static("", id="status")
            yield Static("", id="help")
            yield Footer()

        def on_mount(self) -> None:
            for table_id in _PANE_TABLE_IDS.values():
                table = self.query_one(f"#{table_id}", DataTable)
                table.cursor_type = "row"
                table.add_columns(*PLANNER_TABLE_COLUMNS)
            self._refresh_table()
            self._set_help("1/2/3/4 presets | Space toggle | Enter edit RR_max | i edit instances")
            if self._row_groups["local"]:
                self.query_one("#planner-table-local", DataTable).focus()
            else:
                self.query_one("#planner-table-remote", DataTable).focus()

        def _set_help(self, text: str) -> None:
            self.query_one("#help", Static).update(text)

        def _set_status(self) -> None:
            self.query_one("#status", Static).update(
                _estimate_footer(self._states, request_rate_rps=request_rate_rps)
            )

        def _focused_group(self) -> PlanKey | None:
            if not isinstance(self.focused, DataTable):
                return None
            pane_key = _table_id_to_pane_key(self.focused.id)
            if pane_key is None:
                return None
            row_groups = self._row_groups[pane_key]
            if not row_groups:
                return None
            row = self.focused.cursor_row
            if row < 0 or row >= len(row_groups):
                return None
            return row_groups[row]

        def _refresh_table(self) -> None:
            table_by_pane = {
                pane_key: self.query_one(f"#{table_id}", DataTable)
                for pane_key, table_id in _PANE_TABLE_IDS.items()
            }
            cursor_by_pane = {
                pane: max(0, table.cursor_row) for pane, table in table_by_pane.items()
            }
            for table in table_by_pane.values():
                table.clear(columns=False)
            self._row_groups = {pane_key: [] for pane_key in _PANE_TABLE_IDS}
            for group in self._groups:
                pane_key = _planner_pane_id(group.opcode)
                pane_table = table_by_pane.get(pane_key)
                if pane_table is None:
                    continue
                state = self._states[group.key]
                pane_table.add_row(*_table_row_values(state, self._system_information))
                self._row_groups[pane_key].append(group.key)
            for pane_key, table in table_by_pane.items():
                row_groups = self._row_groups[pane_key]
                if row_groups:
                    table.move_cursor(row=min(cursor_by_pane[pane_key], len(row_groups) - 1))
            self._set_status()

        def _focus_table(self) -> None:
            if (
                isinstance(self.focused, DataTable)
                and _table_id_to_pane_key(self.focused.id) is not None
            ):
                self.focused.focus()
                return
            for pane_key in ("local", "remote"):
                if self._row_groups[pane_key]:
                    self.query_one(f"#{_PANE_TABLE_IDS[pane_key]}", DataTable).focus()
                    return
            self.query_one("#planner-table-local", DataTable).focus()

        def _suppress_enter_reactivation(self) -> None:
            # A modal input dialog closes on Enter and immediately refocuses the
            # table. Suppress the next planner-level Enter handling so the same
            # keystroke doesn't reopen RR editing underneath the dismissed modal.
            self._suppress_next_enter = True

        def _apply_preset(self, preset: PlannerPreset) -> None:
            preset_plan = build_plan_from_preset(self._groups, preset=preset)
            for group in self._groups:
                state = self._states[group.key]
                planned = preset_plan.get(group.key)
                if planned is None:
                    state.enabled = False
                    continue
                state.enabled = True
                state.rr_max = planned.rr_max
                state.instances = planned.instances
                state.registers = planned.registers
            self._refresh_table()
            self._set_help(f"Applied preset: {preset}")

        def _edit_rr_max(self, value: str | None) -> None:
            if value is None or self._editing_group is None:
                self._set_help("RR_max edit cancelled")
                self._editing_group = None
                self._focus_table()
                return
            try:
                rr_max, registers = _parse_register_scope(value)
            except ValueError as exc:
                self._set_help(f"Invalid RR scope: {exc}")
                self._suppress_enter_reactivation()
                self._focus_table()
                return
            state = self._states[self._editing_group]
            state.rr_max = rr_max
            state.registers = registers
            self._refresh_table()
            edited_group = self._states[self._editing_group].group
            self._set_help(f"Updated RR_max for {edited_group.prompt_label}")
            self._editing_group = None
            self._suppress_enter_reactivation()
            self._focus_table()

        def _edit_instances(self, value: str | None) -> None:
            if value is None or self._editing_group is None:
                self._set_help("Instance edit cancelled")
                self._editing_group = None
                self._focus_table()
                return
            group = self._states[self._editing_group].group
            if group.ii_max is None:
                self._set_help("Group is singleton; instances are fixed")
                self._editing_group = None
                self._focus_table()
                return
            try:
                instances = _parse_instances_spec(value, group=group)
            except ValueError as exc:
                self._set_help(f"Invalid instances: {exc}")
                self._suppress_enter_reactivation()
                self._focus_table()
                return
            self._states[self._editing_group].instances = instances
            self._refresh_table()
            self._set_help(f"Updated instances for {group.prompt_label}")
            self._editing_group = None
            self._suppress_enter_reactivation()
            self._focus_table()

        def action_focus_next(self) -> None:
            tables = [
                self.query_one("#planner-table-local", DataTable),
                self.query_one("#planner-table-remote", DataTable),
            ]
            if not any(self._row_groups[pane_key] for pane_key in _PANE_TABLE_IDS):
                return
            if isinstance(self.focused, DataTable):
                current_idx = next(
                    (index for index, table in enumerate(tables) if table.id == self.focused.id),
                    0,
                )
            else:
                current_idx = 0
            for offset in range(1, len(tables) + 1):
                candidate = tables[(current_idx + offset) % len(tables)]
                pane_key = _table_id_to_pane_key(candidate.id)
                if pane_key is not None and self._row_groups[pane_key]:
                    candidate.focus()
                    return

        def on_key(self, event: Key) -> None:
            # Accept Enter/Return variants for row edit while avoiding modal interference.
            if event.key not in {"enter", "ctrl+j", "ctrl+m"}:
                return
            if self._suppress_next_enter:
                self._suppress_next_enter = False
                event.stop()
                return
            if len(self.screen_stack) > 1:
                return
            if isinstance(self.focused, DataTable) and self.focused.id in set(
                _PANE_TABLE_IDS.values()
            ):
                event.stop()
                self.action_edit_rr_max()

        def action_toggle_enabled(self) -> None:
            key = self._focused_group()
            if key is None:
                return
            self._states[key].enabled = not self._states[key].enabled
            self._refresh_table()

        def action_edit_rr_max(self) -> None:
            if len(self.screen_stack) > 1:
                return
            key = self._focused_group()
            if key is None:
                return
            self._editing_group = key
            state = self._states[key]
            current = _format_register_scope(state)
            planner_group = state.group
            self.push_screen(
                _InputDialog(
                    title=f"RR_max for {planner_group.prompt_label}",
                    value=current,
                    hint="RR_max or exact list/range. Enter=save Esc=cancel",
                ),
                self._edit_rr_max,
            )

        def on_data_table_row_selected(self, _event: DataTable.RowSelected) -> None:
            # Keep Enter behavior stable even if DataTable handles Enter locally.
            if self._suppress_next_enter:
                self._suppress_next_enter = False
                return
            self.action_edit_rr_max()

        def action_edit_instances(self) -> None:
            if len(self.screen_stack) > 1:
                return
            key = self._focused_group()
            if key is None:
                return
            group = self._states[key].group
            if group.ii_max is None:
                self._set_help("Group is singleton; no instance selection")
                return
            self._editing_group = key
            current = self._states[key].instances
            default_value = format_int_set(list(current)) if current else "none"
            allowed_text = format_int_set(list(planner_instance_range(group)))
            self.push_screen(
                _InputDialog(
                    title=f"Instances for {group.prompt_label}",
                    value=default_value,
                    hint=f"Use present|all|none|{allowed_text}",
                ),
                self._edit_instances,
            )

        def action_preset_recommended(self) -> None:
            self._apply_preset("recommended")

        def action_preset_full(self) -> None:
            self._apply_preset("full")

        def action_preset_research(self) -> None:
            self._apply_preset("research")

        def action_preset_custom(self) -> None:
            self._apply_preset("custom")

        def action_show_help(self) -> None:
            self._set_help("Space=toggle Enter=RR i=instances 1/2/3/4=presets s=save q=cancel")

        def action_save(self) -> None:
            plan = {
                key: GroupScanPlan(
                    group=state.group.group,
                    opcode=state.group.opcode,
                    rr_max=state.rr_max,
                    instances=state.instances,
                    registers=state.registers,
                )
                for (key, state) in sorted(self._states.items())
                if state.enabled
            }
            try:
                validate_scalar_request_limit(plan)
            except ValueError as exc:
                self._set_help(f"Invalid scan plan: {exc}")
                return
            self.exit(plan)

        def action_cancel(self) -> None:
            self.exit(None)

    return _PlannerApp().run()
