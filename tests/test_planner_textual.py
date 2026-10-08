from __future__ import annotations

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan
from helianthus_vrc_explorer.ui.planner import PlannerGroup, split_planner_groups_by_namespace
from helianthus_vrc_explorer.ui.planner_textual import (
    _EditableGroup,
    _estimate_footer,
    _parse_instances_spec,
    _parse_register_scope,
    _planner_pane_id,
    _table_row_values,
    run_textual_scan_plan,
)


def test_parse_instances_spec_accepts_keywords_and_ranges() -> None:
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x21,
        rr_max_full=0x21,
        present_instances=(0x01, 0x02, 0x03),
    )
    assert _parse_instances_spec("present", group=group) == (0x01, 0x02, 0x03)
    assert _parse_instances_spec("all", group=group) == tuple(range(1, 10))
    assert _parse_instances_spec("1-2", group=group) == (0x01, 0x02)


def test_parse_register_scope_distinguishes_ceiling_from_exact_selectors() -> None:
    assert _parse_register_scope("0x0015") == (0x0015, None)
    assert _parse_register_scope("0x0002,0x0010..0x0012") == (
        0x0012,
        (0x0002, 0x0010, 0x0011, 0x0012),
    )


def test_estimate_footer_reports_requests_and_eta() -> None:
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x02,
        rr_max_full=0x02,
        present_instances=(0x01,),
    )
    states = {
        (0x02, 0x02): _EditableGroup(
            group=group,
            enabled=True,
            rr_max=0x02,
            instances=(0x01, 0x02),
        )
    }
    footer = _estimate_footer(states, request_rate_rps=2.0)
    assert "Plan: 9 requests" in footer
    assert "ETA:" in footer
    assert "1 plan entries selected" in footer


def test_estimate_footer_uses_exact_register_selectors() -> None:
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x0100,
        rr_max_full=0x0100,
        present_instances=(0x01,),
    )
    states = {
        group.key: _EditableGroup(
            group=group,
            enabled=True,
            rr_max=0x0100,
            instances=(0x01, 0x03),
            registers=(0x0002, 0x0010, 0x0100),
        )
    }

    assert "Plan: 9 requests" in _estimate_footer(states, request_rate_rps=None)


def test_table_row_values_show_explicit_namespace_column() -> None:
    remote_group = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Primary Heating Sources",
        descriptor=3.0,
        known=True,
        ii_max=8,
        rr_max=0x0015,
        rr_max_full=0x0015,
        present_instances=(0x01,),
        namespace_label="remote",
    )
    local_only_group = PlannerGroup(
        group=0x00,
        opcode=0x02,
        name="Regulator Parameters",
        descriptor=3.0,
        known=True,
        ii_max=None,
        rr_max=0x00FF,
        rr_max_full=0x00FF,
        present_instances=(0x01,),
    )

    remote_row = _table_row_values(
        _EditableGroup(
            group=remote_group,
            enabled=True,
            rr_max=0x0015,
            instances=(0x01,),
        )
    )
    local_row = _table_row_values(
        _EditableGroup(
            group=local_only_group,
            enabled=False,
            rr_max=0x00FF,
            instances=(0x01,),
        )
    )

    assert remote_row == (
        "✓",
        "0x01",
        "Primary Heating Sources",
        "remote",
        "3.0",
        "present 1/8",
        "0x0015",
    )
    assert local_row == (
        " ",
        "0x00",
        "Regulator Parameters",
        "local",
        "3.0",
        "singleton",
        "0x00FF",
    )


def test_split_planner_groups_by_namespace_prefers_local_then_remote() -> None:
    local_group = PlannerGroup(
        group=0x09,
        opcode=0x02,
        name="System",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x000F,
        rr_max_full=0x000F,
        present_instances=(0x01,),
        namespace_label="local",
    )
    remote_group = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Primary Heating Sources",
        descriptor=3.0,
        known=True,
        ii_max=8,
        rr_max=0x0015,
        rr_max_full=0x0015,
        present_instances=(0x01,),
        namespace_label="remote",
    )

    sections = split_planner_groups_by_namespace([remote_group, local_group])

    assert [title for (title, _rows) in sections] == [
        "Local Devices (0x02)",
        "Remote Devices (0x06)",
    ]
    assert sections[0][1] == [local_group]
    assert sections[1][1] == [remote_group]


def test_planner_pane_id_routes_unexpected_namespaces_into_remote_pane() -> None:
    assert _planner_pane_id(0x02) == "local"
    assert _planner_pane_id(0x06) == "remote"
    assert _planner_pane_id(0x08) == "remote"


def test_run_textual_scan_plan_registers_enter_binding_for_rr_max(
    monkeypatch,
) -> None:
    from textual.app import App

    captured: dict[str, str] = {}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        for binding in self.BINDINGS:
            if binding.action == "edit_rr_max":
                captured["key"] = binding.key
                return None
        raise AssertionError("edit_rr_max binding not found")

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x00,
                opcode=0x02,
                name="Regulator Parameters",
                descriptor=3.0,
                known=True,
                ii_max=None,
                rr_max=0x00FF,
                rr_max_full=0x00FF,
                present_instances=(0x01,),
            )
        ],
        request_rate_rps=None,
    )

    assert "enter" in captured["key"]


def test_run_textual_scan_plan_preserves_exact_default_registers_on_save(monkeypatch) -> None:
    from textual.app import App

    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x0100,
        rr_max_full=0x0100,
        present_instances=(0x01, 0x03),
    )
    default = GroupScanPlan(
        group=0x02,
        opcode=0x02,
        rr_max=0x0100,
        instances=(0x01, 0x03),
        registers=(0x0002, 0x0010, 0x0100),
    )
    captured: dict[str, object] = {}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> object:
        self.exit = lambda result: captured.__setitem__("plan", result)  # type: ignore[method-assign]
        self.action_save()
        return captured["plan"]

    monkeypatch.setattr(App, "run", fake_run)

    result = run_textual_scan_plan(
        [group],
        request_rate_rps=None,
        default_plan={group.key: default},
    )

    assert result == {group.key: default}


def test_run_textual_scan_plan_rr_dialog_registers_enter_submit_binding(
    monkeypatch,
) -> None:
    from textual.app import App

    captured: dict[str, str] = {}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        key = next(iter(self._states))
        self._focused_group = lambda: key  # type: ignore[method-assign]

        def fake_push_screen(screen: object, *args: object, **kwargs: object) -> None:
            for binding in screen.BINDINGS:
                if binding.action == "submit":
                    captured["key"] = binding.key
                    return None
            raise AssertionError("submit binding not found on rr dialog")

        self.push_screen = fake_push_screen  # type: ignore[method-assign]
        self.action_edit_rr_max()
        return None

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x00,
                opcode=0x02,
                name="Regulator Parameters",
                descriptor=3.0,
                known=True,
                ii_max=None,
                rr_max=0x00FF,
                rr_max_full=0x00FF,
                present_instances=(0x01,),
            )
        ],
        request_rate_rps=None,
    )

    assert "enter" in captured["key"]


def test_run_textual_scan_plan_instances_dialog_registers_enter_submit_binding(
    monkeypatch,
) -> None:
    from textual.app import App

    captured: dict[str, str] = {}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        key = next(iter(self._states))
        self._focused_group = lambda: key  # type: ignore[method-assign]

        def fake_push_screen(screen: object, *args: object, **kwargs: object) -> None:
            for binding in screen.BINDINGS:
                if binding.action == "submit":
                    captured["key"] = binding.key
                    return None
            raise AssertionError("submit binding not found on instances dialog")

        self.push_screen = fake_push_screen  # type: ignore[method-assign]
        self.action_edit_instances()
        return None

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x02,
                opcode=0x02,
                name="Heating Circuits",
                descriptor=1.0,
                known=True,
                ii_max=0x09,
                rr_max=0x0025,
                rr_max_full=0x0025,
                present_instances=(0x01, 0x02, 0x03),
            )
        ],
        request_rate_rps=None,
    )

    assert "enter" in captured["key"]


def test_instances_dialog_submit_suppresses_immediate_rr_reopen(monkeypatch) -> None:
    from textual.app import App

    captured: dict[str, bool] = {"reopened": False, "suppressed": False}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        key = next(iter(self._states))
        self._editing_group = key
        self._focus_table = lambda: None  # type: ignore[method-assign]
        self._refresh_table = lambda: None  # type: ignore[method-assign]
        self._set_help = lambda _text: None  # type: ignore[method-assign]
        self.action_edit_rr_max = lambda: captured.__setitem__("reopened", True)  # type: ignore[method-assign]

        self._edit_instances("0-1")
        captured["suppressed"] = self._suppress_next_enter

        self.on_data_table_row_selected(None)  # type: ignore[arg-type]
        return None

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x02,
                opcode=0x02,
                name="Heating Circuits",
                descriptor=1.0,
                known=True,
                ii_max=0x09,
                rr_max=0x0025,
                rr_max_full=0x0025,
                present_instances=(0x01, 0x02, 0x03),
            )
        ],
        request_rate_rps=None,
    )

    assert captured["suppressed"] is True
    assert captured["reopened"] is False


def test_instances_dialog_cancel_does_not_suppress_next_enter(monkeypatch) -> None:
    from textual.app import App

    captured: dict[str, bool] = {"reopened": False, "suppressed": True}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        key = next(iter(self._states))
        self._editing_group = key
        self._focus_table = lambda: None  # type: ignore[method-assign]
        self._refresh_table = lambda: None  # type: ignore[method-assign]
        self._set_help = lambda _text: None  # type: ignore[method-assign]
        self.action_edit_rr_max = lambda: captured.__setitem__("reopened", True)  # type: ignore[method-assign]

        self._edit_instances(None)
        captured["suppressed"] = self._suppress_next_enter

        self.on_data_table_row_selected(None)  # type: ignore[arg-type]
        return None

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x02,
                opcode=0x02,
                name="Heating Circuits",
                descriptor=1.0,
                known=True,
                ii_max=0x09,
                rr_max=0x0025,
                rr_max_full=0x0025,
                present_instances=(0x01, 0x02, 0x03),
            )
        ],
        request_rate_rps=None,
    )

    assert captured["suppressed"] is False
    assert captured["reopened"] is True


def test_instances_dialog_invalid_submit_suppresses_immediate_rr_reopen(monkeypatch) -> None:
    from textual.app import App

    captured: dict[str, bool] = {"reopened": False, "suppressed": False}

    def fake_run(self: App[object], *args: object, **kwargs: object) -> None:
        key = next(iter(self._states))
        self._editing_group = key
        self._focus_table = lambda: None  # type: ignore[method-assign]
        self._refresh_table = lambda: None  # type: ignore[method-assign]
        self._set_help = lambda _text: None  # type: ignore[method-assign]
        self.action_edit_rr_max = lambda: captured.__setitem__("reopened", True)  # type: ignore[method-assign]

        self._edit_instances("bogus")
        captured["suppressed"] = self._suppress_next_enter

        self.on_data_table_row_selected(None)  # type: ignore[arg-type]
        return None

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [
            PlannerGroup(
                group=0x02,
                opcode=0x02,
                name="Heating Circuits",
                descriptor=1.0,
                known=True,
                ii_max=0x09,
                rr_max=0x0025,
                rr_max_full=0x0025,
                present_instances=(0x01, 0x02, 0x03),
            )
        ],
        request_rate_rps=None,
    )

    assert captured["suppressed"] is True
    assert captured["reopened"] is False
