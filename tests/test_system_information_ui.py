from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from helianthus_vrc_explorer.ui.live import RichScanObserver
from helianthus_vrc_explorer.ui.planner import (
    OP00_GROUP_COUNT_NAMES,
    PlannerGroup,
    _render_table,
    format_planner_op00_count,
    prompt_scan_plan,
)
from helianthus_vrc_explorer.ui.planner_textual import run_textual_scan_plan
from helianthus_vrc_explorer.ui.system_information import format_system_information_rows


def _system_information() -> list[dict[str, object]]:
    return [
        {"identifier": "0x0000", "name": "circuit_count", "value": 3.0, "raw_hex": "00004040"},
        {"identifier": "0x0001", "name": "zone_count", "value": 2.0, "raw_hex": "00000040"},
        {"identifier": "0x0005", "name": "generator_count", "value": None, "raw_hex": ""},
        {"identifier": "0x000d", "name": "heat_pump_count", "value": 1.0, "raw_hex": "0000803f"},
    ]


def _group() -> PlannerGroup:
    return PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x00,),
    )


def test_system_information_formatter_uses_human_labels_and_hides_diagnostic_fields() -> None:
    assert format_system_information_rows(_system_information()) == (
        ("Circuit capacity", "3"),
        ("Zone capacity", "2"),
        ("Generators", "unavailable"),
        ("Heat pumps", "1"),
    )


def test_classic_planner_shows_compact_system_information(monkeypatch) -> None:
    from helianthus_vrc_explorer.ui import planner

    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None)
    answers = iter(["n", "y"])
    monkeypatch.setattr(planner, "_ask_yes_no", lambda *_args, **_kwargs: next(answers) == "y")

    prompt_scan_plan(
        console,
        [_group()],
        request_rate_rps=None,
        system_information=_system_information(),
    )

    rendered = output.getvalue()
    assert "System Information" in rendered
    assert "Generators:" in rendered
    assert "Circuit capacity:" not in rendered and "Heat pumps:" not in rendered
    assert "0x0000" not in rendered and "00004040" not in rendered


def test_planner_op00_counts_use_qualified_snapshot_mappings_without_guiding_instances() -> None:
    circuits = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x00,),
        expected_count=3,
    )
    zones = PlannerGroup(
        group=0x03,
        opcode=0x02,
        name="Zones",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x01,),
        expected_count=2,
    )
    boiler = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Boiler",
        descriptor=3.0,
        known=True,
        ii_max=0x08,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x01,),
    )
    heat_pump = PlannerGroup(
        group=0x02,
        opcode=0x06,
        name="Heat Pump",
        descriptor=3.0,
        known=True,
        ii_max=0x08,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x01,),
    )
    vr70 = PlannerGroup(
        group=0x0B,
        opcode=0x06,
        name="Functional Modules (VR70) FM3",
        descriptor=3.0,
        known=True,
        ii_max=0x08,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(),
    )
    snapshot = [
        {"name": "circuit_count", "value": 3.0, "state": "available"},
        {"name": "zone_count", "value": 2.0, "state": "available"},
        {"name": "boiler_count", "value": 1.0, "state": "available"},
        {"name": "heat_pump_count", "value": 0.0, "state": "available"},
        {"name": "vr70_count", "value": 0.0, "state": "available"},
    ]

    assert format_planner_op00_count(circuits, snapshot) == "capacity=3"
    assert format_planner_op00_count(zones, snapshot) == "capacity=2"
    assert format_planner_op00_count(boiler, snapshot) == "1"
    assert format_planner_op00_count(heat_pump, snapshot) == "0"
    assert format_planner_op00_count(vr70, snapshot) == "0"
    assert boiler.present_instances == (0x01,)
    assert heat_pump.present_instances == (0x01,)


def test_planner_op00_count_mapping_inventory_excludes_ambiguous_aggregate_counts() -> None:
    assert OP00_GROUP_COUNT_NAMES == {
        (0x02, 0x02): "circuit_count",
        (0x02, 0x03): "zone_count",
        (0x02, 0x04): "solar_circuit_count",
        (0x02, 0x05): "solar_loaded_tank_count",
        (0x02, 0x08): "delta_t_count",
        (0x06, 0x01): "boiler_count",
        (0x06, 0x02): "heat_pump_count",
        (0x06, 0x03): "recovair_count",
        (0x06, 0x06): "vpm_s_count",
        (0x06, 0x07): "vpm_w_count",
        (0x06, 0x0B): "vr70_count",
        (0x06, 0x0C): "vr71_count",
    }


def test_planner_op00_count_rejects_invalid_snapshot_values() -> None:
    boiler = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Boiler",
        descriptor=3.0,
        known=True,
        ii_max=0x08,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x01,),
    )

    assert (
        format_planner_op00_count(
            boiler, [{"name": "boiler_count", "value": float("nan"), "state": "available"}]
        )
        == "—"
    )
    assert (
        format_planner_op00_count(
            boiler, [{"name": "boiler_count", "value": -1.0, "state": "available"}]
        )
        == "—"
    )
    assert (
        format_planner_op00_count(
            boiler, [{"name": "boiler_count", "value": 1.0, "state": "unavailable"}]
        )
        == "—"
    )
    circuits = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x09,
        rr_max=0x0025,
        rr_max_full=0x0025,
        present_instances=(0x01,),
        expected_count=3,
    )
    assert format_planner_op00_count(circuits, []) == "—"
    assert format_planner_op00_count(circuits) == "capacity=3"


def test_classic_planner_table_replaces_type_with_op00_count() -> None:
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None)
    group = _group()
    _render_table(
        "Known Groups",
        [
            PlannerGroup(
                group=group.group,
                opcode=group.opcode,
                name=group.name,
                descriptor=group.descriptor,
                known=group.known,
                ii_max=group.ii_max,
                rr_max=group.rr_max,
                rr_max_full=group.rr_max_full,
                present_instances=group.present_instances,
                expected_count=3,
            )
        ],
        unknown=False,
        console=console,
    )

    rendered = output.getvalue()
    assert "OP00 context" in rendered
    assert "Type" not in rendered
    assert "nan" not in rendered


def test_live_header_uses_system_information_label_and_hides_trace_tip_when_configured() -> None:
    output = StringIO()
    console = Console(file=output, force_terminal=False, color_system=None)
    observer = RichScanObserver(
        console=console,
        title="Scan",
        trace_file=Path("capture.trace"),
    )

    with observer:
        observer.phase_start("group_discovery", total=18)

    rendered = output.getvalue()
    assert "System Information" in str(observer._progress.tasks[0].description)
    assert "--trace-file" not in rendered


def test_textual_planner_includes_compact_system_information(monkeypatch) -> None:
    from textual.app import App

    captured: list[object] = []

    def fake_run(self: App[object], *_args: object, **_kwargs: object) -> None:
        captured.extend(self.compose())

    monkeypatch.setattr(App, "run", fake_run)

    run_textual_scan_plan(
        [_group()], request_rate_rps=None, system_information=_system_information()
    )

    system_information = next(widget for widget in captured if widget.id == "system-information")
    assert "Generators: unavailable" in str(system_information.render())
    assert "Circuits: 3" not in str(system_information.render())
    assert "0x0000" not in str(system_information.render())
