from __future__ import annotations

from io import StringIO
from pathlib import Path

from rich.console import Console

from helianthus_vrc_explorer.ui.live import RichScanObserver
from helianthus_vrc_explorer.ui.planner import PlannerGroup, prompt_scan_plan
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
        ("Circuits", "3"),
        ("Zones", "2"),
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
    assert "Circuits:" in rendered and "Heat pumps:" in rendered
    assert "0x0000" not in rendered and "00004040" not in rendered


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
    assert "Circuits: 3" in str(system_information.render())
    assert "0x0000" not in str(system_information.render())
