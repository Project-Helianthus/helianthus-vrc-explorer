from __future__ import annotations

import asyncio
from pathlib import Path

from textual.app import App
from textual.widgets import Button, Checkbox, DirectoryTree, Input, Select, Static

from helianthus_vrc_explorer.ui.scan_setup import (
    ArtifactOpenApp,
    ScanSetup,
    ScanSetupApp,
    run_artifact_open_modal,
    run_scan_setup,
)


def _run_public(monkeypatch, exercise, invoke):
    def fake_run(self: App[object], *_args: object, **_kwargs: object):
        async def run() -> None:
            async with self.run_test(size=(110, 52)) as pilot:
                await pilot.pause()
                await exercise(self, pilot)

        asyncio.run(run())
        return self.return_value

    monkeypatch.setattr(App, "run", fake_run)
    return invoke()


def test_scan_setup_defaults_are_stable() -> None:
    assert ScanSetup() == ScanSetup(
        preset="recommended",
        dst="auto",
        dry_run=False,
        output_dir=Path("results"),
        ebusd_csv_path=None,
        myvaillant_map_path=None,
        trace_file=None,
        b509_range=None,
        b509_dump=False,
        b555_dump=False,
        b516_dump=False,
        planner_ui="auto",
        no_tips=False,
        redact=False,
    )


def test_preset_dropdown_updates_description_and_returns_visual_selection(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def exercise(app: ScanSetupApp, pilot) -> None:
        preset = app.query_one("#scan-preset", Select)
        preset.value = "full"
        await pilot.pause()
        captured["description"] = str(app.query_one("#preset-description", Static).render())
        await pilot.click("#scan-continue")
        await pilot.pause()

    result = _run_public(
        monkeypatch,
        exercise,
        lambda: run_scan_setup(initial=ScanSetup(), preset_from_argv=False),
    )

    assert isinstance(result, ScanSetup)
    assert result.preset == "full"
    assert "declared profile slots" in str(captured["description"])
    assert result.output_dir == Path("results")
    assert result.dst == "auto"


def test_argv_preset_is_displayed_and_locked(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def exercise(app: ScanSetupApp, pilot) -> None:
        preset = app.query_one("#scan-preset", Select)
        captured["disabled"] = preset.disabled
        captured["value"] = preset.value
        captured["description"] = str(app.query_one("#preset-description", Static).render())
        await pilot.click("#scan-continue")
        await pilot.pause()

    result = _run_public(
        monkeypatch,
        exercise,
        lambda: run_scan_setup(
            initial=ScanSetup(preset="research"),
            preset_from_argv=True,
        ),
    )

    assert isinstance(result, ScanSetup)
    assert result.preset == "research"
    assert captured == {
        "disabled": True,
        "value": "research",
        "description": (
            "Bounded exploratory coverage for unknown or unqualified areas. Locked by --preset."
        ),
    }


def test_invalid_optional_path_stays_in_setup_and_reports_error(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}
    missing = tmp_path / "missing.csv"

    async def exercise(app: ScanSetupApp, pilot) -> None:
        app.query_one("#ebusd-csv-path", Input).value = str(missing)
        await pilot.click("#scan-continue")
        await pilot.pause()
        captured["status"] = str(app.query_one("#scan-setup-status", Static).render())
        captured["exited"] = app.return_value
        await pilot.click("#scan-cancel")

    result = _run_public(
        monkeypatch,
        exercise,
        lambda: run_scan_setup(initial=ScanSetup(), preset_from_argv=False),
    )
    assert result is None
    assert captured["exited"] is None
    assert "must be an existing file" in str(captured["status"])


def test_invalid_or_unenabled_b509_ranges_are_rejected(monkeypatch) -> None:
    statuses: list[str] = []

    async def exercise(app: ScanSetupApp, pilot) -> None:
        ranges = app.query_one("#b509-range", Input)
        ranges.value = "0x0000..0x000F"
        await pilot.click("#scan-continue")
        await pilot.pause()
        statuses.append(str(app.query_one("#scan-setup-status", Static).render()))

        app.query_one("#b509-dump", Checkbox).value = True
        ranges.value = "0x0000..0xFFFF"
        await pilot.pause()
        app.query_one("#scan-continue", Button).press()
        await pilot.pause()
        statuses.append(str(app.query_one("#scan-setup-status", Static).render()))
        await pilot.click("#scan-cancel")

    result = _run_public(
        monkeypatch,
        exercise,
        lambda: run_scan_setup(initial=ScanSetup(), preset_from_argv=False),
    )
    assert result is None
    assert "enable the B509 dump" in statuses[0]
    assert "max 4096" in statuses[1]


def test_advanced_visual_fields_round_trip_without_transport_io(monkeypatch, tmp_path) -> None:
    ebusd_csv = tmp_path / "15.720.csv"
    ebusd_csv.write_text("name,type\n", encoding="utf-8")
    mapping_csv = tmp_path / "mapping.csv"
    mapping_csv.write_text("name,type\n", encoding="utf-8")
    output_dir = tmp_path / "new-results"
    trace_file = tmp_path / "trace.log"

    async def exercise(app: ScanSetupApp, pilot) -> None:
        app.query_one("#scan-destination", Input).value = "21"
        app.query_one("#scan-output-dir", Input).value = str(output_dir)
        app.query_one("#scan-dry-run", Checkbox).value = True
        app.query_one("#trace-file", Input).value = str(trace_file)
        app.query_one("#ebusd-csv-path", Input).value = str(ebusd_csv)
        app.query_one("#myvaillant-map-path", Input).value = str(mapping_csv)
        app.query_one("#b509-dump", Checkbox).value = True
        app.query_one("#b509-range", Input).value = "0x2700..0x27FF,0x3000..0x300F"
        app.query_one("#b555-dump", Checkbox).value = True
        app.query_one("#b516-dump", Checkbox).value = True
        app.query_one("#planner-ui", Select).value = "classic"
        app.query_one("#scan-redact", Checkbox).value = True
        app.query_one("#scan-show-tips", Checkbox).value = False
        await pilot.pause()
        app.query_one("#scan-continue", Button).press()
        await pilot.pause()

    result = _run_public(
        monkeypatch,
        exercise,
        lambda: run_scan_setup(initial=ScanSetup(), preset_from_argv=False),
    )
    assert result == ScanSetup(
        preset="recommended",
        dst="0x15",
        dry_run=True,
        output_dir=output_dir,
        ebusd_csv_path=ebusd_csv,
        myvaillant_map_path=mapping_csv,
        trace_file=trace_file,
        b509_range=["0x2700..0x27FF", "0x3000..0x300F"],
        b509_dump=True,
        b555_dump=True,
        b516_dump=True,
        planner_ui="classic",
        no_tips=True,
        redact=True,
    )


def test_scan_setup_cancel_returns_none(monkeypatch) -> None:
    async def exercise(app: ScanSetupApp, pilot) -> None:
        await pilot.click("#scan-cancel")
        await pilot.pause()

    assert (
        _run_public(
            monkeypatch,
            exercise,
            lambda: run_scan_setup(initial=ScanSetup(), preset_from_argv=False),
        )
        is None
    )


def test_artifact_open_validates_json_file_and_cancel(monkeypatch, tmp_path) -> None:
    json_path = tmp_path / "scan.json"
    json_path.write_text("{}", encoding="utf-8")
    text_path = tmp_path / "scan.txt"
    text_path.write_text("{}", encoding="utf-8")
    statuses: list[str] = []

    async def exercise(app: ArtifactOpenApp, pilot) -> None:
        field = app.query_one("#artifact-path", Input)
        field.value = str(text_path)
        await pilot.click("#artifact-open")
        await pilot.pause()
        statuses.append(str(app.query_one("#artifact-open-status", Static).render()))
        field.value = str(json_path)
        await pilot.pause()
        app.query_one("#artifact-open", Button).press()
        await pilot.pause()

    result = _run_public(monkeypatch, exercise, run_artifact_open_modal)
    assert result == json_path
    assert "must use the .json extension" in statuses[0]

    async def cancel(app: ArtifactOpenApp, pilot) -> None:
        await pilot.click("#artifact-cancel")
        await pilot.pause()

    assert _run_public(monkeypatch, cancel, run_artifact_open_modal) is None


def test_artifact_tree_parent_navigation_and_nested_json_selection(tmp_path) -> None:
    start = tmp_path / "start"
    start.mkdir()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    json_path = artifacts / "scan.json"
    json_path.write_text("{}", encoding="utf-8")
    (artifacts / "ignore.txt").write_text("not an artifact", encoding="utf-8")

    async def exercise() -> None:
        app = ArtifactOpenApp(initial_directory=start)
        async with app.run_test(size=(110, 52)) as pilot:
            tree = app.query_one("#artifact-tree", DirectoryTree)
            assert tree.path == start.resolve()

            await pilot.click("#artifact-parent")
            for _ in range(20):
                await pilot.pause()
                if tree.path == tmp_path.resolve() and tree.root.children:
                    break
            assert tree.path == tmp_path.resolve()

            tree.root.expand()
            for _ in range(20):
                await pilot.pause()
                artifact_node = next(
                    (
                        node
                        for node in tree.root.children
                        if node.data is not None and node.data.path == artifacts
                    ),
                    None,
                )
                if artifact_node is not None:
                    break
            assert artifact_node is not None
            artifact_node.expand()
            for _ in range(20):
                await pilot.pause()
                file_node = next(
                    (
                        node
                        for node in artifact_node.children
                        if node.data is not None and node.data.path == json_path
                    ),
                    None,
                )
                if file_node is not None:
                    break
            assert file_node is not None
            assert all(
                node.data is None or node.data.path.suffix.lower() != ".txt"
                for node in artifact_node.children
            )

            tree.post_message(DirectoryTree.FileSelected(file_node, json_path))
            await pilot.pause()
            assert app.query_one("#artifact-path", Input).value == str(json_path)
            await pilot.click("#artifact-open")
            await pilot.pause()

        assert app.return_value == json_path

    asyncio.run(exercise())
