from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer import cli
from helianthus_vrc_explorer.ui.scan_setup import ScanSetup


def test_headless_without_preset_fails_before_transport(monkeypatch) -> None:
    monkeypatch.setattr(cli, "Console", lambda **kw: SimpleNamespace(is_terminal=False))
    monkeypatch.setattr(
        cli, "_scan_configured", lambda **kw: (_ for _ in ()).throw(AssertionError("I/O"))
    )
    result = CliRunner().invoke(cli.app, ["scan"])
    assert result.exit_code == 2
    assert "requires a TTY" in result.output


def test_headless_explicit_preset_uses_finite_defaults(monkeypatch) -> None:
    monkeypatch.setattr(cli, "Console", lambda **kw: SimpleNamespace(is_terminal=False))
    assert cli._collect_scan_setup("recommended", "ens") == ScanSetup(
        preset="recommended", dst="0x15", planner_ui="disabled"
    )


def test_omitted_preset_opens_ui_and_round_trips_all_choices(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "Console", lambda **kw: SimpleNamespace(is_terminal=True))
    choices = ScanSetup(
        preset="full",
        dst="0x25",
        output_dir=tmp_path,
        dry_run=True,
        trace_file=tmp_path / "scan.trace",
    )
    calls: list[dict] = []

    def setup(**kwargs):
        assert kwargs["preset_from_argv"] is False
        assert kwargs["initial"].preset == "recommended"
        return choices

    monkeypatch.setattr(cli, "run_scan_setup", setup)
    monkeypatch.setattr(cli, "_scan_configured", lambda **kw: calls.append(kw))
    result = CliRunner().invoke(
        cli.app, ["scan", "--transport", "ens", "--host", "adapter.example.test", "--port", "9999"]
    )
    assert result.exit_code == 0, result.output
    assert calls[0]["dst"] == "0x25"
    assert calls[0]["dry_run"] is True
    assert calls[0]["output_dir"] == tmp_path
    assert calls[0]["preset"] == "full"
    assert calls[0]["host"] == "adapter.example.test"


def test_cancel_does_not_execute_scan(monkeypatch) -> None:
    monkeypatch.setattr(cli, "Console", lambda **kw: SimpleNamespace(is_terminal=True))
    monkeypatch.setattr(cli, "run_scan_setup", lambda **kw: None)
    monkeypatch.setattr(
        cli, "_scan_configured", lambda **kw: (_ for _ in ()).throw(AssertionError("I/O"))
    )
    result = CliRunner().invoke(cli.app, ["scan"])
    assert result.exit_code == 0


@pytest.mark.parametrize("protocol,expected", [("ens", "ens"), ("enhanced", "ens"), ("tcp", "tcp")])
def test_postscan_browser_keeps_trace_after_scan_session_closes(
    monkeypatch, tmp_path: Path, protocol: str, expected: str
) -> None:
    from contextlib import contextmanager

    class Transport:
        closed = False

        @contextmanager
        def session(self):
            yield self
            self.closed = True

    transport = Transport()
    captured: dict = {}
    monkeypatch.chdir(tmp_path)
    later_cwd = tmp_path / "later"
    later_cwd.mkdir()

    @contextmanager
    def observer(**kwargs):
        yield None

    def browse(artifact, **kwargs):
        assert transport.closed
        captured.update(kwargs)

    monkeypatch.setattr(cli, "_build_transport", lambda *a, **kw: transport)
    monkeypatch.setattr(cli, "_probe_scan_identity", lambda *a, **kw: {})
    monkeypatch.setattr(cli, "make_scan_observer", observer)

    def scan(*args, **kwargs):
        monkeypatch.chdir(later_cwd)
        return {
            "schema_version": "2.3",
            "meta": {"destination_address": "0x15", "scan_timestamp": "2026-10-09T18:00:00Z"},
            "operations": {},
        }

    monkeypatch.setattr(cli, "scan_vrc", scan)
    monkeypatch.setattr(cli, "_can_launch_interactive_browse", lambda console: True)
    monkeypatch.setattr(cli, "run_browse_from_artifact", browse)
    trace = tmp_path / "scan.trace"
    cli._scan_configured(
        transport_protocol=protocol, dst="0x15", output_dir=Path("results"), trace_file=trace
    )
    assert captured["connection_settings"]["trace_path"] == trace
    assert captured["connection_settings"]["protocol"] == expected
    assert list((tmp_path / "results").glob("*.json"))
    assert not (later_cwd / "results").exists()


@pytest.mark.parametrize("failure", ["existing_file", "deleted_cwd"])
def test_output_preflight_rejects_before_transport(monkeypatch, tmp_path: Path, capsys, failure):
    monkeypatch.setattr(
        cli, "_build_transport", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("I/O"))
    )
    if failure == "existing_file":
        output = tmp_path / "file"
        output.write_text("preserve")
    else:
        output = Path("results")
        original = Path.resolve

        def resolve(path, *args, **kwargs):
            if path == output:
                raise FileNotFoundError("working directory removed")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "resolve", resolve)
    with pytest.raises(cli.typer.Exit) as exc:
        cli._scan_configured(transport_protocol="ens", dst="0x15", output_dir=output)
    assert exc.value.exit_code == 2
    assert "Cannot prepare output directory" in capsys.readouterr().err
    if failure == "existing_file":
        assert output.read_text() == "preserve"
