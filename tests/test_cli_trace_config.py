from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.ui.scan_setup import ScanSetup
from tests.scan_ui_helpers import invoke_scan


@pytest.mark.parametrize("configuration", ["argument", "environment", "absent"])
def test_cli_passes_resolved_trace_setting_to_scan_observer(
    monkeypatch, tmp_path: Path, configuration: str
) -> None:
    import helianthus_vrc_explorer.cli as cli

    observed: list[Path | None] = []

    @contextmanager
    def observer(**kwargs):
        observed.append(kwargs["trace_file"])
        yield None

    monkeypatch.setattr(cli, "make_scan_observer", observer)
    monkeypatch.delenv("HELIA_EBUSD_TRACE_PATH", raising=False)
    expected = tmp_path / "session.trace"
    trace_file = expected if configuration != "absent" else None
    result = invoke_scan(
        CliRunner(),
        monkeypatch,
        ["--preset", "full"],
        setup=ScanSetup(preset="full", dry_run=True, output_dir=tmp_path, trace_file=trace_file),
    )
    assert result.exit_code == 0, result.output
    assert observed == [None if configuration == "absent" else expected]
