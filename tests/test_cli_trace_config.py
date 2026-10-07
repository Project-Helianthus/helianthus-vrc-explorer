from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


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
    args = ["scan", "--dry-run", "--preset", "full", "--output-dir", str(tmp_path)]
    expected = tmp_path / "session.trace"
    if configuration == "argument":
        args.extend(["--trace-file", str(expected)])
    elif configuration == "environment":
        monkeypatch.setenv("HELIA_EBUSD_TRACE_PATH", str(expected))
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert observed == [None if configuration == "absent" else expected]
