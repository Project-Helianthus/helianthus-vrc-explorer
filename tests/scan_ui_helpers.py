from __future__ import annotations

from collections.abc import Sequence

from typer.testing import CliRunner, Result

from helianthus_vrc_explorer.cli import app
from helianthus_vrc_explorer.ui.scan_setup import ScanSetup


def invoke_scan(
    runner: CliRunner,
    monkeypatch: object,
    argv: Sequence[str] = (),
    *,
    setup: ScanSetup | None = None,
) -> Result:
    """Run public scan with UI-owned configuration supplied by a test double."""
    import helianthus_vrc_explorer.cli as cli

    selected = setup or ScanSetup()
    monkeypatch.setattr(cli, "_collect_scan_setup", lambda _preset, _transport: selected)
    return runner.invoke(app, ["scan", *argv])
