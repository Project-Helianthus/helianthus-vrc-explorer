from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _no_scanner_time_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep compatibility with legacy scanner timeout tests."""

    import helianthus_vrc_explorer.scanner.register as register

    time_module = getattr(register, "time", None)
    if time_module is not None:
        monkeypatch.setattr(time_module, "sleep", lambda _seconds: None)


@pytest.fixture
def dual_namespace_scan_path() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "dual_namespace_scan.json"


@pytest.fixture
def dual_namespace_scan_artifact(dual_namespace_scan_path: Path) -> dict[str, object]:
    return json.loads(dual_namespace_scan_path.read_text(encoding="utf-8"))
