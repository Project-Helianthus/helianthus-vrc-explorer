from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from helianthus_vrc_explorer.artifact_schema import flatten_operations_to_groups


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


def artifact_groups(artifact: dict[str, Any]) -> dict[str, Any]:
    """Extract flattened groups from a v2.3 operations-first artifact.

    Test helper: use this instead of artifact["groups"] to access scan output.
    """
    return flatten_operations_to_groups(artifact)


def artifact_op_group(
    artifact: dict[str, Any], *, op: str, group: str
) -> dict[str, Any]:
    """Access operations[op].groups[group] directly in a v2.3 artifact."""
    return artifact["operations"][op]["groups"][group]
