from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_PATH = _REPO_ROOT / "fixtures" / "offline_acceptance_evidence.json"
_CHECKER_PATH = _REPO_ROOT / "scripts" / "check_offline_acceptance_evidence.py"


def _load_checker_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "offline_acceptance_evidence_checker", _CHECKER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load checker: {_CHECKER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_CHECKER = _load_checker_module()


def _load_fixture() -> dict[str, Any]:
    return json.loads(_FIXTURE_PATH.read_text(encoding="utf-8"))


def test_offline_acceptance_evidence_checker_accepts_sanitized_fixture() -> None:
    assert _CHECKER.validate_offline_acceptance_evidence(_load_fixture()) == []


def test_offline_acceptance_evidence_checker_rejects_raw_payload_removal() -> None:
    mutated = deepcopy(_load_fixture())
    entry = mutated["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x00"]
    entry["registers"]["0x0004"].pop("raw_hex")

    errors = _CHECKER.validate_offline_acceptance_evidence(mutated)

    assert any(error == "0x02/0x09/0x00/0x0004: missing raw_hex" for error in errors)


def test_offline_acceptance_evidence_checker_rejects_operation_collapse() -> None:
    mutated = deepcopy(_load_fixture())
    remote_groups = mutated["operations"].pop("0x06")["groups"]
    mutated["operations"]["0x02"]["groups"].update(remote_groups)

    errors = _CHECKER.validate_offline_acceptance_evidence(mutated)

    assert any(error.startswith("missing required entry: 0x06/") for error in errors)


def test_offline_acceptance_evidence_checker_rejects_incomplete_metadata_removal() -> None:
    mutated = deepcopy(_load_fixture())
    mutated["meta"].pop("incomplete_reason")

    errors = _CHECKER.validate_offline_acceptance_evidence(mutated)

    assert "meta.incomplete_reason must remain user_interrupt" in errors


def test_offline_acceptance_evidence_checker_cli_accepts_canonical_fixture() -> None:
    result = subprocess.run(
        [sys.executable, str(_CHECKER_PATH), str(_FIXTURE_PATH)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout == "offline acceptance evidence passed: 5 entries, schema 2.3\n"


def _delete_path_field(
    artifact: dict[str, Any],
    path: tuple[str, ...],
    field: str,
) -> None:
    target: dict[str, Any] = artifact
    for key in path:
        target = target[key]
    target.pop(field)


@pytest.mark.parametrize(
    ("name", "path", "field", "expected_error"),
    [
        (
            "schema-version",
            (),
            "schema_version",
            "schema_version must be 2.3",
        ),
        (
            "active-response-state",
            ("operations", "0x02", "groups", "0x09", "instances", "0x00", "registers", "0x0004"),
            "response_state",
            "0x02/0x09/0x00/0x0004: missing response_state",
        ),
        (
            "empty-reply-response-state",
            ("operations", "0x06", "groups", "0x0C", "instances", "0x00", "registers", "0x0004"),
            "response_state",
            "0x06/0x0C/0x00/0x0004: missing response_state",
        ),
        (
            "empty-reply-error",
            ("operations", "0x06", "groups", "0x0C", "instances", "0x00", "registers", "0x0004"),
            "error",
            "0x06/0x0C/0x00/0x0004: missing error",
        ),
        (
            "raw-payload",
            ("operations", "0x02", "groups", "0x09", "instances", "0x00", "registers", "0x0004"),
            "raw_hex",
            "0x02/0x09/0x00/0x0004: missing raw_hex",
        ),
        (
            "active-error",
            ("operations", "0x02", "groups", "0x09", "instances", "0x00", "registers", "0x0004"),
            "error",
            "0x02/0x09/0x00/0x0004: missing error",
        ),
        (
            "nack-error",
            ("operations", "0x06", "groups", "0x0C", "instances", "0x00", "registers", "0x0007"),
            "error",
            "0x06/0x0C/0x00/0x0007: missing error",
        ),
        (
            "incomplete-flag",
            ("meta",),
            "incomplete",
            "meta.incomplete must remain true",
        ),
        (
            "incomplete-reason",
            ("meta",),
            "incomplete_reason",
            "meta.incomplete_reason must remain user_interrupt",
        ),
        (
            "remote-operation",
            ("operations",),
            "0x06",
            "missing required entry: 0x06/0x09/0x00/0x0004\n"
            "- missing required entry: 0x06/0x0C/0x00/0x0004\n"
            "- missing required entry: 0x06/0x0C/0x00/0x0007\n"
            "- missing required entry: 0x06/0x69/0x00/0x0000",
        ),
        (
            "unknown-group",
            ("operations", "0x06", "groups"),
            "0x69",
            "missing required entry: 0x06/0x69/0x00/0x0000",
        ),
        (
            "unknown-group-label",
            ("operations", "0x06", "groups", "0x69"),
            "name",
            "0x06/0x69: name must remain 'Unknown 0x69'",
        ),
        (
            "unknown-provenance",
            ("meta", "issue_suggestion"),
            "unknown_groups",
            "meta.issue_suggestion.unknown_groups must remain ['0x69']",
        ),
    ],
)
def test_offline_acceptance_evidence_checker_cli_rejects_missing_canonical_evidence(
    tmp_path: Path,
    name: str,
    path: tuple[str, ...],
    field: str,
    expected_error: str,
) -> None:
    mutated = _load_fixture()
    _delete_path_field(mutated, path, field)
    fixture_path = tmp_path / f"{name}.json"
    fixture_path.write_text(json.dumps(mutated), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(_CHECKER_PATH), str(fixture_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == f"offline acceptance evidence failed:\n- {expected_error}\n"
