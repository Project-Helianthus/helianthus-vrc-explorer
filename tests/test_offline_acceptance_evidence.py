from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURE_PATH = _REPO_ROOT / "fixtures" / "offline_acceptance_evidence.json"


def _load_checker_module() -> ModuleType:
    script_path = _REPO_ROOT / "scripts" / "check_offline_acceptance_evidence.py"
    spec = importlib.util.spec_from_file_location(
        "offline_acceptance_evidence_checker", script_path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load checker: {script_path}")
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
