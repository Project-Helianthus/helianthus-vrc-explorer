#!/usr/bin/env python3
"""Validate the synthetic offline evidence fixture used by the acceptance card."""

from __future__ import annotations

import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.artifact_schema import (
    CURRENT_ARTIFACT_SCHEMA_VERSION,
    ArtifactSchemaError,
    migrate_artifact_schema,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_FIXTURE = _REPO_ROOT / "fixtures" / "offline_acceptance_evidence.json"

_REQUIRED_ENTRIES: dict[tuple[str, str, str, str], dict[str, object]] = {
    ("0x02", "0x09", "0x00", "0x0004"): {
        "raw_hex": "031702",
        "read_opcode": "0x02",
        "response_state": "active",
        "error": None,
    },
    ("0x06", "0x09", "0x00", "0x0004"): {
        "raw_hex": "021703",
        "read_opcode": "0x06",
        "response_state": "active",
        "error": None,
    },
    ("0x06", "0x0C", "0x00", "0x0004"): {
        "raw_hex": None,
        "reply_hex": "",
        "read_opcode": "0x06",
        "response_state": "empty_reply",
        "error": None,
    },
    ("0x06", "0x0C", "0x00", "0x0007"): {
        "raw_hex": None,
        "read_opcode": "0x06",
        "response_state": "nack",
        "error": "nack",
    },
    ("0x06", "0x69", "0x00", "0x0000"): {
        "raw_hex": "00",
        "read_opcode": "0x06",
        "response_state": "active",
        "error": None,
    },
}


def _get_group(
    artifact: dict[str, Any],
    operation: str,
    group: str,
) -> dict[str, Any] | None:
    operations = artifact.get("operations")
    if not isinstance(operations, dict):
        return None
    operation_obj = operations.get(operation)
    if not isinstance(operation_obj, dict):
        return None
    groups = operation_obj.get("groups")
    if not isinstance(groups, dict):
        return None
    group_obj = groups.get(group)
    return group_obj if isinstance(group_obj, dict) else None


def _get_entry(
    artifact: dict[str, Any],
    path: tuple[str, str, str, str],
) -> dict[str, Any] | None:
    operation, group, instance, register = path
    group_obj = _get_group(artifact, operation, group)
    if group_obj is None:
        return None
    instances = group_obj.get("instances")
    if not isinstance(instances, dict):
        return None
    instance_obj = instances.get(instance)
    if not isinstance(instance_obj, dict):
        return None
    registers = instance_obj.get("registers")
    if not isinstance(registers, dict):
        return None
    entry = registers.get(register)
    return entry if isinstance(entry, dict) else None


def validate_offline_acceptance_evidence(artifact: dict[str, Any]) -> list[str]:
    """Return canonical-fixture invariant violations before compatibility migration."""
    errors: list[str] = []
    if artifact.get("schema_version") != CURRENT_ARTIFACT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {CURRENT_ARTIFACT_SCHEMA_VERSION}")
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        return ["meta must be an object"]
    if meta.get("fixture_kind") != "synthetic_offline_evidence":
        errors.append("meta.fixture_kind must identify synthetic offline evidence")
    if meta.get("incomplete") is not True:
        errors.append("meta.incomplete must remain true")
    if meta.get("incomplete_reason") != "user_interrupt":
        errors.append("meta.incomplete_reason must remain user_interrupt")
    issue_suggestion = meta.get("issue_suggestion")
    if not isinstance(issue_suggestion, dict):
        errors.append("meta.issue_suggestion must retain unknown-group provenance")
    else:
        if issue_suggestion.get("suggest_issue") is not True:
            errors.append("meta.issue_suggestion.suggest_issue must remain true")
        if issue_suggestion.get("unknown_groups") != ["0x69"]:
            errors.append("meta.issue_suggestion.unknown_groups must remain ['0x69']")
    unknown_group = _get_group(artifact, "0x06", "0x69")
    if unknown_group is not None and unknown_group.get("name") != "Unknown 0x69":
        errors.append("0x06/0x69: name must remain 'Unknown 0x69'")

    for path, expected_fields in _REQUIRED_ENTRIES.items():
        entry = _get_entry(artifact, path)
        location = "/".join(path)
        if entry is None:
            errors.append(f"missing required entry: {location}")
            continue
        for field, expected in expected_fields.items():
            if field not in entry:
                errors.append(f"{location}: missing {field}")
            elif entry[field] != expected:
                errors.append(f"{location}: {field} must be {expected!r}, got {entry[field]!r}")
    return errors


def _load_fixture(path: Path) -> dict[str, Any]:
    artifact = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(artifact, dict):
        raise ValueError("fixture root must be a JSON object")
    return artifact


def main(argv: list[str]) -> int:
    if len(argv) > 2:
        print("Usage: check_offline_acceptance_evidence.py [fixture.json]", file=sys.stderr)
        return 2
    path = Path(argv[1]) if len(argv) == 2 else _DEFAULT_FIXTURE
    try:
        artifact = _load_fixture(path)
    except (OSError, ValueError, json.JSONDecodeError, ArtifactSchemaError) as exc:
        print(f"offline acceptance evidence: {exc}", file=sys.stderr)
        return 2

    errors = validate_offline_acceptance_evidence(artifact)
    if errors:
        print("offline acceptance evidence failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    try:
        migrated, report = migrate_artifact_schema(deepcopy(artifact))
    except ArtifactSchemaError as exc:
        print(f"offline acceptance evidence: {exc}", file=sys.stderr)
        return 2

    if report.register_count_before != report.register_count_after:
        errors.append(
            "migration changed register count "
            f"({report.register_count_before} -> {report.register_count_after})"
        )
    if errors:
        print("offline acceptance evidence failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "offline acceptance evidence passed: "
        f"{report.register_count_after} entries, schema {migrated['schema_version']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
