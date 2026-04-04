from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from helianthus_vrc_explorer.artifact_schema import (
    CURRENT_ARTIFACT_SCHEMA_VERSION,
    LEGACY_UNVERSIONED_SCHEMA,
    LEGACY_VERSIONED_SCHEMAS,
    count_register_entries,
    iter_register_entries,
    migrate_artifact_schema,
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES_DIR = _REPO_ROOT / "fixtures"


def _load_validator_module() -> ModuleType:
    script_path = _REPO_ROOT / "scripts" / "validate_artifact.py"
    spec = importlib.util.spec_from_file_location("validate_artifact_script", script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load validator module from {script_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_VALIDATOR = _load_validator_module()
_validate_scan_artifact = _VALIDATOR.validate_scan_artifact


def _load_fixture(name: str) -> dict[str, Any]:
    path = _FIXTURES_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _register_identity_set(artifact: dict[str, Any]) -> set[tuple[Any, ...]]:
    identities: set[tuple[Any, ...]] = set()
    for (
        group_key,
        namespace_key,
        instance_key,
        register_key,
        entry,
    ) in iter_register_entries(artifact):
        identities.add(
            (
                group_key,
                namespace_key,
                instance_key,
                register_key,
                entry.get("raw_hex"),
                entry.get("error"),
                entry.get("read_opcode"),
            )
        )
    return identities


def test_migrate_unversioned_fixture_promotes_schema_and_preserves_register_count() -> None:
    legacy_artifact = {
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x000f": {"raw_hex": "3412"},
                        }
                    }
                },
            }
        },
    }

    migrated, report = migrate_artifact_schema(legacy_artifact)

    assert migrated["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert report.source_schema_version == LEGACY_UNVERSIONED_SCHEMA
    assert report.register_count_before == 1
    assert report.register_count_after == 1
    assert migrated["groups"]["0x02"]["dual_namespace"] is False
    assert migrated["groups"]["0x02"]["descriptor_observed"] == 1.0
    register = migrated["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x000f"]
    assert register["raw_hex"] == "3412"


@pytest.mark.parametrize(
    ("fixture_name", "expected_register_count"),
    [
        ("vrc720_full_scan.json", 1),
        ("dual_namespace_scan.json", 10),
        ("demo_browse.json", 12),
    ],
)
def test_checked_in_fixtures_are_versioned_and_register_count_preserved(
    fixture_name: str,
    expected_register_count: int,
) -> None:
    artifact = _load_fixture(fixture_name)

    assert artifact["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert count_register_entries(artifact) == expected_register_count


@pytest.mark.parametrize(
    "fixture_name",
    ["vrc720_full_scan.json", "dual_namespace_scan.json", "demo_browse.json"],
)
def test_migration_preserves_register_identities_for_fixture_legacy_copies(
    fixture_name: str,
) -> None:
    current = _load_fixture(fixture_name)
    legacy = deepcopy(current)
    legacy.pop("schema_version", None)
    groups = legacy.get("groups")
    assert isinstance(groups, dict)
    for group_obj in groups.values():
        if not isinstance(group_obj, dict):
            continue
        if "descriptor_observed" in group_obj:
            group_obj["descriptor_type"] = group_obj.pop("descriptor_observed")
        group_obj.pop("dual_namespace", None)

    migrated, report = migrate_artifact_schema(legacy)

    assert report.register_count_before == report.register_count_after
    assert _register_identity_set(migrated) == _register_identity_set(current)


def test_validator_accepts_legacy_when_enabled() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    artifact.pop("schema_version", None)
    group = artifact["groups"]["0x02"]
    group["descriptor_type"] = group.pop("descriptor_observed")
    group.pop("dual_namespace", None)

    errors, _migrated, source_schema = _validate_scan_artifact(artifact, allow_legacy=True)

    assert errors == []
    assert source_schema == LEGACY_UNVERSIONED_SCHEMA


def test_validator_can_reject_legacy_when_requested() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    artifact.pop("schema_version", None)

    errors, _migrated, _source_schema = _validate_scan_artifact(artifact, allow_legacy=False)

    assert any("legacy unversioned artifact rejected" in error for error in errors)


def test_validator_can_reject_legacy_versioned_when_requested() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    artifact["schema_version"] = next(iter(LEGACY_VERSIONED_SCHEMAS))

    errors, _migrated, source_schema = _validate_scan_artifact(artifact, allow_legacy=False)

    assert source_schema in LEGACY_VERSIONED_SCHEMAS
    assert any("legacy versioned artifact" in error for error in errors)


def test_validator_detects_namespace_opcode_mismatch() -> None:
    artifact = _load_fixture("dual_namespace_scan.json")
    artifact["groups"]["0x09"]["namespaces"]["0x06"]["instances"]["0x00"]["registers"]["0x0004"][
        "read_opcode"
    ] = "0x02"

    errors, _migrated, _source_schema = _validate_scan_artifact(artifact, allow_legacy=True)

    assert any("does not match namespace 0x06" in error for error in errors)


def test_migrate_legacy_empty_namespaces_preserves_flat_instances() -> None:
    legacy_artifact = {
        "schema_version": "2.0",
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "namespaces": {},
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x000f": {"raw_hex": "3412"},
                        }
                    }
                },
            }
        },
    }

    migrated, report = migrate_artifact_schema(legacy_artifact)
    group = migrated["groups"]["0x02"]
    entries = list(iter_register_entries(migrated))

    assert report.register_count_before == 1
    assert report.register_count_after == 1
    assert group["dual_namespace"] is False
    assert "namespaces" not in group
    assert group["instances"]["0x00"]["registers"]["0x000f"]["raw_hex"] == "3412"
    assert entries == [
        ("0x02", None, "0x00", "0x000f", {"raw_hex": "3412"}),
    ]
