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
        op_key,
        group_key,
        instance_key,
        register_key,
        entry,
    ) in iter_register_entries(artifact):
        identities.add(
            (
                op_key,
                group_key,
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
    # v2.3: operations-first structure
    assert "groups" not in migrated
    group_obj = migrated["operations"]["0x02"]["groups"]["0x02"]
    assert group_obj["descriptor_observed"] == 1.0
    register = group_obj["instances"]["0x00"]["registers"]["0x000f"]
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
    # Build a v2.2 legacy copy by inverting the v2.3 operations structure back to groups
    legacy: dict[str, Any] = deepcopy(current)
    legacy.pop("schema_version", None)
    operations = legacy.pop("operations", {})
    groups: dict[str, Any] = {}
    # Track which group_keys appear in multiple ops (need dual_namespace)
    group_ops: dict[str, list[str]] = {}
    for op_key, op_obj in operations.items():
        if not isinstance(op_obj, dict):
            continue
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        for group_key in op_groups:
            group_ops.setdefault(group_key, []).append(op_key)

    for op_key, op_obj in operations.items():
        if not isinstance(op_obj, dict):
            continue
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        for group_key, group_obj in op_groups.items():
            is_multi_op = len(group_ops.get(group_key, [])) > 1
            if is_multi_op:
                # Build dual_namespace structure
                if group_key not in groups:
                    groups[group_key] = {
                        "descriptor_type": group_obj.get("descriptor_observed", 0.0),
                        "dual_namespace": True,
                        "namespaces": {},
                    }
                groups[group_key]["namespaces"][op_key] = {
                    "instances": deepcopy(group_obj.get("instances", {})),
                }
            else:
                groups[group_key] = {
                    "descriptor_type": group_obj.get("descriptor_observed", 0.0),
                    "instances": deepcopy(group_obj.get("instances", {})),
                }
    legacy["groups"] = groups

    migrated, report = migrate_artifact_schema(legacy)

    assert report.register_count_before == report.register_count_after
    assert _register_identity_set(migrated) == _register_identity_set(current)


def test_validator_accepts_legacy_when_enabled() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    # Build legacy (unversioned, groups-first) from current v2.3
    legacy: dict[str, Any] = deepcopy(artifact)
    legacy.pop("schema_version", None)
    operations = legacy.pop("operations", {})
    groups: dict[str, Any] = {}
    for _op_key, op_obj in operations.items():
        for group_key, group_obj in op_obj.get("groups", {}).items():
            g = deepcopy(group_obj)
            g["descriptor_type"] = g.pop("descriptor_observed", 0.0)
            groups[group_key] = g
    legacy["groups"] = groups

    errors, _migrated, source_schema = _validate_scan_artifact(legacy, allow_legacy=True)

    assert errors == []
    assert source_schema == LEGACY_UNVERSIONED_SCHEMA


def test_validator_can_reject_legacy_when_requested() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    # Build legacy copy
    legacy: dict[str, Any] = deepcopy(artifact)
    legacy.pop("schema_version", None)

    errors, _migrated, _source_schema = _validate_scan_artifact(legacy, allow_legacy=False)

    assert any("legacy unversioned artifact rejected" in error for error in errors)


def test_validator_can_reject_legacy_versioned_when_requested() -> None:
    artifact = _load_fixture("vrc720_full_scan.json")
    artifact["schema_version"] = "2.0"

    errors, _migrated, source_schema = _validate_scan_artifact(artifact, allow_legacy=False)

    assert source_schema in LEGACY_VERSIONED_SCHEMAS
    assert any("legacy versioned artifact" in error for error in errors)


def test_validator_detects_namespace_opcode_mismatch() -> None:
    artifact = _load_fixture("dual_namespace_scan.json")
    # In v2.3 format, set a mismatched read_opcode
    artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]["0x00"]["registers"]["0x0004"][
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
    # v2.3: groups-first is now operations-first
    group = migrated["operations"]["0x02"]["groups"]["0x02"]
    entries = list(iter_register_entries(migrated))

    assert report.register_count_before == 1
    assert report.register_count_after == 1
    assert "groups" not in migrated
    assert group["instances"]["0x00"]["registers"]["0x000f"]["raw_hex"] == "3412"
    assert entries == [
        ("0x02", "0x02", "0x00", "0x000f", {"raw_hex": "3412", "response_state": "active"}),
    ]


def test_migrate_21_entries_derives_response_state_and_cleans_known_errors() -> None:
    artifact_21 = {
        "schema_version": "2.1",
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_observed": 1.0,
                "dual_namespace": False,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {
                                "error": "timeout",
                                "flags_access": None,
                                "raw_hex": None,
                            },
                            "0x0002": {
                                "error": "transport_error: no_response",
                                "flags_access": "dormant",
                                "reply_hex": None,
                            },
                            "0x0003": {
                                "error": "transport_error: nack received while reading",
                                "flags_access": None,
                            },
                            "0x0004": {
                                "error": "transport_error: broken framing",
                                "value": 42,
                                "raw_hex": "2a",
                            },
                        }
                    }
                },
            }
        },
    }

    migrated, report = migrate_artifact_schema(artifact_21)
    # v2.3: operations-first
    regs = migrated["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"]

    assert report.source_schema_version == "2.1"
    assert migrated["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert regs["0x0001"]["response_state"] == "timeout"
    assert regs["0x0001"]["error"] is None
    assert regs["0x0002"]["response_state"] == "empty_reply"
    assert regs["0x0002"]["error"] is None
    assert regs["0x0002"]["flags_access"] is None
    assert regs["0x0002"]["reply_hex"] == ""
    assert regs["0x0003"]["response_state"] == "nack"
    assert regs["0x0003"]["error"] is None
    assert regs["0x0004"].get("response_state") is None
    assert regs["0x0004"]["error"] == "transport_error: broken framing"
