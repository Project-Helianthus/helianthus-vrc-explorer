from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from rich.console import Console

from helianthus_vrc_explorer.artifact_schema import (
    CURRENT_ARTIFACT_SCHEMA_VERSION,
    LEGACY_UNVERSIONED_SCHEMA,
    iter_register_entries,
    migrate_artifact_schema,
)
from helianthus_vrc_explorer.scanner.identity import make_register_identity
from helianthus_vrc_explorer.scanner.plan import make_plan_key
from helianthus_vrc_explorer.schema.b524_constraints import (
    CONSTRAINT_SCOPE_DECISION,
    load_default_b524_constraints_catalog,
    lookup_static_constraint,
)
from helianthus_vrc_explorer.ui.html_report import render_html_report
from helianthus_vrc_explorer.ui.planner import PlannerGroup, build_plan_from_preset
from helianthus_vrc_explorer.ui.summary import render_summary

_REPO_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES_DIR = _REPO_ROOT / "fixtures"


def _load_fixture(name: str) -> dict[str, Any]:
    return json.loads((_FIXTURES_DIR / name).read_text(encoding="utf-8"))


def _register_identity_set(artifact: dict[str, Any]) -> set[tuple[Any, ...]]:
    identities: set[tuple[Any, ...]] = set()
    entries = iter_register_entries(artifact)
    for group_key, namespace_key, instance_key, register_key, entry in entries:
        identities.add(
            (
                group_key,
                namespace_key,
                instance_key,
                register_key,
                entry.get("read_opcode"),
                entry.get("raw_hex"),
                entry.get("error"),
            )
        )
    return identities


def _namespace_collision_index(artifact: dict[str, Any]) -> dict[tuple[str, str, str], set[str]]:
    by_coordinate: dict[tuple[str, str, str], set[str]] = {}
    for (
        group_key,
        namespace_key,
        instance_key,
        register_key,
        _entry,
    ) in iter_register_entries(artifact):
        if not isinstance(namespace_key, str):
            continue
        coordinate = (group_key, instance_key, register_key)
        if coordinate not in by_coordinate:
            by_coordinate[coordinate] = set()
        by_coordinate[coordinate].add(namespace_key)
    return {coordinate: keys for coordinate, keys in by_coordinate.items() if len(keys) > 1}


def _normalize_opcode_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = int(value, 0)
    except ValueError:
        return None
    if not (0x00 <= parsed <= 0xFF):
        return None
    return f"0x{parsed:02x}"


def test_issue_208_identity_isolation_keeps_opcode_namespace_distinct() -> None:
    local_key = make_register_identity(opcode=0x02, group=0x09, instance=0x01, register=0x0004)
    remote_key = make_register_identity(opcode=0x06, group=0x09, instance=0x01, register=0x0004)

    assert local_key != remote_key
    assert {local_key, remote_key} == {
        (0x02, 0x09, 0x01, 0x0004),
        (0x06, 0x09, 0x01, 0x0004),
    }


def test_issue_208_artifact_round_trip_stability_preserves_identity_set() -> None:
    artifact = _load_fixture("dual_namespace_scan.json")

    migrated_once, report_once = migrate_artifact_schema(artifact)
    round_trip = json.loads(json.dumps(migrated_once, sort_keys=True))
    migrated_twice, report_twice = migrate_artifact_schema(round_trip)

    assert report_once.target_schema_version == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert migrated_once["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert report_twice.changed is False
    assert _register_identity_set(migrated_once) == _register_identity_set(migrated_twice)


def test_issue_208_constraint_scope_is_opcode_invariant_for_same_group_register() -> None:
    catalog, _source = load_default_b524_constraints_catalog()

    local = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x02, group=0x03, instance=0x00, register=0x0002),
    )
    remote = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x06, group=0x03, instance=0x01, register=0x0002),
    )

    assert local is not None
    assert remote is not None
    assert local == remote
    assert local.scope == CONSTRAINT_SCOPE_DECISION
    assert local.kind == "f32_range"
    assert local.min_value == 15
    assert local.max_value == 30
    assert local.step_value == 0.5

    same_group_different_register = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x02, group=0x03, instance=0x00, register=0x0001),
    )
    assert same_group_different_register is not None
    assert same_group_different_register != local
    assert same_group_different_register.kind == "u16_range"

    different_group_same_register = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x02, group=0x04, instance=0x00, register=0x0002),
    )
    assert different_group_same_register is not None
    assert different_group_same_register != local
    assert different_group_same_register.kind == "u8_range"


def test_issue_208_fixture_backward_compatibility_migrates_legacy_shape() -> None:
    current = _load_fixture("dual_namespace_scan.json")
    collision_index = _namespace_collision_index(current)
    assert collision_index
    assert all(namespaces == {"0x02", "0x06"} for namespaces in collision_index.values())

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

    assert report.source_schema_version == LEGACY_UNVERSIONED_SCHEMA
    assert migrated["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    assert _register_identity_set(migrated) == _register_identity_set(current)
    assert _namespace_collision_index(migrated) == collision_index

    for (
        group_key,
        namespace_key,
        instance_key,
        register_key,
        entry,
    ) in iter_register_entries(migrated):
        coordinate = (group_key, instance_key, register_key)
        if coordinate not in collision_index:
            continue
        assert isinstance(namespace_key, str)
        assert _normalize_opcode_hex(entry.get("read_opcode")) == namespace_key.lower()


def test_issue_208_summary_namespace_totals_are_opcode_authoritative(tmp_path: Path) -> None:
    artifact = {
        "meta": {"destination_address": "0x15"},
        "groups": {
            "0x09": {
                "name": "Regulators",
                "descriptor_observed": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "label": "remote",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {"0x0001": {"read_opcode": "0x02", "error": None}},
                            }
                        },
                    },
                    "0x06": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {"0x0002": {"read_opcode": "0x06", "error": None}},
                            }
                        },
                    },
                },
            }
        },
    }

    console = Console(record=True, width=140)
    render_summary(console, artifact, output_path=tmp_path / "artifact.json")
    text = console.export_text()

    assert "namespaces local (0x02)=1, remote (0x06)=1" in text
    assert "remote (0x02)" not in text
    assert "local (0x06)" not in text


def test_issue_208_html_namespace_isolation_avoids_single_namespace_sentinels() -> None:
    artifact = {
        "meta": {"destination_address": "0x15"},
        "groups": {
            "0x09": {
                "name": "Regulators",
                "dual_namespace": True,
                "descriptor_observed": 1.0,
                "namespaces": {
                    "0x02": {
                        "label": "remote",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {"0x0001": {"read_opcode": "0x02", "raw_hex": "01"}},
                            }
                        },
                    },
                    "0x06": {
                        "label": "local",
                        "instances": {
                            "0x00": {
                                "present": True,
                                "registers": {"0x0002": {"read_opcode": "0x06", "raw_hex": "02"}},
                            }
                        },
                    },
                },
            }
        },
    }

    html = render_html_report(artifact, title="issue-208")

    assert "activeNamespaceByGroup" in html
    forbidden_fallback_patterns = (
        r"""namespaceKey\s*(?:\|\||\?\?)\s*(['"`])single\1""",
        r"""namespaceKey\s*(?:\|\||\?\?)\s*(['"`])0x00\1""",
        r"""fallbackNamespaceKey\s*(?:\|\||\?\?)\s*(['"`])single\1""",
        r"""fallbackNamespaceKey\s*(?:\|\||\?\?)\s*(['"`])0x00\1""",
        r"""read_opcode(?:_label)?\s*(?:\|\||\?\?)\s*(['"`])single\1""",
        r"""read_opcode(?:_label)?\s*(?:\|\||\?\?)\s*(['"`])0x00\1""",
    )
    for pattern in forbidden_fallback_patterns:
        assert re.search(pattern, html, flags=re.IGNORECASE) is None


def test_issue_208_planner_opcode_fidelity_keeps_namespace_specific_keys() -> None:
    groups = [
        PlannerGroup(
            group=0x69,
            opcode=0x02,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x0010,
            rr_max_full=0x0010,
            present_instances=(0x00,),
            namespace_label="local",
            primary=True,
        ),
        PlannerGroup(
            group=0x69,
            opcode=0x06,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x0020,
            rr_max_full=0x0020,
            present_instances=(0x00,),
            namespace_label="remote",
            primary=False,
        ),
    ]

    plan = build_plan_from_preset(groups, preset="full")

    local_key = make_plan_key(0x69, 0x02)
    remote_key = make_plan_key(0x69, 0x06)
    assert sorted(plan) == [local_key, remote_key]
    assert plan[local_key].opcode == 0x02
    assert plan[remote_key].opcode == 0x06
    assert plan[local_key].rr_max == 0x0010
    assert plan[remote_key].rr_max == 0x0020
