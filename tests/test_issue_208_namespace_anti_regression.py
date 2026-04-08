from __future__ import annotations

import json
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
    load_b524_constraints_catalog_from_path,
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
    for op_key, group_key, instance_key, register_key, entry in entries:
        identities.add(
            (
                op_key,
                group_key,
                instance_key,
                register_key,
                entry.get("read_opcode"),
                entry.get("raw_hex"),
                entry.get("error"),
            )
        )
    return identities


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


def test_issue_208_constraint_scope_defaults_to_opcode_0x02_only(
    tmp_path: Path,
) -> None:
    catalog_path = tmp_path / "constraints.csv"
    catalog_path.write_text(
        "\n".join(
            (
                "group,register,type,min,max,step",
                "0x03,0x0002,f32_range,15,30,0.5",
                "0x03,0x0001,u16_range,1,200,1",
                "0x04,0x0002,u8_range,0,10,1",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    catalog = load_b524_constraints_catalog_from_path(catalog_path)

    local = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x02, group=0x03, instance=0x00, register=0x0002),
    )
    remote = lookup_static_constraint(
        catalog,
        identity=make_register_identity(opcode=0x06, group=0x03, instance=0x01, register=0x0002),
    )

    assert local is not None
    assert remote is None
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
    legacy = {
        "meta": {"destination_address": "0x15"},
        "groups": {
            "0x09": {
                "name": "Regulators",
                "descriptor_observed": 1.0,
                "instances": {
                    "0x00": {
                        "present": True,
                        "registers": {
                            "0x0001": {"read_opcode": "0x02", "raw_hex": "01", "error": None}
                        },
                    }
                },
                "namespaces": {},
            }
        },
    }
    migrated, report = migrate_artifact_schema(legacy)

    assert report.source_schema_version == LEGACY_UNVERSIONED_SCHEMA
    assert migrated["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    # v2.3: migrated to operations-first
    migrated_group = migrated["operations"]["0x02"]["groups"]["0x09"]
    # Migration adds response_state='active' to entries that have raw_hex;
    # the legacy dict is untouched (deepcopy), so compare structurally.
    legacy_instances = legacy["groups"]["0x09"]["instances"]
    for ii_key, inst in migrated_group["instances"].items():
        for rr_key, entry in inst["registers"].items():
            legacy_entry = legacy_instances[ii_key]["registers"][rr_key]
            for k, v in legacy_entry.items():
                assert entry[k] == v, f"{ii_key}/{rr_key}/{k}: {entry[k]!r} != {v!r}"
            # response_state is derived during migration
            assert entry.get("response_state") == "active"
    assert report.register_count_before == report.register_count_after


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
    script_open = '<script id="artifact-data" type="application/json">'
    script_start = html.index(script_open) + len(script_open)
    script_end = html.index("</script>", script_start)
    embedded_artifact = json.loads(html[script_start:script_end].strip())

    namespaces = embedded_artifact["groups"]["0x09"]["namespaces"]
    assert set(namespaces) == {"0x02", "0x06"}
    assert '"single":' not in html


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
        ),
    ]

    plan = build_plan_from_preset(groups, preset="research")

    local_key = make_plan_key(0x69, 0x02)
    remote_key = make_plan_key(0x69, 0x06)
    assert sorted(plan) == [local_key, remote_key]
    assert plan[local_key].opcode == 0x02
    assert plan[remote_key].opcode == 0x06
    assert plan[local_key].rr_max == 0x0010
    assert plan[remote_key].rr_max == 0x0020
