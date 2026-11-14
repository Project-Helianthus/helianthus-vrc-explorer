"""Characterize the B524 scan phases through their artifact and operator output.

The first tests pin what an operator sees and what the artifact records for a
synthetic dummy-transport scan and for a replay of the recorded dry-run
artifact, so moving a phase out of ``run_b524_scan`` can be checked byte for
byte. The last tests drive the plan and discovery phase functions directly.
"""

from __future__ import annotations

import io
import json
import struct
from collections import Counter
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from helianthus_vrc_explorer.cli import _load_default_dry_run_fixture_text
from helianthus_vrc_explorer.scanner.b524_plan import _group_name_for_opcode
from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.dummy import DummyTransport


def _f32(value: float) -> str:
    return struct.pack("<f", value).hex()


def synthetic_scan_fixture() -> dict[str, Any]:
    """Return a synthetic regulator with counts, present circuits and one remote device."""

    return {
        "schema_version": "2.5",
        "meta": {
            "system_information": [
                {"identifier": "0x0000", "raw_hex": _f32(2.0), "value": 2.0},
                {"identifier": "0x0001", "raw_hex": _f32(1.0), "value": 1.0},
                {"identifier": "0x0004", "raw_hex": _f32(1.0), "value": 1.0},
                {"identifier": "0x0005", "raw_hex": None, "value": None},
                {"identifier": "0x0006", "raw_hex": _f32(3.0), "value": 3.0},
                {"identifier": "0x0007", "raw_hex": _f32(1.0), "value": 1.0},
                {"identifier": "0x0010", "raw_hex": _f32(0.0), "value": 0.0},
            ]
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x00": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "0100", "flags": 3},
                                    "0x0002": {"raw_hex": "02", "flags": 1},
                                }
                            }
                        }
                    },
                    "0x02": {
                        "instances": {
                            "0x01": {
                                "registers": {
                                    "0x0002": {"raw_hex": "0100"},
                                    "0x0003": {"raw_hex": "02"},
                                }
                            },
                            "0x02": {"registers": {"0x0002": {"raw_hex": "0100"}}},
                        }
                    },
                    "0x03": {
                        "instances": {
                            "0x01": {
                                "registers": {
                                    "0x001c": {"raw_hex": "0100"},
                                    "0x0002": {"raw_hex": "01"},
                                }
                            }
                        }
                    },
                }
            },
            "0x06": {
                "groups": {
                    "0x01": {
                        "instances": {
                            "0x01": {"registers": {"0x0001": {"raw_hex": "01", "flags": 1}}}
                        }
                    }
                }
            },
        },
    }


class OperatorOutput(ScanObserver):
    """Record every observer call in order, as an operator would see it."""

    def __init__(self) -> None:
        self.events: list[tuple[Any, ...]] = []

    def phase_start(self, phase: str, *, total: int) -> None:
        self.events.append(("phase_start", phase, total))

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        self.events.append(("phase_advance", phase, advance))

    def phase_set_total(self, phase: str, *, total: int) -> None:
        self.events.append(("phase_set_total", phase, total))

    def phase_finish(self, phase: str) -> None:
        self.events.append(("phase_finish", phase))

    def status(self, message: str) -> None:
        self.events.append(("status", message))

    def log(self, message: str, *, level: str = "info") -> None:
        self.events.append(("log", level, message))

    @contextmanager
    def suspend(self):  # type: ignore[override]
        self.events.append(("suspend",))
        yield None

    def logs(self) -> list[tuple[str, str]]:
        return [(event[1], event[2]) for event in self.events if event[0] == "log"]

    def lifecycle(self) -> list[tuple[Any, ...]]:
        kinds = {"phase_start", "phase_set_total", "phase_finish"}
        return [event for event in self.events if event[0] in kinds]


class InterruptAfter(TransportInterface):
    """Raise an operator interrupt once a fixed number of requests were answered."""

    def __init__(self, inner: TransportInterface, *, answered: int) -> None:
        self._inner = inner
        self._remaining = answered

    def send(self, dst: int, payload: bytes) -> bytes:
        if self._remaining <= 0:
            raise KeyboardInterrupt
        self._remaining -= 1
        return self._inner.send(dst, payload)


def canonical_artifact(artifact: dict[str, Any]) -> str:
    """Serialize as the command writes it, with wall-clock fields neutralized."""

    meta = artifact["meta"]
    meta["scan_timestamp"] = "<timestamp>"
    meta["scan_duration_seconds"] = 0.0
    scan_plan = meta.get("scan_plan")
    if isinstance(scan_plan, dict) and scan_plan.get("measured_request_rate_rps") is not None:
        scan_plan["measured_request_rate_rps"] = 1.0
    return json.dumps(artifact, indent=2, sort_keys=True) + "\n"


def _recorded_dry_run_artifact(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """Return the artifact that ``scan --dry-run`` replays and its recorded identity."""

    text, _source = _load_default_dry_run_fixture_text()
    assert text is not None
    path = tmp_path / "recorded_dry_run.json"
    path.write_text(text, encoding="utf-8")
    return path, json.loads(text)["meta"].get("identity", {})


def _write_fixture(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic_scan.json"
    path.write_text(json.dumps(synthetic_scan_fixture()), encoding="utf-8")
    return path


def _scan(transport: TransportInterface, **options: Any) -> tuple[dict[str, Any], OperatorOutput]:
    output = OperatorOutput()
    artifact = scan_b524(transport, dst=0x15, observer=output, **options)
    return artifact, output


def _present_register_counts(artifact: dict[str, Any]) -> dict[tuple[str, str, str], int]:
    counts: dict[tuple[str, str, str], int] = {}
    for opcode, operation in artifact["operations"].items():
        for group, group_object in operation["groups"].items():
            for instance, instance_object in group_object.get("instances", {}).items():
                if instance_object.get("present"):
                    counts[(opcode, group, instance)] = len(instance_object.get("registers", {}))
    return counts


_PLAN_AND_DISCOVERY_LOGS = [
    ("info", "Starting scan dst=0x15"),
    (
        "info",
        "Parameter description policy will be resolved from exact profile identity and "
        "planner selection (OP01 local / OP07 remote).",
    ),
]
_UNCATALOGUED_PROFILE_WARNING = (
    "warn",
    "Controller description profile is not in the catalog. Use Full for live writable "
    "descriptions within known bounds, then save/share JSON manually if useful.",
)
_COVERAGE_LOGS = [
    ("info", "Prepared 18 profile register candidates"),
    ("info", "Deriving scan coverage defaults from known profiles"),
]

# (opcode, group, present/slots, register maximum or None for probe-only namespaces)
_NAMESPACE_SUMMARY = [
    (0x02, 0x00, "1/1", 0x00FF),
    (0x02, 0x01, "0/1", 0x0013),
    (0x02, 0x02, "2/9", 0x0025),
    (0x02, 0x03, "0/11", 0x002E),
    (0x02, 0x04, "0/2", 0x000B),
    (0x02, 0x05, "0/2", 0x0004),
    (0x02, 0x08, "0/11", 0x0007),
    (0x02, 0x09, "0/11", 0x000F),
    (0x06, 0x01, "1/8", 0x002F),
    (0x06, 0x02, "0/8", 0x002F),
    (0x06, 0x03, "0/8", 0x002F),
    (0x06, 0x05, "0/8", 0x002F),
    (0x06, 0x06, "0/8", 0x002F),
    (0x06, 0x07, "0/8", 0x002F),
    (0x06, 0x08, "0/8", 0x002F),
    (0x06, 0x09, "0/8", 0x0035),
    (0x06, 0x0A, "0/8", 0x0035),
    (0x06, 0x0B, "0/8", 0x002F),
    (0x06, 0x0C, "0/8", 0x002F),
    (0x06, 0x0D, "0/8", None),
    (0x06, 0x0E, "0/8", 0x0033),
    (0x06, 0x0F, "0/8", 0x0033),
]


def _namespace_summary_logs(
    summary: list[tuple[int, int, str, int | None]],
) -> list[tuple[str, str]]:
    lines = []
    for opcode, group, count, rr_max in summary:
        rr_text = (
            "RR_max=unknown (probe-only)"
            if rr_max is None
            else f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)"
        )
        lines.append(
            (
                "info",
                f"OP=0x{opcode:02X} GG=0x{group:02X}: "
                f"{_group_name_for_opcode(group, opcode)} {count} present, {rr_text}",
            )
        )
    return lines


def test_dummy_transport_scan_operator_output_is_pinned(tmp_path: Path) -> None:
    _artifact, output = _scan(DummyTransport(_write_fixture(tmp_path)))

    assert output.logs() == [
        *_PLAN_AND_DISCOVERY_LOGS,
        ("warn", "System information timeout for ID=0x05"),
        _UNCATALOGUED_PROFILE_WARNING,
        *_COVERAGE_LOGS,
        *_namespace_summary_logs(_NAMESPACE_SUMMARY),
    ]
    assert output.lifecycle() == [
        ("phase_start", "group_discovery", 18),
        ("phase_set_total", "group_discovery", 18),
        ("phase_finish", "group_discovery"),
        ("phase_start", "instance_discovery", 158),
        ("phase_finish", "instance_discovery"),
        ("phase_start", "register_scan", 418),
        ("phase_start", "describe", 1),
        ("phase_finish", "describe"),
        ("phase_finish", "register_scan"),
    ]
    kinds = Counter(event[0] for event in output.events)
    assert kinds["status"] == 566
    assert kinds["phase_advance"] == 584
    assert kinds["suspend"] == 0


def test_dummy_transport_scan_artifact_is_pinned(tmp_path: Path) -> None:
    artifact, _output = _scan(DummyTransport(_write_fixture(tmp_path)))
    meta = artifact["meta"]

    # Insertion order records which phase wrote each section.
    assert list(meta) == [
        "scan_timestamp",
        "scan_duration_seconds",
        "destination_address",
        "schema_sources",
        "incomplete",
        "artifact_contract",
        "system_information",
        "scan_coverage",
        "constraint_catalog_source",
        "constraint_catalog_entries",
        "constraint_scope",
        "profile_context",
        "description_profile_status",
        "description_profile_reminder",
        "parameter_description_policy",
        "instance_counts",
        "device_discovery",
        "device_count",
        "b524_event_acquisition",
        "scan_plan",
        "group_metadata_bounds",
        "constraint_probe_enabled",
        "parameter_description_requests",
        "constraint_dictionary",
        "parameter_description_coverage",
    ]
    available = {
        record["identifier"]: record["value"]
        for record in meta["system_information"]
        if record["state"] == "available"
    }
    assert len(meta["system_information"]) == 18
    assert available == {
        "0x0000": 2.0,
        "0x0001": 1.0,
        "0x0004": 1.0,
        "0x0006": 3.0,
        "0x0007": 1.0,
        "0x0010": 0.0,
    }
    coverage = meta["scan_coverage"]
    assert {key: coverage[key] for key in list(coverage)[:8]} == {
        "preset": "recommended",
        "request_budget": None,
        "exhaustive_wire_space": False,
        "scope": "declared_profile",
        "unknown_groups": [],
        "configured_groups": [f"0x{group:02x}" for group in range(0x12)],
        "discovery_completed": True,
        "qualification_incomplete": True,
    }
    assert coverage["actual_requests"] == 587
    assert coverage["completed"] is True
    profile = meta["profile_context"]
    assert (profile["api_version_raw"], profile["api_revision_raw"]) == ("3", "1")
    assert (profile["api_version"], profile["api_revision"]) == (3.0, 1.0)
    assert profile["feature_hints"] == {"ventilation": False}
    assert meta["description_profile_status"] == {
        "status": "unknown",
        "profile_id": None,
        "device_class": "local",
    }
    assert meta["parameter_description_policy"] == {
        "enabled": True,
        "request_budget": None,
        "legacy_request_budget": None,
        "system_description_opcode": "0x01",
        "device_description_opcode": "0x07",
        "scope": "observed_writable_complete_identity",
        "scheduler": "family_reservation_then_instance_round_robin",
        "unknown_codec_raw_evidence": True,
        "profile_status": "unknown",
        "profile_id": None,
        "local_source": "live",
        "remote_source": "live",
        "local_override": False,
        "remote_override": False,
        "selected_preset": "recommended",
    }
    bounds = meta["group_metadata_bounds"]
    assert sorted(bounds) == [f"0x{group:02x}" for group in range(0x12)]
    assert {entry["source"] for entry in bounds.values()} == {"profile"}
    assert meta["device_count"] == {
        "identifier": "0x0004",
        "expected": 1,
        "observed": 1,
        "mismatch": False,
    }
    assert meta["instance_counts"]["0x02:0x02"]["observed"] == 2
    assert meta["scan_plan"]["estimated_register_requests"] == 418
    assert _present_register_counts(artifact) == {
        ("0x02", "0x00", "0x00"): 256,
        ("0x02", "0x02", "0x01"): 38,
        ("0x02", "0x02", "0x02"): 38,
        ("0x06", "0x01", "0x01"): 48,
    }
    group = artifact["operations"]["0x02"]["groups"]["0x02"]
    assert group["discovery_advisory"] == {
        "kind": "profile_register_candidate",
        "semantic_authority": False,
        "proven_register_opcodes": ["0x02", "0x06"],
        "instance_discovery_decision": {
            "strategy": "multi_operation",
            "decision": "independent_per_operation",
            "tradeoff": "independent probing is authoritative over shared inference",
        },
    }
    assert "issue_suggestion" not in meta
    assert len(canonical_artifact(artifact).encode("utf-8")) == 425346


def test_recorded_artifact_replay_is_pinned(tmp_path: Path) -> None:
    recorded, identity = _recorded_dry_run_artifact(tmp_path)
    artifact, output = _scan(DummyTransport(recorded), operation_identity=identity)
    # The recorded artifact holds no circuit or remote device rows.
    replay_counts = {(0x02, 0x02): "0/9", (0x06, 0x01): "0/8"}

    assert output.logs() == [
        *_PLAN_AND_DISCOVERY_LOGS,
        _UNCATALOGUED_PROFILE_WARNING,
        *_COVERAGE_LOGS,
        *_namespace_summary_logs(
            [
                (opcode, group, replay_counts.get((opcode, group), count), rr_max)
                for opcode, group, count, rr_max in _NAMESPACE_SUMMARY
            ]
        ),
    ]
    meta = artifact["meta"]
    assert meta["identity"] == identity
    assert meta["scan_coverage"]["actual_requests"] == 447
    assert meta["scan_plan"]["estimated_register_requests"] == 256
    assert meta["scan_plan"]["estimated_operation_requests_worst_case"] == 48
    assert meta["b524_event_acquisition"]["status"] == "scheduled_candidates"
    assert meta["b524_operation_read_attempts"] == {"OP09": 24, "OP0B": 0, "total": 24}
    assert _present_register_counts(artifact) == {("0x02", "0x00", "0x00"): 256}
    assert len(canonical_artifact(artifact).encode("utf-8")) == 367324


@pytest.mark.parametrize(
    ("request_budget", "profile_written"),
    [(5, False), (19, False), (20, True)],
)
def test_budget_exhausted_during_discovery_keeps_partial_state(
    tmp_path: Path, request_budget: int, profile_written: bool
) -> None:
    artifact, output = _scan(
        DummyTransport(_write_fixture(tmp_path)), request_budget=request_budget
    )
    meta = artifact["meta"]

    assert meta["incomplete"] is True
    assert meta["incomplete_reason"] == "request_budget_exhausted"
    assert meta["scan_coverage"]["discovery_completed"] is False
    assert meta["scan_coverage"]["completed"] is False
    assert meta["scan_coverage"]["actual_requests"] == request_budget
    # Answered and unanswered identifiers alike stay in the artifact.
    assert len(meta["system_information"]) == 18
    assert ("profile_context" in meta) is profile_written
    assert ("parameter_description_policy" in meta) is profile_written
    assert len(meta["budget_boundary_evidence"]) == request_budget
    assert output.logs()[:2] == _PLAN_AND_DISCOVERY_LOGS


def test_operator_interrupt_during_system_information_keeps_skeleton(tmp_path: Path) -> None:
    artifact, output = _scan(InterruptAfter(DummyTransport(_write_fixture(tmp_path)), answered=3))
    meta = artifact["meta"]

    assert meta["incomplete_reason"] == "user_interrupt"
    assert meta["system_information"] == []
    assert meta["scan_coverage"]["actual_requests"] == 4
    assert "profile_context" not in meta
    assert "parameter_description_coverage" in meta
    assert output.logs() == _PLAN_AND_DISCOVERY_LOGS
    assert output.lifecycle() == [("phase_start", "group_discovery", 18)]


def test_explicit_plan_scan_records_selectors(tmp_path: Path) -> None:
    explicit = {
        make_plan_key(0x02, 0x02): GroupScanPlan(
            group=0x02, opcode=0x02, rr_max=0x03, instances=(0x01, 0x02)
        )
    }
    artifact, output = _scan(
        DummyTransport(_write_fixture(tmp_path)),
        planner_preset="custom",
        explicit_plan=explicit,
    )
    meta = artifact["meta"]

    assert meta["scan_coverage"]["scope"] == "explicit_selectors"
    assert meta["scan_coverage"]["configured_groups"] == ["0x02"]
    # The circuit plan always carries its mandatory instance.
    assert meta["scan_plan"]["groups"]["0x02"]["instances"] == ["0x01", "0x02", "0x09"]
    assert meta["scan_plan"]["estimated_register_requests"] == 12
    assert meta["scan_coverage"]["actual_requests"] == 32
    registers = {
        instance: sorted(instance_object["registers"])
        for instance, instance_object in artifact["operations"]["0x02"]["groups"]["0x02"][
            "instances"
        ].items()
    }
    assert registers == {
        instance: ["0x0000", "0x0001", "0x0002", "0x0003"] for instance in ("0x01", "0x02", "0x09")
    }
    assert output.logs()[-1] == ("info", "Deriving scan coverage defaults from known profiles")
    assert len(canonical_artifact(artifact).encode("utf-8")) == 23261


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"explicit_plan": {}}, "An explicit scan plan requires the custom preset"),
        ({"description_budget": -1}, "description_budget must be a nonnegative integer"),
        ({"description_budget": True}, "description_budget must be a nonnegative integer"),
    ],
)
def test_invalid_scan_requests_fail_before_any_request(
    tmp_path: Path, options: dict[str, Any], message: str
) -> None:
    transport = InterruptAfter(DummyTransport(_write_fixture(tmp_path)), answered=0)

    with pytest.raises(ValueError, match=message):
        scan_b524(transport, dst=0x15, **options)


def test_unavailable_full_screen_planner_warning_keeps_its_place(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sys

    from rich.console import Console

    from helianthus_vrc_explorer.scanner.collaborators import ScanPlanners

    def keep_default_plan(_console, _groups, /, *, default_plan=None, **_options):
        return dict(default_plan or {})

    def no_full_screen_planner():
        raise AssertionError("the classic planner is selected before loading it")

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setitem(sys.modules, "textual", None)
    output = OperatorOutput()
    scan_b524(
        DummyTransport(_write_fixture(tmp_path)),
        dst=0x15,
        observer=output,
        console=Console(force_terminal=True, file=io.StringIO()),
        planner_ui="auto",
        planners=ScanPlanners(
            prompt_scan_plan=keep_default_plan,
            load_textual_scan_plan=no_full_screen_planner,
        ),
    )

    logs = output.logs()
    warning = ("warn", "Textual UI unavailable; falling back to classic planner.")
    # The planner mode is resolved after the group bounds and before any probing.
    assert logs[logs.index(warning) - 1] == _COVERAGE_LOGS[-1]
    assert logs[logs.index(warning) + 1][1].startswith("OP=0x02 GG=0x00: ")
    assert output.events.count(("suspend",)) == 1


def _plan(transport: TransportInterface, **options: Any):
    from helianthus_vrc_explorer.scanner.b524_phases import plan_b524_scan

    request: dict[str, Any] = {
        "dst": 0x15,
        "observer": None,
        "ebusd_host": None,
        "ebusd_port": None,
        "planner_preset": "recommended",
        "probe_constraints": True,
        "explicit_plan": None,
        "description_budget": None,
        "request_budget": None,
        "operation_requests": (),
        "operation_identity": None,
    }
    request.update(options)
    return plan_b524_scan(transport, **request)


def _fallback_bounds():
    from helianthus_vrc_explorer.scanner.b524_probe import GroupMetadata

    return GroupMetadata(rr_max=0x0030, ii_max=0x0A, source="fallback")


def test_plan_phase_lays_out_the_skeleton_without_sending(tmp_path: Path) -> None:
    transport = InterruptAfter(DummyTransport(_write_fixture(tmp_path)), answered=0)

    ctx = _plan(
        transport,
        planner_preset="aggressive",
        ebusd_host="ebusd.invalid",
        ebusd_port=8888,
        request_budget=40,
    )

    assert ctx.transport.counters.send_calls == 0
    assert ctx.transport.request_budget == 40
    assert ctx.planner_preset == "full"
    assert ctx.research_mode is False
    assert ctx.configured_groups == list(range(0x12))
    assert ctx.operation_requests == []
    assert ctx.operation_selection == []
    assert ctx.description_policy is None
    meta = ctx.artifact["meta"]
    assert list(meta) == [
        "scan_timestamp",
        "scan_duration_seconds",
        "destination_address",
        "schema_sources",
        "incomplete",
        "artifact_contract",
        "system_information",
        "scan_coverage",
        "ebusd_host",
        "ebusd_port",
        "constraint_catalog_source",
        "constraint_catalog_entries",
        "constraint_scope",
    ]
    assert meta["scan_coverage"]["preset"] == "full"
    assert meta["scan_coverage"]["request_budget"] == 40
    assert (meta["ebusd_host"], meta["ebusd_port"]) == ("ebusd.invalid", 8888)
    assert ctx.artifact["operations"] == {}


@pytest.mark.parametrize(
    ("preset", "explicit_plan", "configured_groups", "scope"),
    [
        ("research", None, list(range(0x100)), "declared_profile"),
        (
            "custom",
            {
                make_plan_key(0x69, 0x02): GroupScanPlan(
                    group=0x69, opcode=0x02, rr_max=0x0000, instances=(0x00,)
                )
            },
            [0x69],
            "explicit_selectors",
        ),
    ],
)
def test_plan_phase_derives_the_configured_groups(
    tmp_path: Path,
    preset: str,
    explicit_plan: dict[Any, GroupScanPlan] | None,
    configured_groups: list[int],
    scope: str,
) -> None:
    ctx = _plan(
        DummyTransport(_write_fixture(tmp_path)),
        planner_preset=preset,
        explicit_plan=explicit_plan,
    )

    assert ctx.configured_groups == configured_groups
    assert ctx.research_mode is (preset == "research")
    assert ctx.artifact["meta"]["scan_coverage"]["scope"] == scope
    assert ("scan_plan" in ctx.artifact["meta"]) is (explicit_plan is not None)


def test_discovery_phase_resolves_the_planner_mode_between_bounds_and_operations(
    tmp_path: Path,
) -> None:
    from helianthus_vrc_explorer.scanner.b524_phases import discover_b524_scope
    from helianthus_vrc_explorer.scanner.director import discover_groups

    output = OperatorOutput()
    explicit_plan = {
        make_plan_key(0x02, 0x02): GroupScanPlan(
            group=0x02, opcode=0x02, rr_max=0x0001, instances=(0x01,)
        ),
        make_plan_key(0x69, 0x02): GroupScanPlan(
            group=0x69, opcode=0x02, rr_max=0x0000, instances=(0x00,)
        ),
    }
    ctx = _plan(
        DummyTransport(_write_fixture(tmp_path)),
        observer=output,
        planner_preset="custom",
        explicit_plan=explicit_plan,
    )
    fallback = _fallback_bounds()
    seen: dict[str, Any] = {}

    def resolve_planner_mode():
        seen["last_log"] = output.logs()[-1]
        seen["bounds"] = dict(ctx.metadata_map)
        seen["resolved"] = dict(ctx.resolved_group_opcodes)
        return "classic"

    discover_b524_scope(
        ctx,
        discover_groups_fn=discover_groups,
        resolve_planner_mode=resolve_planner_mode,
        fallback_bounds=fallback,
    )

    assert seen["last_log"] == _COVERAGE_LOGS[-1]
    assert seen["bounds"][0x69] is fallback
    assert seen["bounds"][0x02].source == "profile"
    assert seen["resolved"] == {}
    assert ctx.planner_mode == "classic"
    assert [group.group for group in ctx.classified] == [0x02, 0x69]
    assert ctx.resolved_group_opcodes == {0x02: (0x02,), 0x69: (0x02,)}
    assert ctx.availability_group_opcodes == {0x02: (), 0x69: ()}
    assert ctx.information_values[0x0000] == 2.0
    assert ctx.profile_id is None
    assert ctx.ventilation_hint is False
    assert ctx.group_discovery_requests == ctx.transport.counters.send_calls
    assert ctx.artifact["meta"]["parameter_description_policy"]["local_source"] == "live"
    assert ctx.artifact["operations"] == {}


def test_discovery_phase_keeps_resolved_fields_when_stopped(tmp_path: Path) -> None:
    from helianthus_vrc_explorer.scanner.b524_phases import discover_b524_scope
    from helianthus_vrc_explorer.scanner.director import discover_groups

    ctx = _plan(DummyTransport(_write_fixture(tmp_path)))

    def operator_stops():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        discover_b524_scope(
            ctx,
            discover_groups_fn=discover_groups,
            resolve_planner_mode=operator_stops,
            fallback_bounds=_fallback_bounds(),
        )

    assert ctx.description_policy is not None
    assert len(ctx.metadata_map) == 0x12
    assert "parameter_description_policy" in ctx.artifact["meta"]
    assert ctx.planner_mode == "disabled"
    assert ctx.resolved_group_opcodes == {}
    assert ctx.artifact["operations"] == {}


def _discovered(tmp_path: Path, **options: Any):
    from helianthus_vrc_explorer.scanner.b524_phases import discover_b524_scope
    from helianthus_vrc_explorer.scanner.director import discover_groups

    ctx = _plan(DummyTransport(_write_fixture(tmp_path)), **options)
    discover_b524_scope(
        ctx,
        discover_groups_fn=discover_groups,
        resolve_planner_mode=lambda: "disabled",
        fallback_bounds=_fallback_bounds(),
    )
    return ctx


def _present(ctx: Any, opcode: str, group: str) -> list[str]:
    instances = ctx.artifact["operations"][opcode]["groups"][group]["instances"]
    return sorted(key for key, value in instances.items() if value.get("present"))


def test_availability_phase_records_presence_without_reading_registers(tmp_path: Path) -> None:
    from helianthus_vrc_explorer.scanner.b524_phases import probe_b524_availability
    from helianthus_vrc_explorer.scanner.register import probe_instance_availability

    output = OperatorOutput()
    ctx = _discovered(tmp_path, observer=output)
    discovery_events = len(output.events)
    sent_before = ctx.transport.counters.send_calls

    probe_b524_availability(ctx, probe_instance_availability_fn=probe_instance_availability)

    assert ctx.instance_discovery_requests == ctx.transport.counters.send_calls - sent_before
    assert ctx.instance_discovery_requests > 0
    assert ctx.native_dhw_admitted == {(0x02, 0x01): False}
    assert _present(ctx, "0x02", "0x02") == ["0x01", "0x02"]
    assert _present(ctx, "0x06", "0x01") == ["0x01"]
    meta = ctx.artifact["meta"]
    assert meta["scan_coverage"]["discovery_completed"] is True
    assert meta["instance_counts"]["0x02:0x02"]["observed"] == 2
    assert meta["device_count"]["observed"] == 1
    assert meta["b524_event_acquisition"]["status"] == "not_scheduled_unknown_identity"
    assert "scan_plan" not in meta
    phase_events = output.events[discovery_events:]
    assert [event for event in phase_events if event[0].startswith("phase_s")] == [
        ("phase_start", "instance_discovery", 158)
    ]
    assert phase_events[-1] == ("phase_finish", "instance_discovery")
    assert [
        (event[1], event[2]) for event in phase_events if event[0] == "log"
    ] == _namespace_summary_logs(_NAMESPACE_SUMMARY)


def test_scan_phase_uses_its_collaborators_once(tmp_path: Path) -> None:
    from contextlib import nullcontext

    from helianthus_vrc_explorer.scanner.b524_phases import (
        B524ScanCollaborators,
        probe_b524_availability,
        scan_b524_registers,
    )
    from helianthus_vrc_explorer.scanner.register import probe_instance_availability

    ctx = _discovered(tmp_path)
    probe_b524_availability(ctx, probe_instance_availability_fn=probe_instance_availability)
    calls: list[tuple[Any, ...]] = []

    class Hotkeys:
        def poll(self) -> bool:
            raise AssertionError("hotkeys are not polled without a planner")

        def suspend(self):
            return nullcontext()

    def hotkey_reader(*, enabled: bool):
        calls.append(("hotkeys", enabled))
        return nullcontext(Hotkeys())

    def select(artifact, candidates, entries, /, *, policy):
        calls.append(("select", artifact is ctx.artifact, len(candidates), len(entries)))
        return [], {}, []

    def annotate(artifact, /) -> None:
        calls.append(("annotate", artifact is ctx.artifact))

    scan_b524_registers(
        ctx,
        B524ScanCollaborators(
            console=None,
            planners=None,
            planner_ui="auto",
            hotkey_reader_cls=hotkey_reader,
            ebusd_schema=None,
            myvaillant_map=None,
            select_description_candidates=select,
            annotate_artifact=annotate,
        ),
    )

    writable = len(ctx.observed_description_candidates)
    assert writable == len(ctx.observed_description_entries) == 1
    assert calls == [("hotkeys", False), ("select", True, writable, writable), ("annotate", True)]
    assert ctx.description_candidates_prepared is True
    meta = ctx.artifact["meta"]
    assert meta["scan_plan"]["estimated_register_requests"] == 418
    assert meta["constraint_dictionary"] == {}
    assert _present(ctx, "0x02", "0x02") == ["0x01", "0x02"]
    assert "registers" in ctx.artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x09"]


def test_completion_selects_descriptions_late_after_an_interrupt(tmp_path: Path) -> None:
    from helianthus_vrc_explorer.scanner.b524_phases import (
        complete_b524_scan,
        record_operator_interrupt,
    )

    ctx = _discovered(tmp_path)
    selected: list[int] = []

    def select(artifact, candidates, entries, /, *, policy):
        selected.append(len(candidates))
        return [], {}, [{"group": "0x0a", "instance": "0x01", "status": "unknown"}]

    reason = record_operator_interrupt(ctx)
    complete_b524_scan(ctx, incomplete_reason=reason, select_description_candidates=select)

    meta = ctx.artifact["meta"]
    assert selected == [0]
    assert meta["description_remote_profile_statuses"] == [
        {"group": "0x0a", "instance": "0x01", "status": "unknown"}
    ]
    assert meta["incomplete"] is True
    assert meta["incomplete_reason"] == "user_interrupt"
    assert meta["scan_coverage"]["completed"] is False
    assert meta["scan_coverage"]["actual_requests"] == ctx.transport.counters.send_calls
    assert meta["parameter_description_requests"] == 0
    assert list(meta)[-3:] == [
        "parameter_description_coverage",
        "parameter_description_requests",
        "incomplete_reason",
    ]


def test_completion_keeps_the_pending_register_of_an_exhausted_recovery(tmp_path: Path) -> None:
    from helianthus_vrc_explorer.scanner.b524_phases import (
        complete_b524_scan,
        record_transport_recovery_exhausted,
    )
    from helianthus_vrc_explorer.transport.base import TransportRecoveryExhausted

    output = OperatorOutput()
    ctx = _plan(DummyTransport(_write_fixture(tmp_path)), observer=output)
    exc = TransportRecoveryExhausted(
        cause="timeout", phase="receive", request_attempts=3, reconnect_attempts=1
    )
    # Every selector field differs, so a swapped or dropped field lands elsewhere.
    exc.selector = {
        "read_opcode": "0x06",
        "group": "0x0a",
        "instance": "0x03",
        "register": "0x0012",
    }
    exc.entry = {"response_state": "timeout", "raw_hex": None}
    exc.system_information = [(0x0000, 2.0, "00000040")]

    def no_description_policy_yet(*_args: Any, **_options: Any):
        raise AssertionError("no candidates are selected before discovery")

    reason = record_transport_recovery_exhausted(ctx, exc)
    complete_b524_scan(
        ctx, incomplete_reason=reason, select_description_candidates=no_description_policy_yet
    )

    meta = ctx.artifact["meta"]
    assert reason == "transport_recovery_exhausted"
    assert meta["incomplete_reason"] == "transport_recovery_exhausted"
    assert meta["transport_recovery"]["pending_selector"] == exc.selector
    assert meta["transport_recovery"]["retry_count"] == 2
    assert meta["system_information"][0]["value"] == 2.0
    assert list(ctx.artifact["operations"]) == ["0x06"]
    assert list(ctx.artifact["operations"]["0x06"]["groups"]) == ["0x0a"]
    instances = ctx.artifact["operations"]["0x06"]["groups"]["0x0a"]["instances"]
    assert instances == {"0x03": {"present": False, "registers": {"0x0012": exc.entry}}}
    assert output.logs()[-1] == ("warn", str(exc))
