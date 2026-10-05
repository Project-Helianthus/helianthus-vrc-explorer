"""Private orchestration for the B524 scanner facade."""

from __future__ import annotations

import math
import sys
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any, cast

from rich.console import Console

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..protocol.b524 import RegisterOpcode
from ..protocol.b524_metadata import (
    COUNT_GROUP_IDS,
    SYSTEM_INFORMATION_NAMES,
    expected_instance_count,
)
from ..schema.b524_constraints import (
    CONSTRAINT_SCOPE_PROTOCOL,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
)
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..transport.base import TransportInterface, emit_trace_label
from ..transport.instrumented import CountingTransport, ScanRequestBudgetExceeded
from ..ui.planner import PlannerGroup, PlannerPreset, build_plan_from_preset
from .b524_artifact import (
    _artifact_contract_metadata,
    _ensure_group_artifact,
    _hex_u8,
    _hex_u16,
    _instances_object,
    _mark_present_instances,
    _present_instances_for_opcode,
    _record_availability_contract,
    _record_availability_probes,
    _record_namespace_topology,
)
from .b524_plan import (
    _KNOWN_DESCRIPTOR_TYPES,
    PlannerUiMode,
    _group_name_for_opcode,
    _ii_max_for_opcode,
    _instance_discovery_decision,
    _instance_discovery_targets,
    _is_instanced_group,
    _normalize_planner_preset,
    _plan_key,
    _planner_group_is_recommended,
    _planner_ii_max,
    _rr_max_for_opcode,
    _rr_max_full_for_opcode,
    _scan_plan_meta_groups,
    opcode_label,
)
from .b524_probe import (
    ConstraintEntry,
    GroupMetadata,
    _apply_constraint_metadata,
    _constraint_catalog_entry_count,
    _constraint_for_register,
    _constraint_map_to_dict,
    _constraint_mismatch_reason,
    _metadata_map_to_dict,
    _probe_present_instances,
    _probe_unknown_group_opcodes,
    _probe_unknown_present_instances,
)
from .description_acquisition import acquire_descriptions, finish_description_coverage
from .description_scheduler import DescriptionCandidate
from .director import GROUP_CONFIG, DiscoveredGroup, classify_groups
from .plan import GroupScanPlan, PlanKey, RegisterTask, build_work_queue, estimate_register_requests
from .register import namespace_availability_contract, read_register
from .scan import (
    _UNKNOWN_GROUP_DEFAULT_II_MAX,
    _UNKNOWN_GROUP_DEFAULT_RR_MAX,
    _UNKNOWN_GROUP_EXPANDED_INSTANCES,
    _UNKNOWN_GROUP_INITIAL_INSTANCES,
    ScanObserver,
    _apply_contextual_enum_annotations,
    _resolve_planner_mode,
)
from .scan_policy import profile_opcodes


def _system_information_records(
    values: dict[int, float], raw: dict[int, str | None]
) -> list[dict[str, Any]]:
    return [
        {
            "identifier": _hex_u16(identifier),
            "name": name,
            "value": values.get(identifier)
            if math.isfinite(values.get(identifier, float("nan")))
            else None,
            "raw_hex": raw.get(identifier),
            "state": "available"
            if math.isfinite(values.get(identifier, float("nan")))
            else "unavailable",
        }
        for identifier, name in enumerate(SYSTEM_INFORMATION_NAMES)
    ]


def run_b524_scan(
    transport: TransportInterface,
    *,
    dst: int,
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
    ebusd_schema: EbusdCsvSchema | None = None,
    myvaillant_map: MyvaillantRegisterMap | None = None,
    observer: ScanObserver | None = None,
    console: Console | None = None,
    planner_ui: PlannerUiMode = "auto",
    planner_preset: PlannerPreset = "recommended",
    probe_constraints: bool = True,
    explicit_plan: dict[PlanKey, GroupScanPlan] | None = None,
    description_budget: int = 256,
    request_budget: int | None = None,
    discover_groups_fn: Any,
    prompt_scan_plan_fn: Any,
    hotkey_reader_cls: Any,
    probe_instance_availability_fn: Any,
) -> dict[str, Any]:
    """Scan a VRC regulator using B524 and return a JSON-serializable artifact.

    Implements the four-phase scan algorithm:
    - Phase A: bounded ReadSystemInformation discovery
    - Phase B: group classification via GROUP_CONFIG
    - Phase C: instance discovery for groups whose configured ii_max is > 0
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """

    planner_preset = _normalize_planner_preset(planner_preset)
    research_mode = planner_preset == "research"
    if explicit_plan is not None and planner_preset != "custom":
        raise ValueError("An explicit scan plan requires the custom preset")
    if (
        isinstance(description_budget, bool)
        or not isinstance(description_budget, int)
        or description_budget < 0
    ):
        raise ValueError("description_budget must be a nonnegative integer")
    if research_mode and request_budget is None:
        request_budget = 10_000
    configured_groups = (
        sorted({item.group for item in explicit_plan.values()})
        if explicit_plan is not None
        else list(range(0x100))
        if research_mode
        else sorted(GROUP_CONFIG)
    )
    start_perf = time.perf_counter()
    scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    static_constraints, static_constraints_source = load_default_b524_constraints_catalog()

    counting_transport = CountingTransport(transport, request_budget=request_budget)
    transport = counting_transport

    artifact: dict[str, Any] = {
        "schema_version": CURRENT_ARTIFACT_SCHEMA_VERSION,
        "meta": {
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": 0.0,
            "destination_address": _hex_u8(dst),
            "schema_sources": [],
            "incomplete": False,
            "artifact_contract": _artifact_contract_metadata(),
            "system_information": [],
            "scan_coverage": {
                "preset": planner_preset,
                "request_budget": request_budget,
                "exhaustive_wire_space": False,
                "scope": "explicit_selectors" if explicit_plan is not None else "declared_profile",
                "unknown_groups": [],
                "configured_groups": [_hex_u8(group) for group in configured_groups],
                "discovery_completed": False,
            },
        },
        "operations": {},
    }
    if ebusd_host is not None:
        artifact["meta"]["ebusd_host"] = ebusd_host
    if ebusd_port is not None:
        artifact["meta"]["ebusd_port"] = ebusd_port
    if static_constraints_source is not None:
        artifact["meta"]["constraint_catalog_source"] = static_constraints_source
        artifact["meta"]["constraint_catalog_entries"] = _constraint_catalog_entry_count(
            static_constraints
        )
    artifact["meta"]["constraint_scope"] = constraint_scope_metadata()
    artifact["meta"]["constraint_scope"]["qualification"] = "legacy_unqualified"

    incomplete_reason: str | None = None
    description_candidates: list[DescriptionCandidate] = []
    description_entries: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    description_coverage: dict[str, Any] = {}
    if explicit_plan is not None:
        artifact["meta"]["scan_plan"] = {
            "groups": _scan_plan_meta_groups(explicit_plan),
            "estimated_register_requests": estimate_register_requests(explicit_plan),
        }

    try:
        if observer is not None:
            observer.log(f"Starting scan dst={_hex_u8(dst)}", level="info")
            if planner_preset == "full":
                observer.log(
                    "Full preset selected: scan will expand known groups to full instance "
                    "slots independently of counts, with profile RR ranges.",
                    level="warn",
                )
            if research_mode:
                observer.log(
                    "Research preset selected: scan enables broader non-core and "
                    "underspecified fallback probing. Expect very long runs.",
                    level="warn",
                )
            if probe_constraints:
                observer.log(
                    "Targeted parameter descriptions enabled for observed writable parameters "
                    f"(OP01 system / OP07 device), bounded to {description_budget} requests.",
                    level="warn",
                )
        emit_trace_label(transport, f"Starting scan dst={_hex_u8(dst)}")

        group_discovery_requests = 0
        group_discovery_duration_s = 0.0
        instance_discovery_requests = 0
        instance_discovery_duration_s = 0.0

        if observer is not None:
            observer.phase_start("group_discovery", total=0x12)
        emit_trace_label(transport, "Reading System Information")
        group_discovery_start = time.perf_counter()
        group_discovery_start_calls = counting_transport.counters.send_calls
        discovered = discover_groups_fn(transport, dst=dst, observer=observer)

        information_values = {item.group: item.descriptor for item in discovered}
        information_raw = {item.group: item.raw_hex for item in discovered}
        artifact["meta"]["system_information"] = _system_information_records(
            information_values, information_raw
        )
        ventilation_count = information_values.get(16, float("nan"))
        ventilation_hint = (
            math.isfinite(ventilation_count)
            and ventilation_count.is_integer()
            and ventilation_count > 0
        )
        artifact["meta"]["profile_context"] = {
            "profile": "controller_b524",
            "api_version": information_values.get(6)
            if math.isfinite(information_values.get(6, float("nan")))
            else None,
            "api_revision": information_values.get(7)
            if math.isfinite(information_values.get(7, float("nan")))
            else None,
            "qualified_count_mappings": [
                {
                    "identifier": _hex_u16(identifier),
                    "read_opcode": _hex_u8(op),
                    "group": _hex_u8(gg),
                }
                for (op, gg), identifier in COUNT_GROUP_IDS.items()
            ],
            "feature_hints": {"ventilation": ventilation_hint},
            "other_count_routing": "unknown",
        }
        # OP00 identifiers are not groups. Register candidates come from the
        # explicit profile; research explores GG 00..FF by separate register probes.
        candidate_groups = configured_groups
        discovered = [DiscoveredGroup(group=gg, descriptor=float("nan")) for gg in candidate_groups]

        group_discovery_duration_s = time.perf_counter() - group_discovery_start
        group_discovery_requests = (
            counting_transport.counters.send_calls - group_discovery_start_calls
        )
        classified = classify_groups(discovered, observer=observer)
        unknown_descriptor_types = sorted(
            {
                float(group.descriptor)
                for group in classified
                if not math.isnan(group.descriptor)
                and float(group.descriptor) not in _KNOWN_DESCRIPTOR_TYPES
            }
        )
        if unknown_descriptor_types and observer is not None:
            descriptor_text = ", ".join(f"{value:g}" for value in unknown_descriptor_types)
            observer.log(
                "Found new descriptor class(es): "
                f"{descriptor_text}. Continue scan, then report with artifact JSON/HTML.",
                level="warn",
            )
        if observer is not None:
            observer.phase_finish("group_discovery")
            observer.log(f"Prepared {len(classified)} profile register candidates", level="info")

        # Phase B': establish scan coverage defaults from profile/fallback and
        # probe optional opcode 0x01 constraint dictionary (`01 GG RR`).
        metadata_map: dict[int, GroupMetadata] = {}
        constraint_map: dict[int, dict[int, ConstraintEntry]] = {}
        if observer is not None:
            observer.log("Deriving scan coverage defaults from known profiles", level="info")
        emit_trace_label(transport, "Deriving Scan Coverage")

        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            rr_max = int(config["rr_max"]) if config is not None else _UNKNOWN_GROUP_DEFAULT_RR_MAX
            ii_max = int(config["ii_max"]) if config is not None else _UNKNOWN_GROUP_DEFAULT_II_MAX

            source = "profile" if config is not None else "fallback"
            metadata_map[group.group] = GroupMetadata(
                rr_max=rr_max,
                ii_max=ii_max,
                source=source,
            )

        artifact["meta"]["parameter_description_policy"] = {
            "enabled": probe_constraints,
            "request_budget": description_budget,
            "system_description_opcode": "0x01",
            "device_description_opcode": "0x07",
            "scope": "observed_writable_complete_identity",
            "scheduler": "family_reservation_then_instance_round_robin",
            "unknown_codec_raw_evidence": True,
        }

        interactive = (
            console is not None
            and console.is_terminal
            and sys.stdin.isatty()
            and observer is not None
        )
        planner_mode = _resolve_planner_mode(
            interactive=interactive,
            planner_ui=planner_ui,
            observer=observer,
        )

        resolved_group_opcodes: dict[int, tuple[RegisterOpcode, ...]] = {}
        availability_group_opcodes: dict[int, tuple[RegisterOpcode, ...]] = {}
        unknown_opcode_probe_map: dict[int, dict[str, Any]] = {}
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if explicit_plan is not None:
                resolved_group_opcodes[group.group] = tuple(
                    sorted(
                        {
                            item.opcode
                            for item in explicit_plan.values()
                            if item.group == group.group
                        }
                    )
                )
                availability_group_opcodes[group.group] = ()
                continue
            if config is not None:
                resolved_group_opcodes[group.group] = profile_opcodes(group.group, planner_preset)
                availability_group_opcodes[group.group] = resolved_group_opcodes[group.group]
                continue

            opcodes, probe_summary = _probe_unknown_group_opcodes(
                transport,
                dst=dst,
                group=group.group,
                observer=observer,
                research=research_mode,
            )
            resolved_group_opcodes[group.group] = opcodes
            availability_group_opcodes[group.group] = opcodes
            unknown_opcode_probe_map[group.group] = probe_summary
            if not opcodes:
                artifact["meta"]["scan_coverage"]["unknown_groups"].append(_hex_u8(group.group))
            if observer is None:
                continue
            if opcodes:
                observer.log(
                    f"GG=0x{group.group:02X}: responsive opcode namespaces "
                    f"{', '.join(_hex_u8(opcode) for opcode in opcodes)}",
                    level="info",
                )
            else:
                observer.log(
                    f"GG=0x{group.group:02X}: no responsive opcode namespace detected; "
                    "group will be skipped unless planner overrides it.",
                    level="warn",
                )

        # (v2.3: dual_namespace tracking removed -- operations are top-level)
        responsive_unknown_groups = sorted(
            group.group
            for group in classified
            if group.group not in GROUP_CONFIG and resolved_group_opcodes.get(group.group, ())
        )
        if responsive_unknown_groups and observer is not None:
            unknown_text = ", ".join(f"0x{gg:02X}" for gg in responsive_unknown_groups)
            observer.log(
                f"Found {len(responsive_unknown_groups)} unknown groups ({unknown_text}); "
                "deriving namespace coverage from opcode responsiveness probes.",
                level="warn",
            )
        if responsive_unknown_groups or unknown_descriptor_types:
            advisory: dict[str, Any] = {
                "kind": "protocol_discovery",
                "suggest_issue": True,
                "attach_artifacts": ["scan_json", "scan_html"],
            }
            if responsive_unknown_groups:
                advisory["unknown_groups"] = [
                    f"0x{group:02X}" for group in responsive_unknown_groups
                ]
            if unknown_descriptor_types:
                advisory["unknown_descriptor_types"] = unknown_descriptor_types
            artifact["meta"]["issue_suggestion"] = advisory

        for group in classified:
            meta = metadata_map[group.group]
            opcodes = availability_group_opcodes.get(group.group, ())
            multi_op = len(opcodes) > 1
            # NaN descriptors come from synthetic research-mode injection;
            # store as None to keep JSON-serializable and avoid polluting analytics.
            desc_for_artifact = None if math.isnan(group.descriptor) else group.descriptor
            discovery_advisory: dict[str, Any] = {
                "kind": "profile_register_candidate",
                "semantic_authority": False,
                "proven_register_opcodes": [_hex_u8(opcode) for opcode in opcodes],
            }
            if group.group in unknown_opcode_probe_map:
                discovery_advisory["opcode_probe"] = unknown_opcode_probe_map[group.group]
            discovery_advisory["instance_discovery_decision"] = _instance_discovery_decision(
                group=group.group,
                multi_op=multi_op,
            )
            if desc_for_artifact is not None:
                discovery_advisory["descriptor_observed"] = desc_for_artifact
            if group.expected_descriptor is not None:
                discovery_advisory["descriptor_expected"] = group.expected_descriptor
            if group.descriptor_mismatch:
                discovery_advisory["descriptor_mismatch"] = True
            for opcode in opcodes:
                artifact_group_name = _group_name_for_opcode(group.group, opcode)
                namespace_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=opcode,
                )
                _ensure_group_artifact(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    name=artifact_group_name,
                    descriptor_observed=desc_for_artifact,
                    ii_max=namespace_ii_max,
                    discovery_advisory=discovery_advisory,
                )

        instance_targets = _instance_discovery_targets(
            classified,
            metadata_map,
            availability_group_opcodes,
        )

        # Phase C: instance discovery (groups with ii_max > 0 only).
        instance_total = 0
        for group, meta, opcode in instance_targets:
            if GROUP_CONFIG.get(group.group) is None:
                candidate_instances = (
                    _UNKNOWN_GROUP_EXPANDED_INSTANCES
                    if research_mode
                    else _UNKNOWN_GROUP_INITIAL_INSTANCES
                )
                instance_total += len(candidate_instances)
                continue
            namespace_ii_max = _ii_max_for_opcode(
                group=group.group,
                default_ii_max=meta.ii_max,
                opcode=opcode,
            )
            if _is_instanced_group(namespace_ii_max):
                assert namespace_ii_max is not None
                instance_total += namespace_ii_max + 1
        if observer is not None:
            observer.phase_start("instance_discovery", total=instance_total or 1)

        instance_discovery_start = time.perf_counter()
        instance_discovery_start_calls = counting_transport.counters.send_calls
        known_namespace_probe_counts: dict[int, list[str]] = {}
        unknown_namespace_probe_counts: dict[int, list[str]] = {}
        for group, meta, opcode in instance_targets:
            rr_max = meta.rr_max
            config = GROUP_CONFIG.get(group.group)

            if config is None:
                total_slots = len(_UNKNOWN_GROUP_EXPANDED_INSTANCES)
                namespace_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=opcode,
                )
                _record_namespace_topology(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    ii_max=namespace_ii_max,
                )
                instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
                emit_trace_label(
                    transport,
                    "Exploring unknown group "
                    f"0x{group.group:02X} ({opcode_label(opcode)}) "
                    "across multiple instances",
                )
                present_instances = _probe_unknown_present_instances(
                    transport,
                    dst=dst,
                    group=group.group,
                    opcode=opcode,
                    observer=observer,
                    expand_fallback=research_mode,
                )
                _mark_present_instances(instances_obj, instances=present_instances)
                unknown_namespace_probe_counts.setdefault(group.group, []).append(
                    f"{opcode_label(opcode)} {len(present_instances)}/{total_slots}"
                )
                continue

            namespace_ii_max = _ii_max_for_opcode(
                group=group.group,
                default_ii_max=meta.ii_max,
                opcode=opcode,
            )
            _record_namespace_topology(
                artifact,
                group=group.group,
                opcode=opcode,
                ii_max=namespace_ii_max,
            )
            contract = namespace_availability_contract(group=group.group, opcode=opcode)
            instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
            if _is_instanced_group(namespace_ii_max):
                _record_availability_contract(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    contract=contract,
                )
            if not _is_instanced_group(namespace_ii_max):
                _mark_present_instances(instances_obj, instances=(0x00,))
                known_namespace_probe_counts.setdefault(group.group, []).append(
                    f"{_group_name_for_opcode(group.group, opcode)} [{opcode_label(opcode)}] 1/1"
                )
                continue

            assert namespace_ii_max is not None
            emit_trace_label(
                transport,
                f"Identifying instances in group 0x{group.group:02X} ({opcode_label(opcode)})",
            )
            probes = _probe_present_instances(
                transport,
                dst=dst,
                group=group.group,
                opcode=opcode,
                ii_max=namespace_ii_max,
                observer=observer,
                probe_instance_availability_fn=probe_instance_availability_fn,
                expected_count=(
                    expected_instance_count(
                        information_values.get(
                            COUNT_GROUP_IDS.get((int(opcode), group.group), -1), float("nan")
                        ),
                        capacity=namespace_ii_max + 1,
                    )
                    if planner_preset == "recommended"
                    else None
                ),
            )
            _record_availability_probes(
                artifact,
                group=group.group,
                opcode=opcode,
                probes=probes,
            )
            present_instances = tuple(ii for ii, probe in probes.items() if probe.present)
            count_id = COUNT_GROUP_IDS.get((int(opcode), group.group))
            if count_id is not None:
                expected = expected_instance_count(
                    information_values.get(count_id, float("nan")), capacity=namespace_ii_max + 1
                )
                artifact["meta"].setdefault("instance_counts", {})[
                    f"{_hex_u8(opcode)}:{_hex_u8(group.group)}"
                ] = {
                    "identifier": _hex_u16(count_id),
                    "expected": expected,
                    "observed": len(present_instances),
                    "mismatch": expected is not None and expected != len(present_instances),
                    "probed_instances": len(probes),
                }
            _mark_present_instances(instances_obj, instances=present_instances)
            known_namespace_probe_counts.setdefault(group.group, []).append(
                f"{_group_name_for_opcode(group.group, opcode)} "
                f"[{opcode_label(opcode)}] "
                f"{len(present_instances)}/{namespace_ii_max + 1}"
            )

        if observer is not None:
            for group in classified:
                rr_max = metadata_map[group.group].rr_max
                unknown_counts = unknown_namespace_probe_counts.get(group.group)
                if unknown_counts:
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: "
                        f"{', '.join(unknown_counts)} present (experimental), "
                        f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)",
                        level="info",
                    )
                    continue
                known_counts = known_namespace_probe_counts.get(group.group)
                if known_counts:
                    observer.log(
                        f"GG=0x{group.group:02X}: "
                        f"{', '.join(known_counts)} present, "
                        f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)",
                        level="info",
                    )

        if observer is not None:
            observer.phase_finish("instance_discovery")
        instance_discovery_duration_s = time.perf_counter() - instance_discovery_start
        instance_discovery_requests = (
            counting_transport.counters.send_calls - instance_discovery_start_calls
        )
        artifact["meta"]["scan_coverage"]["discovery_completed"] = True

        # Interactive scan planner (TTY only): allow users to trim the register scan scope.
        plan: dict[PlanKey, GroupScanPlan] = {}
        for group in classified:
            meta = metadata_map[group.group]
            for opcode in resolved_group_opcodes.get(group.group, ()):
                namespace_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=opcode,
                )
                present_instances = _present_instances_for_opcode(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                )
                plan[_plan_key(group.group, opcode)] = GroupScanPlan(
                    group=group.group,
                    opcode=opcode,
                    rr_max=_rr_max_for_opcode(
                        group=group.group,
                        default_rr_max=meta.rr_max,
                        opcode=opcode,
                    ),
                    instances=(
                        (0x00,) if not _is_instanced_group(namespace_ii_max) else present_instances
                    ),
                )

        measured_requests = group_discovery_requests + instance_discovery_requests
        measured_duration_s = group_discovery_duration_s + instance_discovery_duration_s
        request_rate_rps: float | None = None
        if measured_requests > 0 and measured_duration_s > 0:
            request_rate_rps = measured_requests / measured_duration_s

        planner_groups: list[PlannerGroup] = []
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            group_meta = metadata_map[group.group]
            resolved_opcodes = resolved_group_opcodes.get(group.group, ())
            opcodes = resolved_opcodes
            if not opcodes:
                continue
            multi_op = len(opcodes) > 1
            for opcode in opcodes:
                requested_plan = (
                    explicit_plan.get(_plan_key(group.group, opcode))
                    if explicit_plan is not None
                    else None
                )
                planner_ii_max = _planner_ii_max(
                    _ii_max_for_opcode(
                        group=group.group,
                        default_ii_max=group_meta.ii_max,
                        opcode=opcode,
                    )
                )
                present_instances = _present_instances_for_opcode(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                )
                if requested_plan is not None:
                    present_instances = requested_plan.instances
                    planner_ii_max = max(requested_plan.instances) or None
                if planner_ii_max is None and not present_instances:
                    present_instances = (0x00,)
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        opcode=opcode,
                        name=_group_name_for_opcode(group.group, opcode),
                        descriptor=group.descriptor,
                        known=config is not None,
                        ii_max=planner_ii_max,
                        rr_max=requested_plan.rr_max
                        if requested_plan is not None
                        else _rr_max_for_opcode(
                            group=group.group,
                            default_rr_max=group_meta.rr_max,
                            opcode=opcode,
                        ),
                        rr_max_full=_rr_max_full_for_opcode(
                            group=group.group,
                            opcode=opcode,
                        ),
                        present_instances=present_instances,
                        expected_count=(
                            expected_instance_count(
                                information_values.get(
                                    COUNT_GROUP_IDS.get((int(opcode), group.group), -1),
                                    float("nan"),
                                ),
                                capacity=planner_ii_max + 1,
                            )
                            if planner_ii_max is not None
                            else None
                        ),
                        namespace_label=(opcode_label(opcode) if multi_op else None),
                        recommended=_planner_group_is_recommended(
                            group=group.group,
                            opcode=opcode,
                        ),
                    )
                )

        if planner_preset != "custom":
            plan = build_plan_from_preset(
                planner_groups,
                preset=planner_preset,
            )
        elif explicit_plan is not None:
            plan = dict(explicit_plan)

        if planner_mode != "disabled" and console is not None and observer is not None:
            with observer.suspend():
                planner_default_plan = dict(plan)
                if planner_mode == "textual":
                    try:
                        from ..ui.planner_textual import run_textual_scan_plan
                    except Exception as exc:
                        if planner_ui == "textual":
                            raise RuntimeError(
                                "Textual planner requested but unavailable."
                            ) from exc
                        observer.log(
                            "Textual planner unavailable; falling back to classic planner.",
                            level="warn",
                        )
                        planner_mode = "classic"
                    else:
                        try:
                            selected = run_textual_scan_plan(
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=planner_default_plan,
                                default_preset=planner_preset,
                            )
                        except Exception as exc:
                            if planner_ui == "textual":
                                raise RuntimeError(
                                    "Textual planner requested but failed to start."
                                ) from exc
                            observer.log(
                                "Textual planner failed to start; falling back to classic planner.",
                                level="warn",
                            )
                            planner_mode = "classic"
                        else:
                            if selected is None:
                                raise KeyboardInterrupt
                            plan = selected
                if planner_mode == "classic":
                    plan = prompt_scan_plan_fn(
                        console,
                        planner_groups,
                        request_rate_rps=request_rate_rps,
                        default_plan=planner_default_plan,
                        default_preset=planner_preset,
                    )

        artifact["meta"]["scan_plan"] = {
            "groups": _scan_plan_meta_groups(plan),
            "estimated_register_requests": estimate_register_requests(plan),
            "measured_request_rate_rps": round(request_rate_rps, 4) if request_rate_rps else None,
        }
        artifact["meta"]["group_metadata_bounds"] = _metadata_map_to_dict(metadata_map)
        artifact["meta"]["constraint_probe_enabled"] = False
        artifact["meta"]["parameter_description_requests"] = 0
        artifact["meta"]["constraint_dictionary"] = _constraint_map_to_dict(constraint_map)
        constraint_mismatches: list[dict[str, Any]] = []

        # Phase D: register scan (supports interactive replanning).
        done: set[RegisterTask] = set()
        work_queue = deque(build_work_queue(plan, done=done))
        if observer is not None:
            observer.phase_start("register_scan", total=len(work_queue) or 1)
        emit_trace_label(transport, "Register Scan")

        active_start = time.perf_counter()
        active_elapsed = 0.0

        with hotkey_reader_cls(enabled=(planner_mode != "disabled")) as hotkeys:
            while work_queue:
                if (
                    planner_mode != "disabled"
                    and console is not None
                    and observer is not None
                    and hotkeys.poll()
                ):
                    # Pause progress rendering and allow replanning without rewriting scanned data.
                    active_elapsed += time.perf_counter() - active_start
                    with hotkeys.suspend(), observer.suspend():
                        if planner_mode == "textual":
                            try:
                                from ..ui.planner_textual import run_textual_scan_plan
                            except Exception as exc:
                                if planner_ui == "textual":
                                    raise RuntimeError(
                                        "Textual planner requested but unavailable."
                                    ) from exc
                                observer.log(
                                    "Textual planner unavailable; falling back to classic planner.",
                                    level="warn",
                                )
                                planner_mode = "classic"
                            else:
                                try:
                                    selected = run_textual_scan_plan(
                                        planner_groups,
                                        request_rate_rps=request_rate_rps,
                                        default_plan=plan,
                                        default_preset=planner_preset,
                                    )
                                except Exception as exc:
                                    if planner_ui == "textual":
                                        raise RuntimeError(
                                            "Textual planner requested but failed to start."
                                        ) from exc
                                    observer.log(
                                        "Textual planner failed to start; "
                                        "falling back to classic planner.",
                                        level="warn",
                                    )
                                    planner_mode = "classic"
                                else:
                                    if selected is None:
                                        raise KeyboardInterrupt
                                    plan = selected
                        if planner_mode == "classic":
                            plan = prompt_scan_plan_fn(
                                console,
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=plan,
                                default_preset=planner_preset,
                            )
                    artifact["meta"]["scan_plan"]["groups"] = _scan_plan_meta_groups(plan)
                    artifact["meta"]["scan_plan"]["estimated_register_requests"] = (
                        estimate_register_requests(plan)
                    )
                    work_queue = deque(build_work_queue(plan, done=done))
                    observer.phase_set_total(
                        "register_scan",
                        total=(len(done) + len(work_queue)) or 1,
                    )
                    remaining = len(work_queue)
                    task_rate_rps = (len(done) / active_elapsed) if active_elapsed > 0 else None
                    if task_rate_rps is None or task_rate_rps <= 0:
                        observer.log(
                            f"Updated scan plan: remaining {remaining} register reads",
                            level="info",
                        )
                    else:
                        eta_s = remaining / task_rate_rps if remaining > 0 else 0.0
                        observer.log(
                            f"Updated scan plan: remaining {remaining} register reads "
                            f"(ETA {eta_s:.1f}s @ {task_rate_rps:.2f} rr/s)",
                            level="info",
                        )
                    active_start = time.perf_counter()
                    continue

                task = work_queue.popleft()
                if observer is not None:
                    observer.status(
                        "Read "
                        f"GG=0x{task.group:02X} "
                        f"II=0x{task.instance:02X} "
                        f"RR=0x{task.register:04X}"
                    )
                    observer.phase_advance("register_scan", advance=1)

                schema_entry = (
                    ebusd_schema.lookup(
                        opcode=task.opcode,
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                    )
                    if ebusd_schema is not None
                    else None
                )
                myvaillant_entry = (
                    myvaillant_map.lookup(
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                        opcode=task.opcode,
                    )
                    if myvaillant_map is not None
                    else None
                )
                type_hint = (
                    myvaillant_entry.type_hint
                    if myvaillant_entry is not None and myvaillant_entry.type_hint is not None
                    else (schema_entry.type_spec if schema_entry is not None else None)
                )

                entry = read_register(
                    transport,
                    dst,
                    task.opcode,
                    group=task.group,
                    instance=task.instance,
                    register=task.register,
                    type_hint=type_hint,
                )
                if schema_entry is not None:
                    entry["ebusd_name"] = schema_entry.name
                if myvaillant_map is not None:
                    lookup_opcode: int | None = None
                    read_opcode = entry.get("read_opcode")
                    if isinstance(read_opcode, str):
                        try:
                            lookup_opcode = int(read_opcode, 0)
                        except ValueError:
                            lookup_opcode = None
                    mv = myvaillant_map.lookup(
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                        opcode=lookup_opcode,
                    )
                    if mv is not None:
                        entry["myvaillant_name"] = mv.leaf
                        if mv.register_class is not None:
                            entry["register_class"] = mv.register_class
                        if entry.get("ebusd_name") is None:
                            mapped_ebusd_name = mv.resolved_ebusd_name(
                                group=task.group,
                                instance=task.instance,
                                register=task.register,
                            )
                            if mapped_ebusd_name:
                                entry["ebusd_name"] = mapped_ebusd_name

                constraint = _constraint_for_register(
                    opcode=task.opcode,
                    group=task.group,
                    instance=task.instance,
                    register=task.register,
                    live_constraints=constraint_map,
                    static_constraints=static_constraints,
                )
                if constraint is not None:
                    _apply_constraint_metadata(entry, constraint)
                    mismatch_reason = _constraint_mismatch_reason(entry, constraint)
                    if mismatch_reason is not None:
                        entry["constraint_mismatch_reason"] = mismatch_reason
                        constraint_mismatches.append(
                            {
                                "group": _hex_u8(task.group),
                                "instance": _hex_u8(task.instance),
                                "register": _hex_u16(task.register),
                                "read_opcode": str(entry.get("read_opcode")),
                                "name": entry.get("myvaillant_name") or entry.get("ebusd_name"),
                                "value": entry.get("value"),
                                "constraint_min": constraint.min_value,
                                "constraint_max": constraint.max_value,
                                "constraint_type": constraint.kind,
                                "constraint_source": constraint.source,
                                "constraint_scope": constraint.scope,
                                "constraint_provenance": constraint.provenance,
                                "constraint_probe_protocol": CONSTRAINT_SCOPE_PROTOCOL,
                                "reason": mismatch_reason,
                            }
                        )
                flags_value = entry.get("flags")
                if (
                    isinstance(flags_value, int)
                    and flags_value in {0, 1, 2, 3}
                    and entry.get("response_state") == "active"
                ):
                    entry["writable"] = bool(flags_value & 2)
                    entry["visible"] = bool(flags_value & 1)
                if probe_constraints and entry.get("response_state") == "active":
                    flags = entry.get("flags")
                    type_spec = entry.get("type")
                    if isinstance(flags, int) and flags in {2, 3}:
                        identity = (int(task.opcode), task.group, task.instance, task.register)
                        description_candidates.append(
                            DescriptionCandidate(
                                *identity, type_spec if isinstance(type_spec, str) else None
                            )
                        )
                        description_entries[identity] = cast(dict[str, Any], entry)
                        entry["parameter_description"] = {
                            "qualification": "unavailable",
                            "reason": "description acquisition pending",
                        }
                if task.opcode == 2 and task.group == 9 and ventilation_hint:
                    ventilation_names = {
                        2: "operating_mode_for_air_ventilation",
                        4: "status_special_function_ventilation",
                        7: "holiday_end",
                        8: "holiday_end_time",
                        9: "holiday_start",
                        10: "holiday_start_time",
                        13: "day_maximum_fan_stage",
                        14: "night_maximum_fan_stage",
                    }
                    if task.register in ventilation_names:
                        entry["candidate_name"] = ventilation_names[task.register]
                        entry["candidate_evidence"] = (
                            "profile_scoped_reconstruction_recovair_count_nonzero"
                        )
                done.add(task)

                _ensure_group_artifact(
                    artifact,
                    group=task.group,
                    opcode=task.opcode,
                    name="Unknown",
                    descriptor_observed=0.0,
                )
                task_group_meta = metadata_map.get(task.group)
                if task_group_meta is not None:
                    _record_namespace_topology(
                        artifact,
                        group=task.group,
                        opcode=task.opcode,
                        ii_max=_ii_max_for_opcode(
                            group=task.group,
                            default_ii_max=task_group_meta.ii_max,
                            opcode=task.opcode,
                        ),
                    )
                instances_obj = _instances_object(
                    artifact,
                    group=task.group,
                    opcode=task.opcode,
                )
                instance_key = _hex_u8(task.instance)
                instance_obj = instances_obj.setdefault(instance_key, {"present": False})
                if isinstance(instance_obj, dict):
                    registers = instance_obj.setdefault("registers", {})
                    registers[_hex_u16(task.register)] = entry

        if probe_constraints:
            acquire_descriptions(
                transport,
                dst=dst,
                candidates=description_candidates,
                entries=description_entries,
                budget=description_budget,
                coverage=description_coverage,
                observer=observer,
            )
        _apply_contextual_enum_annotations(artifact)
        if constraint_mismatches:
            artifact["meta"]["constraint_mismatches"] = constraint_mismatches
            artifact["meta"]["constraint_rescan_recommended"] = True
            if observer is not None:
                observer.log(
                    "Observed register values outside the scoped bundled static "
                    "constraint catalog. Review meta.constraint_mismatches and rerun "
                    "with --probe-constraints if you want live confirmation.",
                    level="warn",
                )

        if observer is not None:
            observer.phase_finish("register_scan")

    except KeyboardInterrupt:
        artifact["meta"]["incomplete"] = True
        incomplete_reason = "user_interrupt"
    except ScanRequestBudgetExceeded as exc:
        artifact["meta"]["incomplete"] = True
        incomplete_reason = "request_budget_exhausted"
        artifact["meta"]["budget_boundary_evidence"] = list(counting_transport.recent_requests)
        if exc.system_information:
            artifact["meta"]["system_information"] = _system_information_records(
                {identifier: value for identifier, value, _ in exc.system_information},
                {identifier: raw for identifier, _, raw in exc.system_information},
            )

    if probe_constraints:
        finish_description_coverage(
            description_candidates,
            description_entries,
            budget=description_budget,
            coverage=description_coverage,
        )
    artifact["meta"]["parameter_description_coverage"] = description_coverage
    artifact["meta"]["parameter_description_requests"] = description_coverage.get("attempted", 0)
    artifact["meta"]["scan_coverage"]["actual_requests"] = counting_transport.counters.send_calls
    artifact["meta"]["scan_coverage"]["completed"] = not artifact["meta"]["incomplete"]
    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason

    return artifact
