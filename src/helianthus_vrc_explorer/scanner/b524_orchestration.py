"""Private orchestration for the B524 scanner facade."""

from __future__ import annotations

import math
import sys
import time
from collections import deque
from datetime import UTC, datetime
from typing import Any

from rich.console import Console

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..protocol.b524 import RegisterOpcode
from ..schema.b524_constraints import (
    CONSTRAINT_SCOPE_PROTOCOL,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
)
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..transport.base import TransportInterface, emit_trace_label
from ..transport.instrumented import CountingTransport
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
    _group_opcodes,
    _ii_max_for_opcode,
    _instance_discovery_decision,
    _instance_discovery_targets,
    _is_instanced_group,
    _normalize_planner_preset,
    _plan_key,
    _planner_group_is_recommended,
    _planner_ii_max,
    _planner_source_opcodes,
    _rr_max_for_opcode,
    _rr_max_full_for_opcode,
    _scan_plan_meta_groups,
    _sorted_namespace_opcodes,
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
    _probe_group_constraints,
    _probe_present_instances,
    _probe_unknown_group_opcodes,
    _probe_unknown_present_instances,
)
from .director import GROUP_CONFIG, DiscoveredGroup, classify_groups
from .plan import GroupScanPlan, PlanKey, RegisterTask, build_work_queue, estimate_register_requests
from .register import namespace_availability_contract, namespace_opcodes_for_group, read_register
from .scan import (
    _UNKNOWN_GROUP_DEFAULT_II_MAX,
    _UNKNOWN_GROUP_DEFAULT_RR_MAX,
    _UNKNOWN_GROUP_EXPANDED_INSTANCES,
    _UNKNOWN_GROUP_INITIAL_INSTANCES,
    ScanObserver,
    _apply_contextual_enum_annotations,
    _resolve_planner_mode,
)


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
    probe_constraints: bool = False,
    discover_groups_fn: Any,
    prompt_scan_plan_fn: Any,
    hotkey_reader_cls: Any,
    probe_instance_availability_fn: Any,
) -> dict[str, Any]:
    """Scan a VRC regulator using B524 and return a JSON-serializable artifact.

    Implements the four-phase scan algorithm:
    - Phase A: group discovery via directory probes
    - Phase B: group classification via GROUP_CONFIG
    - Phase C: instance discovery for groups whose configured ii_max is > 0
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """

    planner_preset = _normalize_planner_preset(planner_preset)
    research_mode = planner_preset == "research"
    start_perf = time.perf_counter()
    scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    static_constraints, static_constraints_source = load_default_b524_constraints_catalog()

    counting_transport = CountingTransport(transport)
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

    incomplete_reason: str | None = None

    try:
        if observer is not None:
            observer.log(f"Starting scan dst={_hex_u8(dst)}", level="info")
            if planner_preset == "full":
                observer.log(
                    "Full preset selected: scan will expand known groups to full instance "
                    "slots and RR ranges.",
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
                    "Live opcode 0x01 constraint probing enabled. This is research-only and "
                    "can add hundreds of extra runtime requests; default scans already use the "
                    "bundled static BASV2 constraint catalog.",
                    level="warn",
                )
        emit_trace_label(transport, f"Starting scan dst={_hex_u8(dst)}")

        group_discovery_requests = 0
        group_discovery_duration_s = 0.0
        instance_discovery_requests = 0
        instance_discovery_duration_s = 0.0

        if observer is not None:
            observer.phase_start("group_discovery", total=0x100)
        emit_trace_label(transport, "Discovering Groups")
        group_discovery_start = time.perf_counter()
        group_discovery_start_calls = counting_transport.counters.send_calls
        discovered = discover_groups_fn(transport, dst=dst, observer=observer)

        # Exhaustive mode: inject synthetic DiscoveredGroup entries for any GG in
        # 0x00..0x11 not already found by directory probing.
        if research_mode:
            discovered_ggs = {dg.group for dg in discovered}
            for gg in range(0x00, 0x12):
                if gg not in discovered_ggs:
                    # Use NaN as the synthetic descriptor so downstream analytics
                    # (unknown_descriptor_types, issue_suggestion) skip it instead
                    # of recording a fake 0.0 observation.
                    discovered.append(DiscoveredGroup(group=gg, descriptor=float("nan")))
                    if observer is not None:
                        observer.log(
                            f"Exhaustive: injected synthetic group GG=0x{gg:02X}",
                            level="info",
                        )

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
            observer.log(f"Discovered {len(classified)} groups", level="info")

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

        if probe_constraints:
            if observer is not None:
                observer.log("Probing opcode 0x01 constraint dictionary", level="info")
            emit_trace_label(transport, "Constraint Dictionary Probe")

            probe_total = 0
            for group in classified:
                group_meta = metadata_map[group.group]
                rr_max = min(group_meta.rr_max, 0xFF)
                probe_total += rr_max + 1
                if rr_max < 0x80:
                    probe_total += 1
            if observer is not None:
                observer.log(
                    f"Live constraint probe will add up to {probe_total} extra requests.",
                    level="warn",
                )
                observer.phase_start("constraint_probe", total=probe_total or 1)

            try:
                for group in classified:
                    group_meta = metadata_map[group.group]
                    constraints = _probe_group_constraints(
                        transport,
                        dst=dst,
                        group=group.group,
                        rr_max=group_meta.rr_max,
                        observer=observer,
                        progress_phase="constraint_probe",
                    )
                    if constraints:
                        constraint_map[group.group] = constraints
            except KeyboardInterrupt:
                # VE32: Preserve partial constraint results, then re-raise
                # so the outer handler sets meta.incomplete=true.
                if observer is not None:
                    observer.log(
                        "Constraint probe interrupted — partial results preserved.",
                        level="warn",
                    )
                raise
            if observer is not None:
                observer.phase_finish("constraint_probe")
                if not constraint_map:
                    observer.log(
                        "Live constraint probe decoded no entries; using bundled static "
                        "constraint catalog only.",
                        level="warn",
                    )
        elif observer is not None:
            observer.log(
                "Skipping live opcode 0x01 constraint probe (using bundled static "
                "constraint catalog).",
                level="info",
            )

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
            if config is not None:
                resolved_group_opcodes[group.group] = _group_opcodes(group.group)
                availability_group_opcodes[group.group] = (
                    _sorted_namespace_opcodes(namespace_opcodes_for_group(group.group))
                    if planner_mode != "disabled"
                    else resolved_group_opcodes[group.group]
                )
                continue

            opcodes, probe_summary = _probe_unknown_group_opcodes(
                transport,
                dst=dst,
                group=group.group,
                observer=observer,
            )
            resolved_group_opcodes[group.group] = opcodes
            availability_group_opcodes[group.group] = opcodes
            unknown_opcode_probe_map[group.group] = probe_summary
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
                "kind": "directory_probe",
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
            )
            _record_availability_probes(
                artifact,
                group=group.group,
                opcode=opcode,
                probes=probes,
            )
            present_instances = tuple(ii for ii, probe in probes.items() if probe.present)
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
            if planner_mode != "disabled":
                opcodes = _planner_source_opcodes(group.group)
            if not opcodes:
                continue
            multi_op = len(opcodes) > 1
            for opcode in opcodes:
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
                        rr_max=_rr_max_for_opcode(
                            group=group.group,
                            default_rr_max=group_meta.rr_max,
                            opcode=opcode,
                        ),
                        rr_max_full=_rr_max_full_for_opcode(
                            group=group.group,
                            opcode=opcode,
                        ),
                        present_instances=present_instances,
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
        artifact["meta"]["constraint_probe_enabled"] = probe_constraints
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

    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason

    return artifact
