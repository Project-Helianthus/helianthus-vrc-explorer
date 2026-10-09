"""Private orchestration for the B524 scanner facade."""

from __future__ import annotations

import inspect
import math
import sys
import time
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, cast

from rich.console import Console

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..protocol.b524 import RegisterOpcode
from ..protocol.b524_metadata import (
    CAPACITY_SYSTEM_INFORMATION_IDS,
    COUNT_GROUP_IDS,
    SYSTEM_INFORMATION_NAMES,
    expected_instance_count,
    module_capacity_crosscheck,
    supported_capacity,
)
from ..protocol.b524_schedules import EventProfileName
from ..schema.b524_constraints import (
    CONSTRAINT_SCOPE_PROTOCOL,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
)
from ..schema.b524_register_names import b524_register_name
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..schema.parameter_descriptions import description_catalog_status
from ..transport.base import TransportInterface, TransportRecoveryExhausted, emit_trace_label
from ..transport.instrumented import CountingTransport, ScanRequestBudgetExceeded
from ..ui.planner import PlannerGroup, PlannerPreset, build_plan_from_preset
from ..ui.planner_selection import (
    DescriptionPolicySelection,
    PlannerSelection,
    default_description_policy,
    description_probe_required,
)
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
from .b524_default_events import DEFAULT_EVENT_WEEKDAY_CODES, build_default_event_requests
from .b524_operation_reads import (
    B524OperationReadRequest,
    acquire_operation_reads,
    record_operation_read_observation,
    validate_operation_read_identity,
)
from .b524_plan import (
    _KNOWN_DESCRIPTOR_TYPES,
    PlannerUiMode,
    _group_name_for_opcode,
    _ii_max_for_opcode,
    _ii_min_for_opcode,
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
    _sorted_namespace_opcodes,
    opcode_label,
    planner_native_opcodes,
    planner_rr_max,
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
    _unknown_instance_candidates,
)
from .description_acquisition import acquire_descriptions, finish_description_coverage
from .description_scheduler import DescriptionCandidate
from .director import GROUP_CONFIG, DiscoveredGroup, classify_groups
from .plan import GroupScanPlan, PlanKey, RegisterTask, build_work_queue, estimate_register_requests
from .register import (
    CONNECTED_DEVICE_GROUPS,
    InstanceAvailabilityProbe,
    namespace_availability_contract,
    read_register,
)
from .scan import (
    _UNKNOWN_GROUP_DEFAULT_II_MAX,
    _UNKNOWN_GROUP_DEFAULT_RR_MAX,
    ScanObserver,
    _apply_contextual_enum_annotations,
    _resolve_planner_mode,
)
from .scan_policy import profile_opcodes


def _planner_kwargs(planner_fn: Any, options: dict[str, Any]) -> dict[str, Any]:
    """Keep injected legacy planner fakes readable while passing typed UI state."""

    try:
        parameters = inspect.signature(planner_fn).parameters.values()
    except (TypeError, ValueError):
        return options
    if any(parameter.kind == inspect.Parameter.VAR_KEYWORD for parameter in parameters):
        return options
    accepted = {parameter.name for parameter in parameters}
    return {name: value for name, value in options.items() if name in accepted}


def _normalize_profile_plan_instances(
    plan: dict[PlanKey, GroupScanPlan],
    *,
    profile_id: str | None = None,
) -> dict[PlanKey, GroupScanPlan]:
    """Apply default-profile instance domains without changing custom plans."""

    normalized: dict[PlanKey, GroupScanPlan] = {}
    for key, group_plan in plan.items():
        instances = group_plan.instances
        if group_plan.opcode == 0x06:
            instances = tuple(ii for ii in instances if 0x01 <= ii <= 0x08)
        elif group_plan.opcode == 0x02 and group_plan.group == 0x02:
            first = 0x00 if profile_id == "basv2_sw0507_hw1704_api1" else 0x01
            instances = tuple(ii for ii in instances if first <= ii <= 0x09)
        normalized[key] = GroupScanPlan(
            group=group_plan.group,
            opcode=group_plan.opcode,
            rr_max=group_plan.rr_max,
            instances=instances,
            registers=group_plan.registers,
        )
    return normalized


def _select_live_description_candidates(
    artifact: dict[str, Any],
    candidates: list[DescriptionCandidate],
    entries: dict[tuple[int, int, int, int], dict[str, Any]],
    *,
    policy: DescriptionPolicySelection,
) -> tuple[
    list[DescriptionCandidate],
    dict[tuple[int, int, int, int], dict[str, Any]],
    list[dict[str, Any]],
]:
    """Apply policy after scalar reads reveal each remote native identity."""

    selected: list[DescriptionCandidate] = []
    selected_entries: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    status_cache: dict[tuple[int, int, int], dict[str, Any]] = {}
    for candidate in candidates:
        device_key = (
            candidate.read_opcode,
            candidate.group if candidate.read_opcode == 0x06 else 0,
            candidate.instance if candidate.read_opcode == 0x06 else 0,
        )
        status = status_cache.get(device_key)
        if status is None:
            selector = {
                "read_opcode": f"0x{candidate.read_opcode:02x}",
                "group": f"0x{candidate.group:02x}",
                "instance": f"0x{candidate.instance:02x}",
                "register": f"0x{candidate.register:04x}",
            }
            status = description_catalog_status(artifact, selector)
            status_cache[device_key] = status
        if not (
            description_probe_required(policy, opcode=candidate.read_opcode)
            or status.get("status") != "exact"
        ):
            continue
        identity = (
            candidate.read_opcode,
            candidate.group,
            candidate.instance,
            candidate.register,
        )
        selected.append(candidate)
        selected_entries[identity] = entries[identity]

    remote_statuses = [
        {
            "group": f"0x{group:02x}",
            "instance": f"0x{instance:02x}",
            **status,
        }
        for (opcode, group, instance), status in sorted(status_cache.items())
        if opcode == 0x06
    ]
    return selected, selected_entries, remote_statuses


def _count_capacity(*, group: int, opcode: int, ii_max: int, profile_id: str | None = None) -> int:
    """Return the count-qualified slots for one OP00 family mapping."""

    if (opcode, group) == (0x02, 0x09):
        return 1
    if (opcode, group) == (0x02, 0x02):
        return ii_max if profile_id == "basv2_sw0507_hw1704_api1" else ii_max - 1
    return ii_max + (opcode != 0x06)


def _system_information_records(
    values: dict[int, float],
    raw: dict[int, str | None],
    diagnostics: dict[int, dict[str, str | int | None]] | None = None,
) -> list[dict[str, Any]]:
    return [
        {
            **(
                {"transport_diagnostic": diagnostics[identifier], "qualification": "unknown"}
                if diagnostics and identifier in diagnostics
                else {}
            ),
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
    description_budget: int | None = None,
    request_budget: int | None = None,
    operation_requests: Sequence[B524OperationReadRequest] = (),
    operation_identity: Mapping[str, Any] | None = None,
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
    read_identity = operation_identity or {}
    device_id = read_identity.get("eid", read_identity.get("device_id"))
    manufacturer = read_identity.get("manufacturer")
    if isinstance(manufacturer, str):
        try:
            manufacturer = int(manufacturer, 0)
        except ValueError:
            manufacturer = None
    explicit_operation_override = bool(operation_requests)
    operation_request_list = list(operation_requests)
    if operation_request_list:
        validate_operation_read_identity(
            operation_request_list, device_id=device_id, manufacturer=manufacturer
        )
    operation_selection = [True] * len(operation_request_list)
    operation_planner_options: dict[str, Any] = {
        "operation_requests": operation_request_list,
        "operation_selection": operation_selection,
    }
    research_mode = planner_preset == "research"
    if explicit_plan is not None and planner_preset != "custom":
        raise ValueError("An explicit scan plan requires the custom preset")
    if description_budget is not None and (
        isinstance(description_budget, bool)
        or not isinstance(description_budget, int)
        or description_budget < 0
    ):
        raise ValueError("description_budget must be a nonnegative integer")
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
            **({"identity": dict(read_identity)} if read_identity else {}),
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

    def store_operation_read_plan() -> None:
        if operation_request_list:
            artifact["meta"]["b524_operation_read_plan"] = [
                {
                    "operation": request.operation,
                    "selector": request.selector,
                    "request_payload_hex": request.payload.hex(),
                    "selected": operation_enabled,
                    "automatic_event": request.automatic_event,
                }
                for request, operation_enabled in zip(
                    operation_request_list, operation_selection, strict=True
                )
            ]

    store_operation_read_plan()
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
    observed_description_candidates: list[DescriptionCandidate] = []
    observed_description_entries: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    description_candidates: list[DescriptionCandidate] = []
    description_entries: dict[tuple[int, int, int, int], dict[str, Any]] = {}
    description_policy: DescriptionPolicySelection | None = None
    description_candidates_prepared = False
    description_reminder_logged = False
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
                    "Parameter description policy will be resolved from exact profile "
                    "identity and planner selection (OP01 local / OP07 remote)"
                    + (
                        f", limited to {description_budget} candidates by request."
                        if description_budget is not None
                        else "."
                    ),
                    level="info",
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
            information_values,
            information_raw,
            {
                item.group: item.transport_diagnostic
                for item in discovered
                if item.transport_diagnostic is not None
            },
        )
        failed_information = [
            item.group for item in discovered if item.transport_diagnostic is not None
        ]
        if failed_information:
            coverage = artifact["meta"]["scan_coverage"]
            coverage["qualification_incomplete"] = True
            coverage["system_information_complete"] = False
            coverage["unknown_system_information"] = [
                _hex_u16(identifier) for identifier in failed_information
            ]
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
        profile_status = description_catalog_status(artifact)
        profile_id = (
            str(profile_status["profile_id"])
            if profile_status.get("status") == "exact" and profile_status.get("profile_id")
            else None
        )
        artifact["meta"]["description_profile_status"] = profile_status
        if profile_status.get("status") != "exact":
            artifact["meta"]["description_profile_reminder"] = {
                "shown_once": True,
                "recommendation": "full_within_known_scope",
                "sharing": "save_and_share_json_manually",
                "automatic_upload": False,
            }
            if observer is not None:
                observer.log(
                    "Unknown description profile: use Full for live writable descriptions "
                    "within known bounds, then save/share JSON manually if useful.",
                    level="warn",
                )
                description_reminder_logged = True
        description_policy = default_description_policy(
            planner_preset,
            exact_profile_known=profile_status.get("status") == "exact",
        )
        operation_planner_options.update(
            description_policy=description_policy,
            description_profile_status=str(profile_status.get("status", "unknown")),
        )
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
            "legacy_request_budget": description_budget,
            "system_description_opcode": "0x01",
            "device_description_opcode": "0x07",
            "scope": "observed_writable_complete_identity",
            "scheduler": "family_reservation_then_instance_round_robin",
            "unknown_codec_raw_evidence": True,
            "profile_status": profile_status.get("status"),
            "profile_id": profile_status.get("profile_id"),
            "local_source": description_policy.local,
            "remote_source": description_policy.remote,
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
                if group.group == 0x0D:
                    availability_group_opcodes[group.group] = _sorted_namespace_opcodes(
                        (*availability_group_opcodes[group.group], 0x06)
                    )
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
                    ii_min=_ii_min_for_opcode(
                        group=group.group, opcode=opcode, profile_id=profile_id
                    ),
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
                candidate_instances = _unknown_instance_candidates(
                    opcode=opcode,
                    expanded=research_mode,
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
                instance_total += (
                    namespace_ii_max + 1
                    if profile_id == "basv2_sw0507_hw1704_api1"
                    and (opcode, group.group) == (0x02, 0x02)
                    else namespace_ii_max
                    if opcode == 0x06 or group.group == 0x02
                    else namespace_ii_max + 1
                )
        if observer is not None:
            observer.phase_start("instance_discovery", total=instance_total or 1)

        instance_discovery_start = time.perf_counter()
        instance_discovery_start_calls = counting_transport.counters.send_calls
        known_namespace_probe_counts: dict[tuple[int, int], str] = {}
        unknown_namespace_probe_counts: dict[tuple[int, int], str] = {}
        native_dhw_admitted: dict[tuple[int, int], bool] = {}
        for group, meta, opcode in instance_targets:
            rr_max = meta.rr_max
            config = GROUP_CONFIG.get(group.group)

            if config is None:
                total_slots = len(_unknown_instance_candidates(opcode=opcode, expanded=True))
                namespace_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=opcode,
                )
                _record_namespace_topology(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    ii_min=_ii_min_for_opcode(
                        group=group.group, opcode=opcode, profile_id=profile_id
                    ),
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
                    research=research_mode,
                )
                _mark_present_instances(instances_obj, instances=present_instances)
                unknown_namespace_probe_counts[(int(opcode), group.group)] = (
                    f"{len(present_instances)}/{total_slots}"
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
                ii_min=_ii_min_for_opcode(group=group.group, opcode=opcode, profile_id=profile_id),
                ii_max=namespace_ii_max,
            )
            contract = namespace_availability_contract(
                group=group.group, opcode=opcode, presence_profile=profile_id
            )
            instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
            if _is_instanced_group(namespace_ii_max):
                _record_availability_contract(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    contract=contract,
                )
            if not _is_instanced_group(namespace_ii_max):
                if (opcode, group.group) == (0x02, 0x01):
                    _record_availability_contract(
                        artifact,
                        group=group.group,
                        opcode=opcode,
                        contract=contract,
                    )
                    probe = probe_instance_availability_fn(
                        transport,
                        dst=dst,
                        group=group.group,
                        instance=0x00,
                        opcode=opcode,
                    )
                    _record_availability_probes(
                        artifact,
                        group=group.group,
                        opcode=opcode,
                        probes={0x00: probe},
                    )
                    native_dhw_admitted[(int(opcode), group.group)] = probe.present
                    if probe.present:
                        _mark_present_instances(instances_obj, instances=(0x00,))
                    if (
                        probe.evidence is not None
                        and probe.evidence.get("availability_qualification") == "unknown"
                    ):
                        coverage = artifact["meta"]["scan_coverage"]
                        coverage["qualification_incomplete"] = True
                        coverage["instance_discovery_complete"] = False
                        coverage.setdefault("unknown_instance_probes", []).append(
                            {
                                "read_opcode": _hex_u8(opcode),
                                "group": _hex_u8(group.group),
                                "instance": "0x00",
                            }
                        )
                    known_namespace_probe_counts[(int(opcode), group.group)] = (
                        "1/1" if probe.present else "0/1"
                    )
                    continue
                _mark_present_instances(instances_obj, instances=(0x00,))
                known_namespace_probe_counts[(int(opcode), group.group)] = "1/1"
                continue

            assert namespace_ii_max is not None
            emit_trace_label(
                transport,
                f"Identifying instances in group 0x{group.group:02X} ({opcode_label(opcode)})",
            )
            count_id = COUNT_GROUP_IDS.get((int(opcode), group.group))
            capacity = (
                supported_capacity(information_values.get(count_id, float("nan")))
                if count_id in CAPACITY_SYSTEM_INFORMATION_IDS
                else None
            )
            expected_count = (
                expected_instance_count(
                    information_values.get(count_id, float("nan")),
                    capacity=_count_capacity(
                        group=group.group,
                        opcode=opcode,
                        ii_max=namespace_ii_max,
                        profile_id=profile_id,
                    ),
                )
                if count_id is not None and count_id not in CAPACITY_SYSTEM_INFORMATION_IDS
                else None
            )

            def retain_probe(
                ii: int,
                probe: InstanceAvailabilityProbe,
                *,
                probe_group: int = group.group,
                probe_opcode: int = opcode,
                probe_instances: dict[str, Any] = instances_obj,
            ) -> None:
                _record_availability_probes(
                    artifact, group=probe_group, opcode=probe_opcode, probes={ii: probe}
                )
                if probe.present:
                    _mark_present_instances(probe_instances, instances=(ii,))

            probes = _probe_present_instances(
                transport,
                dst=dst,
                group=group.group,
                opcode=opcode,
                ii_max=(
                    0x00
                    if planner_preset == "recommended" and (opcode, group.group) == (0x02, 0x09)
                    else namespace_ii_max
                ),
                observer=observer,
                probe_instance_availability_fn=probe_instance_availability_fn,
                stop_at_first_absence=planner_preset == "recommended" and opcode == 6,
                on_probe=retain_probe,
                expected_count=expected_count if planner_preset == "recommended" else None,
                capacity=capacity if planner_preset == "recommended" else None,
                presence_profile=profile_id,
            )
            _record_availability_probes(
                artifact,
                group=group.group,
                opcode=opcode,
                probes=probes,
            )
            if opcode == 6 and group.group in CONNECTED_DEVICE_GROUPS:
                unknown_slots = [
                    ii for ii, probe in probes.items() if probe.connection_state == "unknown"
                ]
                stopped = any(
                    probe.connection_state == "not_connected" for probe in probes.values()
                )
                bounded = planner_preset != "recommended"
                confirmed_present = sum(probe.present for probe in probes.values())
                count_guided_complete = (
                    planner_preset == "recommended"
                    and expected_count is not None
                    and confirmed_present >= expected_count
                )
                complete = not unknown_slots and (bounded or stopped or count_guided_complete)
                artifact["meta"].setdefault("device_discovery", {})[_hex_u8(group.group)] = {
                    "read_opcode": "0x06",
                    "presence_register": "0x0001",
                    "first_instance": "0x01",
                    "last_instance_bound": _hex_u8(namespace_ii_max),
                    "policy": (
                        "bounded_audit"
                        if bounded
                        else "count_guided"
                        if expected_count is not None
                        else "first_confirmed_absence"
                    ),
                    "count_guided_expected": expected_count,
                    "count_guided_complete": count_guided_complete,
                    "presence_name": "device_connected",
                    "absence_semantics": "not_connected_not_physical_absence",
                    "probed_instances": [_hex_u8(ii) for ii in probes],
                    "unknown_instances": [_hex_u8(ii) for ii in unknown_slots],
                    "complete": complete,
                    "exhaustive_physical_inventory": False,
                }
                if not complete:
                    artifact["meta"]["scan_coverage"]["device_discovery_complete"] = False
                    artifact["meta"]["scan_coverage"]["qualification_incomplete"] = True
                else:
                    artifact["meta"]["scan_coverage"].setdefault("device_discovery_complete", True)
            uncertain_instances = [
                ii
                for ii, probe in probes.items()
                if probe.evidence is not None
                and probe.evidence.get("availability_qualification") == "unknown"
            ]
            if uncertain_instances:
                coverage = artifact["meta"]["scan_coverage"]
                coverage["qualification_incomplete"] = True
                coverage["instance_discovery_complete"] = False
                coverage.setdefault("unknown_instance_probes", []).extend(
                    {
                        "read_opcode": _hex_u8(opcode),
                        "group": _hex_u8(group.group),
                        "instance": _hex_u8(ii),
                    }
                    for ii in uncertain_instances
                )
            present_instances = tuple(ii for ii, probe in probes.items() if probe.present)
            count_id = COUNT_GROUP_IDS.get((int(opcode), group.group))
            if count_id is not None:
                is_capacity = count_id in CAPACITY_SYSTEM_INFORMATION_IDS
                expected = (
                    None
                    if is_capacity
                    else expected_instance_count(
                        information_values.get(count_id, float("nan")),
                        capacity=_count_capacity(
                            group=group.group,
                            opcode=opcode,
                            ii_max=namespace_ii_max,
                            profile_id=profile_id,
                        ),
                    )
                )
                supported = (
                    supported_capacity(information_values.get(count_id, float("nan")))
                    if is_capacity
                    else None
                )
                observed = len(
                    [
                        ii
                        for ii in present_instances
                        if not (opcode == 2 and group.group == 2 and ii == 0x09)
                    ]
                )
                artifact["meta"].setdefault("instance_counts", {})[
                    f"{_hex_u8(opcode)}:{_hex_u8(group.group)}"
                ] = {
                    "identifier": _hex_u16(count_id),
                    "expected": expected,
                    "semantics": "capacity" if is_capacity else "expected_population",
                    "capacity": supported,
                    "observed": observed,
                    "mismatch": expected is not None and expected != observed,
                    "capacity_exceeded": supported is not None and observed > supported,
                    "probed_instances": len(probes),
                }
            _mark_present_instances(instances_obj, instances=present_instances)
            slot_capacity = (
                namespace_ii_max + 1
                if profile_id == "basv2_sw0507_hw1704_api1"
                and (opcode, group.group) == (0x02, 0x02)
                else namespace_ii_max
                if opcode == 0x06 or group.group == 0x02
                else namespace_ii_max + 1
            )
            known_namespace_probe_counts[(int(opcode), group.group)] = (
                f"{len(present_instances)}/{slot_capacity}"
            )

        remote_group_object = artifact["operations"].get("0x06", {}).get("groups", {})
        observed_remote_instances = (
            sum(
                1
                for group_key, group_object in remote_group_object.items()
                if int(group_key, 0) in CONNECTED_DEVICE_GROUPS
                if isinstance(group_object, dict)
                for probe in group_object.get("availability_probes", {}).values()
                if isinstance(probe, dict)
                and probe.get("present") is True
                and (probe.get("connection_state") == "connected")
            )
            if isinstance(remote_group_object, dict)
            else 0
        )
        remote_slot_capacity = sum(
            _ii_max_for_opcode(
                group=group.group,
                default_ii_max=metadata_map[group.group].ii_max,
                opcode=0x06,
            )
            or 0
            for group in classified
            if 0x06 in availability_group_opcodes.get(group.group, ())
        )
        aggregate_device_count = expected_instance_count(
            information_values.get(4, float("nan")), capacity=remote_slot_capacity
        )
        artifact["meta"]["device_count"] = {
            "identifier": "0x0004",
            "expected": aggregate_device_count,
            "observed": observed_remote_instances,
            "mismatch": (
                aggregate_device_count is not None
                and aggregate_device_count != observed_remote_instances
            ),
        }
        module_capacity = module_capacity_crosscheck(
            information_values.get(8, float("nan")), information_values.get(9, float("nan"))
        )
        if module_capacity is not None:
            artifact["meta"]["module_capacity_crosscheck"] = {
                "vr70_identifier": "0x0008",
                "vr71_identifier": "0x0009",
                "capacity": module_capacity,
                "semantics": "crosscheck_only",
            }

        if observer is not None:
            for group, meta, opcode in instance_targets:
                key = (int(opcode), group.group)
                count = known_namespace_probe_counts.get(key)
                experimental = key in unknown_namespace_probe_counts
                if experimental:
                    count = unknown_namespace_probe_counts[key]
                if count is None:
                    continue
                qualifier = " (experimental)" if experimental else ""
                if (opcode, group.group) == (0x06, 0x0D):
                    rr_text = "RR_max=unknown (probe-only)"
                else:
                    rr_max = _rr_max_for_opcode(
                        group=group.group, default_rr_max=meta.rr_max, opcode=opcode
                    )
                    rr_text = f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)"
                observer.log(
                    f"OP=0x{opcode:02X} GG=0x{group.group:02X}: "
                    f"{_group_name_for_opcode(group.group, opcode)} {count} present{qualifier}, "
                    f"{rr_text}",
                    level="info",
                )

        if observer is not None:
            observer.phase_finish("instance_discovery")
        instance_discovery_duration_s = time.perf_counter() - instance_discovery_start
        instance_discovery_requests = (
            counting_transport.counters.send_calls - instance_discovery_start_calls
        )
        artifact["meta"]["scan_coverage"]["discovery_completed"] = True

        if explicit_operation_override:
            artifact["meta"]["b524_event_acquisition"] = {
                "source": "explicit_read_plan_override",
                "automatic_default_applied": False,
            }
        else:
            system_in_scope = 0x02 in resolved_group_opcodes.get(0x00, ())
            default_event_instances: dict[EventProfileName, tuple[int, ...]] = {
                "system": (0x00,) if system_in_scope else (),
                "dhw": (
                    _present_instances_for_opcode(artifact, group=0x01, opcode=0x02)
                    if native_dhw_admitted.get((0x02, 0x01), False)
                    else ()
                ),
                "zone": _present_instances_for_opcode(artifact, group=0x03, opcode=0x02),
            }
            default_requests = build_default_event_requests(
                instances=default_event_instances,
                weekday_codes=DEFAULT_EVENT_WEEKDAY_CODES,
            )
            event_metadata: dict[str, Any] = {
                "source": "automatic_scalar_topology_candidates",
                "automatic_default_applied": False,
                "selector_kind": "raw_u8",
                "candidate_window": {
                    "codes": [f"0x{code:02X}" for code in DEFAULT_EVENT_WEEKDAY_CODES],
                    "range": "0x00..0x07",
                    "exhaustive_wire_space": False,
                },
                "editable_in_planner": True,
                "scalar_anchor": "OP02 present instances",
                "profiles": {
                    profile: {
                        "instances": [f"0x{instance:02X}" for instance in instances],
                        "status": (
                            "candidate_from_scalar_anchor"
                            if instances
                            else "not_scheduled_no_scalar_anchor"
                        ),
                    }
                    for profile, instances in default_event_instances.items()
                },
                "setpoint_policy": "conditional_exact_usable_op09_pair",
            }
            if default_requests:
                try:
                    validate_operation_read_identity(
                        default_requests,
                        device_id=device_id,
                        manufacturer=manufacturer,
                    )
                except ValueError:
                    event_metadata["status"] = "not_scheduled_unknown_identity"
                    for profile_metadata in event_metadata["profiles"].values():
                        if profile_metadata["instances"]:
                            profile_metadata["status"] = "not_scheduled_unknown_identity"
                else:
                    operation_request_list.extend(default_requests)
                    operation_selection.extend([True] * len(default_requests))
                    event_metadata["automatic_default_applied"] = True
                    event_metadata["status"] = "scheduled_candidates"
                    event_metadata["worst_case_requests"] = len(default_requests)
                    for profile_metadata in event_metadata["profiles"].values():
                        if profile_metadata["instances"]:
                            profile_metadata["status"] = "scheduled_candidate"
            else:
                event_metadata["status"] = "not_scheduled_no_scalar_anchor"
            artifact["meta"]["b524_event_acquisition"] = event_metadata

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
            opcodes = _sorted_namespace_opcodes(
                (*planner_native_opcodes(group.group), *resolved_opcodes)
            )
            if not opcodes:
                continue
            multi_op = len(opcodes) > 1
            for opcode in opcodes:
                requested_plan = (
                    explicit_plan.get(_plan_key(group.group, opcode))
                    if explicit_plan is not None
                    else None
                )
                qualified_rr_max = (
                    planner_rr_max(group.group, opcode)
                    if config is not None
                    else _rr_max_for_opcode(
                        group=group.group,
                        default_rr_max=group_meta.rr_max,
                        opcode=opcode,
                    )
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
                        rr_max=(
                            requested_plan.rr_max
                            if requested_plan is not None
                            else qualified_rr_max
                        ),
                        rr_max_full=(
                            _rr_max_full_for_opcode(group=group.group, opcode=opcode)
                            if qualified_rr_max is not None
                            else None
                        ),
                        present_instances=present_instances,
                        ii_min=_ii_min_for_opcode(
                            group=group.group, opcode=opcode, profile_id=profile_id
                        ),
                        expected_count=(
                            expected_instance_count(
                                information_values.get(
                                    COUNT_GROUP_IDS.get((int(opcode), group.group), -1),
                                    float("nan"),
                                ),
                                capacity=(
                                    _count_capacity(
                                        group=group.group,
                                        opcode=opcode,
                                        ii_max=planner_ii_max,
                                        profile_id=profile_id,
                                    )
                                ),
                            )
                            if planner_ii_max is not None
                            and COUNT_GROUP_IDS.get((int(opcode), group.group))
                            not in CAPACITY_SYSTEM_INFORMATION_IDS
                            else None
                        ),
                        namespace_label=(opcode_label(opcode) if multi_op else None),
                        recommended=_planner_group_is_recommended(
                            group=group.group,
                            opcode=opcode,
                        ),
                        instances_probed=opcode in resolved_opcodes,
                        research_rr_max=_rr_max_full_for_opcode(
                            group=group.group,
                            opcode=opcode,
                        ),
                        native_dhw_admitted=native_dhw_admitted.get(
                            (int(opcode), group.group), False
                        ),
                    )
                )

        if planner_preset != "custom":
            plan = build_plan_from_preset(
                planner_groups,
                preset=planner_preset,
            )
            plan = _normalize_profile_plan_instances(plan, profile_id=profile_id)
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
                                system_information=artifact["meta"]["system_information"],
                                **_planner_kwargs(run_textual_scan_plan, operation_planner_options),
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
                            if isinstance(selected, PlannerSelection):
                                plan = selected.plan
                                planner_preset = selected.selected_preset
                                description_policy = selected.description_policy
                            else:
                                plan = dict(selected)
                if planner_mode == "classic":
                    selected = prompt_scan_plan_fn(
                        console,
                        planner_groups,
                        request_rate_rps=request_rate_rps,
                        default_plan=planner_default_plan,
                        default_preset=planner_preset,
                        system_information=artifact["meta"]["system_information"],
                        **_planner_kwargs(prompt_scan_plan_fn, operation_planner_options),
                    )
                    if isinstance(selected, PlannerSelection):
                        plan = selected.plan
                        planner_preset = selected.selected_preset
                        description_policy = selected.description_policy
                    else:
                        plan = dict(selected)
                if planner_preset != "custom":
                    plan = _normalize_profile_plan_instances(plan, profile_id=profile_id)

        artifact["meta"]["parameter_description_policy"].update(
            local_source=description_policy.local,
            remote_source=description_policy.remote,
            local_override=description_policy.local_override,
            remote_override=description_policy.remote_override,
            selected_preset=planner_preset,
        )
        artifact["meta"]["scan_coverage"]["preset"] = planner_preset

        store_operation_read_plan()
        artifact["meta"]["scan_plan"] = {
            "groups": _scan_plan_meta_groups(plan),
            "estimated_register_requests": estimate_register_requests(plan),
            "estimated_operation_requests_worst_case": sum(operation_selection),
            "estimated_total_requests_worst_case": (
                estimate_register_requests(plan) + sum(operation_selection)
            ),
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
                        operation_planner_options["description_policy"] = description_policy
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
                                        system_information=artifact["meta"]["system_information"],
                                        **_planner_kwargs(
                                            run_textual_scan_plan, operation_planner_options
                                        ),
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
                                    if isinstance(selected, PlannerSelection):
                                        plan = selected.plan
                                        planner_preset = selected.selected_preset
                                        description_policy = selected.description_policy
                                    else:
                                        plan = dict(selected)
                        if planner_mode == "classic":
                            selected = prompt_scan_plan_fn(
                                console,
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=plan,
                                default_preset=planner_preset,
                                system_information=artifact["meta"]["system_information"],
                                **_planner_kwargs(prompt_scan_plan_fn, operation_planner_options),
                            )
                            if isinstance(selected, PlannerSelection):
                                plan = selected.plan
                                planner_preset = selected.selected_preset
                                description_policy = selected.description_policy
                            else:
                                plan = dict(selected)
                        if planner_preset != "custom":
                            plan = _normalize_profile_plan_instances(plan, profile_id=profile_id)
                    artifact["meta"]["parameter_description_policy"].update(
                        local_source=description_policy.local,
                        remote_source=description_policy.remote,
                        local_override=description_policy.local_override,
                        remote_override=description_policy.remote_override,
                        selected_preset=planner_preset,
                    )
                    artifact["meta"]["scan_coverage"]["preset"] = planner_preset
                    store_operation_read_plan()
                    artifact["meta"]["scan_plan"]["groups"] = _scan_plan_meta_groups(plan)
                    artifact["meta"]["scan_plan"]["estimated_register_requests"] = (
                        estimate_register_requests(plan)
                    )
                    artifact["meta"]["scan_plan"]["estimated_operation_requests_worst_case"] = sum(
                        operation_selection
                    )
                    artifact["meta"]["scan_plan"]["estimated_total_requests_worst_case"] = (
                        estimate_register_requests(plan) + sum(operation_selection)
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
                if observer is not None:
                    observer.phase_advance("register_scan", advance=1)
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

                canonical_name = b524_register_name(
                    opcode=task.opcode,
                    group=task.group,
                    register=task.register,
                )
                if canonical_name is not None:
                    entry["myvaillant_name"] = canonical_name
                if (
                    profile_id == "basv2_sw0507_hw1704_api1"
                    and (task.opcode, task.group) == (0x02, 0x02)
                    and task.register in {0x0007, 0x000E, 0x0014, 0x001E}
                ):
                    entry["candidate_name"] = {
                        0x0007: "circuit_target_flow_temperature",
                        0x000E: "circuit_setback_mode",
                        0x0014: "circuit_outside_temperature_threshold",
                        0x001E: "circuit_status",
                    }[task.register]
                    entry["candidate_evidence"] = "basv2_sw0507_profile_cross_source_candidate"
                if (
                    profile_id == "basv2_sw0507_hw1704_api1"
                    and (task.opcode, task.group, task.register) == (0x02, 0x02, 0x0020)
                    and entry.get("type") == "UCH"
                ):
                    entry["codec_evidence"] = {
                        "observed": "UCH",
                        "width": 1,
                        "qualification": "profile_observed",
                        "contradicts": "legacy_f32_prose",
                    }

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
                    entry["attribute_qualification"] = "profile_scoped_inference"
                    entry["access_role"] = "unknown"
                    entry["persistence"] = "unknown"
                if probe_constraints and entry.get("response_state") == "active":
                    flags = entry.get("flags")
                    type_spec = entry.get("type")
                    if isinstance(flags, int) and flags in {2, 3}:
                        identity = (int(task.opcode), task.group, task.instance, task.register)
                        observed_description_candidates.append(
                            DescriptionCandidate(
                                *identity, type_spec if isinstance(type_spec, str) else None
                            )
                        )
                        observed_description_entries[identity] = cast(dict[str, Any], entry)
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
                        ii_min=_ii_min_for_opcode(
                            group=task.group, opcode=task.opcode, profile_id=profile_id
                        ),
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
                    if task.opcode == 2 and task.group == 2 and task.instance == 0x09:
                        instance_obj.update(
                            designation="virtual_water_circuit",
                            protocol_role="unknown",
                            role_qualification="unqualified",
                        )
                    registers = instance_obj.setdefault("registers", {})
                    registers[_hex_u16(task.register)] = entry

        if probe_constraints:
            assert description_policy is not None
            (
                description_candidates,
                description_entries,
                remote_profile_statuses,
            ) = _select_live_description_candidates(
                artifact,
                observed_description_candidates,
                observed_description_entries,
                policy=description_policy,
            )
            description_candidates_prepared = True
            if remote_profile_statuses:
                artifact["meta"]["description_remote_profile_statuses"] = remote_profile_statuses
            if any(row.get("status") != "exact" for row in remote_profile_statuses):
                artifact["meta"].setdefault(
                    "description_profile_reminder",
                    {
                        "shown_once": True,
                        "recommendation": "full_within_known_scope",
                        "sharing": "save_and_share_json_manually",
                        "automatic_upload": False,
                    },
                )
                if observer is not None and not description_reminder_logged:
                    observer.log(
                        "Unknown remote description profile: use Full for live writable "
                        "descriptions within known bounds, then save/share JSON manually "
                        "if useful.",
                        level="warn",
                    )
                    description_reminder_logged = True
            for candidate in description_candidates:
                identity = (
                    candidate.read_opcode,
                    candidate.group,
                    candidate.instance,
                    candidate.register,
                )
                description_entries[identity]["parameter_description"] = {
                    "qualification": "unavailable",
                    "reason": "description acquisition pending",
                }
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

        if operation_request_list:
            selected_operations = tuple(
                request
                for request, operation_enabled in zip(
                    operation_request_list, operation_selection, strict=True
                )
                if operation_enabled
            )
            if selected_operations:
                acquire_operation_reads(
                    transport,
                    dst=dst,
                    artifact=artifact,
                    requests=selected_operations,
                    device_id=device_id,
                    manufacturer=manufacturer,
                    observer=observer,
                )

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
                getattr(exc, "system_information_diagnostics", {}),
            )
    except TransportRecoveryExhausted as exc:
        artifact["meta"]["incomplete"] = True
        incomplete_reason = "transport_recovery_exhausted"
        artifact["meta"]["transport_recovery"] = {
            "cause": exc.cause,
            "phase": exc.phase,
            "request_attempts": exc.request_attempts,
            "retry_count": exc.retry_count,
            "reconnect_attempts": exc.reconnect_attempts,
            "pending_selector": exc.selector,
        }
        artifact["meta"]["transport_boundary_evidence"] = list(counting_transport.recent_requests)
        if exc.system_information:
            artifact["meta"]["system_information"] = _system_information_records(
                {identifier: value for identifier, value, _ in exc.system_information},
                {identifier: raw for identifier, _, raw in exc.system_information},
                getattr(exc, "system_information_diagnostics", {}),
            )
        if exc.entry is not None and exc.selector is not None:
            selector = exc.selector
            recovery_opcode = int(selector["read_opcode"], 0)
            recovery_group = int(selector["group"], 0)
            _ensure_group_artifact(
                artifact,
                group=recovery_group,
                opcode=recovery_opcode,
                name="Unknown",
                descriptor_observed=0.0,
            )
            instances = _instances_object(artifact, group=recovery_group, opcode=recovery_opcode)
            instance = instances.setdefault(selector["instance"], {"present": False})
            instance.setdefault("registers", {})[selector["register"]] = exc.entry
        if observer is not None:
            observer.log(str(exc), level="warn")

    if probe_constraints:
        if not description_candidates_prepared and description_policy is not None:
            description_candidates, description_entries, remote_profile_statuses = (
                _select_live_description_candidates(
                    artifact,
                    observed_description_candidates,
                    observed_description_entries,
                    policy=description_policy,
                )
            )
            if remote_profile_statuses:
                artifact["meta"]["description_remote_profile_statuses"] = remote_profile_statuses
        finish_description_coverage(
            description_candidates,
            description_entries,
            budget=description_budget,
            coverage=description_coverage,
        )
    store_operation_read_plan()
    if operation_request_list and "b524_operation_reads" not in artifact:
        artifact["b524_operation_reads_schema_version"] = 1
        artifact["b524_operation_reads"] = []
        for request, operation_enabled in zip(
            operation_request_list, operation_selection, strict=True
        ):
            if operation_enabled:
                record = record_operation_read_observation(request)
                record["response_state"] = "unattempted"
                record["error"] = incomplete_reason or "not_acquired"
                artifact["b524_operation_reads"].append(record)
    artifact["meta"]["parameter_description_coverage"] = description_coverage
    artifact["meta"]["parameter_description_requests"] = description_coverage.get(
        "request_attempts", 0
    )
    artifact["meta"]["scan_coverage"]["actual_requests"] = counting_transport.counters.send_calls
    operation_records = artifact.get("b524_operation_reads")
    if isinstance(operation_records, list):
        operation_attempts = {
            "OP09": sum(
                int(record.get("request_attempts", 0))
                for record in operation_records
                if isinstance(record, dict) and record.get("operation") == "GetEvent"
            ),
            "OP0B": sum(
                int(record.get("request_attempts", 0))
                for record in operation_records
                if isinstance(record, dict) and record.get("operation") == "GetEventSetPoint"
            ),
        }
        artifact["meta"]["b524_operation_read_attempts"] = {
            **operation_attempts,
            "total": sum(operation_attempts.values()),
        }
    artifact["meta"]["scan_coverage"]["completed"] = not artifact["meta"]["incomplete"]
    artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
    if incomplete_reason is not None:
        artifact["meta"]["incomplete_reason"] = incomplete_reason

    return artifact
