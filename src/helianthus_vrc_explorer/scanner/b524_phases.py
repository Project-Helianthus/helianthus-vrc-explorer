"""The five phases of the B524 scan over one typed scan context.

``run_b524_scan`` runs plan, discovery, availability, scan and completion in
that order. ``docs/b524-scan-phases.md`` maps every phase to the state it reads
and writes.
"""

from __future__ import annotations

import inspect
import math
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast

from rich.console import Console

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..evidence_compat import api_identity_string
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
    StaticConstraintCatalog,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
)
from ..schema.b524_register_names import b524_register_name
from ..schema.description_profile_reminder import (
    compose_description_profile_reminder,
    remote_rows_need_reminder,
    remote_rows_with_designation,
)
from ..schema.ebusd_csv import EbusdCsvSchema, EbusdRegisterSchemaEntry
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..schema.parameter_descriptions import description_catalog_status
from ..transport.base import TransportInterface, TransportRecoveryExhausted, emit_trace_label
from ..transport.instrumented import CountingTransport, ScanRequestBudgetExceeded
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
from .collaborators import (
    GroupDiscovery,
    InstanceAvailabilityProber,
    PlannerHotkeyReaderFactory,
    PlannerHotkeys,
    ScanPlanners,
)
from .description_acquisition import acquire_descriptions, finish_description_coverage
from .description_scheduler import DescriptionCandidate
from .director import GROUP_CONFIG, ClassifiedGroup, DiscoveredGroup, classify_groups
from .observer import ScanObserver
from .plan import (
    GroupScanPlan,
    PlanKey,
    RegisterTask,
    build_work_queue,
    estimate_register_requests,
)
from .planner_model import PlannerGroup, PlannerPreset, build_plan_from_preset
from .planner_selection import (
    DescriptionPolicySelection,
    PlannerSelection,
    default_description_policy,
)
from .register import (
    CONNECTED_DEVICE_GROUPS,
    InstanceAvailabilityProbe,
    NamespaceAvailabilityContract,
    RegisterEntry,
    namespace_availability_contract,
    read_register,
)
from .scan_policy import profile_opcodes

PlannerMode = Literal["disabled", "textual", "classic"]
PlannerModeResolver = Callable[[], PlannerMode]
type _AvailabilityTarget = tuple[ClassifiedGroup, GroupMetadata, RegisterOpcode]
type _DescriptionIdentity = tuple[int, int, int, int]


@dataclass(slots=True, eq=False)
class B524ScanContext:
    """Local state that the B524 scan phases read and write.

    The plan phase fills the request fields and the artifact skeleton. Each later
    phase fills its own fields one step at a time, so a scan that stops part-way
    keeps every field resolved before it stopped.
    """

    transport: CountingTransport
    dst: int
    observer: ScanObserver | None
    artifact: dict[str, Any]
    planner_preset: PlannerPreset
    research_mode: bool
    probe_constraints: bool
    explicit_plan: dict[PlanKey, GroupScanPlan] | None
    description_budget: int | None
    request_budget: int | None
    configured_groups: list[int]
    start_perf: float
    static_constraints: StaticConstraintCatalog
    device_id: Any
    manufacturer: Any
    explicit_operation_override: bool
    operation_requests: list[B524OperationReadRequest]
    operation_selection: list[bool]
    operation_planner_options: dict[str, Any]
    information_values: dict[int, float] = field(default_factory=dict)
    ventilation_hint: bool = False
    profile_status: dict[str, Any] = field(default_factory=dict)
    profile_id: str | None = None
    description_policy: DescriptionPolicySelection | None = None
    description_reminder_logged: bool = False
    classified: list[ClassifiedGroup] = field(default_factory=list)
    unknown_descriptor_types: list[float] = field(default_factory=list)
    metadata_map: dict[int, GroupMetadata] = field(default_factory=dict)
    planner_mode: PlannerMode = "disabled"
    resolved_group_opcodes: dict[int, tuple[RegisterOpcode, ...]] = field(default_factory=dict)
    availability_group_opcodes: dict[int, tuple[RegisterOpcode, ...]] = field(default_factory=dict)
    unknown_opcode_probe_map: dict[int, dict[str, Any]] = field(default_factory=dict)
    group_discovery_requests: int = 0
    group_discovery_duration_s: float = 0.0
    native_dhw_admitted: dict[tuple[int, int], bool] = field(default_factory=dict)
    instance_discovery_requests: int = 0
    instance_discovery_duration_s: float = 0.0
    observed_description_candidates: list[DescriptionCandidate] = field(default_factory=list)
    observed_description_entries: dict[_DescriptionIdentity, dict[str, Any]] = field(
        default_factory=dict
    )
    description_candidates: list[DescriptionCandidate] = field(default_factory=list)
    description_entries: dict[_DescriptionIdentity, dict[str, Any]] = field(default_factory=dict)
    description_candidates_prepared: bool = False
    description_coverage: dict[str, Any] = field(default_factory=dict)


def system_information_records(
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


def store_operation_read_plan(ctx: B524ScanContext) -> None:
    """Record the operation-read requests and whether each one is selected."""

    if ctx.operation_requests:
        ctx.artifact["meta"]["b524_operation_read_plan"] = [
            {
                "operation": request.operation,
                "selector": request.selector,
                "request_payload_hex": request.payload.hex(),
                "selected": operation_enabled,
                "automatic_event": request.automatic_event,
            }
            for request, operation_enabled in zip(
                ctx.operation_requests, ctx.operation_selection, strict=True
            )
        ]


def _identity_manufacturer(identity: Mapping[str, Any]) -> Any:
    manufacturer = identity.get("manufacturer")
    if isinstance(manufacturer, str):
        try:
            return int(manufacturer, 0)
        except ValueError:
            return None
    return manufacturer


def _validate_scan_request(
    planner_preset: PlannerPreset,
    explicit_plan: dict[PlanKey, GroupScanPlan] | None,
    description_budget: int | None,
) -> None:
    if explicit_plan is not None and planner_preset != "custom":
        raise ValueError("An explicit scan plan requires the custom preset")
    if description_budget is not None and (
        isinstance(description_budget, bool)
        or not isinstance(description_budget, int)
        or description_budget < 0
    ):
        raise ValueError("description_budget must be a nonnegative integer")


def _configured_groups(
    explicit_plan: dict[PlanKey, GroupScanPlan] | None, *, research_mode: bool
) -> list[int]:
    if explicit_plan is not None:
        return sorted({item.group for item in explicit_plan.values()})
    if research_mode:
        return list(range(0x100))
    return sorted(GROUP_CONFIG)


def _artifact_skeleton(
    *,
    dst: int,
    scan_timestamp: str,
    identity: Mapping[str, Any],
    planner_preset: PlannerPreset,
    request_budget: int | None,
    explicit_plan: dict[PlanKey, GroupScanPlan] | None,
    configured_groups: list[int],
) -> dict[str, Any]:
    return {
        "schema_version": CURRENT_ARTIFACT_SCHEMA_VERSION,
        "meta": {
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": 0.0,
            "destination_address": _hex_u8(dst),
            "schema_sources": [],
            "incomplete": False,
            "artifact_contract": _artifact_contract_metadata(),
            "system_information": [],
            **({"identity": dict(identity)} if identity else {}),
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


def _record_plan_sources(
    ctx: B524ScanContext,
    *,
    ebusd_host: str | None,
    ebusd_port: int | None,
    constraints_source: str | None,
) -> None:
    meta = ctx.artifact["meta"]
    if ebusd_host is not None:
        meta["ebusd_host"] = ebusd_host
    if ebusd_port is not None:
        meta["ebusd_port"] = ebusd_port
    if constraints_source is not None:
        meta["constraint_catalog_source"] = constraints_source
        meta["constraint_catalog_entries"] = _constraint_catalog_entry_count(ctx.static_constraints)
    meta["constraint_scope"] = constraint_scope_metadata()
    if ctx.explicit_plan is not None:
        meta["scan_plan"] = {
            "groups": _scan_plan_meta_groups(ctx.explicit_plan),
            "estimated_register_requests": estimate_register_requests(ctx.explicit_plan),
        }


def plan_b524_scan(
    transport: TransportInterface,
    *,
    dst: int,
    observer: ScanObserver | None,
    ebusd_host: str | None,
    ebusd_port: int | None,
    planner_preset: PlannerPreset,
    probe_constraints: bool,
    explicit_plan: dict[PlanKey, GroupScanPlan] | None,
    description_budget: int | None,
    request_budget: int | None,
    operation_requests: Sequence[B524OperationReadRequest],
    operation_identity: Mapping[str, Any] | None,
) -> B524ScanContext:
    """Plan phase: validate the request and lay out the artifact skeleton.

    Raises ``ValueError`` for an invalid request before any request is sent.
    """

    planner_preset = _normalize_planner_preset(planner_preset)
    identity = operation_identity or {}
    device_id = identity.get("eid", identity.get("device_id"))
    manufacturer = _identity_manufacturer(identity)
    operation_request_list = list(operation_requests)
    if operation_request_list:
        validate_operation_read_identity(
            operation_request_list, device_id=device_id, manufacturer=manufacturer
        )
    operation_selection = [True] * len(operation_request_list)
    _validate_scan_request(planner_preset, explicit_plan, description_budget)
    research_mode = planner_preset == "research"
    configured_groups = _configured_groups(explicit_plan, research_mode=research_mode)
    start_perf = time.perf_counter()
    scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    static_constraints, constraints_source = load_default_b524_constraints_catalog()
    counting_transport = CountingTransport(transport, request_budget=request_budget)
    ctx = B524ScanContext(
        transport=counting_transport,
        dst=dst,
        observer=observer,
        artifact=_artifact_skeleton(
            dst=dst,
            scan_timestamp=scan_timestamp,
            identity=identity,
            planner_preset=planner_preset,
            request_budget=request_budget,
            explicit_plan=explicit_plan,
            configured_groups=configured_groups,
        ),
        planner_preset=planner_preset,
        research_mode=research_mode,
        probe_constraints=probe_constraints,
        explicit_plan=explicit_plan,
        description_budget=description_budget,
        request_budget=request_budget,
        configured_groups=configured_groups,
        start_perf=start_perf,
        static_constraints=static_constraints,
        device_id=device_id,
        manufacturer=manufacturer,
        explicit_operation_override=bool(operation_requests),
        operation_requests=operation_request_list,
        operation_selection=operation_selection,
        operation_planner_options={
            "operation_requests": operation_request_list,
            "operation_selection": operation_selection,
        },
    )
    store_operation_read_plan(ctx)
    _record_plan_sources(
        ctx,
        ebusd_host=ebusd_host,
        ebusd_port=ebusd_port,
        constraints_source=constraints_source,
    )
    return ctx


def announce_b524_scan(ctx: B524ScanContext) -> None:
    """Tell the operator which scan starts and how descriptions are chosen."""

    observer = ctx.observer
    if observer is not None:
        observer.log(f"Starting scan dst={_hex_u8(ctx.dst)}", level="info")
        if ctx.planner_preset == "full":
            observer.log(
                "Full preset selected: scan will expand known groups to full instance "
                "slots independently of counts, with profile RR ranges.",
                level="warn",
            )
        if ctx.research_mode:
            observer.log(
                "Research preset selected: scan enables broader non-core and "
                "underspecified fallback probing. Expect very long runs.",
                level="warn",
            )
        if ctx.probe_constraints:
            observer.log(
                "Parameter description policy will be resolved from exact profile "
                "identity and planner selection (OP01 local / OP07 remote)"
                + (
                    f", limited to {ctx.description_budget} candidates by request."
                    if ctx.description_budget is not None
                    else "."
                ),
                level="info",
            )
    emit_trace_label(ctx.transport, f"Starting scan dst={_hex_u8(ctx.dst)}")


def _record_system_information(ctx: B524ScanContext, discovered: list[DiscoveredGroup]) -> None:
    meta = ctx.artifact["meta"]
    ctx.information_values = {item.group: item.descriptor for item in discovered}
    information_raw = {item.group: item.raw_hex for item in discovered}
    meta["system_information"] = system_information_records(
        ctx.information_values,
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
        coverage = meta["scan_coverage"]
        coverage["qualification_incomplete"] = True
        coverage["system_information_complete"] = False
        coverage["unknown_system_information"] = [
            _hex_u16(identifier) for identifier in failed_information
        ]
    ventilation_count = ctx.information_values.get(16, float("nan"))
    ctx.ventilation_hint = (
        math.isfinite(ventilation_count)
        and ventilation_count.is_integer()
        and ventilation_count > 0
    )


def _record_profile_context(ctx: B524ScanContext) -> None:
    values = ctx.information_values
    ctx.artifact["meta"]["profile_context"] = {
        "profile": "controller_b524",
        "api_version_raw": api_identity_string(values.get(6)),
        "api_revision_raw": api_identity_string(values.get(7)),
        "api_version": values.get(6) if math.isfinite(values.get(6, float("nan"))) else None,
        "api_revision": values.get(7) if math.isfinite(values.get(7, float("nan"))) else None,
        "qualified_count_mappings": [
            {
                "identifier": _hex_u16(identifier),
                "read_opcode": _hex_u8(op),
                "group": _hex_u8(gg),
            }
            for (op, gg), identifier in COUNT_GROUP_IDS.items()
        ],
        "feature_hints": {"ventilation": ctx.ventilation_hint},
        "other_count_routing": "unknown",
    }


def _resolve_description_profile(ctx: B524ScanContext) -> None:
    meta = ctx.artifact["meta"]
    profile_status = description_catalog_status(ctx.artifact)
    ctx.profile_status = profile_status
    ctx.profile_id = (
        str(profile_status["profile_id"])
        if profile_status.get("status") == "exact" and profile_status.get("profile_id")
        else None
    )
    meta["description_profile_status"] = profile_status
    if profile_status.get("status") != "exact":
        reminder_text = compose_description_profile_reminder(profile_status, [])
        meta["description_profile_reminder"] = {
            "shown_once": True,
            "recommendation": "full_within_known_scope",
            "sharing": "save_and_share_json_manually",
            "automatic_upload": False,
            **({"summary": reminder_text} if reminder_text else {}),
        }
        if ctx.observer is not None:
            if reminder_text:
                ctx.observer.log(reminder_text, level="warn")
            ctx.description_reminder_logged = True
    ctx.description_policy = default_description_policy(
        ctx.planner_preset,
        exact_profile_known=profile_status.get("status") == "exact",
    )
    ctx.operation_planner_options.update(
        description_policy=ctx.description_policy,
        description_profile_status=str(profile_status.get("status", "unknown")),
    )


def _classify_profile_candidates(ctx: B524ScanContext) -> None:
    # OP00 identifiers are not groups. Register candidates come from the
    # explicit profile; research explores GG 00..FF by separate register probes.
    candidates = [
        DiscoveredGroup(group=gg, descriptor=float("nan")) for gg in ctx.configured_groups
    ]
    ctx.classified = classify_groups(candidates, observer=ctx.observer)
    ctx.unknown_descriptor_types = sorted(
        {
            float(group.descriptor)
            for group in ctx.classified
            if not math.isnan(group.descriptor)
            and float(group.descriptor) not in _KNOWN_DESCRIPTOR_TYPES
        }
    )
    observer = ctx.observer
    if ctx.unknown_descriptor_types and observer is not None:
        descriptor_text = ", ".join(f"{value:g}" for value in ctx.unknown_descriptor_types)
        observer.log(
            "Found new descriptor class(es): "
            f"{descriptor_text}. Continue scan, then report with artifact JSON/HTML.",
            level="warn",
        )
    if observer is not None:
        observer.phase_finish("group_discovery")
        observer.log(f"Prepared {len(ctx.classified)} profile register candidates", level="info")


def _derive_group_bounds(ctx: B524ScanContext, fallback_bounds: GroupMetadata) -> None:
    # Scan coverage defaults come from the profile, or the fallback bounds for a
    # group without one.
    if ctx.observer is not None:
        ctx.observer.log("Deriving scan coverage defaults from known profiles", level="info")
    emit_trace_label(ctx.transport, "Deriving Scan Coverage")
    for group in ctx.classified:
        config = GROUP_CONFIG.get(group.group)
        ctx.metadata_map[group.group] = (
            GroupMetadata(
                rr_max=int(config["rr_max"]),
                ii_max=int(config["ii_max"]),
                source="profile",
            )
            if config is not None
            else fallback_bounds
        )
    assert ctx.description_policy is not None
    ctx.artifact["meta"]["parameter_description_policy"] = {
        "enabled": ctx.probe_constraints,
        "request_budget": ctx.description_budget,
        "legacy_request_budget": ctx.description_budget,
        "system_description_opcode": "0x01",
        "device_description_opcode": "0x07",
        "scope": "observed_writable_complete_identity",
        "scheduler": "family_reservation_then_instance_round_robin",
        "unknown_codec_raw_evidence": True,
        "profile_status": ctx.profile_status.get("status"),
        "profile_id": ctx.profile_status.get("profile_id"),
        "local_source": ctx.description_policy.local,
        "remote_source": ctx.description_policy.remote,
    }


def _log_unknown_group_operations(
    ctx: B524ScanContext, group: int, opcodes: tuple[RegisterOpcode, ...]
) -> None:
    if ctx.observer is None:
        return
    if opcodes:
        ctx.observer.log(
            f"GG=0x{group:02X}: responsive opcode namespaces "
            f"{', '.join(_hex_u8(opcode) for opcode in opcodes)}",
            level="info",
        )
    else:
        ctx.observer.log(
            f"GG=0x{group:02X}: no responsive opcode namespace detected; "
            "group will be skipped unless planner overrides it.",
            level="warn",
        )


def _resolve_group_operations(ctx: B524ScanContext, group: ClassifiedGroup) -> None:
    gg = group.group
    if ctx.explicit_plan is not None:
        ctx.resolved_group_opcodes[gg] = tuple(
            sorted({item.opcode for item in ctx.explicit_plan.values() if item.group == gg})
        )
        ctx.availability_group_opcodes[gg] = ()
        return
    if GROUP_CONFIG.get(gg) is not None:
        ctx.resolved_group_opcodes[gg] = profile_opcodes(gg, ctx.planner_preset)
        ctx.availability_group_opcodes[gg] = ctx.resolved_group_opcodes[gg]
        if gg == 0x0D:
            ctx.availability_group_opcodes[gg] = _sorted_namespace_opcodes(
                (*ctx.availability_group_opcodes[gg], 0x06)
            )
        return

    opcodes, probe_summary = _probe_unknown_group_opcodes(
        ctx.transport,
        dst=ctx.dst,
        group=gg,
        observer=ctx.observer,
        research=ctx.research_mode,
    )
    ctx.resolved_group_opcodes[gg] = opcodes
    ctx.availability_group_opcodes[gg] = opcodes
    ctx.unknown_opcode_probe_map[gg] = probe_summary
    if not opcodes:
        ctx.artifact["meta"]["scan_coverage"]["unknown_groups"].append(_hex_u8(gg))
    _log_unknown_group_operations(ctx, gg, opcodes)


def _record_discovery_suggestion(ctx: B524ScanContext) -> None:
    responsive_unknown_groups = sorted(
        group.group
        for group in ctx.classified
        if group.group not in GROUP_CONFIG and ctx.resolved_group_opcodes.get(group.group, ())
    )
    if responsive_unknown_groups and ctx.observer is not None:
        unknown_text = ", ".join(f"0x{gg:02X}" for gg in responsive_unknown_groups)
        ctx.observer.log(
            f"Found {len(responsive_unknown_groups)} unknown groups ({unknown_text}); "
            "deriving namespace coverage from opcode responsiveness probes.",
            level="warn",
        )
    if responsive_unknown_groups or ctx.unknown_descriptor_types:
        advisory: dict[str, Any] = {
            "kind": "protocol_discovery",
            "suggest_issue": True,
            "attach_artifacts": ["scan_json", "scan_html"],
        }
        if responsive_unknown_groups:
            advisory["unknown_groups"] = [f"0x{group:02X}" for group in responsive_unknown_groups]
        if ctx.unknown_descriptor_types:
            advisory["unknown_descriptor_types"] = ctx.unknown_descriptor_types
        ctx.artifact["meta"]["issue_suggestion"] = advisory


def _discovery_advisory(
    ctx: B524ScanContext,
    group: ClassifiedGroup,
    opcodes: tuple[RegisterOpcode, ...],
    descriptor_observed: float | None,
) -> dict[str, Any]:
    advisory: dict[str, Any] = {
        "kind": "profile_register_candidate",
        "semantic_authority": False,
        "proven_register_opcodes": [_hex_u8(opcode) for opcode in opcodes],
    }
    if group.group in ctx.unknown_opcode_probe_map:
        advisory["opcode_probe"] = ctx.unknown_opcode_probe_map[group.group]
    advisory["instance_discovery_decision"] = _instance_discovery_decision(
        group=group.group,
        multi_op=len(opcodes) > 1,
    )
    if descriptor_observed is not None:
        advisory["descriptor_observed"] = descriptor_observed
    if group.expected_descriptor is not None:
        advisory["descriptor_expected"] = group.expected_descriptor
    if group.descriptor_mismatch:
        advisory["descriptor_mismatch"] = True
    return advisory


def _record_discovered_group(ctx: B524ScanContext, group: ClassifiedGroup) -> None:
    meta = ctx.metadata_map[group.group]
    opcodes = ctx.availability_group_opcodes.get(group.group, ())
    # NaN descriptors come from synthetic research-mode injection;
    # store as None to keep JSON-serializable and avoid polluting analytics.
    descriptor_observed = None if math.isnan(group.descriptor) else group.descriptor
    advisory = _discovery_advisory(ctx, group, opcodes, descriptor_observed)
    for opcode in opcodes:
        _ensure_group_artifact(
            ctx.artifact,
            group=group.group,
            opcode=opcode,
            name=_group_name_for_opcode(group.group, opcode),
            descriptor_observed=descriptor_observed,
            ii_min=_ii_min_for_opcode(group=group.group, opcode=opcode, profile_id=ctx.profile_id),
            ii_max=_ii_max_for_opcode(
                group=group.group,
                default_ii_max=meta.ii_max,
                opcode=opcode,
            ),
            discovery_advisory=advisory,
        )


def discover_b524_scope(
    ctx: B524ScanContext,
    *,
    discover_groups_fn: GroupDiscovery,
    resolve_planner_mode: PlannerModeResolver,
    fallback_bounds: GroupMetadata,
) -> None:
    """Discovery phase: read system information and resolve the groups to scan.

    ``resolve_planner_mode`` runs after the group bounds are known and before
    unknown groups are probed, which keeps the operator's log lines in order.
    ``fallback_bounds`` size a group that has no profile.
    """

    if ctx.observer is not None:
        ctx.observer.phase_start("group_discovery", total=0x12)
    emit_trace_label(ctx.transport, "Reading System Information")
    started = time.perf_counter()
    started_requests = ctx.transport.counters.send_calls
    discovered = discover_groups_fn(ctx.transport, dst=ctx.dst, observer=ctx.observer)
    _record_system_information(ctx, discovered)
    _record_profile_context(ctx)
    _resolve_description_profile(ctx)
    ctx.group_discovery_duration_s = time.perf_counter() - started
    ctx.group_discovery_requests = ctx.transport.counters.send_calls - started_requests
    _classify_profile_candidates(ctx)
    _derive_group_bounds(ctx, fallback_bounds)
    ctx.planner_mode = resolve_planner_mode()
    for group in ctx.classified:
        _resolve_group_operations(ctx, group)
    _record_discovery_suggestion(ctx)
    for group in ctx.classified:
        _record_discovered_group(ctx, group)


# --- Availability phase ---------------------------------------------------------------


@dataclass(slots=True)
class _NamespaceProbeCounts:
    """Present and probed slot counts per namespace for the operator's summary."""

    known: dict[tuple[int, int], str] = field(default_factory=dict)
    unknown: dict[tuple[int, int], str] = field(default_factory=dict)


def _count_capacity(*, group: int, opcode: int, ii_max: int, profile_id: str | None = None) -> int:
    """Return the count-qualified slots for one OP00 family mapping."""

    if (opcode, group) == (0x02, 0x09):
        return 1
    if (opcode, group) == (0x02, 0x02):
        return ii_max if profile_id == "basv2_sw0507_hw1704_api1" else ii_max - 1
    return ii_max + (opcode != 0x06)


def _instance_slot_capacity(ctx: B524ScanContext, *, group: int, opcode: int, ii_max: int) -> int:
    """Return the number of instance slots probed in one instanced namespace."""

    if ctx.profile_id == "basv2_sw0507_hw1704_api1" and (opcode, group) == (0x02, 0x02):
        return ii_max + 1
    if opcode == 0x06 or group == 0x02:
        return ii_max
    return ii_max + 1


def _instance_discovery_total(ctx: B524ScanContext, targets: list[_AvailabilityTarget]) -> int:
    total = 0
    for group, meta, opcode in targets:
        if GROUP_CONFIG.get(group.group) is None:
            total += len(_unknown_instance_candidates(opcode=opcode, expanded=ctx.research_mode))
            continue
        namespace_ii_max = _ii_max_for_opcode(
            group=group.group, default_ii_max=meta.ii_max, opcode=opcode
        )
        if _is_instanced_group(namespace_ii_max):
            assert namespace_ii_max is not None
            total += _instance_slot_capacity(
                ctx, group=group.group, opcode=opcode, ii_max=namespace_ii_max
            )
    return total


def _record_target_topology(
    ctx: B524ScanContext, group: int, opcode: RegisterOpcode, ii_max: int | None
) -> None:
    _record_namespace_topology(
        ctx.artifact,
        group=group,
        opcode=opcode,
        ii_min=_ii_min_for_opcode(group=group, opcode=opcode, profile_id=ctx.profile_id),
        ii_max=ii_max,
    )


def _record_unknown_instance_probes(
    ctx: B524ScanContext, *, group: int, opcode: RegisterOpcode, instances: Sequence[int]
) -> None:
    coverage = ctx.artifact["meta"]["scan_coverage"]
    coverage["qualification_incomplete"] = True
    coverage["instance_discovery_complete"] = False
    coverage.setdefault("unknown_instance_probes", []).extend(
        {"read_opcode": _hex_u8(opcode), "group": _hex_u8(group), "instance": _hex_u8(ii)}
        for ii in instances
    )


def _availability_unknown(probe: InstanceAvailabilityProbe) -> bool:
    return (
        probe.evidence is not None and probe.evidence.get("availability_qualification") == "unknown"
    )


def _probe_unknown_namespace(
    ctx: B524ScanContext, target: _AvailabilityTarget, counts: _NamespaceProbeCounts
) -> None:
    group, meta, opcode = target
    total_slots = len(_unknown_instance_candidates(opcode=opcode, expanded=True))
    namespace_ii_max = _ii_max_for_opcode(
        group=group.group, default_ii_max=meta.ii_max, opcode=opcode
    )
    _record_target_topology(ctx, group.group, opcode, namespace_ii_max)
    instances_obj = _instances_object(ctx.artifact, group=group.group, opcode=opcode)
    emit_trace_label(
        ctx.transport,
        "Exploring unknown group "
        f"0x{group.group:02X} ({opcode_label(opcode)}) "
        "across multiple instances",
    )
    present_instances = _probe_unknown_present_instances(
        ctx.transport,
        dst=ctx.dst,
        group=group.group,
        opcode=opcode,
        observer=ctx.observer,
        expand_fallback=ctx.research_mode,
        research=ctx.research_mode,
    )
    _mark_present_instances(instances_obj, instances=present_instances)
    counts.unknown[(int(opcode), group.group)] = f"{len(present_instances)}/{total_slots}"


def _probe_single_slot_namespace(
    ctx: B524ScanContext,
    *,
    group: int,
    opcode: RegisterOpcode,
    contract: NamespaceAvailabilityContract,
    instances_obj: dict[str, Any],
    counts: _NamespaceProbeCounts,
    prober: InstanceAvailabilityProber,
) -> None:
    key = (int(opcode), group)
    if (opcode, group) != (0x02, 0x01):
        _mark_present_instances(instances_obj, instances=(0x00,))
        counts.known[key] = "1/1"
        return
    # The native hot-water namespace has one slot whose presence is probed.
    _record_availability_contract(ctx.artifact, group=group, opcode=opcode, contract=contract)
    probe = prober(ctx.transport, dst=ctx.dst, group=group, instance=0x00, opcode=opcode)
    _record_availability_probes(ctx.artifact, group=group, opcode=opcode, probes={0x00: probe})
    ctx.native_dhw_admitted[key] = probe.present
    if probe.present:
        _mark_present_instances(instances_obj, instances=(0x00,))
    if _availability_unknown(probe):
        _record_unknown_instance_probes(ctx, group=group, opcode=opcode, instances=(0x00,))
    counts.known[key] = "1/1" if probe.present else "0/1"


def _device_discovery_policy(*, bounded: bool, expected_count: int | None) -> str:
    if bounded:
        return "bounded_audit"
    if expected_count is not None:
        return "count_guided"
    return "first_confirmed_absence"


def _record_device_discovery(
    ctx: B524ScanContext,
    *,
    group: int,
    ii_max: int,
    probes: Mapping[int, InstanceAvailabilityProbe],
    expected_count: int | None,
) -> None:
    unknown_slots = [ii for ii, probe in probes.items() if probe.connection_state == "unknown"]
    stopped = any(probe.connection_state == "not_connected" for probe in probes.values())
    bounded = ctx.planner_preset != "recommended"
    confirmed_present = sum(probe.present for probe in probes.values())
    count_guided_complete = (
        ctx.planner_preset == "recommended"
        and expected_count is not None
        and confirmed_present >= expected_count
    )
    complete = not unknown_slots and (bounded or stopped or count_guided_complete)
    meta = ctx.artifact["meta"]
    meta.setdefault("device_discovery", {})[_hex_u8(group)] = {
        "read_opcode": "0x06",
        "presence_register": "0x0001",
        "first_instance": "0x01",
        "last_instance_bound": _hex_u8(ii_max),
        "policy": _device_discovery_policy(bounded=bounded, expected_count=expected_count),
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
        meta["scan_coverage"]["device_discovery_complete"] = False
        meta["scan_coverage"]["qualification_incomplete"] = True
    else:
        meta["scan_coverage"].setdefault("device_discovery_complete", True)


@dataclass(frozen=True, slots=True)
class _NamespaceCount:
    """Count identifier of one instanced namespace and the values it qualifies."""

    identifier: int | None
    capacity: int | None
    expected: int | None


def _namespace_count(
    ctx: B524ScanContext, *, group: int, opcode: RegisterOpcode, ii_max: int
) -> _NamespaceCount:
    count_id = COUNT_GROUP_IDS.get((int(opcode), group))
    if count_id is None:
        return _NamespaceCount(identifier=None, capacity=None, expected=None)
    value = ctx.information_values.get(count_id, float("nan"))
    if count_id in CAPACITY_SYSTEM_INFORMATION_IDS:
        return _NamespaceCount(
            identifier=count_id, capacity=supported_capacity(value), expected=None
        )
    capacity = _count_capacity(group=group, opcode=opcode, ii_max=ii_max, profile_id=ctx.profile_id)
    return _NamespaceCount(
        identifier=count_id,
        capacity=None,
        expected=expected_instance_count(value, capacity=capacity),
    )


def _record_instance_count(
    ctx: B524ScanContext,
    *,
    group: int,
    opcode: RegisterOpcode,
    count: _NamespaceCount,
    probes: Mapping[int, InstanceAvailabilityProbe],
    present_instances: tuple[int, ...],
    uncertain_instances: list[int],
) -> None:
    assert count.identifier is not None
    is_capacity = count.identifier in CAPACITY_SYSTEM_INFORMATION_IDS
    # The virtual water circuit is not counted by the circuit count.
    observed = len(
        [ii for ii in present_instances if not (opcode == 2 and group == 2 and ii == 0x09)]
    )
    ctx.artifact["meta"].setdefault("instance_counts", {})[
        f"{_hex_u8(opcode)}:{_hex_u8(group)}"
    ] = {
        "identifier": _hex_u16(count.identifier),
        "expected": count.expected,
        "semantics": "capacity" if is_capacity else "expected_population",
        "capacity": count.capacity,
        "observed": observed,
        "mismatch": count.expected is not None and count.expected != observed,
        "capacity_exceeded": count.capacity is not None and observed > count.capacity,
        "probed_instances": len(probes),
        "discovery_complete": not uncertain_instances
        and not any(probe.connection_state == "unknown" for probe in probes.values()),
    }


def _probe_instanced_slots(
    ctx: B524ScanContext,
    *,
    group: int,
    opcode: RegisterOpcode,
    ii_max: int,
    count: _NamespaceCount,
    instances_obj: dict[str, Any],
    prober: InstanceAvailabilityProber,
) -> dict[int, InstanceAvailabilityProbe]:
    recommended = ctx.planner_preset == "recommended"

    def retain_probe(ii: int, probe: InstanceAvailabilityProbe) -> None:
        _record_availability_probes(ctx.artifact, group=group, opcode=opcode, probes={ii: probe})
        if probe.present:
            _mark_present_instances(instances_obj, instances=(ii,))

    # A bundled installation observation documents one reference installation, not a
    # layout invariant: another installation may occupy a slot beyond the first
    # `capacity` instance numbers. It therefore never bounds, shrinks or widens the
    # probe window; an unreadable live capacity keeps the profile default and a live
    # zero keeps skipping the group. A bundled population is context only.
    return _probe_present_instances(
        ctx.transport,
        dst=ctx.dst,
        group=group,
        opcode=opcode,
        ii_max=0x00 if recommended and (opcode, group) == (0x02, 0x09) else ii_max,
        observer=ctx.observer,
        probe_instance_availability_fn=prober,
        stop_at_first_absence=recommended and opcode == 6,
        on_probe=retain_probe,
        expected_count=count.expected if recommended else None,
        capacity=count.capacity if recommended else None,
        presence_profile=ctx.profile_id,
    )


def _probe_instanced_namespace(
    ctx: B524ScanContext,
    *,
    group: int,
    opcode: RegisterOpcode,
    ii_max: int,
    instances_obj: dict[str, Any],
    counts: _NamespaceProbeCounts,
    prober: InstanceAvailabilityProber,
) -> None:
    emit_trace_label(
        ctx.transport,
        f"Identifying instances in group 0x{group:02X} ({opcode_label(opcode)})",
    )
    count = _namespace_count(ctx, group=group, opcode=opcode, ii_max=ii_max)
    probes = _probe_instanced_slots(
        ctx,
        group=group,
        opcode=opcode,
        ii_max=ii_max,
        count=count,
        instances_obj=instances_obj,
        prober=prober,
    )
    _record_availability_probes(ctx.artifact, group=group, opcode=opcode, probes=probes)
    if opcode == 6 and group in CONNECTED_DEVICE_GROUPS:
        _record_device_discovery(
            ctx, group=group, ii_max=ii_max, probes=probes, expected_count=count.expected
        )
    uncertain_instances = [ii for ii, probe in probes.items() if _availability_unknown(probe)]
    if uncertain_instances:
        _record_unknown_instance_probes(
            ctx, group=group, opcode=opcode, instances=uncertain_instances
        )
    present_instances = tuple(ii for ii, probe in probes.items() if probe.present)
    if count.identifier is not None:
        _record_instance_count(
            ctx,
            group=group,
            opcode=opcode,
            count=count,
            probes=probes,
            present_instances=present_instances,
            uncertain_instances=uncertain_instances,
        )
    _mark_present_instances(instances_obj, instances=present_instances)
    slot_capacity = _instance_slot_capacity(ctx, group=group, opcode=opcode, ii_max=ii_max)
    counts.known[(int(opcode), group)] = f"{len(present_instances)}/{slot_capacity}"


def _probe_known_namespace(
    ctx: B524ScanContext,
    target: _AvailabilityTarget,
    counts: _NamespaceProbeCounts,
    prober: InstanceAvailabilityProber,
) -> None:
    group, meta, opcode = target
    namespace_ii_max = _ii_max_for_opcode(
        group=group.group, default_ii_max=meta.ii_max, opcode=opcode
    )
    _record_target_topology(ctx, group.group, opcode, namespace_ii_max)
    contract = namespace_availability_contract(
        group=group.group, opcode=opcode, presence_profile=ctx.profile_id
    )
    instances_obj = _instances_object(ctx.artifact, group=group.group, opcode=opcode)
    if not _is_instanced_group(namespace_ii_max):
        _probe_single_slot_namespace(
            ctx,
            group=group.group,
            opcode=opcode,
            contract=contract,
            instances_obj=instances_obj,
            counts=counts,
            prober=prober,
        )
        return
    assert namespace_ii_max is not None
    _record_availability_contract(ctx.artifact, group=group.group, opcode=opcode, contract=contract)
    _probe_instanced_namespace(
        ctx,
        group=group.group,
        opcode=opcode,
        ii_max=namespace_ii_max,
        instances_obj=instances_obj,
        counts=counts,
        prober=prober,
    )


def _connected_remote_instances(artifact: dict[str, Any]) -> int:
    remote_group_object = artifact["operations"].get("0x06", {}).get("groups", {})
    if not isinstance(remote_group_object, dict):
        return 0
    return sum(
        1
        for group_key, group_object in remote_group_object.items()
        if int(group_key, 0) in CONNECTED_DEVICE_GROUPS
        if isinstance(group_object, dict)
        for probe in group_object.get("availability_probes", {}).values()
        if isinstance(probe, dict)
        and probe.get("present") is True
        and (probe.get("connection_state") == "connected")
    )


def _record_device_count(ctx: B524ScanContext) -> None:
    observed_remote_instances = _connected_remote_instances(ctx.artifact)
    remote_slot_capacity = sum(
        _ii_max_for_opcode(
            group=group.group,
            default_ii_max=ctx.metadata_map[group.group].ii_max,
            opcode=0x06,
        )
        or 0
        for group in ctx.classified
        if 0x06 in ctx.availability_group_opcodes.get(group.group, ())
    )
    aggregate_device_count = expected_instance_count(
        ctx.information_values.get(4, float("nan")), capacity=remote_slot_capacity
    )
    meta = ctx.artifact["meta"]
    meta["device_count"] = {
        "identifier": "0x0004",
        "expected": aggregate_device_count,
        "observed": observed_remote_instances,
        "mismatch": (
            aggregate_device_count is not None
            and aggregate_device_count != observed_remote_instances
        ),
    }
    module_capacity = module_capacity_crosscheck(
        ctx.information_values.get(8, float("nan")), ctx.information_values.get(9, float("nan"))
    )
    if module_capacity is not None:
        meta["module_capacity_crosscheck"] = {
            "vr70_identifier": "0x0008",
            "vr71_identifier": "0x0009",
            "capacity": module_capacity,
            "semantics": "crosscheck_only",
        }


def _namespace_register_text(group: int, opcode: RegisterOpcode, default_rr_max: int) -> str:
    if (opcode, group) == (0x06, 0x0D):
        return "RR_max=unknown (probe-only)"
    rr_max = _rr_max_for_opcode(group=group, default_rr_max=default_rr_max, opcode=opcode)
    return f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)"


def _log_namespace_summary(
    observer: ScanObserver, targets: list[_AvailabilityTarget], counts: _NamespaceProbeCounts
) -> None:
    for group, meta, opcode in targets:
        key = (int(opcode), group.group)
        experimental = key in counts.unknown
        count = counts.unknown[key] if experimental else counts.known.get(key)
        if count is None:
            continue
        qualifier = " (experimental)" if experimental else ""
        observer.log(
            f"OP=0x{opcode:02X} GG=0x{group.group:02X}: "
            f"{_group_name_for_opcode(group.group, opcode)} {count} present{qualifier}, "
            f"{_namespace_register_text(group.group, opcode, meta.rr_max)}",
            level="info",
        )


def _default_event_instances(ctx: B524ScanContext) -> dict[EventProfileName, tuple[int, ...]]:
    system_in_scope = 0x02 in ctx.resolved_group_opcodes.get(0x00, ())
    return {
        "system": (0x00,) if system_in_scope else (),
        "dhw": (
            _present_instances_for_opcode(ctx.artifact, group=0x01, opcode=0x02)
            if ctx.native_dhw_admitted.get((0x02, 0x01), False)
            else ()
        ),
        "zone": _present_instances_for_opcode(ctx.artifact, group=0x03, opcode=0x02),
    }


def _default_event_metadata(
    instances: Mapping[EventProfileName, tuple[int, ...]],
) -> dict[str, Any]:
    return {
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
                "instances": [f"0x{instance:02X}" for instance in profile_instances],
                "status": (
                    "candidate_from_scalar_anchor"
                    if profile_instances
                    else "not_scheduled_no_scalar_anchor"
                ),
            }
            for profile, profile_instances in instances.items()
        },
        "setpoint_policy": "conditional_exact_usable_op09_pair",
    }


def _mark_scheduled_profiles(metadata: dict[str, Any], status: str) -> None:
    for profile_metadata in metadata["profiles"].values():
        if profile_metadata["instances"]:
            profile_metadata["status"] = status


def _admit_default_event_requests(
    ctx: B524ScanContext,
    requests: Sequence[B524OperationReadRequest],
    metadata: dict[str, Any],
) -> None:
    try:
        validate_operation_read_identity(
            requests, device_id=ctx.device_id, manufacturer=ctx.manufacturer
        )
    except ValueError:
        metadata["status"] = "not_scheduled_unknown_identity"
        _mark_scheduled_profiles(metadata, "not_scheduled_unknown_identity")
        return
    ctx.operation_requests.extend(requests)
    ctx.operation_selection.extend([True] * len(requests))
    metadata["automatic_default_applied"] = True
    metadata["status"] = "scheduled_candidates"
    metadata["worst_case_requests"] = len(requests)
    _mark_scheduled_profiles(metadata, "scheduled_candidate")


def _schedule_default_events(ctx: B524ScanContext) -> None:
    """Schedule the default event reads anchored on present scalar instances."""

    if ctx.explicit_operation_override:
        ctx.artifact["meta"]["b524_event_acquisition"] = {
            "source": "explicit_read_plan_override",
            "automatic_default_applied": False,
        }
        return
    instances = _default_event_instances(ctx)
    requests = build_default_event_requests(
        instances=instances, weekday_codes=DEFAULT_EVENT_WEEKDAY_CODES
    )
    metadata = _default_event_metadata(instances)
    if requests:
        _admit_default_event_requests(ctx, requests, metadata)
    else:
        metadata["status"] = "not_scheduled_no_scalar_anchor"
    ctx.artifact["meta"]["b524_event_acquisition"] = metadata


def probe_b524_availability(
    ctx: B524ScanContext, *, probe_instance_availability_fn: InstanceAvailabilityProber
) -> None:
    """Availability phase: find the present instances and schedule the default event reads."""

    targets = _instance_discovery_targets(
        ctx.classified, ctx.metadata_map, ctx.availability_group_opcodes
    )
    instance_total = _instance_discovery_total(ctx, targets)
    if ctx.observer is not None:
        ctx.observer.phase_start("instance_discovery", total=instance_total or 1)
    started = time.perf_counter()
    started_requests = ctx.transport.counters.send_calls
    counts = _NamespaceProbeCounts()
    for target in targets:
        if GROUP_CONFIG.get(target[0].group) is None:
            _probe_unknown_namespace(ctx, target, counts)
        else:
            _probe_known_namespace(ctx, target, counts, probe_instance_availability_fn)
    _record_device_count(ctx)
    if ctx.observer is not None:
        _log_namespace_summary(ctx.observer, targets, counts)
        ctx.observer.phase_finish("instance_discovery")
    ctx.instance_discovery_duration_s = time.perf_counter() - started
    ctx.instance_discovery_requests = ctx.transport.counters.send_calls - started_requests
    ctx.artifact["meta"]["scan_coverage"]["discovery_completed"] = True
    _schedule_default_events(ctx)


# --- Scan phase ---------------------------------------------------------------------


class DescriptionCandidateSelector(Protocol):
    """Select the observed writable registers whose descriptions are read live."""

    def __call__(
        self,
        artifact: dict[str, Any],
        candidates: list[DescriptionCandidate],
        entries: dict[tuple[int, int, int, int], dict[str, Any]],
        /,
        *,
        policy: DescriptionPolicySelection,
    ) -> tuple[
        list[DescriptionCandidate],
        dict[tuple[int, int, int, int], dict[str, Any]],
        list[dict[str, Any]],
    ]: ...


class ArtifactAnnotator(Protocol):
    """Annotate the scanned register values in place."""

    def __call__(self, artifact: dict[str, Any], /) -> None: ...


@dataclass(frozen=True, slots=True)
class B524ScanCollaborators:
    """Planner surfaces, register annotation sources and helpers of the scan phase."""

    console: Console | None
    planners: ScanPlanners | None
    planner_ui: PlannerUiMode
    hotkey_reader_cls: PlannerHotkeyReaderFactory
    ebusd_schema: EbusdCsvSchema | None
    myvaillant_map: MyvaillantRegisterMap | None
    select_description_candidates: DescriptionCandidateSelector
    annotate_artifact: ArtifactAnnotator


@dataclass(frozen=True, slots=True)
class _OperatorPlanner:
    """Interactive planner offered to the operator before and during the register scan."""

    console: Console
    planners: ScanPlanners
    observer: ScanObserver
    planner_ui: PlannerUiMode
    groups: list[PlannerGroup]
    request_rate_rps: float | None


@dataclass(slots=True)
class _RegisterScanRun:
    """Plan and progress of one register scan, kept across replanning."""

    plan: dict[PlanKey, GroupScanPlan]
    done: set[RegisterTask]
    work_queue: deque[RegisterTask]
    live_constraints: dict[int, dict[int, ConstraintEntry]]
    active_start: float
    active_elapsed: float = 0.0
    constraint_mismatches: list[dict[str, Any]] = field(default_factory=list)


def _planner_kwargs(planner_fn: Callable[..., object], options: dict[str, Any]) -> dict[str, Any]:
    """Pass only the planner options that the planner function accepts."""

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


def _record_planner_selection(ctx: B524ScanContext) -> None:
    """Record the preset and description sources chosen in the planner."""

    policy = ctx.description_policy
    assert policy is not None
    meta = ctx.artifact["meta"]
    meta["parameter_description_policy"].update(
        local_source=policy.local,
        remote_source=policy.remote,
        local_override=policy.local_override,
        remote_override=policy.remote_override,
        selected_preset=ctx.planner_preset,
    )
    meta["scan_coverage"]["preset"] = ctx.planner_preset
    store_operation_read_plan(ctx)


def _measured_request_rate(ctx: B524ScanContext) -> float | None:
    measured_requests = ctx.group_discovery_requests + ctx.instance_discovery_requests
    measured_duration_s = ctx.group_discovery_duration_s + ctx.instance_discovery_duration_s
    if measured_requests > 0 and measured_duration_s > 0:
        return measured_requests / measured_duration_s
    return None


def _planner_present_instances(
    ctx: B524ScanContext,
    *,
    group: int,
    opcode: RegisterOpcode,
    requested_plan: GroupScanPlan | None,
    planner_ii_max: int | None,
) -> tuple[int, ...]:
    present_instances = _present_instances_for_opcode(ctx.artifact, group=group, opcode=opcode)
    if requested_plan is not None:
        present_instances = requested_plan.instances
    if planner_ii_max is None and not present_instances:
        present_instances = (0x00,)
    return present_instances


def _planner_expected_count(
    ctx: B524ScanContext, *, group: int, opcode: RegisterOpcode, planner_ii_max: int | None
) -> int | None:
    count_id = COUNT_GROUP_IDS.get((int(opcode), group), -1)
    if planner_ii_max is None or count_id in CAPACITY_SYSTEM_INFORMATION_IDS:
        return None
    return expected_instance_count(
        ctx.information_values.get(count_id, float("nan")),
        capacity=_count_capacity(
            group=group, opcode=opcode, ii_max=planner_ii_max, profile_id=ctx.profile_id
        ),
    )


def _planner_group(
    ctx: B524ScanContext, group: ClassifiedGroup, opcode: RegisterOpcode, *, multi_op: bool
) -> PlannerGroup:
    gg = group.group
    config = GROUP_CONFIG.get(gg)
    group_meta = ctx.metadata_map[gg]
    requested_plan = (
        ctx.explicit_plan.get(_plan_key(gg, opcode)) if ctx.explicit_plan is not None else None
    )
    qualified_rr_max = (
        planner_rr_max(gg, opcode)
        if config is not None
        else _rr_max_for_opcode(group=gg, default_rr_max=group_meta.rr_max, opcode=opcode)
    )
    planner_ii_max = _planner_ii_max(
        _ii_max_for_opcode(group=gg, default_ii_max=group_meta.ii_max, opcode=opcode)
    )
    return PlannerGroup(
        group=gg,
        opcode=opcode,
        name=_group_name_for_opcode(gg, opcode),
        descriptor=group.descriptor,
        known=config is not None,
        ii_max=planner_ii_max,
        rr_max=requested_plan.rr_max if requested_plan is not None else qualified_rr_max,
        rr_max_full=(
            _rr_max_full_for_opcode(group=gg, opcode=opcode)
            if qualified_rr_max is not None
            else None
        ),
        present_instances=_planner_present_instances(
            ctx,
            group=gg,
            opcode=opcode,
            requested_plan=requested_plan,
            planner_ii_max=planner_ii_max,
        ),
        ii_min=_ii_min_for_opcode(group=gg, opcode=opcode, profile_id=ctx.profile_id),
        expected_count=_planner_expected_count(
            ctx, group=gg, opcode=opcode, planner_ii_max=planner_ii_max
        ),
        namespace_label=(opcode_label(opcode) if multi_op else None),
        recommended=_planner_group_is_recommended(group=gg, opcode=opcode),
        instances_probed=opcode in ctx.resolved_group_opcodes.get(gg, ()),
        research_rr_max=_rr_max_full_for_opcode(group=gg, opcode=opcode),
        native_dhw_admitted=ctx.native_dhw_admitted.get((int(opcode), gg), False),
    )


def _planner_groups(ctx: B524ScanContext) -> list[PlannerGroup]:
    planner_groups: list[PlannerGroup] = []
    for group in ctx.classified:
        opcodes = _sorted_namespace_opcodes(
            (*planner_native_opcodes(group.group), *ctx.resolved_group_opcodes.get(group.group, ()))
        )
        planner_groups.extend(
            _planner_group(ctx, group, opcode, multi_op=len(opcodes) > 1) for opcode in opcodes
        )
    return planner_groups


def _observed_register_plan(ctx: B524ScanContext) -> dict[PlanKey, GroupScanPlan]:
    """Plan every resolved namespace over its present instances."""

    plan: dict[PlanKey, GroupScanPlan] = {}
    for group in ctx.classified:
        meta = ctx.metadata_map[group.group]
        for opcode in ctx.resolved_group_opcodes.get(group.group, ()):
            namespace_ii_max = _ii_max_for_opcode(
                group=group.group, default_ii_max=meta.ii_max, opcode=opcode
            )
            present_instances = _present_instances_for_opcode(
                ctx.artifact, group=group.group, opcode=opcode
            )
            plan[_plan_key(group.group, opcode)] = GroupScanPlan(
                group=group.group,
                opcode=opcode,
                rr_max=_rr_max_for_opcode(
                    group=group.group, default_rr_max=meta.rr_max, opcode=opcode
                ),
                instances=(
                    (0x00,) if not _is_instanced_group(namespace_ii_max) else present_instances
                ),
            )
    return plan


def _default_register_plan(
    ctx: B524ScanContext, planner_groups: list[PlannerGroup]
) -> dict[PlanKey, GroupScanPlan]:
    if ctx.planner_preset != "custom":
        plan = build_plan_from_preset(planner_groups, preset=ctx.planner_preset)
        return _normalize_profile_plan_instances(plan, profile_id=ctx.profile_id)
    if ctx.explicit_plan is not None:
        return dict(ctx.explicit_plan)
    return _observed_register_plan(ctx)


def _operator_planner(
    ctx: B524ScanContext,
    collaborators: B524ScanCollaborators,
    planner_groups: list[PlannerGroup],
    request_rate_rps: float | None,
) -> _OperatorPlanner | None:
    if (
        ctx.planner_mode == "disabled"
        or collaborators.console is None
        or ctx.observer is None
        or collaborators.planners is None
    ):
        return None
    return _OperatorPlanner(
        console=collaborators.console,
        planners=collaborators.planners,
        observer=ctx.observer,
        planner_ui=collaborators.planner_ui,
        groups=planner_groups,
        request_rate_rps=request_rate_rps,
    )


def _apply_planner_result(
    ctx: B524ScanContext, selected: Mapping[PlanKey, GroupScanPlan]
) -> dict[PlanKey, GroupScanPlan]:
    if isinstance(selected, PlannerSelection):
        ctx.planner_preset = selected.selected_preset
        ctx.description_policy = selected.description_policy
        return selected.plan
    return dict(selected)


def _fall_back_to_classic_planner(
    ctx: B524ScanContext, operator: _OperatorPlanner, exc: Exception, *, failure: str
) -> None:
    if operator.planner_ui == "textual":
        raise RuntimeError(f"Textual planner requested but {failure}.") from exc
    operator.observer.log(
        f"Textual planner {failure}; falling back to classic planner.", level="warn"
    )
    ctx.planner_mode = "classic"


def _textual_plan(
    ctx: B524ScanContext,
    operator: _OperatorPlanner,
    default_plan: dict[PlanKey, GroupScanPlan],
) -> dict[PlanKey, GroupScanPlan] | None:
    """Return the full-screen planner's plan, or ``None`` after a classic fallback."""

    try:
        run_textual_scan_plan = operator.planners.load_textual_scan_plan()
    except Exception as exc:
        _fall_back_to_classic_planner(ctx, operator, exc, failure="unavailable")
        return None
    try:
        selected = run_textual_scan_plan(
            operator.groups,
            request_rate_rps=operator.request_rate_rps,
            default_plan=default_plan,
            default_preset=ctx.planner_preset,
            system_information=ctx.artifact["meta"]["system_information"],
            **_planner_kwargs(run_textual_scan_plan, ctx.operation_planner_options),
        )
    except Exception as exc:
        _fall_back_to_classic_planner(ctx, operator, exc, failure="failed to start")
        return None
    if selected is None:
        raise KeyboardInterrupt
    return _apply_planner_result(ctx, selected)


def _operator_plan(
    ctx: B524ScanContext,
    operator: _OperatorPlanner,
    default_plan: dict[PlanKey, GroupScanPlan],
) -> dict[PlanKey, GroupScanPlan]:
    """Let the operator choose the register plan, starting from ``default_plan``."""

    plan = default_plan
    if ctx.planner_mode == "textual":
        textual_plan = _textual_plan(ctx, operator, default_plan)
        if textual_plan is not None:
            plan = textual_plan
    if ctx.planner_mode == "classic":
        prompt_scan_plan = operator.planners.prompt_scan_plan
        selected = prompt_scan_plan(
            operator.console,
            operator.groups,
            request_rate_rps=operator.request_rate_rps,
            default_plan=default_plan,
            default_preset=ctx.planner_preset,
            system_information=ctx.artifact["meta"]["system_information"],
            **_planner_kwargs(prompt_scan_plan, ctx.operation_planner_options),
        )
        plan = _apply_planner_result(ctx, selected)
    if ctx.planner_preset != "custom":
        plan = _normalize_profile_plan_instances(plan, profile_id=ctx.profile_id)
    return plan


def _record_plan_estimates(ctx: B524ScanContext, plan: dict[PlanKey, GroupScanPlan]) -> None:
    scan_plan = ctx.artifact["meta"]["scan_plan"]
    scan_plan["groups"] = _scan_plan_meta_groups(plan)
    scan_plan["estimated_register_requests"] = estimate_register_requests(plan)
    scan_plan["estimated_operation_requests_worst_case"] = sum(ctx.operation_selection)
    scan_plan["estimated_total_requests_worst_case"] = estimate_register_requests(plan) + sum(
        ctx.operation_selection
    )


def _record_register_plan(
    ctx: B524ScanContext,
    plan: dict[PlanKey, GroupScanPlan],
    request_rate_rps: float | None,
    live_constraints: dict[int, dict[int, ConstraintEntry]],
) -> None:
    _record_planner_selection(ctx)
    meta = ctx.artifact["meta"]
    meta["scan_plan"] = {}
    _record_plan_estimates(ctx, plan)
    meta["scan_plan"]["measured_request_rate_rps"] = (
        round(request_rate_rps, 4) if request_rate_rps else None
    )
    meta["group_metadata_bounds"] = _metadata_map_to_dict(ctx.metadata_map)
    meta["constraint_probe_enabled"] = False
    meta["parameter_description_requests"] = 0
    meta["constraint_dictionary"] = _constraint_map_to_dict(live_constraints)


def _replan_register_scan(
    ctx: B524ScanContext,
    operator: _OperatorPlanner,
    hotkeys: PlannerHotkeys,
    run: _RegisterScanRun,
) -> None:
    """Pause progress rendering and replan without rewriting scanned data."""

    run.active_elapsed += time.perf_counter() - run.active_start
    with hotkeys.suspend(), operator.observer.suspend():
        ctx.operation_planner_options["description_policy"] = ctx.description_policy
        run.plan = _operator_plan(ctx, operator, run.plan)
    _record_planner_selection(ctx)
    _record_plan_estimates(ctx, run.plan)
    run.work_queue = deque(build_work_queue(run.plan, done=run.done))
    operator.observer.phase_set_total(
        "register_scan", total=(len(run.done) + len(run.work_queue)) or 1
    )
    remaining = len(run.work_queue)
    task_rate_rps = (len(run.done) / run.active_elapsed) if run.active_elapsed > 0 else None
    if task_rate_rps is None or task_rate_rps <= 0:
        operator.observer.log(
            f"Updated scan plan: remaining {remaining} register reads", level="info"
        )
    else:
        eta_s = remaining / task_rate_rps if remaining > 0 else 0.0
        operator.observer.log(
            f"Updated scan plan: remaining {remaining} register reads "
            f"(ETA {eta_s:.1f}s @ {task_rate_rps:.2f} rr/s)",
            level="info",
        )
    run.active_start = time.perf_counter()


def _register_type_hint(
    collaborators: B524ScanCollaborators, task: RegisterTask
) -> tuple[EbusdRegisterSchemaEntry | None, str | None]:
    schema_entry = (
        collaborators.ebusd_schema.lookup(
            opcode=task.opcode, group=task.group, instance=task.instance, register=task.register
        )
        if collaborators.ebusd_schema is not None
        else None
    )
    myvaillant_entry = (
        collaborators.myvaillant_map.lookup(
            group=task.group, instance=task.instance, register=task.register, opcode=task.opcode
        )
        if collaborators.myvaillant_map is not None
        else None
    )
    if myvaillant_entry is not None and myvaillant_entry.type_hint is not None:
        return schema_entry, myvaillant_entry.type_hint
    return schema_entry, (schema_entry.type_spec if schema_entry is not None else None)


def _entry_read_opcode(entry: RegisterEntry) -> int | None:
    read_opcode = entry.get("read_opcode")
    if not isinstance(read_opcode, str):
        return None
    try:
        return int(read_opcode, 0)
    except ValueError:
        return None


def _annotate_register_map(
    entry: RegisterEntry, task: RegisterTask, register_map: MyvaillantRegisterMap
) -> None:
    mapped = register_map.lookup(
        group=task.group,
        instance=task.instance,
        register=task.register,
        opcode=_entry_read_opcode(entry),
    )
    if mapped is None:
        return
    if mapped.register_class is not None:
        entry["register_class"] = mapped.register_class
    if entry.get("ebusd_name") is None:
        mapped_ebusd_name = mapped.resolved_ebusd_name(
            group=task.group, instance=task.instance, register=task.register
        )
        if mapped_ebusd_name:
            entry["ebusd_name"] = mapped_ebusd_name


_CIRCUIT_PROFILE_CANDIDATE_NAMES = {
    0x0007: "circuit_target_flow_temperature",
    0x000E: "circuit_setback_mode",
    0x0014: "circuit_outside_temperature_threshold",
    0x001E: "circuit_status",
}

_VENTILATION_CANDIDATE_NAMES = {
    2: "operating_mode_for_air_ventilation",
    4: "status_special_function_ventilation",
    7: "holiday_end",
    8: "holiday_end_time",
    9: "holiday_start",
    10: "holiday_start_time",
    13: "day_maximum_fan_stage",
    14: "night_maximum_fan_stage",
}


def _annotate_register_names(
    ctx: B524ScanContext, entry: RegisterEntry, task: RegisterTask
) -> None:
    canonical_name = b524_register_name(
        opcode=task.opcode, group=task.group, register=task.register
    )
    if canonical_name is not None:
        entry["register_name"] = canonical_name
    if ctx.profile_id != "basv2_sw0507_hw1704_api1" or (task.opcode, task.group) != (0x02, 0x02):
        return
    if task.register in _CIRCUIT_PROFILE_CANDIDATE_NAMES:
        entry["candidate_name"] = _CIRCUIT_PROFILE_CANDIDATE_NAMES[task.register]
        entry["candidate_evidence"] = "basv2_sw0507_profile_cross_source_candidate"
    if task.register == 0x0020 and entry.get("type") == "UCH":
        entry["codec_evidence"] = {
            "observed": "UCH",
            "width": 1,
            "qualification": "profile_observed",
            "contradicts": "legacy_f32_prose",
        }


def _apply_register_constraint(
    ctx: B524ScanContext, entry: RegisterEntry, task: RegisterTask, run: _RegisterScanRun
) -> None:
    constraint = _constraint_for_register(
        opcode=task.opcode,
        group=task.group,
        instance=task.instance,
        register=task.register,
        live_constraints=run.live_constraints,
        static_constraints=ctx.static_constraints,
    )
    if constraint is None:
        return
    _apply_constraint_metadata(entry, constraint)
    mismatch_reason = _constraint_mismatch_reason(entry, constraint)
    if mismatch_reason is None:
        return
    entry["constraint_mismatch_reason"] = mismatch_reason
    run.constraint_mismatches.append(
        {
            "group": _hex_u8(task.group),
            "instance": _hex_u8(task.instance),
            "register": _hex_u16(task.register),
            "read_opcode": str(entry.get("read_opcode")),
            "name": entry.get("register_name") or entry.get("ebusd_name"),
            "value": entry.get("value"),
            "constraint_min": constraint.min_value,
            "constraint_max": constraint.max_value,
            "constraint_type": constraint.kind,
            "constraint_source": constraint.source,
            "constraint_scope": constraint.scope,
            "constraint_qualified": False,
            "constraint_provenance": constraint.provenance,
            "constraint_probe_protocol": CONSTRAINT_SCOPE_PROTOCOL,
            "reason": mismatch_reason,
        }
    )


def _annotate_register_attributes(entry: RegisterEntry) -> None:
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


def _collect_description_candidate(
    ctx: B524ScanContext, entry: RegisterEntry, task: RegisterTask
) -> None:
    if not ctx.probe_constraints or entry.get("response_state") != "active":
        return
    flags = entry.get("flags")
    type_spec = entry.get("type")
    if isinstance(flags, int) and flags in {2, 3}:
        identity = (int(task.opcode), task.group, task.instance, task.register)
        ctx.observed_description_candidates.append(
            DescriptionCandidate(
                *identity,
                type_spec if isinstance(type_spec, str) else None,
                entry.get("codec_provenance", "length_inferred"),
            )
        )
        ctx.observed_description_entries[identity] = cast(dict[str, Any], entry)


def _annotate_ventilation_candidate(
    ctx: B524ScanContext, entry: RegisterEntry, task: RegisterTask
) -> None:
    if (
        task.opcode == 2
        and task.group == 9
        and ctx.ventilation_hint
        and task.register in _VENTILATION_CANDIDATE_NAMES
    ):
        entry["candidate_name"] = _VENTILATION_CANDIDATE_NAMES[task.register]
        entry["candidate_evidence"] = "profile_scoped_reconstruction_recovair_count_nonzero"


def _store_register_entry(ctx: B524ScanContext, entry: RegisterEntry, task: RegisterTask) -> None:
    _ensure_group_artifact(
        ctx.artifact,
        group=task.group,
        opcode=task.opcode,
        name="Unknown",
        descriptor_observed=0.0,
    )
    task_group_meta = ctx.metadata_map.get(task.group)
    if task_group_meta is not None:
        _record_target_topology(
            ctx,
            task.group,
            task.opcode,
            _ii_max_for_opcode(
                group=task.group, default_ii_max=task_group_meta.ii_max, opcode=task.opcode
            ),
        )
    instances_obj = _instances_object(ctx.artifact, group=task.group, opcode=task.opcode)
    instance_obj = instances_obj.setdefault(_hex_u8(task.instance), {"present": False})
    if not isinstance(instance_obj, dict):
        return
    if task.opcode == 2 and task.group == 2 and task.instance == 0x09:
        instance_obj.update(
            designation="virtual_water_circuit",
            protocol_role="unknown",
            role_qualification="unqualified",
        )
    registers = instance_obj.setdefault("registers", {})
    registers[_hex_u16(task.register)] = entry


def _read_planned_register(
    ctx: B524ScanContext,
    collaborators: B524ScanCollaborators,
    run: _RegisterScanRun,
    task: RegisterTask,
) -> None:
    if ctx.observer is not None:
        ctx.observer.status(
            f"Read GG=0x{task.group:02X} II=0x{task.instance:02X} RR=0x{task.register:04X}"
        )
    schema_entry, type_hint = _register_type_hint(collaborators, task)
    entry = read_register(
        ctx.transport,
        ctx.dst,
        task.opcode,
        group=task.group,
        instance=task.instance,
        register=task.register,
        type_hint=type_hint,
    )
    if ctx.observer is not None:
        ctx.observer.phase_advance("register_scan", advance=1)
    if schema_entry is not None:
        entry["ebusd_name"] = schema_entry.name
    if collaborators.myvaillant_map is not None:
        _annotate_register_map(entry, task, collaborators.myvaillant_map)
    _annotate_register_names(ctx, entry, task)
    _apply_register_constraint(ctx, entry, task, run)
    _annotate_register_attributes(entry)
    _collect_description_candidate(ctx, entry, task)
    _annotate_ventilation_candidate(ctx, entry, task)
    run.done.add(task)
    _store_register_entry(ctx, entry, task)


def _read_registers(
    ctx: B524ScanContext,
    collaborators: B524ScanCollaborators,
    operator: _OperatorPlanner | None,
    run: _RegisterScanRun,
) -> None:
    with collaborators.hotkey_reader_cls(enabled=(ctx.planner_mode != "disabled")) as hotkeys:
        while run.work_queue:
            if operator is not None and hotkeys.poll():
                _replan_register_scan(ctx, operator, hotkeys, run)
                continue
            _read_planned_register(ctx, collaborators, run, run.work_queue.popleft())


def _record_remote_description_reminder(
    ctx: B524ScanContext, remote_rows: list[dict[str, Any]]
) -> None:
    if not remote_rows_need_reminder(remote_rows):
        return
    reminder_text = compose_description_profile_reminder(
        ctx.profile_status, remote_rows_with_designation(ctx.artifact, remote_rows)
    )
    ctx.artifact["meta"].setdefault(
        "description_profile_reminder",
        {
            "shown_once": True,
            "recommendation": "full_within_known_scope",
            "sharing": "save_and_share_json_manually",
            "automatic_upload": False,
            **({"summary": reminder_text} if reminder_text else {}),
        },
    )
    if ctx.observer is not None and not ctx.description_reminder_logged and reminder_text:
        ctx.observer.log(reminder_text, level="warn")
        ctx.description_reminder_logged = True


def _select_description_candidates(
    ctx: B524ScanContext, select: DescriptionCandidateSelector
) -> list[dict[str, Any]]:
    """Select the live description candidates; return the remote profile statuses."""

    assert ctx.description_policy is not None
    ctx.description_candidates, ctx.description_entries, remote_profile_statuses = select(
        ctx.artifact,
        ctx.observed_description_candidates,
        ctx.observed_description_entries,
        policy=ctx.description_policy,
    )
    return remote_profile_statuses


def _record_remote_profile_statuses(
    ctx: B524ScanContext, remote_profile_statuses: list[dict[str, Any]]
) -> None:
    if remote_profile_statuses:
        ctx.artifact["meta"]["description_remote_profile_statuses"] = remote_profile_statuses
    _record_remote_description_reminder(ctx, remote_profile_statuses)


def _acquire_observed_descriptions(
    ctx: B524ScanContext, select: DescriptionCandidateSelector
) -> None:
    if not ctx.probe_constraints:
        return
    remote_profile_statuses = _select_description_candidates(ctx, select)
    ctx.description_candidates_prepared = True
    _record_remote_profile_statuses(ctx, remote_profile_statuses)
    for candidate in ctx.description_candidates:
        identity = (candidate.read_opcode, candidate.group, candidate.instance, candidate.register)
        ctx.description_entries[identity]["parameter_description"] = {
            "qualification": "unavailable",
            "reason": "description acquisition pending",
        }
    acquire_descriptions(
        ctx.transport,
        dst=ctx.dst,
        candidates=ctx.description_candidates,
        entries=ctx.description_entries,
        budget=ctx.description_budget,
        coverage=ctx.description_coverage,
        observer=ctx.observer,
    )


def _record_constraint_mismatches(ctx: B524ScanContext, mismatches: list[dict[str, Any]]) -> None:
    if not mismatches:
        return
    ctx.artifact["meta"]["constraint_mismatches"] = mismatches
    ctx.artifact["meta"]["constraint_rescan_recommended"] = True
    if ctx.observer is not None:
        ctx.observer.log(
            "Observed register values outside the scoped bundled static "
            "constraint catalog. Review meta.constraint_mismatches and rerun "
            "with a live description override in the planner "
            "for current-target confirmation.",
            level="warn",
        )


def _selected_operation_requests(ctx: B524ScanContext) -> tuple[B524OperationReadRequest, ...]:
    return tuple(
        request
        for request, operation_enabled in zip(
            ctx.operation_requests, ctx.operation_selection, strict=True
        )
        if operation_enabled
    )


def _acquire_selected_operation_reads(ctx: B524ScanContext) -> None:
    if not ctx.operation_requests:
        return
    selected_operations = _selected_operation_requests(ctx)
    if selected_operations:
        acquire_operation_reads(
            ctx.transport,
            dst=ctx.dst,
            artifact=ctx.artifact,
            requests=selected_operations,
            device_id=ctx.device_id,
            manufacturer=ctx.manufacturer,
            observer=ctx.observer,
        )


def scan_b524_registers(ctx: B524ScanContext, collaborators: B524ScanCollaborators) -> None:
    """Scan phase: choose the register plan, read it, describe it, then read operations.

    The operator may replan during the register scan; registers already read are kept.
    """

    planner_groups = _planner_groups(ctx)
    plan = _default_register_plan(ctx, planner_groups)
    request_rate_rps = _measured_request_rate(ctx)
    operator = _operator_planner(ctx, collaborators, planner_groups, request_rate_rps)
    if operator is not None:
        with operator.observer.suspend():
            plan = _operator_plan(ctx, operator, dict(plan))
    # No live constraint dictionary is probed; the scan uses the static catalog.
    live_constraints: dict[int, dict[int, ConstraintEntry]] = {}
    _record_register_plan(ctx, plan, request_rate_rps, live_constraints)
    done: set[RegisterTask] = set()
    work_queue = deque(build_work_queue(plan, done=done))
    if ctx.observer is not None:
        ctx.observer.phase_start("register_scan", total=len(work_queue) or 1)
    emit_trace_label(ctx.transport, "Register Scan")
    run = _RegisterScanRun(
        plan=plan,
        done=done,
        work_queue=work_queue,
        live_constraints=live_constraints,
        active_start=time.perf_counter(),
    )
    _read_registers(ctx, collaborators, operator, run)
    _acquire_observed_descriptions(ctx, collaborators.select_description_candidates)
    collaborators.annotate_artifact(ctx.artifact)
    _record_constraint_mismatches(ctx, run.constraint_mismatches)
    if ctx.observer is not None:
        ctx.observer.phase_finish("register_scan")
    _acquire_selected_operation_reads(ctx)


# --- Completion phase ---------------------------------------------------------------


def _record_carried_system_information(
    ctx: B524ScanContext, exc: ScanRequestBudgetExceeded | TransportRecoveryExhausted
) -> None:
    if exc.system_information:
        ctx.artifact["meta"]["system_information"] = system_information_records(
            {identifier: value for identifier, value, _ in exc.system_information},
            {identifier: raw for identifier, _, raw in exc.system_information},
            getattr(exc, "system_information_diagnostics", {}),
        )


def record_operator_interrupt(ctx: B524ScanContext) -> str:
    """Completion: the operator stopped the scan."""

    ctx.artifact["meta"]["incomplete"] = True
    return "user_interrupt"


def record_request_budget_exhausted(ctx: B524ScanContext, exc: ScanRequestBudgetExceeded) -> str:
    """Completion: the request budget ran out; keep the requests sent up to the limit."""

    meta = ctx.artifact["meta"]
    meta["incomplete"] = True
    meta["budget_boundary_evidence"] = list(ctx.transport.recent_requests)
    _record_carried_system_information(ctx, exc)
    return "request_budget_exhausted"


def _record_pending_register(
    ctx: B524ScanContext, selector: dict[str, str], entry: dict[str, Any]
) -> None:
    recovery_opcode = int(selector["read_opcode"], 0)
    recovery_group = int(selector["group"], 0)
    _ensure_group_artifact(
        ctx.artifact,
        group=recovery_group,
        opcode=recovery_opcode,
        name="Unknown",
        descriptor_observed=0.0,
    )
    instances = _instances_object(ctx.artifact, group=recovery_group, opcode=recovery_opcode)
    instance = instances.setdefault(selector["instance"], {"present": False})
    instance.setdefault("registers", {})[selector["register"]] = entry


def record_transport_recovery_exhausted(
    ctx: B524ScanContext, exc: TransportRecoveryExhausted
) -> str:
    """Completion: transport recovery gave up; keep the pending register entry."""

    meta = ctx.artifact["meta"]
    meta["incomplete"] = True
    meta["transport_recovery"] = {
        "cause": exc.cause,
        "phase": exc.phase,
        "request_attempts": exc.request_attempts,
        "retry_count": exc.retry_count,
        "reconnect_attempts": exc.reconnect_attempts,
        "pending_selector": exc.selector,
    }
    meta["transport_boundary_evidence"] = list(ctx.transport.recent_requests)
    _record_carried_system_information(ctx, exc)
    if exc.entry is not None and exc.selector is not None:
        _record_pending_register(ctx, exc.selector, exc.entry)
    if ctx.observer is not None:
        ctx.observer.log(str(exc), level="warn")
    return "transport_recovery_exhausted"


def _record_unattempted_operation_reads(
    ctx: B524ScanContext, incomplete_reason: str | None
) -> None:
    artifact = ctx.artifact
    if not ctx.operation_requests or "b524_operation_reads" in artifact:
        return
    artifact["b524_operation_reads_schema_version"] = 1
    artifact["b524_operation_reads"] = []
    for request in _selected_operation_requests(ctx):
        record = record_operation_read_observation(request)
        record["response_state"] = "unattempted"
        record["error"] = incomplete_reason or "not_acquired"
        artifact["b524_operation_reads"].append(record)


def _operation_attempts(records: list[Any], operation: str) -> int:
    return sum(
        int(record.get("request_attempts", 0))
        for record in records
        if isinstance(record, dict) and record.get("operation") == operation
    )


def _record_operation_read_attempts(ctx: B524ScanContext) -> None:
    operation_records = ctx.artifact.get("b524_operation_reads")
    if not isinstance(operation_records, list):
        return
    operation_attempts = {
        "OP09": _operation_attempts(operation_records, "GetEvent"),
        "OP0B": _operation_attempts(operation_records, "GetEventSetPoint"),
    }
    ctx.artifact["meta"]["b524_operation_read_attempts"] = {
        **operation_attempts,
        "total": sum(operation_attempts.values()),
    }


def complete_b524_scan(
    ctx: B524ScanContext,
    *,
    incomplete_reason: str | None,
    select_description_candidates: DescriptionCandidateSelector,
) -> None:
    """Completion phase: finish coverage and request accounting for a whole or partial scan."""

    meta = ctx.artifact["meta"]
    if ctx.probe_constraints:
        if not ctx.description_candidates_prepared and ctx.description_policy is not None:
            _record_remote_profile_statuses(
                ctx, _select_description_candidates(ctx, select_description_candidates)
            )
        finish_description_coverage(
            ctx.description_candidates,
            ctx.description_entries,
            budget=ctx.description_budget,
            coverage=ctx.description_coverage,
        )
    store_operation_read_plan(ctx)
    _record_unattempted_operation_reads(ctx, incomplete_reason)
    meta["parameter_description_coverage"] = ctx.description_coverage
    meta["parameter_description_requests"] = ctx.description_coverage.get("request_attempts", 0)
    meta["scan_coverage"]["actual_requests"] = ctx.transport.counters.send_calls
    _record_operation_read_attempts(ctx)
    meta["scan_coverage"]["completed"] = not meta["incomplete"]
    meta["scan_duration_seconds"] = round(time.perf_counter() - ctx.start_perf, 4)
    if incomplete_reason is not None:
        meta["incomplete_reason"] = incomplete_reason
