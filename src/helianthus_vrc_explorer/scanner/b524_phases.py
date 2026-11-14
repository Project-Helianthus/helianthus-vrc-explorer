"""Plan and discovery phases of the B524 scan over one typed scan context.

``docs/b524-scan-phases.md`` maps every phase to the state it reads and writes.
The availability, scan and completion phases still run in ``run_b524_scan``.
"""

from __future__ import annotations

import math
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..evidence_compat import api_identity_string
from ..protocol.b524 import RegisterOpcode
from ..protocol.b524_metadata import COUNT_GROUP_IDS, SYSTEM_INFORMATION_NAMES
from ..schema.b524_constraints import (
    StaticConstraintCatalog,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
)
from ..schema.description_profile_reminder import compose_description_profile_reminder
from ..schema.parameter_descriptions import description_catalog_status
from ..transport.base import TransportInterface, emit_trace_label
from ..transport.instrumented import CountingTransport
from .b524_artifact import (
    _artifact_contract_metadata,
    _ensure_group_artifact,
    _hex_u8,
    _hex_u16,
)
from .b524_operation_reads import B524OperationReadRequest, validate_operation_read_identity
from .b524_plan import (
    _KNOWN_DESCRIPTOR_TYPES,
    _group_name_for_opcode,
    _ii_max_for_opcode,
    _ii_min_for_opcode,
    _instance_discovery_decision,
    _normalize_planner_preset,
    _scan_plan_meta_groups,
    _sorted_namespace_opcodes,
)
from .b524_probe import GroupMetadata, _constraint_catalog_entry_count, _probe_unknown_group_opcodes
from .collaborators import GroupDiscovery
from .director import GROUP_CONFIG, ClassifiedGroup, DiscoveredGroup, classify_groups
from .observer import ScanObserver
from .plan import GroupScanPlan, PlanKey, estimate_register_requests
from .planner_model import PlannerPreset
from .planner_selection import DescriptionPolicySelection, default_description_policy
from .scan_policy import profile_opcodes

PlannerMode = Literal["disabled", "textual", "classic"]
PlannerModeResolver = Callable[[], PlannerMode]


@dataclass(slots=True, eq=False)
class B524ScanContext:
    """Local state that the B524 scan phases read and write.

    The plan phase fills the request fields and the artifact skeleton. The
    discovery phase fills the rest one step at a time, so a scan that stops
    part-way keeps every field resolved before it stopped.
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
