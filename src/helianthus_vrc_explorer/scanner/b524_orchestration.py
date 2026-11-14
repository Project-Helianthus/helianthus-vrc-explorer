"""Private orchestration for the B524 scanner facade."""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from typing import Any

from rich.console import Console

from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..schema.parameter_descriptions import (
    description_catalog_status,
    remote_description_reusable,
)
from ..transport.base import TransportInterface, TransportRecoveryExhausted
from ..transport.instrumented import ScanRequestBudgetExceeded
from .b524_operation_reads import B524OperationReadRequest
from .b524_phases import (
    B524ScanCollaborators,
    announce_b524_scan,
    complete_b524_scan,
    discover_b524_scope,
    plan_b524_scan,
    probe_b524_availability,
    record_operator_interrupt,
    record_request_budget_exhausted,
    record_transport_recovery_exhausted,
    scan_b524_registers,
)
from .b524_plan import PlannerUiMode
from .b524_probe import GroupMetadata
from .collaborators import (
    GroupDiscovery,
    InstanceAvailabilityProber,
    PlannerHotkeyReaderFactory,
    ScanPlanners,
)
from .description_scheduler import DescriptionCandidate
from .plan import GroupScanPlan, PlanKey
from .planner_model import PlannerPreset
from .planner_selection import (
    DescriptionPolicySelection,
    description_probe_required,
)
from .scan import (
    _UNKNOWN_GROUP_DEFAULT_II_MAX,
    _UNKNOWN_GROUP_DEFAULT_RR_MAX,
    ScanObserver,
    _apply_contextual_enum_annotations,
    _resolve_planner_mode,
)


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
        selector = {
            "read_opcode": f"0x{candidate.read_opcode:02x}",
            "group": f"0x{candidate.group:02x}",
            "instance": f"0x{candidate.instance:02x}",
            "register": f"0x{candidate.register:04x}",
        }
        if not (
            description_probe_required(policy, opcode=candidate.read_opcode)
            or status.get("status") != "exact"
            or not remote_description_reusable(artifact, selector)
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
    discover_groups_fn: GroupDiscovery,
    planners: ScanPlanners | None,
    hotkey_reader_cls: PlannerHotkeyReaderFactory,
    probe_instance_availability_fn: InstanceAvailabilityProber,
) -> dict[str, Any]:
    """Scan a VRC regulator using B524 and return a JSON-serializable artifact.

    Runs the plan, discovery, availability, scan and completion phases of
    ``b524_phases`` over one ``B524ScanContext``; ``docs/b524-scan-phases.md``
    maps each phase to the state it reads and writes.

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    Without ``planners`` no interactive planner is offered.
    """

    ctx = plan_b524_scan(
        transport,
        dst=dst,
        observer=observer,
        ebusd_host=ebusd_host,
        ebusd_port=ebusd_port,
        planner_preset=planner_preset,
        probe_constraints=probe_constraints,
        explicit_plan=explicit_plan,
        description_budget=description_budget,
        request_budget=request_budget,
        operation_requests=operation_requests,
        operation_identity=operation_identity,
    )
    collaborators = B524ScanCollaborators(
        console=console,
        planners=planners,
        planner_ui=planner_ui,
        hotkey_reader_cls=hotkey_reader_cls,
        ebusd_schema=ebusd_schema,
        myvaillant_map=myvaillant_map,
        select_description_candidates=_select_live_description_candidates,
        annotate_artifact=_apply_contextual_enum_annotations,
    )
    incomplete_reason: str | None = None
    try:
        announce_b524_scan(ctx)
        discover_b524_scope(
            ctx,
            discover_groups_fn=discover_groups_fn,
            resolve_planner_mode=lambda: _resolve_planner_mode(
                interactive=(
                    console is not None
                    and console.is_terminal
                    and sys.stdin.isatty()
                    and observer is not None
                    and planners is not None
                ),
                planner_ui=planner_ui,
                observer=observer,
            ),
            fallback_bounds=GroupMetadata(
                rr_max=_UNKNOWN_GROUP_DEFAULT_RR_MAX,
                ii_max=_UNKNOWN_GROUP_DEFAULT_II_MAX,
                source="fallback",
            ),
        )
        probe_b524_availability(ctx, probe_instance_availability_fn=probe_instance_availability_fn)
        scan_b524_registers(ctx, collaborators)
    except KeyboardInterrupt:
        incomplete_reason = record_operator_interrupt(ctx)
    except ScanRequestBudgetExceeded as exc:
        incomplete_reason = record_request_budget_exhausted(ctx, exc)
    except TransportRecoveryExhausted as exc:
        incomplete_reason = record_transport_recovery_exhausted(ctx, exc)
    complete_b524_scan(
        ctx,
        incomplete_reason=incomplete_reason,
        select_description_candidates=_select_live_description_candidates,
    )
    return ctx.artifact
