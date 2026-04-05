from __future__ import annotations

import contextlib
import math
import os
import struct
import sys
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal, cast

from rich.console import Console

from ..artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from ..protocol.b524 import RegisterOpcode, build_constraint_probe_payload
from ..schema.b524_constraints import (
    CONSTRAINT_SCOPE_PROTOCOL,
    LIVE_PROBE_CONSTRAINT_SCOPE,
    StaticConstraintCatalog,
    StaticConstraintEntry,
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
    lookup_static_constraint,
)
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    emit_trace_label,
)
from ..transport.instrumented import CountingTransport
from ..ui.planner import PlannerGroup, PlannerPreset, build_plan_from_preset, prompt_scan_plan
from .b509 import scan_b509
from .b516 import scan_b516
from .b555 import scan_b555
from .director import (
    GROUP_CONFIG,
    DiscoveredGroup,
    classify_groups,
    discover_groups,
    group_name_for_opcode,
    group_namespace_profiles,
)
from .identity import make_register_identity, opcode_label
from .observer import ScanObserver
from .plan import (
    GroupScanPlan,
    PlanKey,
    RegisterTask,
    build_work_queue,
    estimate_register_requests,
    make_plan_key,
)
from .register import (
    InstanceAvailabilityProbe,
    NamespaceAvailabilityContract,
    RegisterEntry,
    namespace_availability_contract,
    opcodes_for_group,
    probe_instance_availability,
    read_register,
)


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


_LOCAL_REGISTER_OPCODE: RegisterOpcode = 0x02
_REMOTE_REGISTER_OPCODE: RegisterOpcode = 0x06
_UNKNOWN_GROUP_DEFAULT_RR_MAX = 0x0030
_UNKNOWN_GROUP_DEFAULT_II_MAX = 0x0A
_UNKNOWN_GROUP_INITIAL_INSTANCES: tuple[int, ...] = (0x00, 0x01)
_UNKNOWN_GROUP_EXPANDED_INSTANCES: tuple[int, ...] = tuple(range(0x00, 0x0B)) + (0xFF,)
_UNKNOWN_GROUP_PRESENCE_REGISTER = 0x0000
_UNKNOWN_GROUP_OPCODE_CANDIDATES: tuple[RegisterOpcode, ...] = (
    _LOCAL_REGISTER_OPCODE,
    _REMOTE_REGISTER_OPCODE,
)

PlannerUiMode = Literal["disabled", "auto", "textual", "classic"]
_KNOWN_DESCRIPTOR_TYPES = frozenset(
    float(desc) for config in GROUP_CONFIG.values() if (desc := config.get("desc")) is not None
)


def _is_instanced_group(ii_max: int | None) -> bool:
    return ii_max is not None and ii_max > 0


def _normalize_planner_preset(preset: str) -> PlannerPreset:
    normalized = preset.strip().lower()
    if normalized == "aggressive":
        normalized = "full"
    return cast(PlannerPreset, normalized)


def _planner_ii_max(ii_max: int | None) -> int | None:
    return ii_max if _is_instanced_group(ii_max) else None


def _group_opcodes(group: int) -> tuple[RegisterOpcode, ...]:
    return tuple(opcodes_for_group(group))


def _planner_source_opcodes(group: int) -> tuple[RegisterOpcode, ...]:
    if group != 0x01:
        return _group_opcodes(group)

    profiles = group_namespace_profiles(group)
    if not profiles:
        return _group_opcodes(group)
    return tuple(cast(RegisterOpcode, opcode) for opcode in sorted(profiles))


def _primary_opcode(group: int) -> RegisterOpcode:
    return _group_opcodes(group)[0]


def _is_dual_namespace_group(group: int) -> bool:
    return len(_group_opcodes(group)) > 1


def _group_name_for_opcode(group: int, opcode: RegisterOpcode) -> str:
    return group_name_for_opcode(group, int(opcode))


def _group_display_name_for_opcodes(
    *, group: int, opcodes: tuple[RegisterOpcode, ...], fallback: str
) -> str:
    if not opcodes:
        return fallback
    names = [_group_name_for_opcode(group, opcode) for opcode in opcodes]
    unique_names: list[str] = []
    for name in names:
        if name not in unique_names:
            unique_names.append(name)
    return " / ".join(unique_names) if unique_names else fallback


def _rr_max_for_opcode(*, group: int, default_rr_max: int, opcode: int) -> int:
    config = GROUP_CONFIG.get(group)
    if config is None:
        return default_rr_max
    overrides = config.get("rr_max_by_opcode")
    if overrides is None:
        return default_rr_max
    return int(overrides.get(opcode, default_rr_max))


def _ii_max_for_opcode(*, group: int, default_ii_max: int | None, opcode: int) -> int | None:
    config = GROUP_CONFIG.get(group)
    if config is None:
        return default_ii_max
    overrides = config.get("ii_max_by_opcode")
    if overrides is None:
        return default_ii_max
    value = overrides.get(opcode)
    if value is None:
        return default_ii_max
    return int(value)


def _plan_key(group: int, opcode: int) -> PlanKey:
    return make_plan_key(group, opcode)


def _instance_discovery_decision(*, group: int, dual_namespace: bool) -> dict[str, Any]:
    if not dual_namespace:
        return {
            "strategy": "single_namespace",
            "decision": "independent_per_namespace",
            "tradeoff": "not_applicable",
        }

    if group in {0x09, 0x0A}:
        return {
            "strategy": "dual_namespace",
            "decision": "independent_per_namespace",
            "tradeoff": (
                "extra presence probes accepted to avoid cross-namespace false-equivalence "
                "assumptions"
            ),
        }

    return {
        "strategy": "dual_namespace",
        "decision": "independent_per_namespace",
        "tradeoff": "independent probing is authoritative over shared inference",
    }


def _namespace_plan_meta(group_plan: GroupScanPlan) -> tuple[str, dict[str, object]]:
    namespace_key = _hex_u8(group_plan.opcode)
    payload = group_plan.to_meta()
    payload["namespace_key"] = namespace_key
    payload["label"] = opcode_label(group_plan.opcode)
    return namespace_key, payload


def _scan_plan_meta_groups(plan: dict[PlanKey, GroupScanPlan]) -> dict[str, object]:
    serializable: dict[str, object] = {}
    grouped: dict[int, list[GroupScanPlan]] = {}
    for _key, group_plan in sorted(plan.items()):
        grouped.setdefault(group_plan.group, []).append(group_plan)

    for group in sorted(grouped):
        group_plans = sorted(grouped[group], key=lambda gp: gp.opcode)
        group_key = _hex_u8(group)
        namespace_meta: dict[str, object] = {}
        for group_plan in group_plans:
            namespace_key, payload = _namespace_plan_meta(group_plan)
            namespace_meta[namespace_key] = payload
        if len(group_plans) > 1:
            serializable[group_key] = {
                "dual_namespace": True,
                "namespace_identity_keys": "opcode_hex",
                "namespaces": namespace_meta,
            }
            continue
        _, single_payload = _namespace_plan_meta(group_plans[0])
        serializable[group_key] = {
            **single_payload,
            "dual_namespace": False,
            "namespace_identity_keys": "opcode_hex",
            "namespaces": namespace_meta,
        }
    return serializable


def _artifact_contract_metadata() -> dict[str, Any]:
    return {
        "namespace_identity_keys": "opcode_hex",
        "namespace_labels": "presentation_only",
        "topology_authority": (
            "persisted groups[*].dual_namespace and groups[*].namespaces are authoritative for "
            "consumers"
        ),
        "b524_row_identity": {
            "dedupe_key_format": "<group>:<namespace>:<instance>:<register>",
            "path_format": "B524/<group-name>/<namespace-display>/<instance>/<register-name>",
            "round_trip_stability": (
                "namespace keys and persisted topology must be preserved without sentinel rewrite"
            ),
        },
    }


def _ensure_group_artifact(
    artifact: dict[str, Any],
    *,
    group: int,
    name: str,
    descriptor_observed: float | None,
    dual_namespace: bool,
    ii_max: int | None = None,
    discovery_advisory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    group_key = _hex_u8(group)
    default: dict[str, Any] = {
        "name": name,
        "descriptor_observed": descriptor_observed,
        "dual_namespace": dual_namespace,
    }
    if ii_max is not None:
        default["ii_max"] = _hex_u8(ii_max)
    if dual_namespace:
        default["namespaces"] = {}
    else:
        default["instances"] = {}
    group_obj = artifact["groups"].setdefault(group_key, default)
    if dual_namespace:
        group_obj.setdefault("namespaces", {})
        group_obj.pop("instances", None)
    else:
        group_obj.setdefault("instances", {})
        group_obj.pop("namespaces", None)
    group_obj.setdefault("name", name)
    group_obj.setdefault("descriptor_observed", descriptor_observed)
    group_obj["dual_namespace"] = dual_namespace
    if ii_max is not None:
        group_obj["ii_max"] = _hex_u8(ii_max)
    elif dual_namespace:
        group_obj.pop("ii_max", None)
    if discovery_advisory is not None:
        group_obj["discovery_advisory"] = discovery_advisory
    return cast(dict[str, Any], group_obj)


def _ensure_namespace_artifact(
    group_obj: dict[str, Any],
    *,
    group: int,
    opcode: int,
    ii_max: int | None = None,
) -> dict[str, Any]:
    namespaces = group_obj.setdefault("namespaces", {})
    namespace_key = _hex_u8(opcode)
    namespace_group_name = _group_name_for_opcode(group, cast(RegisterOpcode, opcode))
    namespace_obj = namespaces.setdefault(
        namespace_key,
        {
            "label": opcode_label(opcode),
            "group_name": namespace_group_name,
            "instances": {},
        },
    )
    namespace_obj.setdefault("label", opcode_label(opcode))
    if namespace_group_name is not None:
        namespace_obj.setdefault("group_name", namespace_group_name)
    namespace_obj.setdefault("instances", {})
    if ii_max is not None:
        namespace_obj["ii_max"] = _hex_u8(ii_max)
    return cast(dict[str, Any], namespace_obj)


def _instances_object(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    group_obj = artifact["groups"][_hex_u8(group)]
    if bool(group_obj.get("dual_namespace")):
        namespace_obj = _ensure_namespace_artifact(group_obj, group=group, opcode=opcode)
        return cast(dict[str, Any], namespace_obj.setdefault("instances", {}))
    return cast(dict[str, Any], group_obj.setdefault("instances", {}))


def _availability_object(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    group_obj = artifact["groups"][_hex_u8(group)]
    if bool(group_obj.get("dual_namespace")):
        return _ensure_namespace_artifact(group_obj, group=group, opcode=opcode)
    return cast(dict[str, Any], group_obj)


def _serialize_availability_contract(
    contract: NamespaceAvailabilityContract,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": contract.source,
        "namespace_relationship": contract.namespace_relationship,
        "positive_when": contract.positive_when,
        "description": contract.description,
    }
    if contract.probe_register is not None:
        payload["probe_register"] = _hex_u16(contract.probe_register)
    if contract.probe_type_hint is not None:
        payload["probe_type_hint"] = contract.probe_type_hint
    return payload


def _serialize_availability_probe(
    probe: InstanceAvailabilityProbe,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "present": probe.present,
        "source": probe.contract.source,
    }
    evidence = probe.evidence
    if evidence is not None:
        payload.update(dict(evidence))
    return payload


def _record_availability_contract(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
    contract: NamespaceAvailabilityContract,
) -> None:
    target = _availability_object(artifact, group=group, opcode=opcode)
    target["availability_contract"] = _serialize_availability_contract(contract)
    target.setdefault("availability_probes", {})


def _record_availability_probes(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
    probes: Mapping[int, InstanceAvailabilityProbe],
) -> None:
    target = _availability_object(artifact, group=group, opcode=opcode)
    probe_map = cast(dict[str, Any], target.setdefault("availability_probes", {}))
    for instance, probe in sorted(probes.items()):
        probe_map[_hex_u8(instance)] = _serialize_availability_probe(probe)


def _record_namespace_topology(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
    ii_max: int | None,
) -> None:
    group_obj = artifact["groups"].get(_hex_u8(group))
    if not isinstance(group_obj, dict):
        return
    if bool(group_obj.get("dual_namespace")):
        _ensure_namespace_artifact(group_obj, group=group, opcode=opcode, ii_max=ii_max)
        return
    if ii_max is not None:
        group_obj["ii_max"] = _hex_u8(ii_max)


def _promote_group_artifact_to_dual_namespace(
    artifact: dict[str, Any],
    *,
    group: int,
    primary_opcode: RegisterOpcode,
) -> None:
    group_obj = artifact["groups"].get(_hex_u8(group))
    if not isinstance(group_obj, dict) or bool(group_obj.get("dual_namespace")):
        return

    flat_instances = group_obj.pop("instances", {})
    flat_ii_max = group_obj.pop("ii_max", None)
    namespaces = group_obj.setdefault("namespaces", {})
    if not isinstance(namespaces, dict):
        namespaces = {}
        group_obj["namespaces"] = namespaces

    namespace_key = _hex_u8(primary_opcode)
    namespace_obj = namespaces.setdefault(
        namespace_key,
        {
            "label": opcode_label(primary_opcode),
            "group_name": _group_name_for_opcode(group, primary_opcode),
            "instances": {},
        },
    )
    if not isinstance(namespace_obj, dict):
        namespace_obj = {
            "label": opcode_label(primary_opcode),
            "group_name": _group_name_for_opcode(group, primary_opcode),
            "instances": {},
        }
        namespaces[namespace_key] = namespace_obj

    namespace_obj.setdefault("label", opcode_label(primary_opcode))
    if flat_ii_max is not None:
        namespace_obj.setdefault("ii_max", flat_ii_max)
    namespace_obj.setdefault("group_name", _group_name_for_opcode(group, primary_opcode))
    if isinstance(flat_instances, dict) and flat_instances:
        namespace_obj["instances"] = flat_instances
    else:
        namespace_obj.setdefault("instances", {})
    group_obj["dual_namespace"] = True


def _apply_effective_namespace_topology(
    artifact: dict[str, Any],
    *,
    group_dual_namespace_runtime: Mapping[int, bool],
    plan: Mapping[PlanKey, GroupScanPlan],
) -> dict[int, bool]:
    effective = dict(group_dual_namespace_runtime)
    planned_opcodes_by_group: dict[int, set[RegisterOpcode]] = {}
    for group_plan in plan.values():
        group_id = group_plan.group
        planned_opcodes = planned_opcodes_by_group.setdefault(group_id, set())
        planned_opcodes.add(group_plan.opcode)

    for group_id, planned_opcodes in planned_opcodes_by_group.items():
        if len(planned_opcodes) <= 1:
            continue
        effective[group_id] = True
        primary_opcode = (
            _primary_opcode(group_id)
            if group_id in GROUP_CONFIG
            else cast(RegisterOpcode, min(planned_opcodes))
        )
        _promote_group_artifact_to_dual_namespace(
            artifact,
            group=group_id,
            primary_opcode=primary_opcode,
        )
    return effective


def _present_instances_for_opcode(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> tuple[int, ...]:
    instances_obj = _instances_object(artifact, group=group, opcode=opcode)
    return tuple(
        sorted(
            int(ii_key, 0)
            for (ii_key, ii_obj) in instances_obj.items()
            if isinstance(ii_obj, dict) and ii_obj.get("present") is True
        )
    )


def _mark_present_instances(instances_obj: dict[str, Any], *, instances: tuple[int, ...]) -> None:
    for instance in instances:
        instances_obj[_hex_u8(instance)] = {"present": True}


def _entry_is_readable(entry: RegisterEntry) -> bool:
    return entry["error"] is None and entry.get("flags_access") != "absent"


def _entry_is_opcode_responsive(entry: RegisterEntry) -> bool:
    return entry["error"] is None and entry.get("flags_access") != "absent"


def _probe_unknown_group_opcodes(
    transport: TransportInterface,
    *,
    dst: int,
    group: int,
    observer: ScanObserver | None,
) -> tuple[tuple[RegisterOpcode, ...], dict[str, Any]]:
    evidence: dict[str, Any] = {}
    responsive: list[RegisterOpcode] = []

    for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES:
        if observer is not None:
            observer.status(
                f"Probe opcode GG=0x{group:02X} OP={_hex_u8(opcode)} "
                f"II=0x00 RR={_hex_u16(_UNKNOWN_GROUP_PRESENCE_REGISTER)}"
            )
        entry = read_register(
            transport,
            dst,
            opcode,
            group=group,
            instance=0x00,
            register=_UNKNOWN_GROUP_PRESENCE_REGISTER,
        )
        is_responsive = _entry_is_opcode_responsive(entry)
        if is_responsive:
            responsive.append(opcode)
        evidence[_hex_u8(opcode)] = {
            "responsive": is_responsive,
            "error": entry.get("error"),
            "flags_access": entry.get("flags_access"),
            "reply_hex": entry.get("reply_hex"),
            "raw_hex": entry.get("raw_hex"),
        }

    selected = tuple(sorted(set(responsive)))
    probe_summary: dict[str, Any] = {
        "kind": "opcode_responsiveness",
        "selector": {
            "instance": _hex_u8(0x00),
            "register": _hex_u16(_UNKNOWN_GROUP_PRESENCE_REGISTER),
        },
        "candidates": evidence,
        "responsive_opcodes": [_hex_u8(opcode) for opcode in selected],
    }
    return cast(tuple[RegisterOpcode, ...], selected), probe_summary


def _probe_unknown_present_instances(
    transport: TransportInterface,
    *,
    dst: int,
    group: int,
    opcode: RegisterOpcode,
    observer: ScanObserver | None,
) -> tuple[int, ...]:
    present_instances: list[int] = []
    probed: set[int] = set()
    should_expand = False

    for ii in _UNKNOWN_GROUP_INITIAL_INSTANCES:
        if observer is not None:
            observer.status(f"Probe presence GG=0x{group:02X} OP={_hex_u8(opcode)} II=0x{ii:02X}")
        entry = read_register(
            transport,
            dst,
            opcode,
            group=group,
            instance=ii,
            register=_UNKNOWN_GROUP_PRESENCE_REGISTER,
        )
        probed.add(ii)
        if _entry_is_readable(entry):
            present_instances.append(ii)
            should_expand = True
        if observer is not None:
            observer.phase_advance("instance_discovery", advance=1)

    if not should_expand:
        return tuple(present_instances)

    for ii in _UNKNOWN_GROUP_EXPANDED_INSTANCES:
        if ii in probed:
            continue
        if observer is not None:
            observer.status(f"Probe presence GG=0x{group:02X} OP={_hex_u8(opcode)} II=0x{ii:02X}")
        entry = read_register(
            transport,
            dst,
            opcode,
            group=group,
            instance=ii,
            register=_UNKNOWN_GROUP_PRESENCE_REGISTER,
        )
        if _entry_is_readable(entry):
            present_instances.append(ii)
        if observer is not None:
            observer.phase_advance("instance_discovery", advance=1)

    return tuple(sorted(set(present_instances)))


def _probe_present_instances(
    transport: TransportInterface,
    *,
    dst: int,
    group: int,
    opcode: RegisterOpcode,
    ii_max: int,
    observer: ScanObserver | None,
) -> dict[int, InstanceAvailabilityProbe]:
    probes: dict[int, InstanceAvailabilityProbe] = {}
    for ii in range(0x00, ii_max + 1):
        if observer is not None:
            observer.status(f"Probe presence GG=0x{group:02X} OP={_hex_u8(opcode)} II=0x{ii:02X}")
        probe = probe_instance_availability(
            transport,
            dst=dst,
            group=group,
            instance=ii,
            opcode=opcode,
        )
        probes[ii] = probe
        if observer is not None:
            observer.phase_advance("instance_discovery", advance=1)
    return probes


@dataclass(frozen=True, slots=True)
class GroupMetadata:
    """Metadata used to auto-size the scan plan for a discovered group."""

    rr_max: int
    ii_max: int | None
    source: str


@dataclass(frozen=True, slots=True)
class ConstraintEntry:
    """Typed constraint dictionary entry from opcode 0x01."""

    tt: int
    kind: str
    min_value: int | float | str
    max_value: int | float | str
    step_value: int | float
    raw_hex: str
    source: str = "opcode_0x01"
    scope: str = LIVE_PROBE_CONSTRAINT_SCOPE
    provenance: str = "live_probe_from_opcode_0x01"


def _decode_constraint_date(value: bytes) -> str:
    if len(value) != 3:
        raise ValueError(f"Date triplet expects 3 bytes, got {len(value)}")
    day = value[0]
    month = value[1]
    year = 2000 + value[2]
    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise ValueError(f"Invalid date triplet: {value.hex()}")
    return f"{year:04d}-{month:02d}-{day:02d}"


def _parse_constraint_entry(
    *,
    group: int,
    register: int,
    response: bytes,
) -> ConstraintEntry:
    if len(response) < 4:
        raise ValueError(f"Short constraint response: expected >=4 bytes, got {len(response)}")

    tt = response[0]
    if response[1] != group or response[2] != register:
        raise ValueError(
            "Constraint header mismatch: "
            f"expected_gg={group:02x} expected_rr={register:02x} got={response[:4].hex()}"
        )
    body = response[4:]
    if tt == 0x06:
        if len(body) < 3:
            raise ValueError(f"TT=0x06 expects >=3 body bytes, got {len(body)}")
        min_u8, max_u8, step_u8 = body[0], body[1], body[2]
        return ConstraintEntry(
            tt=tt,
            kind="u8_range",
            min_value=min_u8,
            max_value=max_u8,
            step_value=step_u8,
            raw_hex=response.hex(),
        )
    if tt == 0x09:
        if len(body) < 6:
            raise ValueError(f"TT=0x09 expects >=6 body bytes, got {len(body)}")
        min_u16 = int.from_bytes(body[0:2], byteorder="little", signed=False)
        max_u16 = int.from_bytes(body[2:4], byteorder="little", signed=False)
        step_u16 = int.from_bytes(body[4:6], byteorder="little", signed=False)
        return ConstraintEntry(
            tt=tt,
            kind="u16_range",
            min_value=min_u16,
            max_value=max_u16,
            step_value=step_u16,
            raw_hex=response.hex(),
        )
    if tt == 0x0F:
        if len(body) < 12:
            raise ValueError(f"TT=0x0F expects >=12 body bytes, got {len(body)}")
        min_f32 = struct.unpack("<f", body[0:4])[0]
        max_f32 = struct.unpack("<f", body[4:8])[0]
        step_f32 = struct.unpack("<f", body[8:12])[0]
        return ConstraintEntry(
            tt=tt,
            kind="f32_range",
            min_value=min_f32,
            max_value=max_f32,
            step_value=step_f32,
            raw_hex=response.hex(),
        )
    if tt == 0x0C:
        if len(body) < 9:
            raise ValueError(f"TT=0x0C expects >=9 body bytes, got {len(body)}")
        min_date = _decode_constraint_date(body[0:3])
        max_date = _decode_constraint_date(body[3:6])
        step_days = int.from_bytes(body[6:8], byteorder="little", signed=False)
        return ConstraintEntry(
            tt=tt,
            kind="date_range",
            min_value=min_date,
            max_value=max_date,
            step_value=step_days,
            raw_hex=response.hex(),
        )
    raise ValueError(f"Unsupported constraint TT=0x{tt:02X}")


def _probe_group_constraints(
    transport: TransportInterface,
    *,
    dst: int,
    group: int,
    rr_max: int,
    observer: ScanObserver | None,
    progress_phase: str | None = None,
) -> dict[int, ConstraintEntry]:
    """Probe `01 GG RR` entries for one group and return decoded constraints."""

    constraints: dict[int, ConstraintEntry] = {}

    probe_rr_max = min(rr_max, 0xFF)
    rr_candidates = list(range(0x00, probe_rr_max + 1))
    # Observed shared constraint IDs may live above the per-group RR scan window.
    if probe_rr_max < 0x80:
        rr_candidates.append(0x80)

    for rr in rr_candidates:
        try:
            if observer is not None:
                observer.status(f"Probe constraints GG=0x{group:02X} RR=0x{rr:02X}")
            payload = build_constraint_probe_payload(group=group, register=rr)
            try:
                response = transport.send(dst, payload)
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                continue
            except Exception:
                continue
            try:
                parsed = _parse_constraint_entry(group=group, register=rr, response=response)
            except Exception:
                continue
            constraints[rr] = parsed
        finally:
            if observer is not None and progress_phase is not None:
                observer.phase_advance(progress_phase, advance=1)

    if observer is not None and constraints:
        observer.log(
            f"GG=0x{group:02X} constraint_dictionary entries: {len(constraints)}",
            level="info",
        )
    return constraints


def _metadata_map_to_dict(metadata_map: dict[int, GroupMetadata]) -> dict[str, Any]:
    serializable: dict[str, Any] = {}
    for group, meta in sorted(metadata_map.items()):
        payload = asdict(meta)
        rr_max = payload["rr_max"]
        ii_max = payload["ii_max"]
        if isinstance(rr_max, int):
            payload["rr_max"] = _hex_u16(rr_max)
        if isinstance(ii_max, int):
            payload["ii_max"] = _hex_u8(ii_max)
        serializable[_hex_u8(group)] = payload
    return serializable


def _constraint_map_to_dict(
    constraint_map: dict[int, dict[int, ConstraintEntry]],
) -> dict[str, Any]:
    serializable: dict[str, Any] = {}
    for group, rr_map in sorted(constraint_map.items()):
        group_obj: dict[str, Any] = {}
        for register, entry in sorted(rr_map.items()):
            group_obj[_hex_u8(register)] = {
                "tt": _hex_u8(entry.tt),
                "type": entry.kind,
                "min": entry.min_value,
                "max": entry.max_value,
                "step": entry.step_value,
                "raw_hex": entry.raw_hex,
                "source": entry.source,
                "scope": entry.scope,
                "provenance": entry.provenance,
            }
        serializable[_hex_u8(group)] = group_obj
    return serializable


def _constraint_catalog_entry_count(catalog: StaticConstraintCatalog) -> int:
    return sum(len(registers) for registers in catalog.values())


def _constraint_for_register(
    *,
    opcode: int,
    group: int,
    instance: int,
    register: int,
    live_constraints: dict[int, dict[int, ConstraintEntry]],
    static_constraints: StaticConstraintCatalog,
) -> ConstraintEntry | StaticConstraintEntry | None:
    live = live_constraints.get(group, {}).get(register)
    if live is not None:
        return live
    return lookup_static_constraint(
        static_constraints,
        identity=make_register_identity(
            opcode=opcode,
            group=group,
            instance=instance,
            register=register,
        ),
    )


def _iter_group_namespace_instance_maps(
    group_obj: dict[str, Any],
) -> list[tuple[str | None, dict[str, Any]]]:
    if bool(group_obj.get("dual_namespace")):
        namespaces = group_obj.get("namespaces")
        if not isinstance(namespaces, dict):
            return []
        instance_maps: list[tuple[str | None, dict[str, Any]]] = []
        for namespace_key, namespace_obj in namespaces.items():
            if not isinstance(namespace_key, str):
                continue
            if not isinstance(namespace_obj, dict):
                continue
            instances = namespace_obj.get("instances")
            if isinstance(instances, dict):
                instance_maps.append((namespace_key, instances))
        return instance_maps

    instances = group_obj.get("instances")
    if isinstance(instances, dict):
        return [(None, instances)]
    return []


def _group_instances_for_namespace(
    group_obj: dict[str, Any], *, namespace_key: str | None = None
) -> dict[str, Any] | None:
    instance_maps = _iter_group_namespace_instance_maps(group_obj)
    if namespace_key is None:
        return instance_maps[0][1] if instance_maps else None

    for candidate_namespace, instances in instance_maps:
        if candidate_namespace == namespace_key:
            return instances
    if not bool(group_obj.get("dual_namespace")) and namespace_key == _hex_u8(
        _LOCAL_REGISTER_OPCODE
    ):
        # Single-namespace artifacts are local by definition.
        return instance_maps[0][1] if instance_maps else None
    return None


def _apply_constraint_metadata(
    entry: RegisterEntry,
    constraint: ConstraintEntry | StaticConstraintEntry,
) -> None:
    entry["constraint_tt"] = _hex_u8(constraint.tt)
    entry["constraint_type"] = constraint.kind
    entry["constraint_min"] = constraint.min_value
    entry["constraint_max"] = constraint.max_value
    entry["constraint_step"] = constraint.step_value
    entry["constraint_source"] = constraint.source
    entry["constraint_scope"] = constraint.scope
    entry["constraint_provenance"] = constraint.provenance


def _constraint_mismatch_reason(
    entry: RegisterEntry,
    constraint: ConstraintEntry | StaticConstraintEntry,
) -> str | None:
    if constraint.source != "static_catalog":
        return None
    if entry.get("error") is not None or entry.get("flags_access") == "absent":
        return None
    value = entry.get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and math.isnan(value):
        return None

    min_value = constraint.min_value
    max_value = constraint.max_value
    if (
        isinstance(min_value, bool)
        or isinstance(max_value, bool)
        or not isinstance(min_value, (int, float))
        or not isinstance(max_value, (int, float))
    ):
        return None

    epsilon = 1e-6 if any(isinstance(obj, float) for obj in (value, min_value, max_value)) else 0.0
    if float(value) < float(min_value) - epsilon or float(value) > float(max_value) + epsilon:
        return (
            f"value {value!r} outside seeded range "
            f"[{constraint.min_value!r}, {constraint.max_value!r}]"
        )
    return None


def _entry_has_valid_value(entry: RegisterEntry) -> bool:
    """Return True when a register read produced a meaningful value.

    Used for opcode selection (0x02 vs 0x06) in ambiguous cases.
    """

    if entry.get("error") is not None:
        return False
    if entry.get("flags_access") == "absent":
        return False
    raw_hex = entry.get("raw_hex")
    if raw_hex in (None, ""):
        return False
    value = entry.get("value")
    if value is None:
        return False
    return not (isinstance(value, float) and math.isnan(value))


def _entry_int_value(entry: Mapping[str, Any] | None) -> int | None:
    if not isinstance(entry, Mapping):
        return None
    if entry.get("error") is not None:
        return None
    value = entry.get("value")
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    return None


def _resolve_heating_circuit_type_name(raw_value: int) -> tuple[str, str]:
    mapping = {
        1: ("DIRECT_HEATING_CIRCUIT", "DIRECT_HEATING_CIRCUIT"),
        2: ("MIXER_CIRCUIT_EXTERNAL", "MIXER_CIRCUIT_EXTERNAL"),
    }
    return mapping.get(
        raw_value,
        (f"UNKNOWN_{raw_value}", f"UNKNOWN_{raw_value}"),
    )


def _resolve_mixer_circuit_type_name(
    raw_value: int,
    *,
    cooling_enabled: int | None,
    gg05_present: bool,
    system_schema: int | None,
    pool_sensor_present: bool,
) -> tuple[str, str]:
    if raw_value == 0:
        return "INACTIVE", "INACTIVE"
    if raw_value == 1:
        resolved = "COOLING" if cooling_enabled == 1 else "HEATING"
        return "HEATING_OR_COOLING", resolved
    if raw_value == 2:
        pool_candidate_schema = system_schema in {8, 9, 12, 13}
        resolved = "POOL" if (pool_candidate_schema and pool_sensor_present) else "FIXED_VALUE"
        return "FIXED_VALUE_OR_POOL", resolved
    if raw_value == 3:
        resolved = "CYLINDER_CHARGING" if gg05_present else "DHW"
        return "DHW_OR_CYLINDER_CHARGING", resolved
    if raw_value == 4:
        return "RETURN_INCREASE", "RETURN_INCREASE"
    return f"UNKNOWN_{raw_value}", f"UNKNOWN_{raw_value}"


def _resolve_room_influence_type_name(raw_value: int) -> tuple[str, str]:
    mapping = {
        0: ("INACTIVE", "INACTIVE"),
        1: ("ACTIVE", "ACTIVE"),
        2: ("EXTENDED", "EXTENDED"),
    }
    return mapping.get(
        raw_value,
        (f"UNKNOWN_{raw_value}", f"UNKNOWN_{raw_value}"),
    )


def _apply_contextual_enum_annotations(artifact: dict[str, Any]) -> None:
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return

    gg02 = groups.get("0x02")
    if not isinstance(gg02, dict):
        return
    gg02_namespace_maps = _iter_group_namespace_instance_maps(gg02)
    if bool(gg02.get("dual_namespace")):
        gg02_instance_maps = [
            instances
            for namespace_key, instances in gg02_namespace_maps
            if namespace_key == _hex_u8(_LOCAL_REGISTER_OPCODE)
        ]
    else:
        gg02_instance_maps = [instances for _namespace_key, instances in gg02_namespace_maps]
    if not gg02_instance_maps:
        return

    gg00 = groups.get("0x00")
    system_schema: int | None = None
    if isinstance(gg00, dict):
        gg00_instances = _group_instances_for_namespace(gg00, namespace_key="0x02")
        if isinstance(gg00_instances, dict):
            ii00 = gg00_instances.get("0x00")
            if isinstance(ii00, dict):
                regs = ii00.get("registers")
                if isinstance(regs, dict):
                    entry = regs.get("0x0001")
                    if isinstance(entry, dict):
                        system_schema = _entry_int_value(entry)

    gg05_present = "0x05" in groups
    pool_sensor_present = False

    for gg02_instances in gg02_instance_maps:
        for instance_obj in gg02_instances.values():
            if not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                continue

            cooling_enabled = (
                _entry_int_value(registers.get("0x0006"))
                if isinstance(registers.get("0x0006"), dict)
                else None
            )

            rr01 = registers.get("0x0001")
            if isinstance(rr01, dict):
                raw_value = _entry_int_value(rr01)
                if raw_value is not None:
                    raw_name, resolved_name = _resolve_heating_circuit_type_name(raw_value)
                    rr01["enum_raw_name"] = raw_name
                    rr01["enum_resolved_name"] = resolved_name
                    rr01["value_display"] = f"{raw_name} ({resolved_name})"

            rr02 = registers.get("0x0002")
            if isinstance(rr02, dict):
                raw_value = _entry_int_value(rr02)
                if raw_value is not None:
                    raw_name, resolved_name = _resolve_mixer_circuit_type_name(
                        raw_value,
                        cooling_enabled=cooling_enabled,
                        gg05_present=gg05_present,
                        system_schema=system_schema,
                        pool_sensor_present=pool_sensor_present,
                    )
                    rr02["enum_raw_name"] = raw_name
                    rr02["enum_resolved_name"] = resolved_name
                    rr02["value_display"] = f"{raw_name} ({resolved_name})"

            rr03 = registers.get("0x0003")
            if isinstance(rr03, dict):
                raw_value = _entry_int_value(rr03)
                if raw_value is not None:
                    raw_name, resolved_name = _resolve_room_influence_type_name(raw_value)
                    rr03["enum_raw_name"] = raw_name
                    rr03["enum_resolved_name"] = resolved_name
                    rr03["value_display"] = f"{raw_name} ({resolved_name})"


def _resolve_planner_mode(
    *,
    interactive: bool,
    planner_ui: PlannerUiMode,
    observer: ScanObserver | None,
) -> Literal["disabled", "textual", "classic"]:
    if not interactive:
        return "disabled"
    if planner_ui == "disabled":
        return "disabled"
    if planner_ui == "classic":
        return "classic"
    if planner_ui == "textual":
        return "textual"
    try:
        import textual  # noqa: F401, PLC0415
    except Exception:
        if observer is not None:
            observer.log("Textual UI unavailable; falling back to classic planner.", level="warn")
        return "classic"
    return "textual"


class _PlannerHotkeyReader(contextlib.AbstractContextManager["_PlannerHotkeyReader"]):
    """Best-effort single-key planner hotkey reader (`p`) for POSIX terminals."""

    def __init__(self, *, enabled: bool) -> None:
        self._enabled = enabled
        self._active = False
        self._fd: int | None = None
        self._old_termios: Any = None

    def __enter__(self) -> _PlannerHotkeyReader:
        self._activate()
        return self

    def _activate(self) -> None:
        if not self._enabled or sys.platform == "win32" or not sys.stdin.isatty():
            return
        if self._active:
            return
        try:
            import termios  # noqa: PLC0415
            import tty  # noqa: PLC0415

            fd = sys.stdin.fileno()
            self._old_termios = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self._fd = fd
            self._active = True
        except Exception:
            self._active = False

    def _deactivate(self) -> None:
        if not self._active or self._fd is None:
            return
        fd = self._fd
        self._fd = None
        self._active = False
        try:
            import termios  # noqa: PLC0415

            if self._old_termios is not None:
                termios.tcsetattr(fd, termios.TCSADRAIN, self._old_termios)
        except Exception:
            pass

    def __exit__(self, *_exc: object) -> None:
        self._deactivate()
        return None

    def poll(self) -> bool:
        if not self._active or self._fd is None:
            return False
        try:
            import select  # noqa: PLC0415

            ready, _w, _x = select.select([sys.stdin], [], [], 0.0)
            if not ready:
                return False
            raw = os.read(self._fd, 1)
        except (OSError, ValueError):
            return False
        if not raw:
            return False
        ch = raw.decode("utf-8", errors="ignore").lower()
        return ch == "p"

    @contextlib.contextmanager
    def suspend(self) -> Any:
        was_active = self._active
        if was_active:
            self._deactivate()
        try:
            yield None
        finally:
            if was_active:
                self._activate()


def scan_b524(
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
) -> dict[str, Any]:
    """Scan a VRC regulator using B524 and return a JSON-serializable artifact.

    Implements the Phase A/B/C/D algorithm described in `AGENTS.md`:
    - Phase A: group discovery via directory probes
    - Phase B: group classification via GROUP_CONFIG
    - Phase C: instance discovery for groups whose configured ii_max is > 0
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """

    planner_preset = _normalize_planner_preset(planner_preset)
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
        "groups": {},
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
                    "Full preset selected: scan will expand all instance slots and full RR "
                    "ranges. Expect multi-hour BASV2 runs.",
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
        discovered = discover_groups(transport, dst=dst, observer=observer)

        # Exhaustive mode: inject synthetic DiscoveredGroup entries for any GG in
        # 0x00..0x11 not already found by directory probing.
        if planner_preset == "exhaustive":
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
        unknown_groups = sorted(
            group.group for group in classified if group.group not in GROUP_CONFIG
        )
        unknown_descriptor_types = sorted(
            {
                float(group.descriptor)
                for group in classified
                if not math.isnan(group.descriptor)
                and float(group.descriptor) not in _KNOWN_DESCRIPTOR_TYPES
            }
        )
        if unknown_groups and observer is not None:
            unknown_text = ", ".join(f"0x{gg:02X}" for gg in unknown_groups)
            observer.log(
                f"Found {len(unknown_groups)} unknown groups ({unknown_text}); "
                "deriving namespace coverage from opcode responsiveness probes.",
                level="warn",
            )
        if unknown_descriptor_types and observer is not None:
            descriptor_text = ", ".join(f"{value:g}" for value in unknown_descriptor_types)
            observer.log(
                "Found new descriptor class(es): "
                f"{descriptor_text}. Continue scan, then report with artifact JSON/HTML.",
                level="warn",
            )
        if unknown_groups or unknown_descriptor_types:
            advisory: dict[str, Any] = {
                "kind": "protocol_discovery",
                "suggest_issue": True,
                "attach_artifacts": ["scan_json", "scan_html"],
            }
            if unknown_groups:
                advisory["unknown_groups"] = [f"0x{group:02X}" for group in unknown_groups]
            if unknown_descriptor_types:
                advisory["unknown_descriptor_types"] = unknown_descriptor_types
            artifact["meta"]["issue_suggestion"] = advisory
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

        resolved_group_opcodes: dict[int, tuple[RegisterOpcode, ...]] = {}
        unknown_opcode_probe_map: dict[int, dict[str, Any]] = {}
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is not None:
                resolved_group_opcodes[group.group] = _group_opcodes(group.group)
                continue

            opcodes, probe_summary = _probe_unknown_group_opcodes(
                transport,
                dst=dst,
                group=group.group,
                observer=observer,
            )
            resolved_group_opcodes[group.group] = opcodes
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

        group_dual_namespace_runtime: dict[int, bool] = {
            group: len(opcodes) > 1 for group, opcodes in resolved_group_opcodes.items()
        }

        # Phase C: instance discovery (groups with ii_max > 0 only).
        instance_total = 0
        for group in classified:
            meta = metadata_map[group.group]
            opcodes = resolved_group_opcodes.get(group.group, ())
            if GROUP_CONFIG.get(group.group) is None:
                instance_total += len(_UNKNOWN_GROUP_EXPANDED_INSTANCES) * len(opcodes)
                continue
            for opcode in opcodes:
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
        for group in classified:
            meta = metadata_map[group.group]
            rr_max = meta.rr_max
            opcodes = resolved_group_opcodes.get(group.group, ())
            dual_namespace = len(opcodes) > 1
            config = GROUP_CONFIG.get(group.group)
            # NaN descriptors come from synthetic exhaustive-mode injection;
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
                dual_namespace=dual_namespace,
            )
            if desc_for_artifact is not None:
                discovery_advisory["descriptor_observed"] = desc_for_artifact
            if group.expected_descriptor is not None:
                discovery_advisory["descriptor_expected"] = group.expected_descriptor
            if group.descriptor_mismatch:
                discovery_advisory["descriptor_mismatch"] = True
            artifact_group_name = _group_display_name_for_opcodes(
                group=group.group,
                opcodes=opcodes,
                fallback=group.name,
            )
            _ensure_group_artifact(
                artifact,
                group=group.group,
                name=artifact_group_name,
                descriptor_observed=desc_for_artifact,
                dual_namespace=dual_namespace,
                ii_max=(meta.ii_max if not dual_namespace else None),
                discovery_advisory=discovery_advisory,
            )

            if not opcodes:
                continue

            if config is None:
                namespace_probe_counts: list[str] = []
                total_slots = len(_UNKNOWN_GROUP_EXPANDED_INSTANCES)
                for opcode in opcodes:
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
                    )
                    _mark_present_instances(instances_obj, instances=present_instances)
                    namespace_probe_counts.append(
                        f"{opcode_label(opcode)} {len(present_instances)}/{total_slots}"
                    )
                if observer is not None:
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: "
                        f"{', '.join(namespace_probe_counts)} present (experimental), "
                        f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)",
                        level="info",
                    )
                continue

            known_namespace_probe_counts: list[str] = []
            for opcode in opcodes:
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
                    known_namespace_probe_counts.append(
                        f"{_group_name_for_opcode(group.group, opcode)} "
                        f"[{opcode_label(opcode)}] 1/1"
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
                )
                _record_availability_probes(
                    artifact,
                    group=group.group,
                    opcode=opcode,
                    probes=probes,
                )
                present_instances = tuple(ii for ii, probe in probes.items() if probe.present)
                _mark_present_instances(instances_obj, instances=present_instances)
                known_namespace_probe_counts.append(
                    f"{_group_name_for_opcode(group.group, opcode)} "
                    f"[{opcode_label(opcode)}] "
                    f"{len(present_instances)}/{namespace_ii_max + 1}"
                )

            if observer is not None:
                observer.log(
                    f"GG=0x{group.group:02X}: "
                    f"{', '.join(known_namespace_probe_counts)} present, "
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
        planner_groups: list[PlannerGroup] = []
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            group_meta = metadata_map[group.group]
            opcodes = resolved_group_opcodes.get(group.group, ())
            if planner_mode != "disabled" and config is not None:
                opcodes = _planner_source_opcodes(group.group)
            if not opcodes:
                continue
            primary_opcode = opcodes[0]
            dual_namespace = len(opcodes) > 1
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
                        rr_max_full=_rr_max_for_opcode(
                            group=group.group,
                            default_rr_max=group_meta.rr_max,
                            opcode=opcode,
                        ),
                        present_instances=present_instances,
                        namespace_label=(opcode_label(opcode) if dual_namespace else None),
                        primary=(opcode == primary_opcode),
                        exhaustive_only=bool(config and config.get("exhaustive_only")),
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
                    plan = prompt_scan_plan(
                        console,
                        planner_groups,
                        request_rate_rps=request_rate_rps,
                        default_plan=planner_default_plan,
                        default_preset=planner_preset,
                    )

        group_dual_namespace_effective = _apply_effective_namespace_topology(
            artifact,
            group_dual_namespace_runtime=group_dual_namespace_runtime,
            plan=plan,
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

        with _PlannerHotkeyReader(enabled=(planner_mode != "disabled")) as hotkeys:
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
                            plan = prompt_scan_plan(
                                console,
                                planner_groups,
                                request_rate_rps=request_rate_rps,
                                default_plan=plan,
                                default_preset=planner_preset,
                            )
                    group_dual_namespace_effective = _apply_effective_namespace_topology(
                        artifact,
                        group_dual_namespace_runtime=group_dual_namespace_runtime,
                        plan=plan,
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
                    name="Unknown",
                    descriptor_observed=None,
                    dual_namespace=group_dual_namespace_effective.get(task.group, False),
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


def scan_vrc(
    transport: TransportInterface,
    *,
    dst: int,
    b509_ranges: list[tuple[int, int]],
    b555_dump: bool = False,
    b516_dump: bool = False,
    ebusd_host: str | None = None,
    ebusd_port: int | None = None,
    ebusd_schema: EbusdCsvSchema | None = None,
    myvaillant_map: MyvaillantRegisterMap | None = None,
    observer: ScanObserver | None = None,
    console: Console | None = None,
    planner_ui: PlannerUiMode = "auto",
    planner_preset: PlannerPreset = "recommended",
    probe_constraints: bool = False,
) -> dict[str, Any]:
    """Run the full VRC scan flow: B524 primary scan, optional B555/B516 dumps, then B509."""

    artifact = scan_b524(
        transport,
        dst=dst,
        ebusd_host=ebusd_host,
        ebusd_port=ebusd_port,
        ebusd_schema=ebusd_schema,
        myvaillant_map=myvaillant_map,
        observer=observer,
        console=console,
        planner_ui=planner_ui,
        planner_preset=planner_preset,
        probe_constraints=probe_constraints,
    )
    meta = artifact.get("meta")
    if isinstance(meta, dict) and bool(meta.get("incomplete", False)):
        return artifact

    scan_fn = getattr(transport, "send_proto", None)
    if not callable(scan_fn):
        return artifact

    if b555_dump:
        b555_artifact = scan_b555(
            transport,  # type: ignore[arg-type]
            dst=dst,
            observer=observer,
        )
        artifact["b555_dump"] = b555_artifact

        b555_meta = b555_artifact.get("meta", {})
        if (
            isinstance(b555_meta, dict)
            and bool(b555_meta.get("incomplete"))
            and isinstance(meta, dict)
        ):
            meta["incomplete"] = True
            if "incomplete_reason" not in meta:
                reason = b555_meta.get("incomplete_reason")
                if isinstance(reason, str):
                    meta["incomplete_reason"] = f"b555_{reason}"
            return artifact

    if b516_dump:
        b516_artifact = scan_b516(
            transport,  # type: ignore[arg-type]
            dst=dst,
            observer=observer,
        )
        artifact["b516_dump"] = b516_artifact

        b516_meta = b516_artifact.get("meta", {})
        if (
            isinstance(b516_meta, dict)
            and bool(b516_meta.get("incomplete"))
            and isinstance(meta, dict)
        ):
            meta["incomplete"] = True
            if "incomplete_reason" not in meta:
                reason = b516_meta.get("incomplete_reason")
                if isinstance(reason, str):
                    meta["incomplete_reason"] = f"b516_{reason}"
            return artifact

    b509_dump = scan_b509(
        transport,  # type: ignore[arg-type]
        dst=dst,
        ranges=b509_ranges,
        ebusd_schema=ebusd_schema,
        observer=observer,
    )
    artifact["b509_dump"] = b509_dump

    b509_meta = b509_dump.get("meta", {})
    if isinstance(b509_meta, dict) and bool(b509_meta.get("incomplete")) and isinstance(meta, dict):
        meta["incomplete"] = True
        if "incomplete_reason" not in meta:
            reason = b509_meta.get("incomplete_reason")
            if isinstance(reason, str):
                meta["incomplete_reason"] = f"b509_{reason}"

    return artifact


def default_output_filename(*, dst: int, scan_timestamp: str | None = None) -> str:
    """Return the default artifact file name.

    Format (per `AGENTS.md`): `b524_scan_<DST>_<ISO8601>.json`
    """

    stamp = scan_timestamp
    if stamp is None:
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    else:
        # "2026-02-06T19:44:24Z" -> "2026-02-06T194424Z"
        stamp = stamp.replace(":", "")

    return f"b524_scan_{_hex_u8(dst)}_{stamp}.json"
