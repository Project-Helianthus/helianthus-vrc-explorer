"""Private B524 artifact construction helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

from .register import InstanceAvailabilityProbe, NamespaceAvailabilityContract, RegisterEntry


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _artifact_contract_metadata() -> dict[str, Any]:
    return {
        "operation_identity_keys": "opcode_hex",
        "operation_labels": "presentation_only",
        "topology_authority": (
            "operations-first: operations[op_key].groups[gg].instances are authoritative for "
            "consumers"
        ),
        "b524_row_identity": {
            "dedupe_key_format": "<group>:<operation>:<instance>:<register>",
            "path_format": (
                "B524/<section>/<operation>/<group-name>"
                "/<operation-display>/<instance>/<register-name>"
            ),
            "round_trip_stability": (
                "operation keys and persisted topology must be preserved without sentinel rewrite"
            ),
        },
    }


def _ensure_group_artifact(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
    name: str,
    descriptor_observed: float | None,
    ii_max: int | None = None,
    discovery_advisory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Ensure operations[op_hex].groups[group_key] exists in the artifact."""
    op_hex = _hex_u8(opcode)
    group_key = _hex_u8(group)
    op_obj = artifact["operations"].setdefault(op_hex, {})
    op_groups = op_obj.setdefault("groups", {})
    default: dict[str, Any] = {
        "name": name,
        "descriptor_observed": descriptor_observed,
        "instances": {},
    }
    if ii_max is not None:
        default["ii_max"] = _hex_u8(ii_max)
    group_obj = op_groups.setdefault(group_key, default)
    group_obj.setdefault("instances", {})
    group_obj.setdefault("name", name)
    group_obj.setdefault("descriptor_observed", descriptor_observed)
    if ii_max is not None:
        group_obj["ii_max"] = _hex_u8(ii_max)
    if discovery_advisory is not None:
        group_obj["discovery_advisory"] = discovery_advisory
    return cast(dict[str, Any], group_obj)


def _instances_object(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    """Return operations[op_hex].groups[group_key].instances, creating if needed."""
    op_hex = _hex_u8(opcode)
    group_key = _hex_u8(group)
    op_obj = artifact["operations"].setdefault(op_hex, {})
    op_groups = op_obj.setdefault("groups", {})
    group_obj = op_groups.setdefault(group_key, {"instances": {}})
    return cast(dict[str, Any], group_obj.setdefault("instances", {}))


def _availability_object(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    """Return operations[op_hex].groups[group_key] for availability data."""
    op_hex = _hex_u8(opcode)
    group_key = _hex_u8(group)
    op_obj = artifact["operations"].setdefault(op_hex, {})
    op_groups = op_obj.setdefault("groups", {})
    return cast(dict[str, Any], op_groups.setdefault(group_key, {"instances": {}}))


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
    """Write ii_max to operations[op_hex].groups[group_key]."""
    op_hex = _hex_u8(opcode)
    group_key = _hex_u8(group)
    op_obj = artifact["operations"].get(op_hex)
    if not isinstance(op_obj, dict):
        return
    op_groups = op_obj.get("groups")
    if not isinstance(op_groups, dict):
        return
    group_obj = op_groups.get(group_key)
    if not isinstance(group_obj, dict):
        return
    if ii_max is not None:
        group_obj["ii_max"] = _hex_u8(ii_max)


def _present_instances_for_opcode(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> tuple[int, ...]:
    op_hex = _hex_u8(opcode)
    group_key = _hex_u8(group)
    op_obj = artifact["operations"].get(op_hex)
    if not isinstance(op_obj, dict):
        return ()
    op_groups = op_obj.get("groups")
    if not isinstance(op_groups, dict):
        return ()
    group_obj = op_groups.get(group_key)
    if not isinstance(group_obj, dict):
        return ()
    instances_obj = group_obj.get("instances")
    if not isinstance(instances_obj, dict):
        return ()
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
    response_state = entry.get("response_state")
    if response_state in {"nack", "timeout"}:
        return False
    if response_state not in {"active", "empty_reply"}:
        return False
    return entry["error"] is None and entry.get("flags_access") != "absent"


def _entry_is_opcode_responsive(entry: RegisterEntry) -> bool:
    # Kept separate for intent clarity: responsiveness checks reuse readability semantics.
    return _entry_is_readable(entry)
