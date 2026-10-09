"""Private probing and constraint helpers for the B524 scanner facade."""

from __future__ import annotations

import math
import struct
from dataclasses import asdict, dataclass
from typing import Any, cast

from ..protocol.b524 import (
    RegisterOpcode,
    build_constraint_probe_payload,
    build_register_read_payload,
)
from ..protocol.b524_metadata import decode_parameter_description
from ..schema.b524_constraints import (
    LIVE_PROBE_CONSTRAINT_SCOPE,
    StaticConstraintCatalog,
    StaticConstraintEntry,
    lookup_static_constraint,
)
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportRecoveryExhausted,
)
from .b524_artifact import _entry_is_opcode_responsive, _entry_is_readable
from .identity import make_register_identity
from .observer import ScanObserver
from .register import (
    InstanceAvailabilityProbe,
    RegisterEntry,
    probe_instance_availability,
    read_register,
)


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


_LOCAL_REGISTER_OPCODE: RegisterOpcode = 0x02
_REMOTE_REGISTER_OPCODE: RegisterOpcode = 0x06
_UNKNOWN_GROUP_INITIAL_INSTANCES: tuple[int, ...] = (0x00, 0x01)
_UNKNOWN_GROUP_EXPANDED_INSTANCES: tuple[int, ...] = tuple(range(0x00, 0x0B)) + (0xFF,)
_UNKNOWN_GROUP_PRESENCE_REGISTER = 0x0000
_UNKNOWN_GROUP_OPCODE_CANDIDATES: tuple[RegisterOpcode, ...] = (
    _LOCAL_REGISTER_OPCODE,
    _REMOTE_REGISTER_OPCODE,
)
_UNKNOWN_GROUP_RESEARCH_SELECTORS: tuple[tuple[int, int], ...] = (
    (0x00, 0x0000),
    (0x00, 0x0001),
    (0x01, 0x0000),
    (0x01, 0x0001),
)
_QUALIFIED_DESCRIPTION_CODECS = frozenset(
    {"UCH", "BOOL", "I8", "UIN", "I16", "U32", "I32", "EXP", "HDA:3", "HTI"}
)


def _unknown_instance_candidates(*, opcode: RegisterOpcode, expanded: bool) -> tuple[int, ...]:
    """Return bounded unknown-group selectors for one read namespace."""

    if opcode == 0x06:
        return tuple(range(0x01, 0x09)) if expanded else (0x01, 0x02)
    return _UNKNOWN_GROUP_EXPANDED_INSTANCES if expanded else _UNKNOWN_GROUP_INITIAL_INSTANCES


def _unknown_opcode_research_selectors(opcode: RegisterOpcode) -> tuple[tuple[int, int], ...]:
    if opcode == 0x06:
        return tuple(
            (instance, register)
            for instance in _unknown_instance_candidates(opcode=opcode, expanded=True)
            for register in (0x0000, 0x0001)
        )
    return _UNKNOWN_GROUP_RESEARCH_SELECTORS


def _unknown_probe_evidence(
    entry: RegisterEntry,
    *,
    opcode: RegisterOpcode,
    group: int,
    instance: int,
    register: int,
) -> dict[str, Any]:
    responsive = _entry_is_opcode_responsive(entry)
    return {
        "selector": {
            "instance": _hex_u8(instance),
            "register": _hex_u16(register),
        },
        "request_hex": build_register_read_payload(
            opcode,
            group=group,
            instance=instance,
            register=register,
        ).hex(),
        "responsive": responsive,
        "classification": "responsive" if responsive else "unknown",
        "response_state": entry.get("response_state"),
        "error": entry.get("error"),
        "flags_access": entry.get("flags_access"),
        "reply_hex": entry.get("reply_hex"),
        "raw_hex": entry.get("raw_hex"),
    }


def _probe_unknown_group_opcodes(
    transport: TransportInterface,
    *,
    dst: int,
    group: int,
    observer: ScanObserver | None,
    research: bool = False,
) -> tuple[tuple[RegisterOpcode, ...], dict[str, Any]]:
    if research:
        research_evidence: dict[str, Any] = {}
        research_responsive: list[RegisterOpcode] = []
        for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES:
            probes: list[dict[str, Any]] = []
            for instance, register in _unknown_opcode_research_selectors(opcode):
                if observer is not None:
                    observer.status(
                        f"Research opcode GG=0x{group:02X} OP={_hex_u8(opcode)} "
                        f"II={_hex_u8(instance)} RR={_hex_u16(register)}"
                    )
                entry = read_register(
                    transport,
                    dst,
                    opcode,
                    group=group,
                    instance=instance,
                    register=register,
                )
                probes.append(
                    _unknown_probe_evidence(
                        entry,
                        opcode=opcode,
                        group=group,
                        instance=instance,
                        register=register,
                    )
                )
            is_responsive = any(probe["responsive"] for probe in probes)
            if is_responsive:
                research_responsive.append(opcode)
            research_evidence[_hex_u8(opcode)] = {
                "responsive": is_responsive,
                # Negative sentinel probes cannot establish group absence.
                "classification": "responsive" if is_responsive else "unknown",
                "probes": probes,
            }

        selected = tuple(sorted(set(research_responsive)))
        return cast(tuple[RegisterOpcode, ...], selected), {
            "kind": "bounded_research_opcode_responsiveness",
            "selectors_by_opcode": {
                _hex_u8(opcode): [
                    {
                        "instance": _hex_u8(instance),
                        "register": _hex_u16(register),
                    }
                    for instance, register in _unknown_opcode_research_selectors(opcode)
                ]
                for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES
            },
            "candidates": research_evidence,
            "responsive_opcodes": [_hex_u8(opcode) for opcode in selected],
            "negative_result_meaning": "unknown_not_absent",
        }

    evidence: dict[str, Any] = {}
    responsive: list[RegisterOpcode] = []

    for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES:
        instance = 0x01 if opcode == 0x06 else 0x00
        if observer is not None:
            observer.status(
                f"Probe opcode GG=0x{group:02X} OP={_hex_u8(opcode)} "
                f"II={_hex_u8(instance)} RR={_hex_u16(_UNKNOWN_GROUP_PRESENCE_REGISTER)}"
            )
        entry = read_register(
            transport,
            dst,
            opcode,
            group=group,
            instance=instance,
            register=_UNKNOWN_GROUP_PRESENCE_REGISTER,
        )
        is_responsive = _entry_is_opcode_responsive(entry)
        if is_responsive:
            responsive.append(opcode)
        evidence[_hex_u8(opcode)] = {
            "instance": _hex_u8(instance),
            "responsive": is_responsive,
            "response_state": entry.get("response_state"),
            "error": entry.get("error"),
            "flags_access": entry.get("flags_access"),
            "reply_hex": entry.get("reply_hex"),
            "raw_hex": entry.get("raw_hex"),
        }

    selected = tuple(sorted(set(responsive)))
    probe_summary: dict[str, Any] = {
        "kind": "opcode_responsiveness",
        "selectors_by_opcode": {
            _hex_u8(opcode): {
                "instance": evidence[_hex_u8(opcode)]["instance"],
                "register": _hex_u16(_UNKNOWN_GROUP_PRESENCE_REGISTER),
            }
            for opcode in _UNKNOWN_GROUP_OPCODE_CANDIDATES
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
    expand_fallback: bool,
    research: bool = False,
) -> tuple[int, ...]:
    if research:
        research_present_instances: list[int] = []
        for ii in _unknown_instance_candidates(opcode=opcode, expanded=True):
            readable = False
            for register in (0x0000, 0x0001):
                if observer is not None:
                    observer.status(
                        f"Research presence GG=0x{group:02X} OP={_hex_u8(opcode)} "
                        f"II=0x{ii:02X} RR={_hex_u16(register)}"
                    )
                entry = read_register(
                    transport,
                    dst,
                    opcode,
                    group=group,
                    instance=ii,
                    register=register,
                )
                # A full echoed reply is positive evidence. Timeouts, empty
                # replies, NACKs and status-only replies remain unknown and the
                # secondary anchor is still attempted.
                readable = (
                    _entry_is_readable(entry)
                    and entry.get("response_state") == "active"
                    and entry.get("raw_hex") is not None
                )
                if readable:
                    break
            if readable:
                research_present_instances.append(ii)
            if observer is not None:
                observer.phase_advance("instance_discovery", advance=1)
        return tuple(research_present_instances)

    present_instances: list[int] = []
    probed: set[int] = set()
    should_expand = False

    for ii in _unknown_instance_candidates(opcode=opcode, expanded=False):
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

    if not should_expand or not expand_fallback:
        return tuple(present_instances)

    for ii in _unknown_instance_candidates(opcode=opcode, expanded=True):
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
    probe_instance_availability_fn: Any = probe_instance_availability,
    expected_count: int | None = None,
    capacity: int | None = None,
    stop_at_first_absence: bool = False,
    on_probe: Any = None,
) -> dict[int, InstanceAvailabilityProbe]:
    probes: dict[int, InstanceAvailabilityProbe] = {}
    present_count = 0
    if expected_count == 0 and (opcode, group) != (0x02, 0x02):
        # A qualified zero count or capacity avoids ordinary default-slot probes.
        # The circuit's independent virtual DHW slot still needs a probe.
        return probes
    first_ii = 1 if opcode == 6 or (opcode == 2 and group == 2) else 0
    ordinary_ii_max = ii_max
    if capacity == 0:
        if (opcode, group) != (0x02, 0x02):
            return probes
        # Leave II09 to the independent virtual-slot probe below.
        ordinary_ii_max = 0
    for ii in range(first_ii, ordinary_ii_max + 1):
        if observer is not None:
            observer.status(f"Probe presence GG=0x{group:02X} OP={_hex_u8(opcode)} II=0x{ii:02X}")
        probe = probe_instance_availability_fn(
            transport,
            dst=dst,
            group=group,
            instance=ii,
            opcode=opcode,
        )
        probes[ii] = probe
        if on_probe is not None:
            on_probe(ii, probe)
        if (
            stop_at_first_absence
            and not (expected_count is not None and expected_count > 0)
            and probe.connection_state == "not_connected"
        ):
            if observer is not None:
                observer.phase_advance("instance_discovery", advance=1)
            break
        present_count += int(probe.present and not (opcode == 2 and group == 2 and ii == 0x09))
        if expected_count is not None and expected_count > 0 and present_count >= expected_count:
            if observer is not None:
                observer.phase_advance("instance_discovery", advance=1)
            break
        if observer is not None:
            observer.phase_advance("instance_discovery", advance=1)

    # The OP=02/GG=02 virtual water circuit is outside the count-guided
    # heating-circuit quota. Its actual availability still needs a probe: the
    # resulting evidence can be positive, false, or unknown and is never
    # manufactured from the mandatory scan-plan selector.
    virtual_instance = 0x09 if opcode == 0x02 and group == 0x02 else None
    if (
        virtual_instance is not None
        and virtual_instance <= ii_max
        and virtual_instance not in probes
    ):
        probe = probe_instance_availability_fn(
            transport,
            dst=dst,
            group=group,
            instance=virtual_instance,
            opcode=opcode,
        )
        probes[virtual_instance] = probe
        if on_probe is not None:
            on_probe(virtual_instance, probe)
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
    min_value: int | float | str | None
    max_value: int | float | str | None
    step_value: int | float | None
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
    try:
        import datetime as _dt_mod

        _dt_mod.date(year, month, day)
    except ValueError as exc:
        raise ValueError(
            f"Invalid date triplet: {value.hex()} ({year:04d}-{month:02d}-{day:02d})"
        ) from exc
    return f"{year:04d}-{month:02d}-{day:02d}"


def _parse_constraint_entry(
    *,
    group: int,
    register: int,
    response: bytes,
) -> ConstraintEntry:
    # Archived legacy heuristic only. The first byte is response framing length;
    # archived guesses are never qualified or used for edit validation.
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
            step_value=step_u8 if step_u8 != 0 else None,
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
            step_value=step_u16 if step_u16 != 0 else None,
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
            min_value=min_f32 if math.isfinite(min_f32) else None,
            max_value=max_f32 if math.isfinite(max_f32) else None,
            step_value=step_f32 if math.isfinite(step_f32) else None,
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
    """Retained compatibility shim: legacy probing cannot qualify metadata.

    Use probe_parameter_description after reading the complete parameter identity
    and its codec. This shim deliberately sends no requests.
    """
    if observer is not None:
        observer.log("Legacy short-selector constraint probing is disabled", level="warn")
    return {}


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


def _apply_constraint_metadata(
    entry: RegisterEntry,
    constraint: ConstraintEntry | StaticConstraintEntry,
) -> None:
    entry["constraint_qualification"] = "legacy_unqualified"
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
    # Archived short-selector guesses cannot contradict a current read. Only a
    # complete matched description can validate an edit.
    return None


def probe_parameter_description(
    transport: TransportInterface,
    *,
    dst: int,
    opcode: int,
    group: int,
    instance: int,
    register: int,
    type_spec: str | None,
) -> dict[str, Any]:
    if opcode not in {2, 6}:
        raise ValueError("Description read opcode must be 0x02 or 0x06")
    description_opcode = 1 if opcode == 2 else 7
    request = build_constraint_probe_payload(
        group, register, instance=instance, opcode=description_opcode
    )
    selector = {
        "description_opcode": _hex_u8(description_opcode),
        "read_opcode": _hex_u8(opcode),
        "group": _hex_u8(group),
        "instance": _hex_u8(instance),
        "register": _hex_u16(register),
    }
    metadata: dict[str, Any] = {
        "qualification": "unavailable",
        **selector,
        "destination_address": _hex_u8(dst),
        "profile": "controller_b524",
        "request_hex": request.hex(),
        "selector": selector,
    }
    try:
        response = transport.send(dst, request)
        metadata["reply_hex"] = response.hex()
        if len(response) < 3:
            raise ValueError("Description response too short for GG/RR16 echo")
        reply_group = response[0]
        reply_register = int.from_bytes(response[1:3], "little")
        echo_matches = reply_group == group and reply_register == register
        metadata["reply_echo"] = {
            "group": _hex_u8(reply_group),
            "register": _hex_u16(reply_register),
            "matches_selector": echo_matches,
            "instance": "not_echoed_by_protocol",
        }
        if not echo_matches:
            raise ValueError("Description GG/RR16 echo mismatch")
        normalized_type = type_spec.strip().upper() if type_spec is not None else None
        if normalized_type not in _QUALIFIED_DESCRIPTION_CODECS:
            reason = (
                "parameter codec is unknown"
                if normalized_type is None
                else f"parameter codec is unsupported for description decoding: {normalized_type}"
            )
            metadata.update(
                {
                    "qualification": "unqualified",
                    "reason": reason,
                    "source": "complete_description",
                }
            )
            if normalized_type is not None:
                metadata["type"] = normalized_type
            return metadata
        metadata.update(
            decode_parameter_description(
                response,
                opcode=description_opcode,
                group=group,
                instance=instance,
                register=register,
                type_spec=normalized_type,
            )
        )
    except TransportRecoveryExhausted as exc:
        metadata["reason"] = str(exc)
        exc.selector = {**selector, "request_hex": request.hex()}
        exc.parameter_description = metadata
        raise
    except TransportCommandNotEnabled:
        raise
    except (TransportError, ValueError) as exc:
        metadata["reason"] = str(exc)
    return metadata
