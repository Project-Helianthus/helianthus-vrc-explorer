"""Private probing and constraint helpers for the B524 scanner facade."""

from __future__ import annotations

import math
import struct
from dataclasses import asdict, dataclass
from typing import Any, cast

from ..protocol.b524 import RegisterOpcode, build_constraint_probe_payload
from ..schema.b524_constraints import (
    LIVE_PROBE_CONSTRAINT_SCOPE,
    StaticConstraintCatalog,
    StaticConstraintEntry,
    lookup_static_constraint,
)
from ..transport.base import TransportCommandNotEnabled, TransportError, TransportInterface
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
            "response_state": entry.get("response_state"),
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
    expand_fallback: bool,
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

    if not should_expand or not expand_fallback:
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
    probe_instance_availability_fn: Any = probe_instance_availability,
) -> dict[int, InstanceAvailabilityProbe]:
    probes: dict[int, InstanceAvailabilityProbe] = {}
    for ii in range(0x00, ii_max + 1):
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
    if entry.get("response_state") != "active":
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
