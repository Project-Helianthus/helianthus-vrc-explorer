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

from ..protocol.b524 import RegisterOpcode, build_constraint_probe_payload
from ..schema.b524_constraints import (
    StaticConstraintCatalog,
    StaticConstraintEntry,
    load_default_b524_constraints_catalog,
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
from .director import GROUP_CONFIG, DiscoveredGroup, classify_groups, discover_groups
from .observer import ScanObserver
from .plan import (
    GroupScanPlan,
    PlanKey,
    RegisterTask,
    build_work_queue,
    estimate_register_requests,
)
from .register import RegisterEntry, is_instance_present, opcodes_for_group, read_register


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


def _primary_opcode(group: int) -> RegisterOpcode:
    return _group_opcodes(group)[0]


def _opcode_label(opcode: int) -> str:
    labels: dict[int, str] = {
        _LOCAL_REGISTER_OPCODE: "local",
        _REMOTE_REGISTER_OPCODE: "remote",
    }
    return labels.get(opcode, _hex_u8(opcode))


def _is_dual_namespace_group(group: int) -> bool:
    return len(_group_opcodes(group)) > 1


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
    return (group, opcode)


def _scan_plan_meta_groups(plan: dict[PlanKey, GroupScanPlan]) -> dict[str, object]:
    serializable: dict[str, object] = {}
    for _key, group_plan in sorted(plan.items()):
        group_key = _hex_u8(group_plan.group)
        if _is_dual_namespace_group(group_plan.group):
            group_obj = serializable.setdefault(
                group_key,
                {
                    "dual_namespace": True,
                    "namespaces": {},
                },
            )
            assert isinstance(group_obj, dict)
            namespaces = group_obj.setdefault("namespaces", {})
            assert isinstance(namespaces, dict)
            namespace_meta = group_plan.to_meta()
            namespace_meta["label"] = _opcode_label(group_plan.opcode)
            namespaces[_hex_u8(group_plan.opcode)] = namespace_meta
            continue
        serializable[group_key] = group_plan.to_meta()
    return serializable


def _ensure_group_artifact(
    artifact: dict[str, Any],
    *,
    group: int,
    name: str,
    descriptor_observed: float | None,
    dual_namespace: bool,
) -> dict[str, Any]:
    group_key = _hex_u8(group)
    default: dict[str, Any] = {
        "name": name,
        "descriptor_observed": descriptor_observed,
        "dual_namespace": dual_namespace,
    }
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
    return group_obj


def _ensure_namespace_artifact(group_obj: dict[str, Any], *, opcode: int) -> dict[str, Any]:
    namespaces = group_obj.setdefault("namespaces", {})
    namespace_key = _hex_u8(opcode)
    namespace_obj = namespaces.setdefault(
        namespace_key,
        {
            "label": _opcode_label(opcode),
            "instances": {},
        },
    )
    namespace_obj.setdefault("label", _opcode_label(opcode))
    namespace_obj.setdefault("instances", {})
    return namespace_obj


def _instances_object(
    artifact: dict[str, Any],
    *,
    group: int,
    opcode: int,
) -> dict[str, Any]:
    group_obj = artifact["groups"][_hex_u8(group)]
    if bool(group_obj.get("dual_namespace")):
        namespace_obj = _ensure_namespace_artifact(group_obj, opcode=opcode)
        return namespace_obj.setdefault("instances", {})
    return group_obj.setdefault("instances", {})


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
) -> tuple[int, ...]:
    present_instances: list[int] = []
    for ii in range(0x00, ii_max + 1):
        if observer is not None:
            observer.status(f"Probe presence GG=0x{group:02X} OP={_hex_u8(opcode)} II=0x{ii:02X}")
        is_present = is_instance_present(
            transport,
            dst=dst,
            group=group,
            instance=ii,
            opcode=opcode,
        )
        if is_present:
            present_instances.append(ii)
        if observer is not None:
            observer.phase_advance("instance_discovery", advance=1)
    return tuple(present_instances)


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
            }
        serializable[_hex_u8(group)] = group_obj
    return serializable


def _constraint_catalog_entry_count(catalog: StaticConstraintCatalog) -> int:
    return sum(len(registers) for registers in catalog.values())


def _constraint_for_register(
    *,
    group: int,
    register: int,
    live_constraints: dict[int, dict[int, ConstraintEntry]],
    static_constraints: StaticConstraintCatalog,
) -> ConstraintEntry | StaticConstraintEntry | None:
    live = live_constraints.get(group, {}).get(register)
    if live is not None:
        return live
    return static_constraints.get(group, {}).get(register)


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
    gg02_instances = gg02.get("instances")
    if not isinstance(gg02_instances, dict):
        return

    gg00 = groups.get("0x00")
    system_schema: int | None = None
    if isinstance(gg00, dict):
        gg00_instances = gg00.get("instances")
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
        "schema_version": "2.0",
        "meta": {
            "scan_timestamp": scan_timestamp,
            "scan_duration_seconds": 0.0,
            "destination_address": _hex_u8(dst),
            "schema_sources": [],
            "incomplete": False,
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
                "scanned conservatively as singleton by default.",
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

        # Phase C: instance discovery (groups with ii_max > 0 only).
        instance_total = 0
        for group in classified:
            meta = metadata_map[group.group]
            if GROUP_CONFIG.get(group.group) is None:
                instance_total += len(_UNKNOWN_GROUP_EXPANDED_INSTANCES) * len(
                    _group_opcodes(group.group)
                )
                continue
            if group.group in {0x09, 0x0A}:
                shared_present: tuple[int, ...]
                shared_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=_REMOTE_REGISTER_OPCODE,
                )
                if _is_instanced_group(shared_ii_max):
                    assert shared_ii_max is not None
                    instance_total += shared_ii_max + 1
                continue
            for opcode in _group_opcodes(group.group):
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
            opcodes = _group_opcodes(group.group)
            dual_namespace = len(opcodes) > 1
            config = GROUP_CONFIG.get(group.group)
            # NaN descriptors come from synthetic exhaustive-mode injection;
            # store as None to keep JSON-serializable and avoid polluting analytics.
            desc_for_artifact = None if math.isnan(group.descriptor) else group.descriptor
            _ensure_group_artifact(
                artifact,
                group=group.group,
                name=group.name,
                descriptor_observed=desc_for_artifact,
                dual_namespace=dual_namespace,
            )

            if config is None:
                namespace_probe_counts: list[str] = []
                total_slots = len(_UNKNOWN_GROUP_EXPANDED_INSTANCES)
                for opcode in opcodes:
                    instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
                    emit_trace_label(
                        transport,
                        "Exploring unknown group "
                        f"0x{group.group:02X} ({_opcode_label(opcode)}) "
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
                        f"{_opcode_label(opcode)} {len(present_instances)}/{total_slots}"
                    )
                if observer is not None:
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: "
                        f"{', '.join(namespace_probe_counts)} present (experimental), "
                        f"RR_max=0x{rr_max:04X} ({rr_max + 1} registers/instance)",
                        level="info",
                    )
                continue

            if group.group in {0x09, 0x0A}:
                shared_ii_max = _ii_max_for_opcode(
                    group=group.group,
                    default_ii_max=meta.ii_max,
                    opcode=_REMOTE_REGISTER_OPCODE,
                )
                if not _is_instanced_group(shared_ii_max):
                    shared_present = (0x00,)
                else:
                    assert shared_ii_max is not None
                    emit_trace_label(
                        transport,
                        "Identifying instances in group "
                        f"0x{group.group:02X} via shared remote probe",
                    )
                    shared_present = _probe_present_instances(
                        transport,
                        dst=dst,
                        group=group.group,
                        opcode=_REMOTE_REGISTER_OPCODE,
                        ii_max=shared_ii_max,
                        observer=observer,
                    )
                for opcode in opcodes:
                    instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
                    _mark_present_instances(instances_obj, instances=shared_present)
                if observer is not None:
                    total_instances = 1 if shared_ii_max is None else shared_ii_max + 1
                    observer.log(
                        f"GG=0x{group.group:02X} {group.name}: "
                        f"{len(shared_present)}/{total_instances} present "
                        f"(shared across local/remote), "
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
                instances_obj = _instances_object(artifact, group=group.group, opcode=opcode)
                if not _is_instanced_group(namespace_ii_max):
                    _mark_present_instances(instances_obj, instances=(0x00,))
                    known_namespace_probe_counts.append(f"{_opcode_label(opcode)} 1/1")
                    continue

                assert namespace_ii_max is not None
                emit_trace_label(
                    transport,
                    f"Identifying instances in group 0x{group.group:02X} ({_opcode_label(opcode)})",
                )
                present_instances = _probe_present_instances(
                    transport,
                    dst=dst,
                    group=group.group,
                    opcode=opcode,
                    ii_max=namespace_ii_max,
                    observer=observer,
                )
                _mark_present_instances(instances_obj, instances=present_instances)
                known_namespace_probe_counts.append(
                    f"{_opcode_label(opcode)} {len(present_instances)}/{namespace_ii_max + 1}"
                )

            if observer is not None:
                observer.log(
                    f"GG=0x{group.group:02X} {group.name}: "
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
            for opcode in _group_opcodes(group.group):
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
            opcodes = _group_opcodes(group.group)
            primary_opcode = opcodes[0]
            primary_rr_max = _rr_max_for_opcode(
                group=group.group,
                default_rr_max=group_meta.rr_max,
                opcode=primary_opcode,
            )
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
                        name=group.name,
                        descriptor=group.descriptor,
                        known=config is not None and not config.get("exhaustive_only", False),
                        ii_max=planner_ii_max,
                        rr_max=primary_rr_max,
                        rr_max_full=_rr_max_for_opcode(
                            group=group.group,
                            default_rr_max=group_meta.rr_max,
                            opcode=opcode,
                        ),
                        present_instances=present_instances,
                        namespace_label=(_opcode_label(opcode) if dual_namespace else None),
                        primary=(opcode == primary_opcode),
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

                # Some groups are ambiguous and may respond to either opcode family (0x02 vs 0x06).
                # When in doubt (unknown group), probe both but keep only the best/most-meaningful
                # reply in the artifact.
                opcodes_to_try: tuple[RegisterOpcode, ...]
                if task.group in GROUP_CONFIG:
                    opcodes_to_try = (cast(RegisterOpcode, task.opcode),)
                else:
                    opcodes_to_try = (_LOCAL_REGISTER_OPCODE, _REMOTE_REGISTER_OPCODE)

                best_entry: RegisterEntry | None = None
                best_quality = -1
                for opcode in opcodes_to_try:
                    schema_entry = (
                        ebusd_schema.lookup(
                            opcode=opcode,
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
                            opcode=opcode,
                        )
                        if myvaillant_map is not None
                        else None
                    )
                    type_hint = (
                        myvaillant_entry.type_hint
                        if myvaillant_entry is not None and myvaillant_entry.type_hint is not None
                        else (schema_entry.type_spec if schema_entry is not None else None)
                    )

                    candidate = read_register(
                        transport,
                        dst,
                        opcode,
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
                        type_hint=type_hint,
                    )
                    if schema_entry is not None:
                        candidate["ebusd_name"] = schema_entry.name

                    # Prefer a meaningful value over status-only / no_data replies; otherwise prefer
                    # a clean reply (no error) over transport/decode failures.
                    quality = (
                        2
                        if _entry_has_valid_value(candidate)
                        else (1 if candidate["error"] is None else 0)
                    )
                    if quality > best_quality:
                        best_entry = candidate
                        best_quality = quality
                    if quality == 2:
                        break

                assert best_entry is not None
                entry = best_entry
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
                    group=task.group,
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
                                "reason": mismatch_reason,
                            }
                        )
                done.add(task)

                _ensure_group_artifact(
                    artifact,
                    group=task.group,
                    name="Unknown",
                    descriptor_observed=None,
                    dual_namespace=_is_dual_namespace_group(task.group),
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
                    "Observed register values outside the bundled static constraint catalog. "
                    "Review meta.constraint_mismatches and rerun with --probe-constraints if "
                    "you want live confirmation.",
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
