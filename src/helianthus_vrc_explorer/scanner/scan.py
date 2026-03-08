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
from typing import Any, Literal

from rich.console import Console

from ..protocol.b524 import RegisterOpcode, build_constraint_probe_payload
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
from .director import GROUP_CONFIG, B524UnsupportedError, classify_groups, discover_groups
from .observer import ScanObserver
from .plan import GroupScanPlan, RegisterTask, build_work_queue, estimate_register_requests
from .register import RegisterEntry, is_instance_present, opcode_for_group, read_register


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


_LOCAL_REGISTER_OPCODE: RegisterOpcode = 0x02
_REMOTE_REGISTER_OPCODE: RegisterOpcode = 0x06
_UNKNOWN_GROUP_DEFAULT_RR_MAX = 0x0030
_UNKNOWN_GROUP_DEFAULT_II_MAX = 0x0A

PlannerUiMode = Literal["auto", "textual", "classic"]
_KNOWN_DESCRIPTOR_TYPES = frozenset(
    float(desc) for config in GROUP_CONFIG.values() if (desc := config.get("desc")) is not None
)


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
    - Phase C: instance discovery for desc==1.0 groups using per-group heuristics
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """

    start_perf = time.perf_counter()
    scan_timestamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    counting_transport = CountingTransport(transport)
    transport = counting_transport

    artifact: dict[str, Any] = {
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

    incomplete_reason: str | None = None

    try:
        if observer is not None:
            observer.log(f"Starting scan dst={_hex_u8(dst)}", level="info")
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
        try:
            discovered = discover_groups(transport, dst=dst, observer=observer)
        except B524UnsupportedError as exc:
            if observer is not None:
                observer.phase_finish("group_discovery")
                observer.log(str(exc), level="warn")
            artifact["meta"]["b524_supported"] = False
            artifact["meta"]["b524_skip_reason"] = "first_directory_probe_no_data"
            artifact["meta"]["scan_duration_seconds"] = round(time.perf_counter() - start_perf, 4)
            return artifact
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
                if float(group.descriptor) not in _KNOWN_DESCRIPTOR_TYPES
            }
        )
        if unknown_groups and observer is not None:
            unknown_text = ", ".join(f"0x{gg:02X}" for gg in unknown_groups)
            observer.log(
                f"Found {len(unknown_groups)} unknown groups ({unknown_text}); "
                "skipped by default (enable in planner).",
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
            if config is not None and group.descriptor == 1.0:
                ii_max = int(config["ii_max"])
            elif config is not None:
                ii_max = None
            else:
                ii_max = _UNKNOWN_GROUP_DEFAULT_II_MAX if group.descriptor == 1.0 else None

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
        elif observer is not None:
            observer.log(
                "Skipping opcode 0x01 constraint probe (using static annotations).",
                level="info",
            )

        # Phase C: instance discovery (desc==1.0 groups only).
        instance_total = 0
        for group in classified:
            if group.descriptor == 1.0:
                meta = metadata_map[group.group]
                assert meta.ii_max is not None
                instance_total += meta.ii_max + 1
        if observer is not None:
            observer.phase_start("instance_discovery", total=instance_total or 1)

        instance_discovery_start = time.perf_counter()
        instance_discovery_start_calls = counting_transport.counters.send_calls
        for group in classified:
            if group.descriptor == 1.0:
                emit_trace_label(
                    transport,
                    f"Identifying instances in group 0x{group.group:02X}",
                )
            group_key = _hex_u8(group.group)
            group_obj: dict[str, Any] = {
                "name": group.name,
                "descriptor_type": group.descriptor,
                "instances": {},
            }
            artifact["groups"][group_key] = group_obj

            config = GROUP_CONFIG.get(group.group)
            if config is None:
                continue

            if group.descriptor != 1.0:
                # Singleton / Type 6 groups: no instance enumeration; scan II=0x00 later.
                group_obj["instances"][_hex_u8(0x00)] = {"present": True}
                continue

            meta = metadata_map[group.group]
            ii_max = meta.ii_max
            rr_max = meta.rr_max
            assert ii_max is not None
            present_count = 0
            for ii in range(0x00, ii_max + 1):
                if observer is not None:
                    observer.status(f"Probe presence GG=0x{group.group:02X} II=0x{ii:02X}")
                is_present = is_instance_present(
                    transport,
                    dst=dst,
                    group=group.group,
                    instance=ii,
                )
                if is_present:
                    present_count += 1
                    group_obj["instances"][_hex_u8(ii)] = {"present": True}
                if observer is not None:
                    observer.phase_advance("instance_discovery", advance=1)

            if observer is not None:
                observer.log(
                    f"GG=0x{group.group:02X} {group.name}: "
                    f"{present_count}/{ii_max + 1} present, "
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
        plan: dict[int, GroupScanPlan] = {}
        for group in classified:
            config = GROUP_CONFIG.get(group.group)
            if config is None:
                config_meta = metadata_map[group.group]
                rr_max = config_meta.rr_max
            else:
                rr_max = metadata_map[group.group].rr_max

            group_obj = artifact["groups"][_hex_u8(group.group)]
            if group.descriptor == 1.0:
                present_instances_for_plan: list[int] = []
                for ii_key, ii_obj in group_obj.get("instances", {}).items():
                    if not isinstance(ii_obj, dict):
                        continue
                    if ii_obj.get("present") is True:
                        present_instances_for_plan.append(int(ii_key, 0))
                plan[group.group] = GroupScanPlan(
                    group=group.group,
                    opcode=opcode_for_group(group.group),
                    rr_max=rr_max,
                    instances=tuple(sorted(present_instances_for_plan)),
                )
            else:
                plan[group.group] = GroupScanPlan(
                    group=group.group,
                    opcode=opcode_for_group(group.group),
                    rr_max=rr_max,
                    instances=(0x00,),
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

            if config is None:
                rr_max_default = group_meta.rr_max
                ii_max_default = group_meta.ii_max
                present_instances_default: tuple[int, ...]
                if group.descriptor == 1.0:
                    if ii_max_default is None:
                        ii_max_default = _UNKNOWN_GROUP_DEFAULT_II_MAX
                    present_instances_default = tuple(range(0x00, ii_max_default + 1))
                else:
                    ii_max_default = None
                    present_instances_default = (0x00,)
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=False,
                        ii_max=ii_max_default,
                        rr_max=rr_max_default,
                        present_instances=present_instances_default,
                    )
                )
                continue

            group_obj = artifact["groups"][_hex_u8(group.group)]
            if group.descriptor == 1.0:
                present_instances_for_planner: list[int] = [
                    int(ii_key, 0)
                    for (ii_key, ii_obj) in group_obj.get("instances", {}).items()
                    if isinstance(ii_obj, dict) and ii_obj.get("present") is True
                ]
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=True,
                        ii_max=group_meta.ii_max,
                        rr_max=group_meta.rr_max,
                        present_instances=tuple(sorted(present_instances_for_planner)),
                    )
                )
            else:
                planner_groups.append(
                    PlannerGroup(
                        group=group.group,
                        name=group.name,
                        descriptor=group.descriptor,
                        known=True,
                        ii_max=None,
                        rr_max=group_meta.rr_max,
                        present_instances=(0x00,),
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
            "groups": {_hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())},
            "estimated_register_requests": estimate_register_requests(plan),
            "measured_request_rate_rps": round(request_rate_rps, 4) if request_rate_rps else None,
        }
        artifact["meta"]["group_metadata_bounds"] = _metadata_map_to_dict(metadata_map)
        artifact["meta"]["constraint_probe_enabled"] = probe_constraints
        artifact["meta"]["constraint_dictionary"] = _constraint_map_to_dict(constraint_map)

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
                    artifact["meta"]["scan_plan"]["groups"] = {
                        _hex_u8(gg): gp.to_meta() for (gg, gp) in sorted(plan.items())
                    }
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
                    opcodes_to_try = (opcode_for_group(task.group),)
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
                    type_hint = schema_entry.type_spec if schema_entry is not None else None

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
                    mv = myvaillant_map.lookup(
                        group=task.group,
                        instance=task.instance,
                        register=task.register,
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

                constraint = constraint_map.get(task.group, {}).get(task.register)
                if constraint is not None:
                    entry["constraint_tt"] = _hex_u8(constraint.tt)
                    entry["constraint_type"] = constraint.kind
                    entry["constraint_min"] = constraint.min_value
                    entry["constraint_max"] = constraint.max_value
                    entry["constraint_step"] = constraint.step_value
                done.add(task)

                group_key = _hex_u8(task.group)
                group_obj = artifact["groups"].setdefault(
                    group_key,
                    {"name": "Unknown", "descriptor_type": None, "instances": {}},
                )
                instances_obj = group_obj.setdefault("instances", {})
                instance_key = _hex_u8(task.instance)
                instance_obj = instances_obj.setdefault(instance_key, {"present": False})
                if isinstance(instance_obj, dict):
                    registers = instance_obj.setdefault("registers", {})
                    registers[_hex_u16(task.register)] = entry

        _apply_contextual_enum_annotations(artifact)

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
    """Run the full VRC scan flow: B524 primary scan, then B509 register dump."""

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
