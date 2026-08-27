from __future__ import annotations

import contextlib
import math
import os
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Literal

from rich.console import Console

from ..protocol.b524 import RegisterOpcode
from ..schema.ebusd_csv import EbusdCsvSchema
from ..schema.myvaillant_map import MyvaillantRegisterMap
from ..transport.base import (
    TransportInterface,
)
from ..ui.planner import PlannerPreset, prompt_scan_plan
from . import b524_plan, b524_probe
from .b509 import scan_b509
from .b516 import scan_b516
from .b524_plan import PlannerUiMode
from .b555 import scan_b555
from .director import (
    discover_groups,
)
from .observer import ScanObserver
from .register import (
    RegisterEntry,
    probe_instance_availability,
)

_planner_primary_opcode = b524_plan._planner_primary_opcode
_planner_source_opcodes = b524_plan._planner_source_opcodes
_probe_unknown_group_opcodes = b524_probe._probe_unknown_group_opcodes
ConstraintEntry = b524_probe.ConstraintEntry
GroupMetadata = b524_probe.GroupMetadata
_decode_constraint_date = b524_probe._decode_constraint_date
_parse_constraint_entry = b524_probe._parse_constraint_entry


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


def _iter_group_namespace_instance_maps(
    group_obj: dict[str, Any],
) -> list[tuple[str | None, dict[str, Any]]]:
    """Iterate instance maps for a group object.

    In v2.3, each group_obj under an operation simply has instances directly.
    """
    instances = group_obj.get("instances")
    if isinstance(instances, dict):
        return [(None, instances)]
    return []


def _group_instances_for_namespace(
    group_obj: dict[str, Any], *, namespace_key: str | None = None
) -> dict[str, Any] | None:
    """Return instances from a group object (v2.3: direct access)."""
    instances = group_obj.get("instances")
    if isinstance(instances, dict):
        return instances
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
    # v2.3: look up GG=0x02 under OP=0x02
    op_02 = artifact.get("operations", {}).get(_hex_u8(_LOCAL_REGISTER_OPCODE))
    if not isinstance(op_02, dict):
        return
    op_02_groups = op_02.get("groups")
    if not isinstance(op_02_groups, dict):
        return

    gg02 = op_02_groups.get("0x02")
    if not isinstance(gg02, dict):
        return
    gg02_namespace_maps = _iter_group_namespace_instance_maps(gg02)
    gg02_instance_maps = [instances for _namespace_key, instances in gg02_namespace_maps]
    if not gg02_instance_maps:
        return

    gg00 = op_02_groups.get("0x00")
    system_schema: int | None = None
    if isinstance(gg00, dict):
        gg00_instances = _group_instances_for_namespace(gg00)
        if isinstance(gg00_instances, dict):
            ii00 = gg00_instances.get("0x00")
            if isinstance(ii00, dict):
                regs = ii00.get("registers")
                if isinstance(regs, dict):
                    entry = regs.get("0x0001")
                    if isinstance(entry, dict):
                        system_schema = _entry_int_value(entry)

    gg05_present = "0x05" in op_02_groups
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

    Implements the four-phase scan algorithm:
    - Phase A: group discovery via directory probes
    - Phase B: group classification via GROUP_CONFIG
    - Phase C: instance discovery for groups whose configured ii_max is > 0
    - Phase D: register scan RR=0..rr_max for each present instance

    Partial scans are supported: Ctrl+C yields `meta.incomplete=true`.
    """
    from .b524_orchestration import run_b524_scan

    return run_b524_scan(
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
        discover_groups_fn=discover_groups,
        prompt_scan_plan_fn=prompt_scan_plan,
        hotkey_reader_cls=_PlannerHotkeyReader,
        probe_instance_availability_fn=probe_instance_availability,
    )


def scan_vrc(
    transport: TransportInterface,
    *,
    dst: int,
    b509_ranges: list[tuple[int, int]],
    b509_dump: bool = False,
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
    """Run VRC scan flow: B524 primary scan, optional B555/B516/B509 dumps."""

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

    if not b509_dump:
        return artifact

    b509_artifact = scan_b509(
        transport,  # type: ignore[arg-type]
        dst=dst,
        ranges=b509_ranges,
        ebusd_schema=ebusd_schema,
        observer=observer,
    )
    artifact["b509_dump"] = b509_artifact

    b509_meta = b509_artifact.get("meta", {})
    if isinstance(b509_meta, dict) and bool(b509_meta.get("incomplete")) and isinstance(meta, dict):
        meta["incomplete"] = True
        if "incomplete_reason" not in meta:
            reason = b509_meta.get("incomplete_reason")
            if isinstance(reason, str):
                meta["incomplete_reason"] = f"b509_{reason}"

    return artifact


def default_output_filename(*, dst: int, scan_timestamp: str | None = None) -> str:
    """Return the default artifact file name.

    Format: `b524_scan_<DST>_<ISO8601>.json`
    """

    stamp = scan_timestamp
    if stamp is None:
        stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    else:
        # "2026-02-06T19:44:24Z" -> "2026-02-06T194424Z"
        stamp = stamp.replace(":", "")

    return f"b524_scan_{_hex_u8(dst)}_{stamp}.json"
