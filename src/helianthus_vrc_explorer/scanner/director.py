from __future__ import annotations

import json
import logging
import math
import struct
from dataclasses import dataclass
from importlib.resources import files
from typing import Final, NotRequired, TypedDict, cast

from ..protocol.b524 import build_directory_probe_payload
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportProtocolFailure,
    TransportRecoveryExhausted,
    TransportTimeout,
)
from ..transport.instrumented import ScanRequestBudgetExceeded
from .observer import ScanObserver

logger = logging.getLogger(__name__)
_KNOWN_GROUP_DISCOVERY_RETRIES: Final[int] = 2


class GroupConfig(TypedDict):
    # Informational: last-observed descriptor value. NOT a structural authority.
    desc: NotRequired[float]
    name: str
    ii_max: int
    rr_max: int
    opcodes: list[int]
    name_by_opcode: NotRequired[dict[int, str]]
    # Namespace-capable opcode families known for this group. This can include
    # future namespaces even when active scanning still uses a conservative subset.
    namespace_opcodes: NotRequired[list[int]]
    rr_max_by_opcode: NotRequired[dict[int, int]]
    ii_max_by_opcode: NotRequired[dict[int, int]]
    # Legacy key name preserved for compatibility with older scan artifacts.
    # When True, this group was historically excluded from recommended/full presets.
    # No longer used in preset logic; kept for schema backward-compatibility.
    exhaustive_only: NotRequired[bool]


# Known groups (hardcoded reference, validated against CSV).
GROUP_CONFIG: Final[dict[int, GroupConfig]] = {
    0x00: {
        "desc": 3.0,
        "name": "System",
        "ii_max": 0x00,
        "rr_max": 0x00FF,
        "opcodes": [0x02],
        "namespace_opcodes": [0x02],
        "name_by_opcode": {0x02: "System"},
        "rr_max_by_opcode": {0x02: 0x00FF},
        "ii_max_by_opcode": {0x02: 0x00},
    },
    0x01: {
        "desc": 3.0,
        "name": "Native Domestic Hot Water",
        "ii_max": 0x00,
        "rr_max": 0x0013,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Native Domestic Hot Water", 0x06: "Primary Heating Source"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0013, 0x06: 0x0015},
        "ii_max_by_opcode": {0x02: 0x00, 0x06: 0x08},
    },
    0x02: {
        "desc": 1.0,
        "name": "Circuits",
        "ii_max": 0x09,
        "rr_max": 0x0025,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Circuits", 0x06: "Secondary Heating Source"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0025, 0x06: 0x0015},
        "ii_max_by_opcode": {0x02: 0x09, 0x06: 0x08},
    },
    0x03: {
        "desc": 1.0,
        "name": "Zones",
        "ii_max": 0x0A,
        "rr_max": 0x002E,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Zones", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x002E, 0x06: 0x002E},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x04: {
        "desc": 6.0,
        "name": "Solar Circuit",
        "ii_max": 0x00,
        "rr_max": 0x000B,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Solar Circuit", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x000B, 0x06: 0x000B},
        "ii_max_by_opcode": {0x02: 0x01, 0x06: 0x0A},
    },
    0x05: {
        "desc": 1.0,
        "name": "Solar Loaded Cylinder",
        "ii_max": 0x01,
        "rr_max": 0x0004,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Solar Loaded Cylinder", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0004, 0x06: 0x0004},
        "ii_max_by_opcode": {0x02: 0x01, 0x06: 0x0A},
    },
    0x08: {
        "name": "DeltaT",
        "ii_max": 0x0A,
        "rr_max": 0x0007,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "DeltaT", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0007, 0x06: 0x0004},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x09: {
        "desc": 1.0,
        "name": "Ventilation",
        "ii_max": 0x0A,
        "rr_max": 0x0035,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Ventilation", 0x06: "Regulators"},
        "rr_max_by_opcode": {0x02: 0x000F, 0x06: 0x0035},
    },
    0x0A: {
        "desc": 1.0,
        "name": "Unknown",
        "ii_max": 0x0A,
        "rr_max": 0x004D,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Unknown", 0x06: "Thermostats"},
        "rr_max_by_opcode": {0x02: 0x004D, 0x06: 0x0035},
    },
    0x0C: {
        "desc": 1.0,
        "name": "Functional Modules (VR71)",
        "ii_max": 0x0A,
        "rr_max": 0x002F,
        "opcodes": [0x06],
        "name_by_opcode": {0x02: "Unknown", 0x06: "Functional Modules (VR71)"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x002F, 0x06: 0x002F},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x06: {
        "name": "Device",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x06],
        "name_by_opcode": {0x02: "Device", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0030, 0x06: 0x0030},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x07: {
        "name": "Generator",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x06],
        "name_by_opcode": {0x02: "Generator", 0x06: "Unknown"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0030, 0x06: 0x0030},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x0B: {
        "name": "Functional Modules (VR70)",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x06],
        "name_by_opcode": {0x02: "Unknown", 0x06: "Functional Modules (VR70)"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0010, 0x06: 0x0010},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x0D: {
        "name": "Unknown",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x02, 0x06],
    },
    0x0E: {
        "name": "Clock",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Unknown", 0x06: "Clock"},
    },
    0x0F: {
        "name": "Base Stations",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Unknown", 0x06: "Base Stations"},
    },
    0x10: {
        "name": "Unknown",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
    },
    0x11: {
        "name": "Unknown",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
    },
}
KNOWN_CORE_GROUPS: Final[frozenset[int]] = frozenset({0x02, 0x03})

# Presentation annotations only: no changes to bounds, admission, or presence predicates.
_REMOTE_GROUP_NAMES: Final[dict[str, str]] = json.loads(
    files("helianthus_vrc_explorer.data")
    .joinpath("b524_remote_group_names.json")
    .read_text(encoding="utf-8")
)


def remote_group_display_name(group: int | str) -> str | None:
    try:
        number = int(group, 0) if isinstance(group, str) else group
    except ValueError:
        return None
    return _REMOTE_GROUP_NAMES.get(f"0x{number:02x}")


def operation_group_display_name(group: int | str, opcode: int) -> str | None:
    """Return curated operation-scoped names without overriding other saved labels."""
    if opcode == 0x06:
        return remote_group_display_name(group)
    try:
        number = int(group, 0) if isinstance(group, str) else group
    except ValueError:
        return None
    if opcode != 0x02:
        return None
    return {
        0x00: "System",
        0x01: "Native Domestic Hot Water",
        0x02: "Circuits",
        0x03: "Zones",
        0x04: "Solar Circuit",
        0x05: "Solar Loaded Cylinder",
        0x06: "Device",
        0x07: "Generator",
        0x08: "DeltaT",
        0x09: "Ventilation",
    }.get(number)


@dataclass(frozen=True, slots=True)
class NamespaceProfile:
    opcode: int
    name: str
    ii_max: int
    rr_max: int


def group_namespace_profiles(group: int) -> dict[int, NamespaceProfile]:
    """Return namespace-aware profile rows keyed by opcode.

    The returned map is canonical for config/model surfaces that need opcode-first
    identity decisions without depending on scanner heuristics.
    """

    config = GROUP_CONFIG.get(group)
    if config is None:
        return {}

    namespace_opcodes = config.get("namespace_opcodes", config["opcodes"])
    rr_overrides = config.get("rr_max_by_opcode", {})
    ii_overrides = config.get("ii_max_by_opcode", {})
    name_overrides = config.get("name_by_opcode", {})
    default_name = str(config["name"])
    default_rr = int(config["rr_max"])
    default_ii = int(config["ii_max"])

    profiles: dict[int, NamespaceProfile] = {}
    for opcode in namespace_opcodes:
        op = int(opcode)
        profiles[op] = NamespaceProfile(
            opcode=op,
            name=(remote_group_display_name(group) if op == 0x06 else None)
            or operation_group_display_name(group, op)
            or str(name_overrides.get(op, default_name)),
            ii_max=0x08 if op == 0x06 else int(ii_overrides.get(op, default_ii)),
            rr_max=int(rr_overrides.get(op, default_rr)),
        )
    return profiles


def group_name_for_opcode(group: int, opcode: int) -> str:
    if int(opcode) == 0x06 and (remote_name := remote_group_display_name(group)):
        return remote_name
    if int(opcode) == 0x02 and (local_name := operation_group_display_name(group, opcode)):
        return local_name
    config = GROUP_CONFIG.get(group)
    if config is None:
        return f"Unknown 0x{group:02X}"
    name_overrides = config.get("name_by_opcode")
    if isinstance(name_overrides, dict):
        override = name_overrides.get(int(opcode))
        if isinstance(override, str) and override.strip():
            return override
    profiles = group_namespace_profiles(group)
    profile = profiles.get(int(opcode))
    if profile is not None:
        return profile.name
    return str(config["name"])


@dataclass(frozen=True, slots=True)
class DiscoveredGroup:
    group: int
    descriptor: float
    raw_hex: str | None = None
    transport_diagnostic: dict[str, str | int | None] | None = None


@dataclass(frozen=True, slots=True)
class ClassifiedGroup:
    group: int
    descriptor: float
    name: str
    expected_descriptor: float | None
    descriptor_mismatch: bool


def _parse_directory_descriptor(resp: bytes, group: int) -> float:
    if len(resp) != 4:
        # A short response isn't evidence of a terminator (NaN). Treat it as a transient
        # failure and let discovery continue.
        raise ValueError(
            "Short system information response: "
            f"expected 4 bytes, got {len(resp)} bytes for ID=0x{group:02X}"
        )
    return cast(float, struct.unpack("<f", resp[:4])[0])


def _directory_probe_retry_budget(group: int) -> int:
    if group in GROUP_CONFIG:
        return 1 + _KNOWN_GROUP_DISCOVERY_RETRIES
    return 1


def _report_discovery_issue(observer: ScanObserver | None, message: str) -> None:
    """Report one terminal issue without duplicating it in TTY and logging output."""

    if observer is not None:
        observer.log(message, level="warn")
    else:
        logger.warning("%s", message)


def discover_groups(
    transport: TransportInterface,
    dst: int,
    *,
    observer: ScanObserver | None = None,
) -> list[DiscoveredGroup]:
    """Read bounded system information identifiers 0000..0011.

    NaN and unavailable identifiers do not terminate later information probes.
    The historical function name is retained for caller compatibility.
    """

    discovered: list[DiscoveredGroup] = []
    probes = 0

    for gg in range(0x00, 0x12):
        probes += 1
        if observer is not None:
            observer.phase_advance("group_discovery", advance=1)
        payload = build_directory_probe_payload(gg)
        attempts = _directory_probe_retry_budget(gg)
        descriptor: float | None = None
        last_response: bytes | None = None
        skip_group = False
        for attempt in range(1, attempts + 1):
            retrying = attempt < attempts
            try:
                resp = transport.send(dst, payload)
                last_response = resp
            except ScanRequestBudgetExceeded as exc:
                exc.system_information_diagnostics = {
                    item.group: item.transport_diagnostic
                    for item in discovered
                    if item.transport_diagnostic is not None
                }
                exc.system_information = [
                    (item.group, item.descriptor, item.raw_hex) for item in discovered
                ]
                if last_response is not None:
                    exc.system_information.append((gg, float("nan"), last_response.hex()))
                raise
            except TransportRecoveryExhausted as exc:
                exc.system_information_diagnostics = {
                    item.group: item.transport_diagnostic
                    for item in discovered
                    if item.transport_diagnostic is not None
                }
                partial_system_information = [
                    (item.group, item.descriptor, item.raw_hex) for item in discovered
                ]
                if last_response is not None:
                    partial_system_information.append((gg, float("nan"), last_response.hex()))
                exc.system_information = partial_system_information
                exc.selector = {
                    "read_opcode": "0x00",
                    "identifier": f"0x{gg:04x}",
                    "request_hex": payload.hex(),
                }
                raise
            except TransportProtocolFailure as exc:
                discovered.append(
                    DiscoveredGroup(
                        group=gg,
                        descriptor=float("nan"),
                        raw_hex=last_response.hex() if last_response is not None else None,
                        transport_diagnostic={
                            "cause": exc.cause,
                            "phase": exc.phase,
                            "request_attempts": exc.request_attempts,
                            "retry_count": exc.retry_count,
                            "reconnect_attempts": exc.reconnect_attempts,
                            "unexpected_symbol": exc.unexpected_symbol,
                        },
                    )
                )
                _report_discovery_issue(
                    observer, f"System information protocol failure for ID=0x{gg:02X}: {exc}"
                )
                skip_group = True
                break
            except TransportTimeout:
                if retrying:
                    logger.debug(
                        "System information timeout for ID=0x%02X (attempt %d/%d); retrying",
                        gg,
                        attempt,
                        attempts,
                    )
                    continue
                _report_discovery_issue(observer, f"System information timeout for ID=0x{gg:02X}")
                skip_group = True
                break
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                if retrying:
                    logger.debug(
                        "System information transport error for ID=0x%02X: %s (attempt %d/%d); "
                        "retrying",
                        gg,
                        exc,
                        attempt,
                        attempts,
                    )
                    continue
                _report_discovery_issue(
                    observer, f"System information transport error for ID=0x{gg:02X}: {exc}"
                )
                skip_group = True
                break

            if gg == 0x00 and resp == b"\x00":
                if retrying:
                    logger.debug(
                        "System information ID=0x00 returned status-only 0x00 "
                        "(attempt %d/%d); retrying",
                        attempt,
                        attempts,
                    )
                    continue
                message = (
                    "System information ID=0x00 returned status-only 0x00; "
                    "treating as transient and continuing"
                )
                _report_discovery_issue(observer, message)
                skip_group = True
                break

            try:
                descriptor = _parse_directory_descriptor(resp, gg)
            except ValueError as exc:
                if retrying:
                    logger.debug("%s (attempt %d/%d); retrying", exc, attempt, attempts)
                    continue
                _report_discovery_issue(observer, str(exc))
                skip_group = True
                break

            break

        if skip_group or descriptor is None:
            # Keep observed malformed/status bytes even if a later retry times out.
            # NaN marks the value unavailable, so this evidence cannot guide instance counts.
            if last_response is not None and not any(item.group == gg for item in discovered):
                discovered.append(
                    DiscoveredGroup(group=gg, descriptor=float("nan"), raw_hex=last_response.hex())
                )
            continue

        discovered.append(DiscoveredGroup(group=gg, descriptor=descriptor, raw_hex=resp.hex()))

    if observer is not None:
        observer.phase_set_total("group_discovery", total=probes)

    return discovered


def classify_groups(
    discovered: list[DiscoveredGroup],
    *,
    observer: ScanObserver | None = None,
) -> list[ClassifiedGroup]:
    """Phase C (per issue wording): Map discovered groups using GROUP_CONFIG.

    Descriptors are advisory metadata for semantic identity and namespace topology once a group
    is a scan candidate; discovery-time filtering still happens earlier in Phase A.
    """

    classified: list[ClassifiedGroup] = []
    for group in discovered:
        config = GROUP_CONFIG.get(group.group)
        if config is None:
            classified.append(
                ClassifiedGroup(
                    group=group.group,
                    descriptor=group.descriptor,
                    name="Unknown",
                    expected_descriptor=None,
                    descriptor_mismatch=False,
                )
            )
            continue

        expected = config.get("desc") if math.isfinite(group.descriptor) else None
        mismatch = expected is not None and expected != group.descriptor
        if mismatch:
            logger.info(
                "Descriptor mismatch for GG=0x%02X: expected %s, got %s",
                group.group,
                expected,
                group.descriptor,
            )
            if observer is not None:
                observer.log(
                    f"Descriptor mismatch for GG=0x{group.group:02X}: "
                    f"expected {expected}, got {group.descriptor}",
                    level="info",
                )
        classified.append(
            ClassifiedGroup(
                group=group.group,
                descriptor=group.descriptor,
                name=config["name"],
                expected_descriptor=expected,
                descriptor_mismatch=mismatch,
            )
        )

    return classified
