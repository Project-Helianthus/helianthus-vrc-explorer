from __future__ import annotations

import logging
import math
import struct
from dataclasses import dataclass
from typing import Final, NotRequired, TypedDict, cast

from ..protocol.b524 import build_directory_probe_payload
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportTimeout,
)
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
    # Legacy key name preserved for compatibility.
    # When True, this group is only included in the research preset
    # (and legacy exhaustive alias), never in conservative/recommended/full.
    exhaustive_only: NotRequired[bool]


# Known groups (hardcoded reference, validated against CSV).
# Source of truth: `AGENTS.md` (keep in sync).
GROUP_CONFIG: Final[dict[int, GroupConfig]] = {
    0x00: {
        "desc": 3.0,
        "name": "Regulator Parameters",
        "ii_max": 0x00,
        "rr_max": 0x00FF,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Regulator Parameters", 0x06: "Primary Heating Sources"},
    },
    0x01: {
        "desc": 3.0,
        "name": "Hot Water Circuit",
        "ii_max": 0x00,
        "rr_max": 0x0013,
        "opcodes": [0x02],
        "name_by_opcode": {0x02: "Hot Water Circuit", 0x06: "Secondary Heating Sources"},
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0013, 0x06: 0x0015},
        "ii_max_by_opcode": {0x02: 0x00, 0x06: 0x00},
    },
    0x02: {
        "desc": 1.0,
        "name": "Heating Circuits",
        "ii_max": 0x0A,
        "rr_max": 0x0025,
        "opcodes": [0x02],
        "namespace_opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0025, 0x06: 0x0025},
        "ii_max_by_opcode": {0x02: 0x0A, 0x06: 0x0A},
    },
    0x03: {
        "desc": 1.0,
        "name": "Zones",
        "ii_max": 0x0A,
        "rr_max": 0x002E,
        "opcodes": [0x02],
    },
    0x04: {
        "desc": 6.0,
        "name": "Solar Circuit",
        "ii_max": 0x00,
        "rr_max": 0x000B,
        "opcodes": [0x02],
    },
    0x05: {
        "desc": 1.0,
        "name": "Hot Water Cylinder",
        "ii_max": 0x01,
        "rr_max": 0x0004,
        "opcodes": [0x02],
    },
    0x08: {
        "name": "Buffer / Solar Cylinder 2",
        "ii_max": 0x0A,
        "rr_max": 0x0007,
        "opcodes": [0x02, 0x06],
        "rr_max_by_opcode": {0x02: 0x0007, 0x06: 0x0004},
        "ii_max_by_opcode": {0x02: 0x00, 0x06: 0x0A},
    },
    0x09: {
        "desc": 1.0,
        "name": "Regulators",
        "ii_max": 0x0A,
        "rr_max": 0x0035,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Unknown 0x09 (local)", 0x06: "Regulators"},
        "rr_max_by_opcode": {0x02: 0x000F, 0x06: 0x0035},
    },
    0x0A: {
        "desc": 1.0,
        "name": "Thermostats",
        "ii_max": 0x0A,
        "rr_max": 0x004D,
        "opcodes": [0x02, 0x06],
        "name_by_opcode": {0x02: "Unknown 0x0A (local)", 0x06: "Thermostats"},
        "rr_max_by_opcode": {0x02: 0x004D, 0x06: 0x0035},
    },
    0x0C: {
        "desc": 1.0,
        "name": "Functional Modules",
        "ii_max": 0x0A,
        "rr_max": 0x002F,
        "opcodes": [0x06],
    },
    0x06: {
        "name": "Unknown 0x06",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x06],
        "exhaustive_only": True,
    },
    0x07: {
        "name": "Unknown 0x07",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x06],
        "exhaustive_only": True,
    },
    0x0B: {
        "name": "Unknown 0x0B",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x06],
        "exhaustive_only": True,
    },
    0x0D: {
        "name": "Unknown 0x0D (VWZIO?)",
        "ii_max": 0x0A,
        "rr_max": 0x0030,
        "opcodes": [0x02, 0x06],
        "exhaustive_only": True,
    },
    0x0E: {
        "name": "Unknown 0x0E",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "exhaustive_only": True,
    },
    0x0F: {
        "name": "Unknown 0x0F",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "exhaustive_only": True,
    },
    0x10: {
        "name": "Unknown 0x10",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "exhaustive_only": True,
    },
    0x11: {
        "name": "Unknown 0x11",
        "ii_max": 0x0A,
        "rr_max": 0x0010,
        "opcodes": [0x02, 0x06],
        "exhaustive_only": True,
    },
}
KNOWN_CORE_GROUPS: Final[frozenset[int]] = frozenset({0x02, 0x03})


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
            name=str(name_overrides.get(op, default_name)),
            ii_max=int(ii_overrides.get(op, default_ii)),
            rr_max=int(rr_overrides.get(op, default_rr)),
        )
    return profiles


def group_name_for_opcode(group: int, opcode: int) -> str:
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


@dataclass(frozen=True, slots=True)
class ClassifiedGroup:
    group: int
    descriptor: float
    name: str
    expected_descriptor: float | None
    descriptor_mismatch: bool


def _parse_directory_descriptor(resp: bytes, group: int) -> float:
    if len(resp) < 4:
        # A short response isn't evidence of a terminator (NaN). Treat it as a transient
        # failure and let discovery continue.
        raise ValueError(
            "Short directory probe response: "
            f"expected >=4 bytes, got {len(resp)} bytes for GG=0x{group:02X}"
        )
    return cast(float, struct.unpack("<f", resp[:4])[0])


def _directory_probe_retry_budget(group: int) -> int:
    if group in GROUP_CONFIG:
        return 1 + _KNOWN_GROUP_DISCOVERY_RETRIES
    return 1


def discover_groups(
    transport: TransportInterface,
    dst: int,
    *,
    observer: ScanObserver | None = None,
) -> list[DiscoveredGroup]:
    """Phase A: Probe GG=0x00..0xFF via directory probe (opcode 0x00).

    Terminator logic: stop on the first NaN descriptor.
    Directory descriptors are not semantic authority for group identity, namespace topology,
    or scan-plan inclusion. The only authoritative structural signal here is the NaN terminator.
    """

    discovered: list[DiscoveredGroup] = []
    probes = 0

    for gg in range(0x00, 0x100):
        probes += 1
        if observer is not None:
            observer.status(f"Directory probe GG=0x{gg:02X}")
            observer.phase_advance("group_discovery", advance=1)
        payload = build_directory_probe_payload(gg)
        attempts = _directory_probe_retry_budget(gg)
        descriptor: float | None = None
        skip_group = False
        for attempt in range(1, attempts + 1):
            retrying = attempt < attempts
            try:
                resp = transport.send(dst, payload)
            except TransportTimeout:
                if retrying:
                    logger.warning(
                        "Directory probe timeout for GG=0x%02X (attempt %d/%d); retrying",
                        gg,
                        attempt,
                        attempts,
                    )
                    if observer is not None:
                        observer.log(
                            f"Directory probe timeout for GG=0x{gg:02X} "
                            f"(attempt {attempt}/{attempts}); retrying",
                            level="warn",
                        )
                    continue
                logger.warning("Directory probe timeout for GG=0x%02X", gg)
                if observer is not None:
                    observer.log(f"Directory probe timeout for GG=0x{gg:02X}", level="warn")
                skip_group = True
                break
            except TransportError as exc:
                if isinstance(exc, TransportCommandNotEnabled):
                    raise
                if retrying:
                    logger.warning(
                        "Directory probe transport error for GG=0x%02X: %s (attempt %d/%d); "
                        "retrying",
                        gg,
                        exc,
                        attempt,
                        attempts,
                    )
                    if observer is not None:
                        observer.log(
                            f"Directory probe transport error for GG=0x{gg:02X}: {exc} "
                            f"(attempt {attempt}/{attempts}); retrying",
                            level="warn",
                        )
                    continue
                logger.warning("Directory probe transport error for GG=0x%02X: %s", gg, exc)
                if observer is not None:
                    observer.log(
                        f"Directory probe transport error for GG=0x{gg:02X}: {exc}",
                        level="warn",
                    )
                skip_group = True
                break

            if gg == 0x00 and resp == b"\x00":
                if retrying:
                    logger.warning(
                        "Directory probe GG=0x00 returned status-only 0x00 "
                        "(attempt %d/%d); retrying",
                        attempt,
                        attempts,
                    )
                    if observer is not None:
                        observer.log(
                            "Directory probe GG=0x00 returned status-only 0x00 "
                            f"(attempt {attempt}/{attempts}); retrying",
                            level="warn",
                        )
                    continue
                message = (
                    "Directory probe GG=0x00 returned status-only 0x00; "
                    "treating as transient and continuing"
                )
                logger.warning("%s", message)
                if observer is not None:
                    observer.log(message, level="warn")
                skip_group = True
                break

            try:
                descriptor = _parse_directory_descriptor(resp, gg)
            except ValueError as exc:
                if retrying:
                    logger.warning("%s (attempt %d/%d); retrying", exc, attempt, attempts)
                    if observer is not None:
                        observer.log(
                            f"{exc} (attempt {attempt}/{attempts}); retrying",
                            level="warn",
                        )
                    continue
                logger.warning("%s", exc)
                if observer is not None:
                    observer.log(str(exc), level="warn")
                skip_group = True
                break

            break

        if skip_group or descriptor is None:
            # Transport failures are not evidence of a NaN terminator; skip without advancing the
            # NaN streak.
            continue

        if math.isnan(descriptor):
            logger.info("Directory terminator at GG=0x%02X (NaN)", gg)
            if observer is not None:
                observer.log(f"Directory terminator at GG=0x{gg:02X} (NaN)", level="info")
            break

        discovered.append(DiscoveredGroup(group=gg, descriptor=descriptor))
        if observer is not None:
            observer.log(f"Discovered group GG=0x{gg:02X} desc={descriptor}", level="info")

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

        expected = config.get("desc")
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
