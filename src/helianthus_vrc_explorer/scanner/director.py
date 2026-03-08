from __future__ import annotations

import logging
import math
import struct
from dataclasses import dataclass
from typing import Final, TypedDict

from ..protocol.b524 import build_directory_probe_payload
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportTimeout,
)
from .observer import ScanObserver

logger = logging.getLogger(__name__)


class GroupConfig(TypedDict):
    # Informational: last-observed descriptor value. NOT a structural authority.
    desc: float
    name: str
    ii_max: int
    rr_max: int


# Known groups (hardcoded reference, validated against CSV).
# Source of truth: `AGENTS.md` (keep in sync).
GROUP_CONFIG: Final[dict[int, GroupConfig]] = {
    0x00: {"desc": 3.0, "name": "Regulator Parameters", "ii_max": 0x00, "rr_max": 0x00FF},
    0x01: {"desc": 3.0, "name": "Hot Water Circuit", "ii_max": 0x00, "rr_max": 0x13},
    0x02: {"desc": 1.0, "name": "Heating Circuits", "ii_max": 0x0A, "rr_max": 0x25},
    0x03: {"desc": 1.0, "name": "Zones", "ii_max": 0x0A, "rr_max": 0x2F},
    0x04: {"desc": 6.0, "name": "Solar Circuit", "ii_max": 0x00, "rr_max": 0x0B},
    0x05: {"desc": 1.0, "name": "Hot Water Cylinder", "ii_max": 0x01, "rr_max": 0x04},
    0x09: {"desc": 1.0, "name": "Radio Sensors VRC7xx", "ii_max": 0x0A, "rr_max": 0x2F},
    0x0A: {"desc": 1.0, "name": "Radio Sensors VR92", "ii_max": 0x0A, "rr_max": 0x3F},
    0x0C: {"desc": 1.0, "name": "Remote Accessories / FM5 Slots", "ii_max": 0x0A, "rr_max": 0x2F},
}
KNOWN_CORE_GROUPS: Final[frozenset[int]] = frozenset({0x02, 0x03})


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


class B524UnsupportedError(RuntimeError):
    """Raised when directory probing indicates B524 is unsupported on target."""


def _parse_directory_descriptor(resp: bytes, group: int) -> float:
    if len(resp) < 4:
        # A short response isn't evidence of a terminator (NaN). Treat it as a transient
        # failure and let discovery continue.
        raise ValueError(
            "Short directory probe response: "
            f"expected >=4 bytes, got {len(resp)} bytes for GG=0x{group:02X}"
        )
    return struct.unpack("<f", resp[:4])[0]


def discover_groups(
    transport: TransportInterface,
    dst: int,
    *,
    observer: ScanObserver | None = None,
) -> list[DiscoveredGroup]:
    """Phase A: Probe GG=0x00..0xFF via directory probe (opcode 0x00).

    Terminator logic: stop on the first NaN descriptor.
    Descriptor `0.0` is a weak negative hint only: known core groups remain candidates.
    """

    discovered: list[DiscoveredGroup] = []
    probes = 0

    for gg in range(0x00, 0x100):
        probes += 1
        if observer is not None:
            observer.status(f"Directory probe GG=0x{gg:02X}")
            observer.phase_advance("group_discovery", advance=1)
        payload = build_directory_probe_payload(gg)
        try:
            resp = transport.send(dst, payload)
        except TransportTimeout:
            logger.warning("Directory probe timeout for GG=0x%02X", gg)
            if observer is not None:
                observer.log(f"Directory probe timeout for GG=0x{gg:02X}", level="warn")
            # Transport failures are not evidence of a NaN terminator; skip without advancing the
            # NaN streak.
            continue
        except TransportError as exc:
            if isinstance(exc, TransportCommandNotEnabled):
                raise
            logger.warning("Directory probe transport error for GG=0x%02X: %s", gg, exc)
            if observer is not None:
                observer.log(
                    f"Directory probe transport error for GG=0x{gg:02X}: {exc}",
                    level="warn",
                )
            continue

        if gg == 0x00 and resp == b"\x00":
            raise B524UnsupportedError(
                "B524 unsupported: directory probe GG=0x00 returned status-only 0x00"
            )

        try:
            descriptor = _parse_directory_descriptor(resp, gg)
        except ValueError as exc:
            logger.warning("%s", exc)
            if observer is not None:
                observer.log(str(exc), level="warn")
            continue

        if descriptor == 0.0:
            if gg in KNOWN_CORE_GROUPS:
                discovered.append(DiscoveredGroup(group=gg, descriptor=descriptor))
                if observer is not None:
                    observer.log(
                        f"GG=0x{gg:02X} descriptor=0.0 but known core group - included",
                        level="info",
                    )
            elif observer is not None:
                observer.log(
                    f"GG=0x{gg:02X} descriptor=0.0, non-core group - skipped (weak hint)",
                    level="info",
                )
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

    Descriptors are opaque hints, not structural authority.
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

        expected = config["desc"]
        mismatch = expected != group.descriptor
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
