"""Shared test support for the BASV2 Full-scan case (issue 323).

`fixtures/basv2_full_scan_inventory.json` is the sanitized output of
`scripts/export_controller_observations.py` for one Full scan, filtered to the selectors
these tests need. It carries selectors, response states and grades, but no value: every
reply below is synthetic. The six present remote devices carry the class and firmware that
the bundled catalogue records for the reference installation.
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterable, Mapping
from copy import deepcopy
from importlib import resources
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout
from helianthus_vrc_explorer.ui.live import NullScanObserver

INVENTORY_PATH = Path(__file__).resolve().parent / "fixtures" / "basv2_full_scan_inventory.json"
PROFILE_ID = "basv2_sw0507_hw1704_api1"
IDENTITY = {
    "eid": "BASV2",
    "device_id": "BASV2",
    "sw": "0507",
    "hw": "1704",
    "manufacturer": "0xb5",
}

Slot = tuple[str, str]  # (group, instance) of the remote OP06 namespace

# The six remote devices present in the reference installation: (class, firmware) per slot.
PRESENT_DEVICES: dict[Slot, tuple[str, str]] = {
    ("0x01", "0x01"): ("08", "0c0100"),
    ("0x09", "0x01"): ("15", "080500"),
    ("0x0a", "0x01"): ("35", "021100"),
    ("0x0c", "0x01"): ("26", "010000"),
    ("0x0e", "0x01"): ("0f", "010f00"),
    ("0x0f", "0x01"): ("15", "050700"),
}
# OP00 values of the reference installation (capacities for circuits and zones, counts for
# the others). Identifiers 0x0006/0x0007 are the API version and revision.
SYSTEM_INFORMATION: dict[int, float] = {
    0: 3.0,
    1: 3.0,
    2: 1.0,
    3: 1.0,
    4: 6.0,
    6: 1.0,
    7: 1.0,
    8: 0.0,
    9: 1.0,
    10: 1.0,
    11: 0.0,
    12: 1.0,
    13: 0.0,
    14: 0.0,
    15: 0.0,
    16: 0.0,
}
CIRCUIT_PROBE_REGISTER = 0x0002
ZONE_PROBE_REGISTER = 0x001C


def inventory() -> dict[str, Any]:
    return json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))


def _selectors(opcode: str) -> list[dict[str, str]]:
    return [
        row["selector"]
        for row in inventory()["observations"]
        if row["selector"]["opcode"] == opcode
    ]


def remote_slots() -> set[Slot]:
    """Every (group, instance) the Full scan probed in the remote namespace."""

    return {(sel["group"], sel["instance"]) for sel in _selectors("0x06")}


def local_slots(group: str) -> set[int]:
    return {int(sel["instance"], 16) for sel in _selectors("0x02") if sel["group"] == group}


class Regulator(TransportInterface):
    """A synthetic BASV2 that answers from the inventory and records every request."""

    def __init__(
        self,
        devices: Mapping[Slot, tuple[str, str]] = PRESENT_DEVICES,
        system_information: Mapping[int, float] = SYSTEM_INFORMATION,
    ) -> None:
        self.devices = dict(devices)
        self.system_information = dict(system_information)
        self.requests: list[bytes] = []
        self._slots = remote_slots()
        self._circuits = local_slots("0x02")
        self._zones = local_slots("0x03")

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.requests.append(payload)
        opcode = payload[0]
        if opcode == 0x00:
            identifier = payload[1] | payload[2] << 8
            return struct.pack("<f", self.system_information.get(identifier, float("nan")))
        if opcode not in (0x02, 0x06):
            return b""
        group, instance = payload[2], payload[3]
        register = int.from_bytes(payload[4:6], "little")
        echo = payload[4:6]
        if opcode == 0x06:
            slot = (f"0x{group:02x}", f"0x{instance:02x}")
            if slot not in self._slots:
                raise TransportTimeout("slot is not in the inventory")
            device = self.devices.get(slot)
            if register == 0x0001:
                return bytes((1, group)) + echo + bytes([1 if device else 0])
            if register == 0x0002:
                return bytes((1, group)) + echo + bytes([int(device[0], 16) if device else 0])
            if register == 0x0004:
                return (
                    bytes((1, group))
                    + echo
                    + (bytes.fromhex(device[1]) if device else b"\xff\xff\xff")
                )
            # Writable, so that every slot yields a description candidate.
            return bytes((3, group)) + echo + struct.pack("<f", 1.0)
        if group == 0x02 and register == CIRCUIT_PROBE_REGISTER:
            if instance not in self._circuits:
                raise TransportTimeout("circuit slot is not in the inventory")
            value = 1 if instance in {0, 1, 9} else 0
            return bytes((3, group)) + echo + value.to_bytes(2, "little")
        if group == 0x03 and register == ZONE_PROBE_REGISTER:
            if instance not in self._zones:
                raise TransportTimeout("zone slot is not in the inventory")
            return bytes((3, group)) + echo + bytes([1 if instance in {0, 1} else 0xFF])
        return bytes((3, group)) + echo + struct.pack("<f", 1.0)

    def probed(self, artifact: Mapping[str, Any], opcode: str, group: str) -> set[int]:
        """Slots whose presence the scan decided, as stored in the artifact."""

        probes = artifact["operations"][opcode]["groups"][group].get("availability_probes", {})
        return {int(instance, 16) for instance in probes}


def myvaillant_map() -> MyvaillantRegisterMap:
    resource = resources.files("helianthus_vrc_explorer.data").joinpath(
        "myvaillant_register_map.csv"
    )
    with resources.as_file(resource) as path:
        return MyvaillantRegisterMap.from_path(path)


def scan(
    preset: str,
    regulator: Regulator | None = None,
    *,
    observer: NullScanObserver | None = None,
) -> tuple[dict[str, Any], Regulator]:
    from helianthus_vrc_explorer.scanner.scan import scan_b524

    regulator = regulator or Regulator()
    artifact = scan_b524(
        regulator,
        dst=0x15,
        planner_preset=preset,  # type: ignore[arg-type]
        probe_constraints=preset == "full",
        observer=observer or NullScanObserver(),
        operation_identity=IDENTITY,
        myvaillant_map=myvaillant_map(),
    )
    return artifact, regulator


# --- artifacts for the status and header tests ------------------------------------------


def _register(type_spec: str, value: object, raw_hex: str, error: str | None = None) -> dict:
    return {
        "type": type_spec,
        "value": value,
        "raw_hex": raw_hex,
        "error": error,
        "response_state": "active",
    }


def remote_artifact(
    devices: Mapping[Slot, tuple[str, str]] = PRESENT_DEVICES,
    *,
    unreadable_identity: Iterable[Slot] = (),
    undecided_presence: Iterable[Slot] = (),
) -> dict[str, Any]:
    """A scan artifact with every inventoried remote slot: devices connected, others empty.

    `unreadable_identity` slots are connected but answer the class/firmware registers with
    the unavailable sentinel. `undecided_presence` slots have a presence probe whose reply
    could not be read, which is neither connected nor absent.
    """

    unreadable, undecided = set(unreadable_identity), set(undecided_presence)
    groups: dict[str, Any] = {}
    for group, instance in sorted(remote_slots()):
        device = devices.get((group, instance))
        connected = device is not None
        if (group, instance) in unreadable:
            registers = {
                "0x0001": _register("BOOL", True, "01"),
                "0x0002": _register("HEX:1", 255, "ff"),
                "0x0004": _register("FWU", None, "ffffff", "parse_error: unavailable"),
            }
        else:
            class_raw, firmware_raw = device or ("00", "ffffff")
            registers = {
                "0x0001": _register("BOOL", connected, "01" if connected else "00"),
                "0x0002": _register("HEX:1", int(class_raw, 16), class_raw),
                "0x0004": (
                    _register("FWU", "firmware", firmware_raw)
                    if connected
                    else _register("FWU", None, firmware_raw, "parse_error: unavailable")
                ),
            }
        if (group, instance) in undecided:
            probe = {"present": None, "connection_state": "unknown", "source": "heuristic_probe"}
        else:
            probe = {
                "present": connected,
                "connection_state": "connected" if connected else "not_connected",
                "source": "heuristic_probe",
            }
        entry = groups.setdefault(group, {"name": "Unknown", "instances": {}})
        entry["instances"][instance] = {"present": connected, "registers": registers}
        entry.setdefault("availability_probes", {})[instance] = probe
    return {
        "schema_version": "2.4",
        "meta": {
            "identity": {
                "eid": "BASV2",
                "device_id": "BASV2",
                "sw": "0507",
                "hw": "1704",
                "manufacturer": "0xb5",
            },
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
                "api_version_raw": "1",
                "api_revision_raw": "1",
            },
        },
        "operations": {"0x06": {"groups": groups}},
    }


def description_candidates(artifact: Mapping[str, Any]) -> list[DescriptionCandidate]:
    """One writable description candidate per remote slot, as a Full scan produces."""

    return [
        DescriptionCandidate(0x06, int(group, 16), int(instance, 16), 0x0009, "EXP")
        for group, instance in sorted(
            (group, instance)
            for group, group_obj in artifact["operations"]["0x06"]["groups"].items()
            for instance in group_obj["instances"]
        )
    ]


def remote_status_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """The stored `description_remote_profile_statuses` rows for a Full scan of the artifact."""

    from helianthus_vrc_explorer.scanner.b524_orchestration import (
        _select_live_description_candidates,
    )
    from helianthus_vrc_explorer.ui.planner_selection import default_description_policy

    candidates = description_candidates(artifact)
    entries = {candidate.native_identity: {} for candidate in candidates}
    _, _, rows = _select_live_description_candidates(
        deepcopy(artifact),
        candidates,
        entries,
        policy=default_description_policy("full", exact_profile_known=True),
    )
    return rows
