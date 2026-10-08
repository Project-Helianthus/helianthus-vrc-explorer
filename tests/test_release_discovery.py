from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.parser import (
    ValueParseError,
    encode_typed_value,
    parse_typed_value,
)
from helianthus_vrc_explorer.scanner.b524_probe import _probe_present_instances
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, estimate_register_requests
from helianthus_vrc_explorer.scanner.register import probe_instance_availability, read_register
from helianthus_vrc_explorer.scanner.scan_policy import parse_scan_plan
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout
from helianthus_vrc_explorer.ui.planner import PlannerGroup, build_plan_from_preset


class ConnectedSlots(TransportInterface):
    def __init__(self, values: dict[int, object]) -> None:
        self.values = values
        self.requests: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.requests.append(payload)
        value = self.values.get(payload[3], False)
        if value == "timeout":
            raise TransportTimeout("synthetic transport unknown")
        return bytes((1, payload[2], 1, 0, int(value)))


def test_device_discovery_starts_one_and_stops_on_confirmed_not_connected() -> None:
    bus = ConnectedSlots({1: True, 2: True, 3: False})
    probes = _probe_present_instances(
        bus, dst=0x15, group=14, opcode=6, ii_max=10, observer=None, stop_at_first_absence=True
    )
    assert list(probes) == [1, 2, 3]
    assert [p.connection_state for p in probes.values()] == [
        "connected",
        "connected",
        "not_connected",
    ]
    assert all(payload[:3] == bytes((6, 0, 14)) for payload in bus.requests)


def test_timeout_is_unknown_and_does_not_terminate_discovery() -> None:
    bus = ConnectedSlots({1: "timeout", 2: True, 3: False})
    probes = _probe_present_instances(
        bus, dst=0x15, group=14, opcode=6, ii_max=10, observer=None, stop_at_first_absence=True
    )
    assert probes[1].connection_state == "unknown"
    assert probes[2].present is True
    assert list(probes) == [1, 2, 3]


def test_unconnected_device_is_not_promoted_by_readable_inventory_header() -> None:
    bus = ConnectedSlots({1: False})
    probe = probe_instance_availability(bus, dst=0x15, group=12, instance=1, opcode=6)
    assert probe.present is False
    assert probe.connection_state == "not_connected"
    assert len(bus.requests) == 1


def test_full_device_audit_preserves_all_slots_after_first_not_connected() -> None:
    bus = ConnectedSlots({1: False, 3: True})
    probes = _probe_present_instances(
        bus, dst=0x15, group=14, opcode=6, ii_max=4, observer=None, stop_at_first_absence=False
    )
    assert list(probes) == [1, 2, 3, 4]
    assert probes[3].present


def test_local_circuit_plan_always_includes_virtual_water_slot_once() -> None:
    plan = GroupScanPlan(group=2, opcode=2, instances=(1, 2), rr_max=20)
    assert plan.instances == (1, 2, 9)
    assert GroupScanPlan(group=2, opcode=2, instances=plan.instances, rr_max=20) == plan
    assert GroupScanPlan(group=2, opcode=6, instances=(1,), rr_max=20).instances == (1,)


def test_custom_circuit_plan_expands_mandatory_slot_and_estimate() -> None:
    plan = parse_scan_plan(
        {
            "schema_version": 1,
            "groups": [
                {
                    "opcode": "0x02",
                    "group": "0x02",
                    "instances": [1, 2],
                    "registers": [9, 19],
                }
            ],
        }
    )
    assert plan[(2, 2)].instances == (1, 2, 9)
    assert estimate_register_requests(plan) == 6


def test_recommended_count_three_retains_independent_virtual_slot() -> None:
    group = PlannerGroup(
        group=2,
        opcode=2,
        name="Circuits",
        descriptor=1,
        known=True,
        ii_max=9,
        rr_max=20,
        rr_max_full=255,
        present_instances=(1, 2),
        recommended=True,
    )
    plan = build_plan_from_preset([group], preset="recommended")
    assert plan[(2, 2)].instances == (1, 2, 9)


@pytest.mark.parametrize(
    "raw,text", [("021100", "02.17.00"), ("0c0100", "12.01.00"), ("010f00", "01.15.00")]
)
def test_remote_firmware_numeric_triplet_roundtrip(raw: str, text: str) -> None:
    assert parse_typed_value("FWU", bytes.fromhex(raw)) == text
    assert encode_typed_value("FWU", text).hex() == raw


def test_remote_firmware_unavailable_keeps_raw_without_numeric_version() -> None:
    with pytest.raises(ValueParseError, match="unavailable"):
        parse_typed_value("FWU", bytes.fromhex("ffffff"))


def test_numeric_remote_firmware_does_not_change_legacy_local_codec() -> None:
    class Firmware(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:
            return bytes((1, payload[2], 4, 0)) + bytes.fromhex("021100")

    remote = read_register(Firmware(), 0x15, 6, 10, 1, 4, type_hint="FW")
    local = read_register(Firmware(), 0x15, 2, 9, 0, 4, type_hint="FW")
    assert remote["type"] == "FWU"
    assert remote["value"] == "02.17.00"
    assert local["type"] == "FW"
    assert local["value"] == "02.11.00"
