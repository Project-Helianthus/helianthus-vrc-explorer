"""Regression cases for default slot data that is not installed-instance evidence."""

from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b524_metadata import COUNT_GROUP_IDS
from helianthus_vrc_explorer.scanner.b524_probe import _probe_present_instances
from helianthus_vrc_explorer.scanner.register import probe_instance_availability
from helianthus_vrc_explorer.schema.b524_register_names import b524_register_name
from helianthus_vrc_explorer.transport.base import TransportInterface


class _ReplyTransport(TransportInterface):
    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.requests: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.requests.append(payload)
        return self.reply


@pytest.mark.parametrize("group", [0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A])
def test_empty_local_reply_is_unknown_not_present(group: int) -> None:
    probe = probe_instance_availability(
        _ReplyTransport(b""), dst=0x15, group=group, instance=0x01, opcode=0x02
    )
    assert probe.present is False
    assert probe.evidence is not None
    assert probe.evidence["response_state"] == "empty_reply"
    assert probe.evidence["availability_qualification"] == "unknown"


@pytest.mark.parametrize(
    "flags,present", [(0x03, True), (0x01, True), (0x02, False), (0x00, False)]
)
def test_solar_default_temperature_in_hidden_slot_is_not_presence(
    flags: int, present: bool
) -> None:
    # Both slots return 20 degrees; only the configured slot is visible.
    transport = _ReplyTransport(bytes((flags, 0x04, 0x04, 0x00)) + bytes.fromhex("0000a041"))
    probe = probe_instance_availability(transport, dst=0x15, group=0x04, instance=0x01, opcode=0x02)
    assert probe.present is present
    assert probe.evidence is not None
    assert probe.evidence["value"] == 20.0
    if not present:
        assert probe.evidence["availability_qualification"] == "unknown"


@pytest.mark.parametrize("group,identifier", [(0x04, 2), (0x05, 3), (0x08, 11)])
def test_system_counts_route_to_their_own_local_groups(group: int, identifier: int) -> None:
    assert COUNT_GROUP_IDS[(0x02, group)] == identifier
    assert (0x06, group) not in COUNT_GROUP_IDS


def test_recommended_zero_count_does_not_probe_default_delta_t_slots() -> None:
    transport = _ReplyTransport(b"")
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x08,
        opcode=0x02,
        ii_max=0x0A,
        observer=None,
        expected_count=0,
    )
    assert probes == {}
    assert transport.requests == []


def test_zero_capacity_skips_ordinary_candidates_but_keeps_virtual_circuit_slot() -> None:
    transport = _ReplyTransport(bytes.fromhex("030101000100"))
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x02,
        opcode=0x02,
        ii_max=0x09,
        observer=None,
        capacity=0,
    )
    assert list(probes) == [0x09]


def test_basv2_sw0507_circuit_profile_admits_native_zero_and_rejects_visible_zero() -> None:
    class CircuitTransport(_ReplyTransport):
        def send(self, dst, payload):
            self.requests.append(payload)
            instance = payload[3]
            value = 1 if instance in {0, 1, 9} else 0
            flags = 3 if instance <= 2 else 2
            return bytes((flags, 2, 2, 0)) + value.to_bytes(2, "little")

    transport = CircuitTransport(b"")
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x02,
        opcode=0x02,
        ii_max=0x09,
        observer=None,
        presence_profile="basv2_sw0507_hw1704_api1",
    )
    assert list(probes) == list(range(10))
    assert probes[0].present is True
    assert probes[1].present is True
    assert probes[2].present is False
    assert probes[9].present is True


def test_basv2_sw0507_does_not_hardcode_observed_inactive_ii02() -> None:
    transport = _ReplyTransport(bytes.fromhex("030202000100"))
    probe = probe_instance_availability(
        transport,
        dst=0x15,
        group=0x02,
        instance=0x02,
        opcode=0x02,
        presence_profile="basv2_sw0507_hw1704_api1",
    )
    assert probe.present is True
    assert probe.evidence is not None
    assert probe.evidence["raw_hex"] == "0100"


def test_recommended_solar_count_stops_after_the_configured_slot() -> None:
    transport = _ReplyTransport(bytes.fromhex("030404000000a041"))
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x04,
        opcode=0x02,
        ii_max=0x01,
        observer=None,
        expected_count=1,
    )
    assert list(probes) == [0x00]
    assert len(transport.requests) == 1


def test_solar_unknown_first_slot_does_not_fill_the_expected_count() -> None:
    class _SparseSolarTransport(_ReplyTransport):
        def send(self, dst: int, payload: bytes) -> bytes:
            self.requests.append(payload)
            flags = 0x02 if payload[3] == 0 else 0x03
            return bytes((flags, 0x04, 0x04, 0x00)) + bytes.fromhex("0000a041")

    transport = _SparseSolarTransport(b"")
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x04,
        opcode=0x02,
        ii_max=0x01,
        observer=None,
        expected_count=1,
    )
    assert list(probes) == [0x00, 0x01]
    assert probes[0].present is False
    assert probes[1].present is True


@pytest.mark.parametrize(
    "reply,present,state",
    [
        ("010d010001", True, "connected"),
        ("010d010000", False, "not_connected"),
        ("", False, "unknown"),
        ("010d010002", False, "unknown"),
        ("010d01000100", False, "unknown"),
        ("010d020001", False, "unknown"),
        ("010d0100", False, "unknown"),
    ],
)
def test_vr41_uses_device_connected_without_header_fallback(
    reply: str, present: bool, state: str
) -> None:
    transport = _ReplyTransport(bytes.fromhex(reply))
    probe = probe_instance_availability(transport, 0x15, 0x0D, 1, opcode=0x06)
    assert probe.present is present
    assert probe.connection_state == state
    assert transport.requests == [bytes.fromhex("06000d010100")]
    assert b524_register_name(opcode=6, group=0x0D, register=1) == "device_connected"
    assert b524_register_name(opcode=6, group=0x0C, register=1) == "device_connected"


@pytest.mark.parametrize(
    "reply,present,unknown",
    [
        ("030101000100", True, False),
        ("030101000000", False, False),
        ("030101000200", True, False),
        ("0301010001", False, True),
        ("", False, True),
        ("030102000100", False, True),
    ],
)
def test_native_dhw_gate_requires_correlated_supported_circuit_type(
    reply: str, present: bool, unknown: bool
) -> None:
    transport = _ReplyTransport(bytes.fromhex(reply))
    probe = probe_instance_availability(transport, 0x15, 1, 0, opcode=2)
    assert probe.present is present
    assert transport.requests == [bytes.fromhex("020001000100")]
    assert probe.evidence is not None
    assert (probe.evidence.get("availability_qualification") == "unknown") is unknown


def test_remote_op00_count_hints_do_not_reuse_aggregate_device_count() -> None:
    assert COUNT_GROUP_IDS[(6, 1)] == 12
    assert COUNT_GROUP_IDS[(6, 2)] == 13
    assert COUNT_GROUP_IDS[(6, 6)] == 15
    assert COUNT_GROUP_IDS[(6, 7)] == 14
    assert COUNT_GROUP_IDS[(6, 9)] == 10
    assert COUNT_GROUP_IDS[(6, 11)] == 8
    assert COUNT_GROUP_IDS[(6, 12)] == 9
    assert 4 not in COUNT_GROUP_IDS.values()
    assert (6, 8) not in COUNT_GROUP_IDS
    assert COUNT_GROUP_IDS[(2, 9)] == 16


@pytest.mark.parametrize(
    "count,present,expected_probes",
    [(1, {2}, [1, 2]), (2, {2, 4}, [1, 2, 3, 4]), (2, {2}, list(range(1, 9))), (None, {2}, [1])],
)
def test_remote_positive_count_keeps_sparse_slots_eligible(count, present, expected_probes):
    class SparseRemoteTransport(_ReplyTransport):
        def send(self, dst, payload):
            self.requests.append(payload)
            return bytes((1, payload[2], 1, 0, int(payload[3] in present)))

    transport = SparseRemoteTransport(b"")
    probes = _probe_present_instances(
        transport,
        dst=0x15,
        group=0x0B,
        opcode=0x06,
        ii_max=8,
        observer=None,
        expected_count=count,
        stop_at_first_absence=True,
    )
    assert list(probes) == expected_probes
    assert {ii for ii, probe in probes.items() if probe.present} == present.intersection(
        expected_probes
    )
