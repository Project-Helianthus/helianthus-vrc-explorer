"""Regression cases for default slot data that is not installed-instance evidence."""

from __future__ import annotations

import pytest

from helianthus_vrc_explorer.protocol.b524_metadata import COUNT_GROUP_IDS
from helianthus_vrc_explorer.scanner.b524_probe import _probe_present_instances
from helianthus_vrc_explorer.scanner.register import probe_instance_availability
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
