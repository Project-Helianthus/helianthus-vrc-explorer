from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.b524_probe import (
    _probe_unknown_group_opcodes,
    _probe_unknown_present_instances,
)
from helianthus_vrc_explorer.transport.base import (
    TransportInterface,
    TransportNack,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.instrumented import ScanRequestBudgetExceeded


def _selector(payload: bytes) -> tuple[int, int, int]:
    return payload[0], payload[3], int.from_bytes(payload[4:6], "little")


class _ResearchOpcodeBus(TransportInterface):
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        selector = _selector(payload)
        self.calls.append(selector)
        opcode, instance, register = selector
        if opcode == 0x02 and (instance, register) == (0x01, 0x01):
            return bytes.fromhex("0101010001")
        if register == 0:
            raise TransportTimeout("no response")
        if opcode == 0x02:
            return b""
        raise TransportNack("unsupported")


def test_research_opcode_probe_continues_after_first_sentinel_failures() -> None:
    transport = _ResearchOpcodeBus()

    opcodes, summary = _probe_unknown_group_opcodes(
        transport,
        dst=0x15,
        group=0x01,
        observer=None,
        research=True,
    )

    expected_selectors = [
        *((0x02, instance, register) for instance, register in ((0, 0), (0, 1), (1, 0), (1, 1))),
        *((0x06, instance, register) for instance in range(1, 9) for register in (0, 1)),
    ]
    assert transport.calls == expected_selectors
    assert opcodes == (0x02,)
    assert summary["candidates"]["0x02"]["classification"] == "responsive"
    assert summary["candidates"]["0x06"]["classification"] == "unknown"
    assert len(summary["candidates"]["0x02"]["probes"]) == 4
    assert summary["candidates"]["0x02"]["probes"][0]["request_hex"] == "020001000000"
    assert summary["candidates"]["0x02"]["probes"][0]["classification"] == "unknown"
    assert summary["candidates"]["0x02"]["probes"][3]["reply_hex"] == "0101010001"


def test_all_unsupported_research_opcode_probes_remain_unknown_not_absent() -> None:
    class _UnsupportedBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            raise TransportNack("unsupported")

    opcodes, summary = _probe_unknown_group_opcodes(
        _UnsupportedBus(), dst=0x15, group=0x69, observer=None, research=True
    )

    assert opcodes == ()
    assert summary["negative_result_meaning"] == "unknown_not_absent"
    assert summary["candidates"]["0x02"]["classification"] == "unknown"
    assert summary["candidates"]["0x06"]["classification"] == "unknown"
    assert all(
        probe["response_state"] == "nack"
        for candidate in summary["candidates"].values()
        for probe in candidate["probes"]
    )


def test_legacy_opcode_probe_default_keeps_one_sentinel_per_family() -> None:
    class _LegacyBus(TransportInterface):
        def __init__(self) -> None:
            self.calls: list[tuple[int, int, int]] = []

        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            self.calls.append(_selector(payload))
            if payload[0] == 0x02:
                return b""
            raise TransportNack("unsupported")

    transport = _LegacyBus()
    opcodes, summary = _probe_unknown_group_opcodes(transport, dst=0x15, group=0x69, observer=None)

    assert transport.calls == [(0x02, 0, 0), (0x06, 1, 0)]
    assert opcodes == (0x02,)
    assert summary["kind"] == "opcode_responsiveness"


class _ExpandedInstanceBus(TransportInterface):
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        selector = _selector(payload)
        self.calls.append(selector)
        _, instance, register = selector
        if (instance, register) == (0xFF, 0x01):
            return bytes.fromhex("0169010001")
        if register == 0:
            raise TransportTimeout("no response")
        raise TransportNack("unsupported")


def test_research_instance_probe_covers_all_instances_and_secondary_anchor() -> None:
    transport = _ExpandedInstanceBus()

    present = _probe_unknown_present_instances(
        transport,
        dst=0x15,
        group=0x69,
        opcode=0x02,
        observer=None,
        expand_fallback=True,
        research=True,
    )

    assert present == (0xFF,)
    assert transport.calls == [
        (0x02, instance, register) for instance in (*range(0x0B), 0xFF) for register in (0, 1)
    ]


def test_research_probe_does_not_swallow_global_budget_exception() -> None:
    class _BudgetBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            raise ScanRequestBudgetExceeded("bounded")

    with pytest.raises(ScanRequestBudgetExceeded):
        _probe_unknown_group_opcodes(
            _BudgetBus(), dst=0x15, group=0x69, observer=None, research=True
        )
