from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp
import helianthus_vrc_explorer.transport.enhanced_tcp as enhanced_tcp
from helianthus_vrc_explorer.scanner.description_acquisition import acquire_descriptions
from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.transport.base import AttemptHook, TransportInterface, TransportTimeout
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from helianthus_vrc_explorer.transport.enhanced_tcp import EnhancedTcpConfig, EnhancedTcpTransport
from helianthus_vrc_explorer.transport.instrumented import (
    CountingTransport,
    ScanRequestBudgetExceeded,
)


class _RetryingDescriptionTransport(TransportInterface):
    def __init__(self, attempts_for: Callable[[int, int], int]) -> None:
        self._attempts_for = attempts_for
        self.candidates_by_opcode = {0x01: 0, 0x07: 0}
        self.attempt_opcodes: list[int] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        raise AssertionError("CountingTransport must forward the attempt hook")

    def send_with_attempt_hook(self, dst: int, payload: bytes, attempt_hook: AttemptHook) -> bytes:
        del dst
        opcode = payload[0]
        self.candidates_by_opcode[opcode] += 1
        candidate_number = self.candidates_by_opcode[opcode]
        for _ in range(self._attempts_for(opcode, candidate_number)):
            attempt_hook()
            self.attempt_opcodes.append(opcode)
        return bytes((payload[1],)) + payload[3:5] + bytes((0, 20, 1))


def _entries(
    candidates: list[DescriptionCandidate],
) -> dict[tuple[int, int, int, int], dict[str, Any]]:
    return {candidate.native_identity: {} for candidate in candidates}


def test_actual_attempt_budget_preserves_every_remote_reserved_first_attempt() -> None:
    candidates = [
        *(DescriptionCandidate(0x02, 0x01, 0x00, register, "UCH") for register in range(224)),
        *(DescriptionCandidate(0x06, 0x09, 0x00, register, "UCH") for register in range(32)),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(
        lambda opcode, number: 2 if opcode == 0x01 and number <= 36 else 1
    )
    transport = CountingTransport(inner, request_budget=198)

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=256,
            coverage=coverage,
        )

    local = coverage["by_read_operation"]["0x02"]
    remote = coverage["by_read_operation"]["0x06"]
    assert transport.counters.send_calls == 198
    assert inner.attempt_opcodes.count(0x01) == 166
    assert inner.attempt_opcodes.count(0x07) == 32
    assert local == {
        "eligible": 224,
        "scheduled": 166,
        "attempted": 130,
        "matched": 130,
        "unavailable": 0,
        "unqualified": 0,
        "budget_skipped": 58,
        "not_attempted": 36,
        "request_attempts": 166,
        "retries": 36,
        "received": 130,
        "interpreted": 130,
        "planned": 166,
        "omitted": 94,
    }
    assert remote["eligible"] == remote["scheduled"] == remote["attempted"] == 32
    assert remote["matched"] == remote["request_attempts"] == 32
    assert remote["retries"] == remote["not_attempted"] == 0


def test_remote_retry_cannot_consume_its_own_later_reserved_first_attempt() -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        *(DescriptionCandidate(0x06, 0x09, 0x00, register, "UCH") for register in range(3)),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(
        lambda opcode, number: 3 if opcode == 0x07 and number == 1 else 1
    )
    transport = CountingTransport(inner, request_budget=4)

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=4,
            coverage=coverage,
        )

    remote = coverage["by_read_operation"]["0x06"]
    assert inner.attempt_opcodes == [0x01, 0x07, 0x07, 0x07]
    assert remote["scheduled"] == 3
    assert remote["attempted"] == 2
    assert remote["request_attempts"] == 3
    assert remote["retries"] == 1
    assert remote["not_attempted"] == 1
    assert (
        entries[candidates[1].native_identity]["parameter_description"]["request_attempted"] is True
    )
    assert (
        entries[candidates[2].native_identity]["parameter_description"]["request_attempted"] is True
    )


def test_odd_capacity_reserves_extra_local_first_and_one_remote_first() -> None:
    candidates = [
        *(DescriptionCandidate(0x02, 0x01, 0x00, register, "UCH") for register in range(3)),
        *(DescriptionCandidate(0x06, 0x09, 0x00, register, "UCH") for register in range(3)),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(
        lambda opcode, number: 3 if opcode == 0x01 and number == 1 else 1
    )
    transport = CountingTransport(inner, request_budget=3)

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=3,
            coverage=coverage,
        )

    assert inner.attempt_opcodes == [0x01, 0x01, 0x07]
    assert coverage["by_read_operation"]["0x02"]["attempted"] == 2
    assert coverage["by_read_operation"]["0x06"]["attempted"] == 1


def test_zero_remaining_global_budget_has_no_phantom_description_attempts() -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        DescriptionCandidate(0x06, 0x09, 0x00, 0, "UCH"),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(lambda _opcode, _number: 1)
    transport = CountingTransport(inner, request_budget=1)
    transport.send(0x15, b"\x01\x01\x00\x00\x00")

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=256,
            coverage=coverage,
        )

    assert transport.counters.send_calls == 1
    assert coverage["effective_request_budget"] == 0
    assert coverage["attempted"] == coverage["request_attempts"] == 0
    assert coverage["budget_skipped"] == 2


def test_zero_remaining_budget_preserves_existing_matched_description_and_scalar() -> None:
    candidate = DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH")
    matched = {
        "qualification": "matched",
        "request_attempted": True,
        "request_attempts": 1,
        "min": 0,
        "max": 20,
    }
    entries = {candidate.native_identity: {"value": 7, "parameter_description": matched}}
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(lambda _opcode, _number: 1)
    transport = CountingTransport(inner, request_budget=1)
    transport.send(0x15, b"\x01\x01\x00\x00\x00")

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=[candidate],
            entries=entries,
            budget=1,
            coverage=coverage,
        )

    assert entries[candidate.native_identity]["value"] == 7
    assert entries[candidate.native_identity]["parameter_description"] is matched


def test_counting_transport_without_global_cap_preserves_all_internal_retries() -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        DescriptionCandidate(0x06, 0x09, 0x00, 0, "UCH"),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(
        lambda opcode, number: 3 if opcode == 0x01 and number == 1 else 1
    )
    transport = CountingTransport(inner)

    acquire_descriptions(
        transport,
        dst=0x15,
        candidates=candidates,
        entries=entries,
        budget=2,
        coverage=coverage,
    )

    assert inner.attempt_opcodes == [0x01, 0x01, 0x01, 0x07]
    assert coverage["attempted"] == coverage["matched"] == 2
    assert coverage["request_attempts"] == 4
    assert coverage["retries"] == 2


def test_logical_description_budget_does_not_cap_actual_retry_attempts() -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        DescriptionCandidate(0x06, 0x09, 0x00, 0, "UCH"),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = _RetryingDescriptionTransport(
        lambda opcode, number: 3 if opcode == 0x01 and number == 1 else 1
    )
    transport = CountingTransport(inner, request_budget=10)

    acquire_descriptions(
        transport,
        dst=0x15,
        candidates=candidates,
        entries=entries,
        budget=2,
        coverage=coverage,
    )

    assert inner.attempt_opcodes == [0x01, 0x01, 0x01, 0x07]
    assert coverage["scheduled"] == coverage["attempted"] == 2
    assert coverage["request_attempts"] == 4
    assert coverage["retries"] == 2


def _ebusd_retrying_transport(monkeypatch: pytest.MonkeyPatch) -> TransportInterface:
    inner = EbusdTcpTransport(EbusdTcpConfig(timeout_max_retries=1))
    calls = 0

    def _send_once(_seq: int, _dst: int, payload: bytes) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise TransportTimeout("ERR: timeout")
        return bytes((payload[1],)) + payload[3:5] + bytes((0, 20, 1))

    monkeypatch.setattr(inner, "_send_once", _send_once)
    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    return inner


def _enhanced_retrying_transport(monkeypatch: pytest.MonkeyPatch) -> TransportInterface:
    inner = EnhancedTcpTransport(EnhancedTcpConfig(collision_max_retries=1))
    calls = 0

    def _send_once(
        _seq: int,
        *,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        expect_response: bool,
        attempt_hook: AttemptHook | None = None,
        retry_safe: bool,
        attempt_admitted_hook: AttemptHook,
    ) -> bytes:
        nonlocal calls
        del dst, primary, secondary, expect_response, retry_safe
        calls += 1
        if attempt_hook is not None:
            attempt_hook()
        attempt_admitted_hook()
        if calls == 1:
            raise enhanced_tcp._EnhancedCollision("collision")
        return bytes((payload[1],)) + payload[3:5] + bytes((0, 20, 1))

    monkeypatch.setattr(inner, "_send_proto_once", _send_once)
    monkeypatch.setattr(enhanced_tcp.time, "sleep", lambda _seconds: None)
    return inner


@pytest.mark.parametrize(
    "transport_factory",
    [_ebusd_retrying_transport, _enhanced_retrying_transport],
    ids=["ebusd", "enhanced"],
)
def test_real_transport_retry_hook_preserves_later_family_first_attempt(
    monkeypatch: pytest.MonkeyPatch,
    transport_factory: Callable[[pytest.MonkeyPatch], TransportInterface],
) -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        DescriptionCandidate(0x06, 0x09, 0x00, 0, "UCH"),
    ]
    entries = _entries(candidates)
    entries[candidates[0].native_identity]["value"] = 42
    coverage: dict[str, Any] = {}
    transport = CountingTransport(transport_factory(monkeypatch), request_budget=2)

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=2,
            coverage=coverage,
        )

    assert transport.counters.send_calls == 2
    local = entries[candidates[0].native_identity]["parameter_description"]
    remote = entries[candidates[1].native_identity]["parameter_description"]
    assert local["request_attempted"] is True
    assert local["request_attempts"] == 1
    assert local["qualification"] == "unavailable"
    assert local["request_hex"] == "0101000000"
    assert entries[candidates[0].native_identity]["value"] == 42
    assert remote["request_attempted"] is True
    assert remote["request_attempts"] == 1
    assert remote["qualification"] == "matched"


def test_enhanced_local_nack_rejection_releases_bus_before_reserved_remote_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidates = [
        DescriptionCandidate(0x02, 0x01, 0x00, 0, "UCH"),
        DescriptionCandidate(0x06, 0x09, 0x00, 0, "UCH"),
    ]
    entries = _entries(candidates)
    coverage: dict[str, Any] = {}
    inner = EnhancedTcpTransport(EnhancedTcpConfig(nack_max_retries=1))
    remote_response = bytes((0x09, 0x00, 0x00, 0x00, 0x14, 0x01))
    received = iter(
        (
            enhanced_tcp._EBUS_NACK,
            enhanced_tcp._EBUS_ACK,
            len(remote_response),
            *remote_response,
            enhanced_tcp._crc(bytes((len(remote_response),)) + remote_response),
        )
    )
    arbitration_calls = 0
    bus_owned = False
    sent_symbols: list[int] = []

    def _start_arbitration(_src: int) -> None:
        nonlocal arbitration_calls, bus_owned
        assert bus_owned is False
        arbitration_calls += 1
        bus_owned = True

    def _send_symbol(symbol: int) -> None:
        nonlocal bus_owned
        assert bus_owned is True
        sent_symbols.append(symbol)
        if symbol == enhanced_tcp._EBUS_SYN:
            bus_owned = False

    monkeypatch.setattr(inner, "_start_arbitration", _start_arbitration)
    monkeypatch.setattr(inner, "_send_symbol_with_echo", _send_symbol)
    monkeypatch.setattr(inner, "_recv_bus_symbol", lambda **_kwargs: next(received))
    transport = CountingTransport(inner, request_budget=2)

    with pytest.raises(ScanRequestBudgetExceeded, match="descriptions"):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=2,
            coverage=coverage,
        )

    assert arbitration_calls == 2
    assert bus_owned is False
    assert sent_symbols.count(enhanced_tcp._EBUS_SYN) == 2
    assert transport.counters.send_calls == 2
    assert (
        entries[candidates[0].native_identity]["parameter_description"]["qualification"]
        == "unavailable"
    )
    assert (
        entries[candidates[1].native_identity]["parameter_description"]["qualification"]
        == "matched"
    )
