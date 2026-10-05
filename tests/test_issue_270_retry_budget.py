from __future__ import annotations

from collections.abc import Callable

import pytest

import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp
import helianthus_vrc_explorer.transport.enhanced_tcp as enhanced_tcp
from helianthus_vrc_explorer.transport.base import (
    TransportDisconnected,
    TransportError,
    TransportInterface,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from helianthus_vrc_explorer.transport.enhanced_tcp import EnhancedTcpConfig, EnhancedTcpTransport
from helianthus_vrc_explorer.transport.instrumented import (
    CountingTransport,
    ScanRequestBudgetExceeded,
)


class _PlainTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: list[tuple[int, bytes]] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.calls.append((dst, payload))
        return b"\x01"


@pytest.mark.parametrize(
    ("failure", "config"),
    [
        (TransportTimeout("ERR: timeout"), EbusdTcpConfig(timeout_max_retries=1)),
        (TransportError("ERR: SYN received"), EbusdTcpConfig(collision_max_retries=1)),
        (TransportTimeout("Timed out talking to ebusd"), EbusdTcpConfig()),
    ],
    ids=["timeout", "collision", "connection-retry"],
)
def test_ebusd_retry_cannot_exceed_one_request_attempt(
    monkeypatch: pytest.MonkeyPatch,
    failure: TransportError,
    config: EbusdTcpConfig,
) -> None:
    transport = EbusdTcpTransport(config)
    calls = 0

    def _send_once(_seq: int, _dst: int, _payload: bytes) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise failure
        return b"\x01"

    monkeypatch.setattr(transport, "_send_once", _send_once)
    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    counted = CountingTransport(transport, request_budget=1)

    with pytest.raises(ScanRequestBudgetExceeded, match="budget exhausted"):
        counted.send(0x15, b"\x00\x00\x00")

    assert calls == 1
    assert counted.counters.send_calls == 1
    assert list(counted.recent_requests) == [
        {
            "attempt": 1,
            "destination_address": "0x15",
            "request_hex": "000000",
            "reply_hex": None,
        }
    ]


def test_ebusd_internal_retry_consumes_two_slots_and_retains_raw_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = EbusdTcpTransport(EbusdTcpConfig(timeout_max_retries=1))
    replies: list[bytes | TransportError] = [TransportTimeout("ERR: timeout"), b"\x02"]

    def _send_once(_seq: int, _dst: int, _payload: bytes) -> bytes:
        result = replies.pop(0)
        if isinstance(result, TransportError):
            raise result
        return result

    monkeypatch.setattr(transport, "_send_once", _send_once)
    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    counted = CountingTransport(transport, request_budget=2)

    assert counted.send(0x15, b"\x02\x00\x02") == b"\x02"

    assert counted.counters.send_calls == 2
    evidence = list(counted.recent_requests)
    assert [item["attempt"] for item in evidence] == [1, 2]
    assert [item["request_hex"] for item in evidence] == ["020002", "020002"]
    assert evidence[0]["reply_hex"] is None
    assert evidence[1]["reply_hex"] == "02"


def test_exhausted_transport_retry_retains_last_error_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = EbusdTcpTransport(EbusdTcpConfig(timeout_max_retries=1))
    monkeypatch.setattr(
        transport,
        "_send_once",
        lambda _seq, _dst, _payload: (_ for _ in ()).throw(TransportTimeout("ERR: timeout")),
    )
    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    counted = CountingTransport(transport, request_budget=3)

    with pytest.raises(TransportTimeout, match="timeout retries exhausted"):
        counted.send(0x15, b"\x00")

    evidence = list(counted.recent_requests)
    assert len(evidence) == 2
    assert evidence[-1]["error_type"] == "TransportTimeout"


@pytest.mark.parametrize(
    ("failure_factory", "config"),
    [
        (
            lambda: TransportTimeout("adapter timeout"),
            EnhancedTcpConfig(timeout_max_retries=0, reconnect_max_retries=1),
        ),
        (
            lambda: enhanced_tcp._EnhancedCollision("collision"),
            EnhancedTcpConfig(collision_max_retries=1),
        ),
        (
            lambda: TransportDisconnected("disconnected"),
            EnhancedTcpConfig(reconnect_max_retries=1),
        ),
    ],
    ids=["timeout-reconnect", "collision", "disconnect-reconnect"],
)
def test_enhanced_outer_retry_cannot_exceed_one_request_attempt(
    monkeypatch: pytest.MonkeyPatch,
    failure_factory: Callable[[], TransportError],
    config: EnhancedTcpConfig,
) -> None:
    transport = EnhancedTcpTransport(config)
    arbitration_calls = 0

    def _start_arbitration(_src: int) -> None:
        nonlocal arbitration_calls
        arbitration_calls += 1
        raise failure_factory()

    monkeypatch.setattr(transport, "_start_arbitration", _start_arbitration)
    monkeypatch.setattr(transport, "_reconnect", lambda _seq, _attempt: None)
    monkeypatch.setattr(enhanced_tcp.time, "sleep", lambda _seconds: None)
    counted = CountingTransport(transport, request_budget=1)

    with pytest.raises(ScanRequestBudgetExceeded, match="budget exhausted"):
        counted.send(0x15, b"\x00")

    assert arbitration_calls == 1
    assert counted.counters.send_calls == 1
    assert len(counted.recent_requests) == 1


def test_enhanced_local_nack_retry_consumes_another_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = EnhancedTcpTransport(EnhancedTcpConfig(nack_max_retries=1))
    sent_symbols: list[int] = []

    monkeypatch.setattr(transport, "_start_arbitration", lambda _src: None)
    monkeypatch.setattr(transport, "_send_symbol_with_echo", sent_symbols.append)
    monkeypatch.setattr(transport, "_recv_bus_symbol", lambda **_kwargs: enhanced_tcp._EBUS_NACK)
    counted = CountingTransport(transport, request_budget=1)

    with pytest.raises(ScanRequestBudgetExceeded, match="budget exhausted"):
        counted.send(0x15, b"\x00")

    # One telegram was emitted; the local NACK retransmission was stopped before
    # its first symbol and did not become a limit+1 request.
    assert len(sent_symbols) == 6
    assert counted.counters.send_calls == 1
    assert len(counted.recent_requests) == 1


def test_no_budget_default_hook_keeps_plain_transport_behavior() -> None:
    inner = _PlainTransport()
    counted = CountingTransport(inner)

    assert counted.send(0x15, b"\x00") == b"\x01"

    assert inner.calls == [(0x15, b"\x00")]
    assert counted.counters.send_calls == 1
    assert list(counted.recent_requests)[0]["reply_hex"] == "01"


def test_counting_transport_forwards_an_outer_hook_for_every_inner_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = EbusdTcpTransport(EbusdTcpConfig(timeout_max_retries=1))
    replies: list[bytes | TransportError] = [TransportTimeout("ERR: timeout"), b"\x01"]
    hook_calls: list[int] = []

    def _send_once(_seq: int, _dst: int, _payload: bytes) -> bytes:
        result = replies.pop(0)
        if isinstance(result, TransportError):
            raise result
        return result

    monkeypatch.setattr(transport, "_send_once", _send_once)
    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    counted = CountingTransport(transport)

    assert counted.send_with_attempt_hook(0x15, b"\x00", lambda: hook_calls.append(1)) == b"\x01"

    assert hook_calls == [1, 1]
    assert counted.counters.send_calls == 2
