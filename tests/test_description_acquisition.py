from __future__ import annotations

from typing import Any

import pytest

from helianthus_vrc_explorer.scanner.description_acquisition import acquire_descriptions
from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from helianthus_vrc_explorer.transport.instrumented import (
    CountingTransport,
    ScanRequestBudgetExceeded,
)


class DescriptionTransport(TransportInterface):
    def __init__(self) -> None:
        self.opcodes: list[int] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.opcodes.append(payload[0])
        return bytes((payload[1],)) + payload[3:5] + bytes((0, 20, 1))


def test_remaining_send_budget_is_shared_before_acquisition() -> None:
    inner = DescriptionTransport()
    transport = CountingTransport(inner, request_budget=5)
    candidates = [
        DescriptionCandidate(opcode, 1, 0, rr, "UCH") for opcode in (2, 6) for rr in range(5)
    ]
    entries: dict[tuple[int, int, int, int], dict[str, Any]] = {
        item.native_identity: {} for item in candidates
    }
    coverage: dict[str, Any] = {}
    with pytest.raises(ScanRequestBudgetExceeded):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=256,
            coverage=coverage,
        )
    assert len(inner.opcodes) == 5
    assert inner.opcodes.count(1) == 3
    assert inner.opcodes.count(7) == 2
    assert coverage["eligible"] == 10
    assert coverage["attempted"] == coverage["matched"] == 5
    assert coverage["budget_skipped"] == 5
    assert coverage["effective_request_budget"] == 5
    assert coverage["request_budget"] == 256


@pytest.mark.parametrize("exhaust_budget", [False, True])
def test_description_attempt_counters_include_internal_retries(
    monkeypatch: pytest.MonkeyPatch, exhaust_budget: bool
) -> None:
    inner = EbusdTcpTransport(EbusdTcpConfig())
    calls = 0

    def command_lines(*args: object, **kwargs: object) -> list[str]:
        nonlocal calls
        calls += 1
        if exhaust_budget or calls == 1:
            return ["ERR: timeout"]
        return ["010000001401"]

    monkeypatch.setattr(inner, "_send_command_lines", command_lines)
    monkeypatch.setattr("helianthus_vrc_explorer.transport.ebusd_tcp.time.sleep", lambda _: None)
    transport = CountingTransport(inner, request_budget=2)
    candidates = [
        DescriptionCandidate(2, 1, 0, rr, "UCH") for rr in range(2 if exhaust_budget else 1)
    ]
    entries: dict[tuple[int, int, int, int], dict[str, Any]] = {
        item.native_identity: {} for item in candidates
    }
    coverage: dict[str, Any] = {}
    if exhaust_budget:
        with pytest.raises(ScanRequestBudgetExceeded):
            acquire_descriptions(
                transport,
                dst=0x15,
                candidates=candidates,
                entries=entries,
                budget=256,
                coverage=coverage,
            )
    else:
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=candidates,
            entries=entries,
            budget=256,
            coverage=coverage,
        )
    assert calls == 2
    assert coverage["attempted"] == 1
    assert coverage["request_attempts"] == 2
    assert coverage["retries"] == 1
    description = entries[candidates[0].native_identity]["parameter_description"]
    assert description["request_attempted"] is True
    assert description["request_attempts"] == 2
    assert description["request_hex"] == "0101000000"
    if exhaust_budget:
        assert description["qualification"] == "unavailable"
        assert coverage["not_attempted"] == 1
    else:
        assert description["qualification"] == "matched"
