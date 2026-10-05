from __future__ import annotations

from typing import Any

import pytest

from helianthus_vrc_explorer.scanner.description_acquisition import acquire_descriptions
from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.transport.base import TransportInterface
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
