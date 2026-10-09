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
from helianthus_vrc_explorer.ui.live import NullScanObserver


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


class RecordingDescriptionObserver(NullScanObserver):
    def __init__(self) -> None:
        self.events: list[tuple[str, str, int]] = []

    def phase_start(self, phase: str, *, total: int) -> None:
        self.events.append(("start", phase, total))

    def phase_set_total(self, phase: str, *, total: int) -> None:
        self.events.append(("total", phase, total))

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        self.events.append(("advance", phase, advance))

    def phase_finish(self, phase: str) -> None:
        self.events.append(("finish", phase, 0))


def test_description_progress_counts_actual_requests_and_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner = EbusdTcpTransport(EbusdTcpConfig())
    calls = 0

    def command_lines(*args: object, **kwargs: object) -> list[str]:
        nonlocal calls
        calls += 1
        return ["ERR: timeout"] if calls == 1 else ["010000001401"]

    monkeypatch.setattr(inner, "_send_command_lines", command_lines)
    monkeypatch.setattr("helianthus_vrc_explorer.transport.ebusd_tcp.time.sleep", lambda _: None)
    transport = CountingTransport(inner)
    candidate = DescriptionCandidate(2, 1, 0, 0, "UCH")
    observer = RecordingDescriptionObserver()
    acquire_descriptions(
        transport,
        dst=0x15,
        candidates=[candidate],
        entries={candidate.native_identity: {}},
        budget=None,
        coverage={},
        observer=observer,
    )
    assert observer.events == [
        ("start", "describe", 1),
        ("total", "describe", 2),
        ("advance", "describe", 2),
        ("finish", "describe", 0),
    ]


def test_description_progress_does_not_finish_on_budget_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inner = EbusdTcpTransport(EbusdTcpConfig())
    monkeypatch.setattr(inner, "_send_command_lines", lambda *_args, **_kwargs: ["ERR: timeout"])
    monkeypatch.setattr("helianthus_vrc_explorer.transport.ebusd_tcp.time.sleep", lambda _: None)
    transport = CountingTransport(inner, request_budget=1)
    candidate = DescriptionCandidate(2, 1, 0, 0, "UCH")
    observer = RecordingDescriptionObserver()
    with pytest.raises(ScanRequestBudgetExceeded):
        acquire_descriptions(
            transport,
            dst=0x15,
            candidates=[candidate],
            entries={candidate.native_identity: {}},
            budget=None,
            coverage={},
            observer=observer,
        )
    assert ("start", "describe", 1) in observer.events
    assert ("advance", "describe", 1) in observer.events
    assert not any(event[0] == "finish" for event in observer.events)
