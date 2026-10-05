from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from .base import TransportError, TransportInterface


class ScanRequestBudgetExceeded(RuntimeError):
    """The configured scan request limit was reached before sending another request."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.system_information: list[tuple[int, float, str | None]] = []


@dataclass(slots=True)
class TransportCounters:
    send_calls: int = 0


class CountingTransport(TransportInterface):
    """Transport wrapper that counts `send()` calls.

    Useful for request/second estimates and scan planning.
    """

    def __init__(self, inner: TransportInterface, *, request_budget: int | None = None) -> None:
        if request_budget is not None and (
            isinstance(request_budget, bool)
            or not isinstance(request_budget, int)
            or request_budget < 1
        ):
            raise ValueError("request_budget must be a positive integer or None")
        self._inner = inner
        self.request_budget = request_budget
        self.counters = TransportCounters()
        self.recent_requests: deque[dict[str, Any]] = deque(maxlen=64)

    def send(self, dst: int, payload: bytes) -> bytes:
        if self.request_budget is not None and self.counters.send_calls >= self.request_budget:
            raise ScanRequestBudgetExceeded("B524 request budget exhausted")
        self.counters.send_calls += 1
        evidence: dict[str, Any] = {
            "attempt": self.counters.send_calls,
            "destination_address": f"0x{dst:02x}",
            "request_hex": payload.hex(),
            "reply_hex": None,
        }
        try:
            response = self._inner.send(dst, payload)
        except TransportError as exc:
            evidence["error_type"] = type(exc).__name__
            self.recent_requests.append(evidence)
            raise
        evidence["reply_hex"] = response.hex()
        self.recent_requests.append(evidence)
        return response

    def trace_label(self, label: str) -> None:
        fn = getattr(self._inner, "trace_label", None)
        if callable(fn):
            fn(label)
