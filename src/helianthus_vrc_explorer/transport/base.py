from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class TransportError(Exception):
    """Base class for transport-layer errors."""


class TransportTimeout(TransportError):
    """Raised when a transport request times out."""


class TransportNack(TransportError):
    """Raised when the target explicitly NACKs (0xFF) the request.

    This is a definitive protocol-level rejection for the specific telegram.
    """


class TransportCommandNotEnabled(TransportError):
    """Raised when ebusd rejects a command because it is not enabled.

    Most commonly this happens when the `hex` command is disabled and ebusd is not
    started with `--enablehex`.
    """


class TransportHostError(TransportError):
    """Raised when the adapter reports a host-side error (invalid command/parameter).

    Host errors are non-retryable — the request was malformed from the adapter's
    perspective.  Retrying the identical request would produce the same error.
    """


class TransportDisconnected(TransportError):
    """Raised when the TCP connection is cleanly closed by the peer (EOF).

    Distinguished from TransportError to allow targeted reconnect handling.
    """


class TransportInterface(ABC):
    """Transport interface for sending B524 payloads and receiving raw responses."""

    @abstractmethod
    def send(self, dst: int, payload: bytes) -> bytes:
        """Send a request and return the raw response payload.

        Args:
            dst: Destination address (0x00..0xFF).
            payload: Raw B524 payload bytes (without ebus framing).
        """


def emit_trace_label(transport: TransportInterface, label: str) -> None:
    """Best-effort: emit a trace label on transports that support it.

    This avoids changing the `TransportInterface.send()` signature while still allowing
    higher-level code to annotate ebusd traces with human-readable operation labels.
    """

    fn: Any = getattr(transport, "trace_label", None)
    if callable(fn):
        fn(label)
