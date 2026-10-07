from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any

AttemptHook = Callable[[], None]


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


class TransportRecoveryExhausted(TransportError):
    """Raised when bounded recovery cannot restore an interrupted read.

    The public fields intentionally contain only categorical diagnostics.  Raw
    socket messages can contain private endpoint details and are retained only
    as exception chaining, not in the user-facing message.
    """

    _CAUSES = frozenset(
        {
            "disconnected",
            "protocol_sync_error",
            "socket_error",
            "timeout",
            "transport_error",
        }
    )
    _PHASES = frozenset({"command_ack", "connect", "receive", "reconnect", "send", "transaction"})

    def __init__(
        self,
        *,
        cause: str,
        phase: str,
        request_attempts: int,
        reconnect_attempts: int,
    ) -> None:
        self.cause = cause if cause in self._CAUSES else "transport_error"
        self.phase = phase if phase in self._PHASES else "transaction"
        self.request_attempts = max(1, request_attempts)
        self.retry_count = max(0, self.request_attempts - 1)
        self.reconnect_attempts = max(0, reconnect_attempts)
        self.selector: dict[str, str] | None = None
        self.entry: dict[str, Any] | None = None
        self.system_information: list[tuple[int, float, str | None]] = []
        self.parameter_description: dict[str, Any] | None = None
        super().__init__(
            "transport recovery exhausted: "
            f"cause={self.cause} phase={self.phase} "
            f"request_attempts={self.request_attempts} retry_count={self.retry_count} "
            f"reconnect_attempts={self.reconnect_attempts}"
        )


class TransportInterface(ABC):
    """Transport interface for sending B524 payloads and receiving raw responses."""

    @abstractmethod
    def send(self, dst: int, payload: bytes) -> bytes:
        """Send a request and return the raw response payload.

        Args:
            dst: Destination address (0x00..0xFF).
            payload: Raw B524 payload bytes (without ebus framing).
        """

    def send_with_attempt_hook(
        self,
        dst: int,
        payload: bytes,
        attempt_hook: AttemptHook,
    ) -> bytes:
        """Send while notifying a caller immediately before each request attempt.

        Transports with internal retries override this method and invoke the hook
        for every B524 request attempt.  The default preserves compatibility for
        transports whose ``send`` implementation performs one attempt.
        """

        attempt_hook()
        return self.send(dst, payload)


def emit_trace_label(transport: TransportInterface, label: str) -> None:
    """Best-effort: emit a trace label on transports that support it.

    This avoids changing the `TransportInterface.send()` signature while still allowing
    higher-level code to annotate ebusd traces with human-readable operation labels.
    """

    fn: Any = getattr(transport, "trace_label", None)
    if callable(fn):
        fn(label)
