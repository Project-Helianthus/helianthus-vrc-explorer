"""Serialized transport ownership for the interactive Browser."""

from __future__ import annotations

import math
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypeVar, cast

from ..transport.base import TransportInterface
from ..transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from ..transport.enhanced_tcp import EnhancedTcpConfig, EnhancedTcpTransport

type BrowserTransportKind = Literal["tcp", "ens"]
T = TypeVar("T")


def _u8(name: str, value: int, *, destination: bool = False) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be an integer in range 0..255")
    if destination and value in {0x00, 0xA9, 0xAA}:
        raise ValueError(f"{name} is a reserved eBUS address")


@dataclass(frozen=True, slots=True)
class BrowserTransportConfig:
    """Ephemeral connection input collected by the Browser Connect form."""

    kind: BrowserTransportKind
    host: str
    port: int
    source: int
    destination: int
    timeout_s: float = 5.0
    trace_path: Path | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"tcp", "ens"}:
            raise ValueError("kind must be 'tcp' or 'ens'")
        if not isinstance(self.host, str) or not self.host.strip():
            raise ValueError("host must be a non-empty string")
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1 <= self.port <= 65535
        ):
            raise ValueError("port must be an integer in range 1..65535")
        _u8("source", self.source)
        _u8("destination", self.destination, destination=True)
        if (
            isinstance(self.timeout_s, bool)
            or not isinstance(self.timeout_s, (int, float))
            or not math.isfinite(self.timeout_s)
            or self.timeout_s <= 0
        ):
            raise ValueError("timeout_s must be a positive finite number")
        if self.trace_path is not None and not isinstance(self.trace_path, Path):
            raise TypeError("trace_path must be a pathlib.Path or None")


def create_browser_transport(config: BrowserTransportConfig) -> TransportInterface:
    """Create the existing transport selected by ephemeral Browser settings."""

    if config.kind == "tcp":
        return EbusdTcpTransport(
            EbusdTcpConfig(
                host=config.host,
                port=config.port,
                timeout_s=float(config.timeout_s),
                src=config.source,
                trace_path=config.trace_path,
            )
        )
    return EnhancedTcpTransport(
        EnhancedTcpConfig(
            host=config.host,
            port=config.port,
            timeout_s=float(config.timeout_s),
            src=config.source,
            trace_path=config.trace_path,
        )
    )


class BrowserSession:
    """Own one transport and run all operations on one background worker.

    ``submit`` returns immediately, so the Textual event loop can keep rendering
    while a connection, scan, confirmation preparation, write, or recheck waits
    on transport I/O. FIFO executor order prevents another Browser operation from
    interleaving with the final identity/pre-read/write/readback sequence.
    """

    def __init__(self, transport: TransportInterface) -> None:
        self.transport = transport
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="vrc-browser")
        self._state_lock = threading.Lock()
        self._closed = False
        self._session_context: Any = None

    @classmethod
    def from_config(cls, config: BrowserTransportConfig) -> BrowserSession:
        return cls(create_browser_transport(config))

    def submit(
        self,
        operation: Callable[..., T],
        /,
        *args: object,
        **kwargs: object,
    ) -> Future[T]:
        with self._state_lock:
            if self._closed:
                raise RuntimeError("BrowserSession is closed")

        def run() -> T:
            return operation(self.transport, *args, **kwargs)

        return cast(Future[T], self._executor.submit(run))

    def connect(self) -> Future[TransportInterface]:
        """Open one persistent connection on the worker without blocking the UI."""

        def open_session(transport: TransportInterface) -> TransportInterface:
            if self._session_context is not None:
                return transport
            session_factory = getattr(transport, "session", None)
            if callable(session_factory):
                context = session_factory()
                context.__enter__()
                self._session_context = context
            return transport

        return self.submit(open_session)

    def close(self, *, wait: bool = True) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True

        def close_transport() -> None:
            context = self._session_context
            self._session_context = None
            if context is not None:
                context.__exit__(None, None, None)
                return
            close = getattr(self.transport, "close", None)
            if callable(close):
                close()

        future = self._executor.submit(close_transport)
        if wait:
            future.result()
        self._executor.shutdown(wait=wait, cancel_futures=False)
