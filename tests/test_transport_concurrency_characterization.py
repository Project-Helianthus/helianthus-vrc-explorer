"""Deterministic public-operation schedules; all I/O is scripted in memory."""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

import pytest

from helianthus_vrc_explorer.transport.base import TransportTimeout
from helianthus_vrc_explorer.transport.enhanced_tcp import (
    _ENH_REQ_INFO,
    _ENH_REQ_INIT,
    _ENH_REQ_SEND,
    _ENH_REQ_START,
    _ENH_RES_INFO,
    _ENH_RES_RECEIVED,
    _ENH_RES_RESETTED,
    _ENH_RES_STARTED,
    EnhancedTcpConfig,
    EnhancedTcpTransport,
    _crc,
    _encode_enh,
)

_WAIT = 5.0  # Deadlock watchdog only; ordering comes from Events and the lock probe.


@dataclass
class _Exchange:
    request: bytes
    response: bytes | TimeoutError
    pause: bool = False


def _info(payload: bytes) -> bytes:
    return _encode_enh(_ENH_RES_INFO, len(payload)) + b"".join(
        _encode_enh(_ENH_RES_INFO, value) for value in payload
    )


def _init() -> _Exchange:
    return _Exchange(_encode_enh(_ENH_REQ_INIT, 1), _encode_enh(_ENH_RES_RESETTED, 1))


def _proto(stale: bytes) -> list[_Exchange]:
    """Follow the existing identification-read fixture shape with synthetic data."""
    telegram = bytes((0x31, 0x15, 0x07, 0x04, 0))
    telegram += bytes((_crc(telegram),))
    exchanges = [
        _Exchange(
            _encode_enh(_ENH_REQ_START, telegram[0]),
            _encode_enh(_ENH_RES_STARTED, telegram[0]),
            pause=True,
        )
    ]
    segment = b"\x01A"
    for index, value in enumerate(telegram[1:]):
        response = _encode_enh(_ENH_RES_RECEIVED, value)
        if index == len(telegram[1:]) - 1:
            response += b"".join(
                _encode_enh(_ENH_RES_RECEIVED, symbol)
                for symbol in b"\x00" + segment + bytes((_crc(segment),))
            )
        exchanges.append(_Exchange(_encode_enh(_ENH_REQ_SEND, value), response))
    exchanges.extend(
        [
            _Exchange(_encode_enh(_ENH_REQ_SEND, 0), _encode_enh(_ENH_RES_RECEIVED, 0)),
            _Exchange(
                _encode_enh(_ENH_REQ_SEND, 0xAA),
                _encode_enh(_ENH_RES_RECEIVED, 0xAA) + stale,
            ),
        ]
    )
    return exchanges


class _ScriptedSocket:
    def __init__(
        self,
        exchanges: list[_Exchange],
        entered: threading.Event,
        release: threading.Event,
    ) -> None:
        self.exchanges = deque(exchanges)
        self.pending: _Exchange | None = None
        self.entered = entered
        self.release = release
        self.blocking = True
        self.closed = False
        self.sent: list[bytes] = []

    def settimeout(self, _timeout: float) -> None:
        self.blocking = True

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def setsockopt(self, *_args: object) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        assert not self.closed
        assert self.pending is None, "A request overtook an unread response"
        exchange = self.exchanges.popleft()
        assert data == exchange.request, "Transaction bytes interleaved"
        self.sent.append(data)
        self.pending = exchange

    def recv(self, _size: int) -> bytes:
        assert not self.closed, "A request used a closed session"
        if not self.blocking:
            raise BlockingIOError
        exchange = self.pending
        assert exchange is not None, "Response read without an owning request"
        if exchange.pause:
            self.entered.set()
            assert self.release.wait(_WAIT), "Scripted read was never released"
        self.pending = None
        if isinstance(exchange.response, TimeoutError):
            raise exchange.response
        return exchange.response

    def close(self) -> None:
        self.closed = True


@pytest.mark.parametrize("first", ["info", "proto", "timeout", "reset"])
@pytest.mark.parametrize("contender", ["request", "close"])
def test_request_owns_response_until_close_or_next_request(
    monkeypatch: pytest.MonkeyPatch, first: str, contender: str
) -> None:
    """Pause a request at recv, probe contention, then finish before its successor."""
    entered = threading.Event()
    release = threading.Event()
    contended = threading.Event()
    transport = EnhancedTcpTransport(EnhancedTcpConfig(src=0x31, timeout_s=60))
    # A complete stale INFO response and an incomplete frame must not leak into
    # the next operation, whether it reuses the session or opens a fresh one.
    stale = _info(b"S") + _encode_enh(_ENH_RES_INFO, 1)[:1]
    if first == "proto":
        first_steps = _proto(stale)
    else:
        response: bytes | TimeoutError
        if first == "timeout":
            response = TimeoutError("scripted receive timeout")
        elif first == "reset":
            response = _encode_enh(_ENH_RES_RESETTED, 1) + stale
        else:
            response = _info(b"A") + stale
        first_steps = [_Exchange(_encode_enh(_ENH_REQ_INFO, 0), response, pause=True)]
    next_info = _Exchange(_encode_enh(_ENH_REQ_INFO, 1), _info(b"B"))
    sockets: list[_ScriptedSocket] = []

    def connect(*_args: object) -> _ScriptedSocket:
        steps = [_init(), next_info]
        if not sockets:
            steps = [_init(), *first_steps, next_info]
        sock = _ScriptedSocket(steps, entered, release)
        sockets.append(sock)
        return sock

    monkeypatch.setattr(
        "helianthus_vrc_explorer.transport.enhanced_tcp.socket.create_connection", connect
    )
    results: dict[str, bytes | None | Exception] = {}
    unexpected: list[BaseException] = []

    def record(name: str, operation: Callable[[], bytes | None]) -> None:
        try:
            results[name] = operation()
        except TransportTimeout as exc:
            results[name] = exc
        except BaseException as exc:
            unexpected.append(exc)

    def first_request() -> bytes:
        if first == "proto":
            return transport.send_proto(0x15, 0x07, 0x04, b"")
        return transport.request_info(0)

    def successor() -> bytes | None:
        # A nonblocking probe proves the contender reached a held transaction
        # lock while the first request was paused, without timing assertions or
        # replacing/instrumenting the production RLock.
        acquired = transport._lock.acquire(blocking=False)
        if acquired:
            transport._lock.release()
        contended.set()
        assert not acquired, "Public request released its lock before response completion"
        if contender == "close":
            transport.close()
            return None
        return transport.request_info(1)

    threads = [
        threading.Thread(target=record, args=("first", first_request)),
        threading.Thread(target=record, args=("successor", successor)),
    ]
    started: list[threading.Thread] = []
    try:
        threads[0].start()
        started.append(threads[0])
        assert entered.wait(_WAIT), "First request never reached scripted receive"
        threads[1].start()
        started.append(threads[1])
        assert contended.wait(_WAIT), "Contender never probed the transaction lock"
        assert sockets[0].pending is not None
        assert not sockets[0].closed
    finally:
        release.set()
        for thread in started:
            thread.join(_WAIT)
    assert all(not thread.is_alive() for thread in started), "Transport worker leaked"
    try:
        assert not unexpected, unexpected
        if first in {"timeout", "reset"}:
            assert isinstance(results["first"], TransportTimeout)
        else:
            assert results["first"] == b"A"
        if contender == "close":
            assert results["successor"] is None
            assert transport._session is None
            assert not transport._messages
            assert transport._enh_pending_first is None
            assert all(sock.closed for sock in sockets)
            # A request after close must open a new session, never reuse the
            # first request's queued complete or partial response.
            assert transport.request_info(1) == b"B"
        else:
            assert results["successor"] == b"B"
        expected_connections = 1 + (first == "reset") + (contender == "close")
        assert len(sockets) == expected_connections
        assert all(sock.pending is None for sock in sockets)
        assert not sockets[-1].exchanges
        assert sum(_encode_enh(_ENH_REQ_INFO, 1) in sock.sent for sock in sockets) == 1
    finally:
        transport.close()
    assert all(sock.closed for sock in sockets)
