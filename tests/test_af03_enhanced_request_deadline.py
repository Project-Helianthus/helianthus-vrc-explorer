"""One nonrenewable elapsed deadline per logical Enhanced TCP operation.

Every clock, sleep, lock and socket here is an in-memory script: no wall clock,
real sleep, thread, loopback listener or adapter is used.  Each fake phase
consumes a known, binary-exact amount of virtual time so equality with the
deadline is never a rounding accident.  This is a software budget for
transport-controlled waits; nothing here measures native or physical timing.
"""

from __future__ import annotations

import socket
import threading
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from helianthus_vrc_explorer.transport import enhanced_tcp
from helianthus_vrc_explorer.transport.base import (
    TransportRecoveryExhausted,
    TransportTimeout,
)
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
    _EnhancedCollision,
    _EnhancedTcpSession,
)

_SRC = 0xF7
_DST = 0x15
_READ = bytes.fromhex("020003001600")  # Retry-safe B524 register read shape.
_WRITE = bytes.fromhex("020103001600")  # Recognized write: never resubmitted.
_RECV_LIMIT = 5000  # A regressed loop fails here instead of spinning.


class VirtualClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _decode(frame: bytes) -> tuple[int, int]:
    assert len(frame) == 2
    return (frame[0] >> 2) & 0x0F, ((frame[0] & 0x03) << 6) | (frame[1] & 0x3F)


def _wire(logical: bytes) -> list[int]:
    symbols: list[int] = []
    for value in logical:
        if value == 0xA9:
            symbols.extend((0xA9, 0x00))
        elif value == 0xAA:
            symbols.extend((0xA9, 0x01))
        else:
            symbols.append(value)
    return symbols


def _received(symbol: int) -> bytes:
    return _encode_enh(_ENH_RES_RECEIVED, symbol)


class FakeSocket:
    """Socket double: every blocking wait is bounded by the applied timeout."""

    def __init__(self, peer: Peer) -> None:
        self.peer = peer
        self.timeout: float | None = None
        self.blocking = True
        self.closed = False
        self.rx: deque[tuple[float, bytes]] = deque()

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout
        self.blocking = True

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def setsockopt(self, *_args: object) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        assert not self.closed
        self.peer.waits.append(("send", self.peer.clock.now, self.timeout))
        if _decode(bytes(data)) in self.peer.stalled_sends:
            # A full send buffer blocks for exactly the applied timeout.
            assert self.timeout is not None
            self.peer.clock.advance(self.timeout)
            raise TimeoutError("scripted send timeout")
        self.peer.sent.append(_decode(bytes(data)))
        self.peer.on_send(self, *_decode(bytes(data)))

    def recv(self, _size: int) -> bytes:
        assert not self.closed
        if not self.blocking:
            # Stale-buffer drain: only what has already arrived.
            if self.rx and self.rx[0][0] == 0.0:
                return self.rx.popleft()[1]
            raise BlockingIOError
        peer = self.peer
        peer.recv_calls += 1
        assert peer.recv_calls < _RECV_LIMIT, "regressed receive loop"
        assert self.timeout is not None
        peer.waits.append(("recv", peer.clock.now, self.timeout))
        if self.rx:
            cost, chunk = self.rx[0]
        elif peer.idle is not None:
            cost, chunk = next(peer.idle)
            self.rx.appendleft((cost, chunk))
        else:
            cost, chunk = (float("inf"), b"")
        if cost > self.timeout:
            # The OS waits exactly the applied timeout; the bytes stay pending.
            peer.clock.advance(self.timeout)
            if self.rx:
                self.rx[0] = (cost - self.timeout, chunk)
            raise TimeoutError("scripted receive timeout")
        self.rx.popleft()
        peer.clock.advance(cost)
        return chunk

    def close(self) -> None:
        self.closed = True


class Peer:
    """Scripted ENH adapter plus bus target for one retry-safe request shape."""

    def __init__(
        self,
        clock: VirtualClock,
        *,
        payload: bytes = _READ,
        responses: tuple[bytes, ...] = (b"\x01",),
        cost: float = 0.03125,
        connect_cost: float = 0.03125,
    ) -> None:
        self.clock = clock
        self.cost = cost
        self.connect_cost = connect_cost
        telegram = bytes((_SRC, _DST, 0xB5, 0x24, len(payload))) + payload
        self.telegram_wire = _wire(telegram[1:] + bytes((_crc(telegram),)))
        self.responses = deque(responses)
        self.response_costs: dict[int, float] = {}
        self.sent: list[tuple[int, int]] = []
        self.waits: list[tuple[str, float, float | None]] = []
        self.connect_timeouts: list[float] = []
        self.sockets: list[FakeSocket] = []
        self.recv_calls = 0
        self.idle: Iterator[tuple[float, bytes]] | None = None
        self.init_cost: float | None = None
        self.on_start: Callable[[FakeSocket], None] | None = None
        self.on_info: Callable[[FakeSocket, int], None] | None = None
        self.echo_limit: int | None = None
        self.target_replies = True
        self.stalled_sends: set[tuple[int, int]] = set()
        self.connect_failure: type[OSError] | None = None
        self._telegram_seen: int | None = None

    def connect(self, _address: object, timeout: float) -> FakeSocket:
        self.connect_timeouts.append(timeout)
        if self.connect_failure is TimeoutError:
            self.clock.advance(timeout)
            raise TimeoutError("scripted connect timeout")
        self.clock.advance(self.connect_cost)
        if self.connect_failure is not None:
            raise self.connect_failure("scripted connect failure")
        sock = FakeSocket(self)
        self.sockets.append(sock)
        return sock

    def _queue(self, sock: FakeSocket, frame: bytes, cost: float | None = None) -> None:
        sock.rx.append((self.cost if cost is None else cost, frame))

    def _queue_response(self, sock: FakeSocket) -> None:
        body = self.responses.popleft()
        segment = bytes((len(body),)) + body
        for index, symbol in enumerate(_wire(segment + bytes((_crc(segment),)))):
            self._queue(sock, _received(symbol), self.response_costs.get(index))

    def on_send(self, sock: FakeSocket, command: int, data: int) -> None:
        if command == _ENH_REQ_INIT:
            self._queue(sock, _encode_enh(_ENH_RES_RESETTED, data), self.init_cost)
        elif command == _ENH_REQ_INFO:
            assert self.on_info is not None
            self.on_info(sock, data)
        elif command == _ENH_REQ_START:
            self._telegram_seen = 0
            if self.on_start is not None:
                self.on_start(sock)
            else:
                self._queue(sock, _encode_enh(_ENH_RES_STARTED, data))
        elif command == _ENH_REQ_SEND:
            if self._telegram_seen is None:
                self._queue(sock, _received(data))  # ACK/NACK/SYN echoes.
                if data == 0xFF and self.responses:
                    self._queue_response(sock)
                return
            self._telegram_seen += 1
            if self.echo_limit is not None and self._telegram_seen > self.echo_limit:
                return
            self._queue(sock, _received(data))
            if self._telegram_seen == len(self.telegram_wire):
                self._telegram_seen = None
                if self.target_replies:
                    self._queue(sock, _received(0x00))
                    self._queue_response(sock)


def _cycle(*chunks: tuple[float, bytes]) -> Iterator[tuple[float, bytes]]:
    while True:
        yield from chunks


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> VirtualClock:
    virtual = VirtualClock()
    # Replace the module reference only; process-wide time is untouched.
    monkeypatch.setattr(
        enhanced_tcp, "time", SimpleNamespace(monotonic=virtual.monotonic, sleep=virtual.sleep)
    )
    return virtual


def _transport(
    monkeypatch: pytest.MonkeyPatch,
    peer: Peer,
    *,
    max_command_s: float = 1.0,
    **config: object,
) -> EnhancedTcpTransport:
    monkeypatch.setattr(
        enhanced_tcp,
        "socket",
        SimpleNamespace(
            create_connection=peer.connect,
            IPPROTO_TCP=socket.IPPROTO_TCP,
            TCP_NODELAY=socket.TCP_NODELAY,
        ),
    )
    settings: dict[str, object] = {"timeout_s": 4.0, "max_command_s": max_command_s}
    settings.update(config)
    return EnhancedTcpTransport(EnhancedTcpConfig(**settings))  # type: ignore[arg-type]


def _assert_deadline_outcome(
    exc: TransportRecoveryExhausted, *, request_attempts: int, reconnect_attempts: int
) -> None:
    assert (exc.cause, exc.phase) == ("timeout", "transaction")
    assert exc.request_attempts == request_attempts
    assert exc.retry_count == max(0, request_attempts - 1)
    assert exc.reconnect_attempts == reconnect_attempts
    assert isinstance(exc.__cause__, enhanced_tcp.RequestDeadlineExpired)


# --- configuration -------------------------------------------------------------


def test_max_command_s_is_a_finite_thirty_second_default() -> None:
    config = EnhancedTcpConfig()
    assert config.max_command_s == 30.0
    assert EnhancedTcpTransport(EnhancedTcpConfig(max_command_s=0.5))._config.max_command_s == 0.5


@pytest.mark.parametrize(
    ("value", "error"),
    [
        (0, ValueError),
        (-1.0, ValueError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (True, TypeError),
        ("30", TypeError),
    ],
)
def test_max_command_s_rejects_non_finite_non_positive_or_non_numeric(
    value: object, error: type[Exception]
) -> None:
    with pytest.raises(error, match=r"^max_command_s: "):
        EnhancedTcpTransport(EnhancedTcpConfig(max_command_s=value))  # type: ignore[arg-type]


# --- complete public operations through the production low-level loops --------


def test_every_wait_is_clamped_and_each_independent_request_gets_a_fresh_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, responses=(b"\x01", b"\x02"))
    transport = _transport(monkeypatch, peer)

    assert transport.send(_DST, _READ) == b"\x01"
    first_end = clock.now
    assert first_end == 0.625  # Lazy connect + INIT reuse the request's root.
    assert transport._active_root() is None
    # The second request runs past one budget of cumulative time: a fresh root.
    assert transport.send(_DST, _READ) == b"\x02"
    assert clock.now == first_end + 0.5625 > 1.0
    assert transport._active_root() is None

    assert peer.connect_timeouts == [1.0]
    assert len(peer.waits) == (15 + 19) + (14 + 18)  # Sends + receives per request.
    for kind, now, timeout in peer.waits:
        start = 0.0 if now < first_end else first_end
        assert timeout == min(4.0, start + 1.0 - now), (kind, now)
    transport.close()


def test_arbitration_received_flood_cannot_renew_the_activity_timer(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, cost=0.125, connect_cost=0.0)
    peer.on_start = lambda _sock: setattr(peer, "idle", _cycle((0.125, _received(0x10))))
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert clock.now == 1.0
    assert peer.sent == [(_ENH_REQ_INIT, 0x01), (_ENH_REQ_START, _SRC)]
    assert peer.sockets[0].closed and transport._session is None
    assert transport._active_root() is None


def test_info_flood_while_waiting_for_echo_cannot_buy_time(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, cost=0.125, connect_cost=0.0)
    peer.echo_limit = 0

    def _start(sock: FakeSocket) -> None:
        sock.rx.append((0.125, _encode_enh(_ENH_RES_STARTED, _SRC)))
        peer.idle = _cycle((0.125, _encode_enh(_ENH_RES_INFO, 0x00)))

    peer.on_start = _start
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert clock.now == 1.0
    # One telegram symbol was sent; nothing was emitted after expiry.
    assert peer.sent[-1] == (_ENH_REQ_SEND, _DST)
    assert len(peer.sent) == 3


@pytest.mark.parametrize(
    "idle",
    [
        pytest.param(((0.125, _received(0x10)),), id="received-frames"),
        pytest.param(
            ((0.0625, _received(0x10)[:1]), (0.0625, _received(0x10)[1:])),
            id="partial-enh-frames",
        ),
        pytest.param(((0.0625, b"\x80"), (0.0625, b"\x01")), id="malformed-then-data"),
    ],
)
def test_request_info_progress_or_malformed_input_cannot_buy_time(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    idle: tuple[tuple[float, bytes], ...],
) -> None:
    peer = Peer(clock, cost=0.125, connect_cost=0.0)
    peer.on_info = lambda _sock, _info_id: setattr(peer, "idle", _cycle(*idle))
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.request_info(0x00)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert clock.now == 1.0
    assert peer.sent == [(_ENH_REQ_INIT, 0x01), (_ENH_REQ_INFO, 0x00)]
    assert peer.sockets[0].closed and transport._session is None
    assert transport._active_root() is None


def test_request_info_reply_queued_at_equality_is_refused_and_next_info_is_clean(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, connect_cost=0.0)
    replies = deque([(0.875, b"AB"), (0.125, b"C")])

    def _info(sock: FakeSocket, _info_id: int) -> None:
        cost, payload = replies.popleft()
        frames = _encode_enh(_ENH_RES_INFO, len(payload)) + b"".join(
            _encode_enh(_ENH_RES_INFO, value) for value in payload
        )
        sock.rx.append((cost, frames))  # The whole reply arrives in one chunk.

    peer.on_info = _info
    peer.init_cost = 0.125
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.request_info(0x00)
    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert clock.now == 1.0

    assert transport.request_info(0x01) == b"C"
    assert len(peer.sockets) == 2  # The ambiguous session was discarded.


def test_slow_response_byte_waits_only_the_remaining_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, connect_cost=0.0)
    peer.response_costs = {0: 0.75}
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert peer.waits[-1] == ("recv", 0.4375, 0.5625)
    assert clock.now == 1.0
    # No ACK, NACK or end-of-message symbol followed the telegram.
    assert len(peer.sent) == 2 + len(peer.telegram_wire)
    assert peer.sockets[0].closed


def test_escaped_response_byte_completed_at_equality_is_refused(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, responses=(b"\xa9",), connect_cost=0.0)
    peer.response_costs = {2: 0.5}  # Wire: length, A9, escape suffix 00, CRC.
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert peer.waits[-1] == ("recv", 0.5, 0.5)
    assert clock.now == 1.0
    assert len(peer.sent) == 2 + len(peer.telegram_wire)


def test_response_crc_retry_shares_the_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, responses=(b"\x01", b"\x01"), connect_cost=0.0)
    transport = _transport(monkeypatch, peer, max_command_s=0.75)
    original = peer._queue_response
    corrupted = False

    def _queue_bad_then_slow(sock: FakeSocket) -> None:
        nonlocal corrupted
        if corrupted:
            peer.response_costs = {0: 0.5}
            original(sock)
            return
        corrupted = True
        original(sock)
        cost, _frame = sock.rx.pop()
        sock.rx.append((cost, _received(0x00)))  # Wrong CRC symbol.

    peer._queue_response = _queue_bad_then_slow  # type: ignore[method-assign]

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert clock.now == 0.75
    sent_after_telegram = peer.sent[2 + len(peer.telegram_wire) :]
    assert sent_after_telegram == [(_ENH_REQ_SEND, 0xFF)]  # One NACK, never an ACK.


def test_recognized_write_waiting_for_ack_expires_without_resubmission(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, payload=_WRITE, connect_cost=0.0)
    peer.target_replies = False  # Every echo arrives, then no command ACK.
    transport = _transport(monkeypatch, peer)
    hook_calls = 0

    def _hook() -> None:
        nonlocal hook_calls
        hook_calls += 1

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _WRITE, _hook)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert hook_calls == 1
    assert peer.sent[0] == (_ENH_REQ_INIT, 0x01)
    assert peer.sent[1:] == [(_ENH_REQ_START, _SRC)] + [
        (_ENH_REQ_SEND, symbol) for symbol in peer.telegram_wire
    ]
    assert peer.waits[-1] == ("recv", 0.40625, 0.59375)
    assert clock.now == 1.0
    assert peer.sockets[0].closed


# --- standalone session setup ----------------------------------------------------


def test_standalone_session_init_at_equality_is_refused(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, connect_cost=0.5)
    peer.init_cost = 0.5
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised, transport.session():
        pytest.fail("session body must not run after setup expiry")

    _assert_deadline_outcome(raised.value, request_attempts=0, reconnect_attempts=0)
    assert peer.connect_timeouts == [1.0]
    assert peer.waits == [("send", 0.5, 0.5), ("recv", 0.5, 0.5)]
    assert transport._session_depth == 0 and transport._session is None
    assert transport._active_root() is None


@pytest.mark.parametrize("failure", [None, TimeoutError, ConnectionRefusedError])
def test_connect_ending_at_equality_is_refused_before_init(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    tmp_path: Path,
    failure: type[OSError] | None,
) -> None:
    peer = Peer(clock, connect_cost=1.0)
    peer.connect_failure = failure
    trace_path = tmp_path / "connect.trace"
    transport = _transport(monkeypatch, peer, trace_path=trace_path)

    with pytest.raises(TransportRecoveryExhausted) as raised, transport.session():
        pytest.fail("session body must not run after setup expiry")

    _assert_deadline_outcome(raised.value, request_attempts=0, reconnect_attempts=0)
    assert peer.connect_timeouts == [1.0]
    assert clock.now == 1.0
    assert peer.sent == []
    assert all(sock.closed for sock in peer.sockets)
    assert transport._session is None and transport._session_depth == 0
    transport.close()
    assert "INIT" not in trace_path.read_text(encoding="utf-8")


def test_send_buffer_stall_is_bounded_by_the_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, connect_cost=0.0)
    peer.init_cost = 0.125
    peer.stalled_sends = {(_ENH_REQ_INFO, 0x00)}
    transport = _transport(monkeypatch, peer)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.request_info(0x00)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert peer.waits[-1] == ("send", 0.125, 0.875)
    assert clock.now == 1.0
    assert peer.sockets[0].closed and transport._session is None


def test_session_setup_budget_is_not_charged_to_later_requests(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock, connect_cost=0.375)
    peer.init_cost = 0.375
    transport = _transport(monkeypatch, peer)

    with transport.session():
        assert clock.now == 0.75
        assert transport._active_root() is None  # Setup root ends before the body.
        assert transport.send(_DST, _READ) == b"\x01"
        assert clock.now == 0.75 + 0.5625


# --- retry, reconnect and backoff share the root ----------------------------------


def _scripted_attempts(
    monkeypatch: pytest.MonkeyPatch,
    transport: EnhancedTcpTransport,
    clock: VirtualClock,
    *,
    cost: float,
    failure: Callable[[], Exception] | None,
    result: bytes = b"\x01",
) -> list[float]:
    admitted_at: list[float] = []

    def _send_once(_seq: int, **kwargs: object) -> bytes:
        hook = kwargs["attempt_hook"]
        if callable(hook):
            hook()
        admitted = kwargs["attempt_admitted_hook"]
        assert callable(admitted)
        admitted()
        admitted_at.append(clock.now)
        clock.advance(cost)
        if failure is not None:
            raise failure()
        return result

    monkeypatch.setattr(transport, "_send_proto_once", _send_once)
    return admitted_at


@pytest.mark.parametrize(
    ("backoff_ms", "attempts", "slept"),
    [(1000, 1, [0.75]), (250, 2, [0.25, 0.25])],
)
def test_collision_backoff_is_clamped_and_counts_admitted_attempts(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    backoff_ms: int,
    attempts: int,
    slept: list[float],
) -> None:
    peer = Peer(clock)
    transport = _transport(
        monkeypatch,
        peer,
        collision_backoff_min_ms=backoff_ms,
        collision_backoff_max_ms=backoff_ms,
    )
    admitted_at = _scripted_attempts(
        monkeypatch,
        transport,
        clock,
        cost=0.25,
        failure=lambda: _EnhancedCollision("synthetic collision"),
    )

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=attempts, reconnect_attempts=0)
    assert len(admitted_at) == attempts
    assert clock.slept == slept
    assert clock.now == 1.0


def test_reconnect_delay_connect_and_init_share_the_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, tmp_path: Path
) -> None:
    peer = Peer(clock, connect_cost=0.125)
    peer.init_cost = 0.125
    trace_path = tmp_path / "deadline.trace"
    transport = _transport(
        monkeypatch,
        peer,
        trace_path=trace_path,
        timeout_max_retries=0,
        reconnect_max_retries=3,
        reconnect_delay_s=0.5,
    )
    admitted_at = _scripted_attempts(
        monkeypatch,
        transport,
        clock,
        cost=0.25,
        failure=lambda: TransportTimeout("synthetic timeout"),
    )

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=1)
    assert admitted_at == [0.0]
    assert clock.slept == [0.5]
    assert peer.connect_timeouts == [0.25]
    assert peer.waits == [("send", 0.875, 0.125), ("recv", 0.875, 0.125)]
    assert clock.now == 1.0
    assert peer.sockets[0].closed and transport._session is None
    assert (
        "REQUEST_FAILED cause=timeout phase=transaction "
        "request_attempts=1 retry_count=0 reconnect_attempts=1"
    ) in trace_path.read_text(encoding="utf-8")


def test_expiry_at_recovery_begins_no_reconnect(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock)
    transport = _transport(
        monkeypatch, peer, timeout_max_retries=0, reconnect_max_retries=3, reconnect_delay_s=0
    )
    _scripted_attempts(
        monkeypatch,
        transport,
        clock,
        cost=1.0,
        failure=lambda: TransportTimeout("synthetic timeout"),
    )

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert peer.connect_timeouts == []


def test_reconnect_delay_is_clamped_to_the_remaining_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock)
    transport = _transport(
        monkeypatch, peer, timeout_max_retries=0, reconnect_max_retries=3, reconnect_delay_s=2.0
    )
    _scripted_attempts(
        monkeypatch,
        transport,
        clock,
        cost=0.25,
        failure=lambda: TransportTimeout("synthetic timeout"),
    )

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=1)
    assert clock.slept == [0.75]
    assert peer.connect_timeouts == []


@pytest.mark.parametrize(
    ("failure", "config"),
    [
        (lambda: TransportTimeout("synthetic"), {"timeout_max_retries": 2}),
        (
            lambda: _EnhancedCollision("synthetic"),
            {"collision_backoff_min_ms": 0, "collision_backoff_max_ms": 0},
        ),
        (lambda: enhanced_tcp._EnhancedNack("synthetic"), {"nack_max_retries": 1}),
        (lambda: enhanced_tcp._EnhancedCrcMismatch("synthetic"), {"nack_max_retries": 1}),
        (lambda: enhanced_tcp._EnhancedCommandNotAcknowledgedBeforeSyn("synthetic"), {}),
    ],
    ids=["timeout", "collision-no-backoff", "nack", "crc", "syn-boundary"],
)
def test_no_retry_branch_admits_an_attempt_at_expiry(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    failure: Callable[[], Exception],
    config: dict[str, int],
) -> None:
    transport = _transport(monkeypatch, Peer(clock), **config)
    hook_calls: list[float] = []
    admitted_at = _scripted_attempts(monkeypatch, transport, clock, cost=1.0, failure=failure)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, lambda: hook_calls.append(clock.now))

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert admitted_at == hook_calls == [0.0]


def test_success_returned_at_equality_is_refused_and_the_next_request_is_clean(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock)
    transport = _transport(monkeypatch, peer)
    _scripted_attempts(monkeypatch, transport, clock, cost=1.0, failure=None)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_proto(_DST, 0x07, 0x04, b"")
    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert transport._active_root() is None

    _scripted_attempts(monkeypatch, transport, clock, cost=0.5, failure=None, result=b"\x02")
    assert transport.send_proto(_DST, 0x07, 0x04, b"") == b"\x02"


# --- hooks, cancellation and serialization ------------------------------------------


def test_reentrant_public_call_reuses_the_active_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    transport = _transport(monkeypatch, Peer(clock))
    _scripted_attempts(monkeypatch, transport, clock, cost=0.25, failure=None)
    roots: list[object] = []

    def _hook() -> None:
        roots.append(transport._active_root())
        assert transport.send_proto(_DST, 0x07, 0x04, b"") == b"\x01"
        roots.append(transport._active_root())

    assert transport.send_with_attempt_hook(_DST, _READ, _hook) == b"\x01"
    assert roots[0] is not None and roots[1] is roots[0]
    assert clock.now == 0.5
    assert transport._active_root() is None


def test_hook_overrunning_the_deadline_does_not_admit_its_attempt(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    transport = _transport(monkeypatch, Peer(clock))
    started: list[int] = []
    monkeypatch.setattr(transport, "_start_arbitration", started.append)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, lambda: clock.advance(1.0))

    _assert_deadline_outcome(raised.value, request_attempts=0, reconnect_attempts=0)
    assert started == []


@pytest.mark.parametrize(
    ("nack_at", "hook_cost", "hook_calls_expected"),
    [(1.0, 0.0, 1), (0.75, 0.25, 2)],
    ids=["expired-before-retry-hook", "retry-hook-overruns"],
)
def test_local_nack_retry_after_expiry_calls_no_hook_and_emits_no_symbol(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    nack_at: float,
    hook_cost: float,
    hook_calls_expected: int,
) -> None:
    transport = _transport(monkeypatch, Peer(clock))
    symbols: list[int] = []
    hook_calls = 0

    def _symbol(symbol: int) -> None:
        symbols.append(symbol)
        clock.advance(0.0625)

    def _nack(**_kwargs: object) -> int:
        clock.advance(nack_at - clock.now)
        return 0xFF

    def _hook() -> None:
        nonlocal hook_calls
        hook_calls += 1
        if hook_calls > 1:
            clock.advance(hook_cost)

    monkeypatch.setattr(transport, "_start_arbitration", lambda _src: None)
    monkeypatch.setattr(transport, "_send_symbol_with_echo", _symbol)
    monkeypatch.setattr(transport, "_recv_bus_symbol", _nack)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, _hook)

    _assert_deadline_outcome(raised.value, request_attempts=1, reconnect_attempts=0)
    assert hook_calls == hook_calls_expected
    assert len(symbols) == 11 and 0xAA not in symbols
    assert clock.now == 1.0


@pytest.mark.parametrize("error", [KeyboardInterrupt, RuntimeError])
def test_cancellation_and_hook_errors_propagate_and_clear_the_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, error: type[BaseException]
) -> None:
    transport = _transport(monkeypatch, Peer(clock))
    raised_error = error("caller stop")
    _scripted_attempts(monkeypatch, transport, clock, cost=0.25, failure=None)

    def _hook() -> None:
        raise raised_error

    with pytest.raises(error) as raised:
        transport.send_with_attempt_hook(_DST, _READ, _hook)
    assert raised.value is raised_error
    assert transport._active_root() is None
    assert transport.send(_DST, _READ) == b"\x01"


class FakeLock:
    """Reentrant lock double whose contended wait consumes virtual time."""

    def __init__(self, clock: VirtualClock, *, wait: float | None) -> None:
        self.clock = clock
        self.wait = wait
        self.waits: list[float] = []
        self.inner = threading.RLock()
        self.depth = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        self.waits.append(timeout)
        if self.wait is not None:
            self.clock.advance(min(self.wait, timeout))
            if self.wait > timeout:
                return False
        self.inner.acquire()
        self.depth += 1
        return True

    def release(self) -> None:
        self.depth -= 1
        self.inner.release()

    def __enter__(self) -> bool:
        # Uncontended reentrant use, e.g. close(); never consumes virtual time.
        self.inner.acquire()
        self.depth += 1
        return True

    def __exit__(self, *_exc: object) -> None:
        self.release()


def _enter_session(transport: EnhancedTcpTransport) -> None:
    with transport.session():
        pass


_ENTRIES: dict[str, Callable[[EnhancedTcpTransport, list[int]], object]] = {
    "send": lambda t, _h: t.send(_DST, _READ),
    "send_with_attempt_hook": lambda t, h: t.send_with_attempt_hook(
        _DST, _READ, lambda: h.append(1)
    ),
    "send_proto": lambda t, _h: t.send_proto(_DST, 0x07, 0x04, b""),
    "request_info": lambda t, _h: t.request_info(0x00),
    "session": lambda t, _h: _enter_session(t),
}


@pytest.mark.parametrize("entry", sorted(_ENTRIES))
@pytest.mark.parametrize("wait", [2.0, 1.0], ids=["lock-timeout", "acquired-at-equality"])
def test_lock_wait_is_bounded_and_expiry_before_admission_has_zero_attempts(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, entry: str, wait: float
) -> None:
    peer = Peer(clock)
    transport = _transport(monkeypatch, peer)
    lock = FakeLock(clock, wait=wait)
    transport._lock = lock  # type: ignore[assignment]
    hook_calls: list[int] = []
    # Another holder's healthy session: an operation that never began must not
    # touch it, discard it or re-enter it.
    held = FakeSocket(peer)
    transport._session = _EnhancedTcpSession(sock=held)  # type: ignore[arg-type]
    transport._session_depth = 1

    with pytest.raises(TransportRecoveryExhausted) as raised:
        _ENTRIES[entry](transport, hook_calls)

    _assert_deadline_outcome(raised.value, request_attempts=0, reconnect_attempts=0)
    assert lock.waits[0] == 1.0
    assert clock.now == 1.0
    assert lock.depth == 0
    assert hook_calls == []
    assert peer.connect_timeouts == [] and peer.sent == [] and peer.waits == []
    assert transport._session is not None and transport._session.sock is held
    assert not held.closed and transport._session_depth == 1
    assert transport._trace_seq == 0
    assert transport._active_root() is None


def test_direct_private_helper_keeps_its_local_timeout_without_a_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = Peer(clock)
    transport = _transport(monkeypatch, peer, max_command_s=0.5)
    sock = FakeSocket(peer)
    sock.rx.append((0.75, _received(0x42)))
    transport._session = _EnhancedTcpSession(sock=sock)  # type: ignore[arg-type]

    assert transport._recv_bus_symbol() == 0x42
    assert peer.waits == [("recv", 0.0, 4.0)]
