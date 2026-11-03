"""One nonrenewable elapsed deadline per logical ebusd TCP operation.

Every clock, sleep, connection and socket here is an in-memory script: no wall
clock, real sleep, thread, loopback listener or daemon is used.  Each fake phase
consumes a known, binary-exact amount of virtual time so equality with the
deadline is never a rounding accident.  This is a software budget for
transport-controlled waits; nothing here measures native or physical timing.
"""

from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from helianthus_vrc_explorer.transport import ebusd_tcp
from helianthus_vrc_explorer.transport.base import (
    TransportError,
    TransportRecoveryExhausted,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
from helianthus_vrc_explorer.transport.request_deadline import RequestDeadlineExpired

_HOST = "ebusd.invalid"
_PORT = 8888
_DST = 0x15
_READ = bytes.fromhex("020003001600")  # Retry-safe B524 register read shape.
_WRITE = bytes.fromhex("020103001600")  # Recognized write: never resubmitted.
_READ_CMD = "hex 15B52406020003001600"
_WRITE_CMD = "hex 15B52406020103001600"
_RECV_LIMIT = 5000  # A regressed loop fails here instead of spinning.

Script = list[tuple[float, bytes]] | None


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


class FakeSocket:
    """Socket double: every blocking wait is bounded by the applied timeout."""

    def __init__(self, peer: FakeEbusd) -> None:
        self.peer = peer
        self.timeout: float | None = None
        self.closed = False
        self.eof = False
        self.pending: deque[tuple[float, bytes]] = deque()
        self.commands: list[str] = []

    def settimeout(self, timeout: float | None) -> None:
        assert timeout is not None and timeout > 0
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        assert not self.closed
        peer = self.peer
        peer.send_timeouts.append(self.timeout)
        if peer.stall_send:
            # A full send buffer blocks for exactly the applied timeout.
            assert self.timeout is not None
            peer.clock.advance(self.timeout)
            raise TimeoutError("scripted send timeout")
        command = data.decode("ascii").rstrip("\n")
        peer.commands.append(command)
        self.commands.append(command)
        script = peer.responses.popleft() if peer.responses else None
        if script is not None:
            self.pending.extend(script)

    def recv(self, size: int) -> bytes:
        assert not self.closed
        peer = self.peer
        peer.recv_calls += 1
        assert peer.recv_calls < _RECV_LIMIT, "regressed receive loop"
        assert self.timeout is not None
        peer.recv_timeouts.append(self.timeout)
        if self.eof:
            return b""
        if self.pending:
            cost, chunk = self.pending[0]
        elif peer.idle is not None:
            cost, chunk = next(peer.idle)
            self.pending.appendleft((cost, chunk))
        else:
            cost, chunk = (math.inf, b"")
        if cost > self.timeout:
            # The OS waits exactly the applied timeout; the bytes stay pending.
            peer.clock.advance(self.timeout)
            if self.pending:
                self.pending[0] = (cost - self.timeout, chunk)
            raise TimeoutError("scripted receive timeout")
        self.pending.popleft()
        peer.clock.advance(cost)
        if not chunk:
            self.eof = True
            return b""
        if len(chunk) > size:
            self.pending.appendleft((0.0, chunk[size:]))
            chunk = chunk[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeEbusd:
    """Scripted ebusd command port: one response script per written command."""

    def __init__(
        self,
        clock: VirtualClock,
        responses: list[Script],
        *,
        connect_cost: float = 0.25,
    ) -> None:
        self.clock = clock
        self.responses: deque[Script] = deque(responses)
        self.connect_cost = connect_cost
        self.connect_timeouts: list[float] = []
        self.connect_failure: type[OSError] | None = None
        self.sockets: list[FakeSocket] = []
        self.commands: list[str] = []
        self.send_timeouts: list[float | None] = []
        self.recv_timeouts: list[float] = []
        self.recv_calls = 0
        self.stall_send = False
        self.idle: Iterator[tuple[float, bytes]] | None = None

    def connect(self, timeout_s: float) -> FakeSocket:
        self.connect_timeouts.append(timeout_s)
        if self.connect_failure is TimeoutError:
            self.clock.advance(timeout_s)
            raise TimeoutError("scripted connect timeout")
        self.clock.advance(self.connect_cost)
        if self.connect_failure is not None:
            raise self.connect_failure("scripted connect failure")
        sock = FakeSocket(self)
        self.sockets.append(sock)
        return sock


def _reply(cost: float, *lines: str, terminator: bool = True) -> list[tuple[float, bytes]]:
    body = b"".join(line.encode("ascii") + b"\n" for line in lines)
    return [(cost, body + (b"\n" if terminator else b""))]


def _repeat(cost: float, chunk: bytes) -> Iterator[tuple[float, bytes]]:
    while True:
        yield (cost, chunk)


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> VirtualClock:
    virtual = VirtualClock()
    # Replace the module reference, not the process-wide time functions.
    monkeypatch.setattr(
        ebusd_tcp, "time", SimpleNamespace(monotonic=virtual.monotonic, sleep=virtual.sleep)
    )
    return virtual


def _transport(
    monkeypatch: pytest.MonkeyPatch,
    peer: FakeEbusd,
    **overrides: object,
) -> EbusdTcpTransport:
    settings: dict[str, object] = {"host": _HOST, "port": _PORT, "timeout_s": 1.0}
    settings.update(overrides)
    transport = EbusdTcpTransport(EbusdTcpConfig(**settings))  # type: ignore[arg-type]
    monkeypatch.setattr(transport, "_connect", peer.connect)
    return transport


def _assert_terminal(
    raised: pytest.ExceptionInfo[TransportRecoveryExhausted],
    *,
    request_attempts: int,
    reconnect_attempts: int,
) -> None:
    failure = raised.value
    assert type(failure) is TransportRecoveryExhausted
    assert (failure.cause, failure.phase) == ("timeout", "transaction")
    assert failure.request_attempts == request_attempts
    assert failure.retry_count == max(0, request_attempts - 1)
    assert failure.reconnect_attempts == reconnect_attempts
    # The internal expiry is translated, never leaked or retried.
    assert isinstance(failure.__cause__, RequestDeadlineExpired)
    # No endpoint or socket text in the terminal diagnostic.
    assert _HOST not in str(failure)
    assert str(_PORT) not in str(failure)
    assert "scripted" not in str(failure)


# --- Budget validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("budget", "error"),
    [
        (0, ValueError),
        (0.0, ValueError),
        (-1.0, ValueError),
        (math.nan, ValueError),
        (math.inf, ValueError),
        (-math.inf, ValueError),
        (True, TypeError),
        (False, TypeError),
        ("30", TypeError),
        (None, TypeError),
    ],
)
def test_invalid_budget_fails_at_construction_before_io(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, budget: object, error: type
) -> None:
    peer = FakeEbusd(clock, [])
    with pytest.raises(error, match="max_command_s"):
        _transport(monkeypatch, peer, max_command_s=budget)
    assert peer.connect_timeouts == []
    assert clock.now == 0.0


def test_default_budget_is_finite_and_integer_budget_is_accepted(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    assert EbusdTcpConfig().max_command_s == 30.0
    peer = FakeEbusd(clock, [_reply(0.25, "01AA")])
    transport = _transport(monkeypatch, peer, max_command_s=30)
    assert transport.send(_DST, _READ) == b"\xaa"


# --- One root across attempts, backoff and reconnect ---------------------------------


def test_bus_lost_backoff_is_capped_by_remainder_and_ends_terminally(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.5, "ERR: no signal")] * 3, connect_cost=0.3)
    transport = _transport(monkeypatch, peer, max_command_s=1.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    # 0.8 s used, so the fixed 15 s wait is truncated to the 0.2 s remainder.
    assert clock.slept == [pytest.approx(0.2)]
    assert clock.slept[0] < 15.0
    assert clock.now == 1.0
    # The truncated wait ends in expiry, never in a fresh send.
    assert peer.commands == [_READ_CMD]
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)
    assert transport._active_root() is None


@pytest.mark.parametrize("err_line", ["ERR: timeout", "ERR: SYN received"])
def test_no_request_or_hook_is_admitted_at_equality(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, err_line: str
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, err_line)] * 3)
    transport = _transport(monkeypatch, peer, max_command_s=1.0)
    hooks: list[float] = []

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, lambda: hooks.append(clock.now))

    # The 5 s settle wait is truncated to 0.5 s and lands exactly on the deadline.
    assert clock.slept == [0.5]
    assert clock.now == 1.0
    assert hooks == [0.0]
    assert peer.commands == [_READ_CMD]
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


def test_reply_completed_at_the_deadline_is_refused(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, "ERR: timeout"), _reply(0.25, "01AA")])
    transport = _transport(monkeypatch, peer, max_command_s=6.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    # Second attempt starts at 5.5 s; its reply completes at exactly 6.0 s.
    assert clock.slept == [5.0]
    assert clock.now == 6.0
    assert peer.commands == [_READ_CMD, _READ_CMD]
    _assert_terminal(raised, request_attempts=2, reconnect_attempts=0)


def test_timeout_collision_reconnect_and_no_signal_share_one_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(
        clock,
        [
            _reply(0.25, "ERR: timeout"),
            _reply(0.25, "ERR: SYN received"),
            None,  # Silence: connection-level timeout, one connection retry.
            _reply(0.25, "ERR: no signal"),
            _reply(0.25, "01AA"),
        ],
    )
    transport = _transport(monkeypatch, peer, max_command_s=13.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    # 0.5 + 5 + 0.5 + 5 + (0.25 + 1.0) + 0.5 = 12.75 s; 15 s wait capped to 0.25 s.
    assert clock.slept == [5.0, 5.0, 0.25]
    assert clock.now == 13.0
    # The reconnect after the silent attempt is clamped to the 0.75 s remainder.
    assert peer.connect_timeouts == [1.0, 1.0, 1.0, 0.75]
    assert peer.commands == [_READ_CMD] * 4
    _assert_terminal(raised, request_attempts=4, reconnect_attempts=1)


@pytest.mark.parametrize(
    ("overrides", "err_line", "expected"),
    [
        ({"timeout_max_retries": 1}, "ERR: timeout", "timeout retries exhausted"),
        ({"collision_max_retries": 1}, "ERR: SYN received", "collision retries exhausted"),
        ({"no_signal_max_s": 1.0}, "ERR: no signal", "no-signal polling exceeded"),
    ],
)
def test_shorter_independent_limits_still_win_inside_the_root(
    monkeypatch: pytest.MonkeyPatch,
    clock: VirtualClock,
    overrides: dict[str, object],
    err_line: str,
    expected: str,
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, err_line)] * 4)
    transport = _transport(monkeypatch, peer, max_command_s=60.0, **overrides)

    with pytest.raises(TransportError, match=expected) as raised:
        transport.send(_DST, _READ)

    assert not isinstance(raised.value, TransportRecoveryExhausted)
    assert peer.commands == [_READ_CMD] * 2


def test_hook_overrunning_the_deadline_does_not_admit_its_attempt(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, "01AA")])
    transport = _transport(monkeypatch, peer, max_command_s=1.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, lambda: clock.advance(1.0))

    assert peer.connect_timeouts == []
    assert peer.commands == []
    _assert_terminal(raised, request_attempts=0, reconnect_attempts=0)


def test_reconnect_counts_only_when_its_attempt_is_admitted(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [None, _reply(0.25, "01AA")])
    transport = _transport(monkeypatch, peer, timeout_s=0.25, max_command_s=1.0)
    hooks: list[float] = []

    def hook() -> None:
        hooks.append(clock.now)
        if len(hooks) == 2:
            clock.advance(0.5)  # An uninterruptible caller hook overruns the root.

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _READ, hook)

    # The connection retry was decided at 0.5 s but never began.
    assert hooks == [0.0, 0.5]
    assert len(peer.connect_timeouts) == 1
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


def test_expired_write_is_terminal_and_never_resubmitted(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [None, _reply(0.25, "01AA")])
    transport = _transport(monkeypatch, peer, timeout_s=5.0, max_command_s=1.0)
    hooks: list[float] = []

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send_with_attempt_hook(_DST, _WRITE, lambda: hooks.append(clock.now))

    # The response wait is clamped to the 0.75 s remainder, not the 5 s phase limit.
    assert peer.recv_timeouts == [0.75]
    assert clock.now == 1.0
    assert peer.commands == [_WRITE_CMD]
    assert hooks == [0.0]
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


# --- Transport-controlled waits are clamped to the remainder -------------------------


@pytest.mark.parametrize("operation", ["send", "hook", "proto", "command", "command_all"])
def test_every_public_operation_bounds_a_silent_daemon(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, operation: str
) -> None:
    peer = FakeEbusd(clock, [None] * 4)
    transport = _transport(monkeypatch, peer, timeout_s=5.0, max_command_s=2.0)
    calls: dict[str, Callable[[], object]] = {
        "send": lambda: transport.send(_DST, _READ),
        "hook": lambda: transport.send_with_attempt_hook(_DST, _READ, lambda: None),
        "proto": lambda: transport.send_proto(_DST, 0x07, 0x04, b""),
        "command": lambda: transport.command_lines("info"),
        "command_all": lambda: transport.command_lines("info", read_all=True),
    }

    with pytest.raises(TransportRecoveryExhausted) as raised:
        calls[operation]()

    assert clock.now == 2.0
    assert max(peer.recv_timeouts) <= 2.0
    assert len(peer.commands) == 1
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)
    assert transport._active_root() is None


def test_connect_wait_is_clamped_to_remainder(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [])
    peer.connect_failure = TimeoutError
    transport = _transport(monkeypatch, peer, timeout_s=5.0, max_command_s=0.5)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    assert peer.connect_timeouts == [0.5]
    assert clock.now == 0.5
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


def test_write_and_flush_wait_is_clamped_to_remainder(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, "01AA")], connect_cost=0.75)
    peer.stall_send = True
    transport = _transport(monkeypatch, peer, timeout_s=5.0, max_command_s=1.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    assert peer.send_timeouts == [0.25]
    assert clock.now == 1.0
    assert peer.sockets[0].closed
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


@pytest.mark.parametrize("chunk", [b" \n", b"\t \r\n", b"0"])
def test_trickle_of_whitespace_or_partial_line_cannot_renew_the_read(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, chunk: bytes
) -> None:
    peer = FakeEbusd(clock, [[]])
    peer.idle = _repeat(0.5, chunk)
    transport = _transport(monkeypatch, peer, timeout_s=1.0, max_command_s=2.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.send(_DST, _READ)

    # Each chunk arrives inside the 1 s phase limit, yet the root still ends it.
    assert clock.now == 2.0
    assert peer.recv_timeouts == [1.0, 1.0, 0.75, 0.25]
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


def test_read_all_cannot_consume_a_fresh_phase_budget(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [[]])
    peer.idle = _repeat(0.5, b"address 08: synthetic\n")
    transport = _transport(monkeypatch, peer, timeout_s=1.0, max_command_s=2.0)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        transport.command_lines("info", read_all=True)

    assert clock.now == 2.0
    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)


def test_read_all_returns_lines_through_blank_terminator_or_idle_end(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    lines = ["address 08: synthetic", "address 15: synthetic"]
    peer = FakeEbusd(clock, [_reply(0.25, *lines), _reply(0.25, *lines, terminator=False)])
    transport = _transport(monkeypatch, peer, timeout_s=1.0, max_command_s=30.0)

    assert transport.command_lines("info", read_all=True) == lines
    # Without a terminator, the phase limit (not the root) ends the response.
    assert transport.command_lines("info", read_all=True) == lines
    assert peer.commands == ["info", "info"]


def test_retained_line_buffer_is_bounded(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [[]])
    peer.idle = _repeat(0.0, b"0" * 4096)
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    with transport.session():
        with pytest.raises(TransportError, match="line exceeded 8192 bytes"):
            transport.send(_DST, _READ)
        assert transport._session is None

    assert peer.recv_calls <= 4
    assert peer.sockets[0].closed
    assert peer.commands == [_READ_CMD]


# --- Optional trailing input and session isolation -----------------------------------


@pytest.mark.parametrize("persistent", [True, False])
def test_first_payload_wins_and_trailing_lines_drain_within_the_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock, persistent: bool
) -> None:
    script = [(0.25, b"0x 02AABB\n"), (0.0078125, b"ERR: trailing noise\n\n")]
    peer = FakeEbusd(clock, [script, _reply(0.25, "01CC")])
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    if persistent:
        with transport.session():
            first = transport.send(_DST, _READ)
            second = transport.send(_DST, _READ)
        assert len(peer.sockets) == 1
    else:
        first = transport.send(_DST, _READ)
        second = transport.send(_DST, _READ)
        assert len(peer.sockets) == 2
    assert (first, second) == (b"\xaa\xbb", b"\xcc")
    assert all(sock.closed for sock in peer.sockets)


def test_missing_optional_trailer_is_not_a_request_failure(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, "01AA", terminator=False), _reply(0.25, "01BB")])
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    with transport.session():
        assert transport.send(_DST, _READ) == b"\xaa"
        # Full-window silence isolates the tail; the session is reused.
        assert transport.send(_DST, _READ) == b"\xbb"

    assert len(peer.sockets) == 1
    assert clock.now == 0.25 + 0.25 + 0.01 + 0.25 + 0.0


def test_trickling_trailer_closes_the_persistent_session_after_a_timely_reply(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    script = [(0.25, b"01AA\n"), (0.0078125, b"ERR: late tail\n"), (1.0, b"\n")]
    peer = FakeEbusd(clock, [script, _reply(0.25, "01BB")])
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    with transport.session():
        assert transport.send(_DST, _READ) == b"\xaa"
        assert transport._session is None
        assert transport.send(_DST, _READ) == b"\xbb"

    # The unread terminator stays on the closed socket; it never reaches command two.
    assert peer.sockets[0].closed
    assert [chunk for _cost, chunk in peer.sockets[0].pending] == [b"\n"]
    assert peer.sockets[0].commands == [_READ_CMD]
    assert peer.sockets[1].commands == [_READ_CMD]


def test_bytes_after_the_terminator_are_never_lent_to_the_next_command(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [[(0.25, b"01AA\n\n01EE\n")], _reply(0.25, "01BB")])
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    with transport.session():
        assert transport.send(_DST, _READ) == b"\xaa"
        assert transport._session is None
        assert transport.send(_DST, _READ) == b"\xbb"

    assert peer.sockets[0].closed
    assert peer.sockets[1].commands == [_READ_CMD]


def test_optional_drain_is_skipped_when_it_could_consume_the_remainder(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.4921875, "01AA"), _reply(0.125, "01BB")])
    transport = _transport(monkeypatch, peer, max_command_s=0.5)

    with transport.session():
        # Only 2**-7 s remain after the reply: no drain wait, a timely result.
        assert transport.send(_DST, _READ) == b"\xaa"
        assert clock.now == 0.7421875
        assert peer.recv_calls == 1
        # The pending terminator cannot be isolated, so that session is closed.
        assert transport._session is None
        assert transport.send(_DST, _READ) == b"\xbb"

    assert peer.sockets[0].closed
    assert len(peer.sockets) == 2


def test_next_command_is_isolated_after_mandatory_expiry(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    partial = [(0.25, b"02A"), (5.0, b"A\n\n")]
    peer = FakeEbusd(clock, [partial, _reply(0.25, "01BB")])
    transport = _transport(monkeypatch, peer, max_command_s=1.0)

    with transport.session():
        with pytest.raises(TransportRecoveryExhausted) as raised:
            transport.send(_DST, _READ)
        assert transport._session is None
        assert transport._active_root() is None
        # A new independent operation gets a fresh root and a fresh session.
        assert transport.send(_DST, _READ) == b"\xbb"

    _assert_terminal(raised, request_attempts=1, reconnect_attempts=0)
    assert peer.sockets[0].closed
    assert peer.sockets[1].commands == [_READ_CMD]


# --- Standalone session setup --------------------------------------------------------


def test_standalone_session_setup_has_its_own_finite_root(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [])
    peer.connect_failure = TimeoutError
    transport = _transport(monkeypatch, peer, timeout_s=5.0, max_command_s=1.0)

    with pytest.raises(TransportRecoveryExhausted) as raised, transport.session():
        pass

    assert peer.connect_timeouts == [1.0]
    assert transport._session_depth == 0
    assert transport._active_root() is None
    _assert_terminal(raised, request_attempts=0, reconnect_attempts=0)


def test_session_setup_does_not_consume_a_later_request_budget(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.875, "01AA")], connect_cost=0.75)
    transport = _transport(monkeypatch, peer, max_command_s=1.0)

    with transport.session():
        assert clock.now == 0.75
        assert transport.send(_DST, _READ) == b"\xaa"

    assert clock.now == 0.75 + 0.875


def test_command_timeout_reply_is_unchanged_for_writes(
    monkeypatch: pytest.MonkeyPatch, clock: VirtualClock
) -> None:
    peer = FakeEbusd(clock, [_reply(0.25, "ERR: timeout")] * 2)
    transport = _transport(monkeypatch, peer, max_command_s=30.0)

    with pytest.raises(TransportTimeout, match="ERR: timeout") as raised:
        transport.send(_DST, _WRITE)

    assert not isinstance(raised.value, TransportRecoveryExhausted)
    assert peer.commands == [_WRITE_CMD]
