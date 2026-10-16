"""Characterize bounded recovery, without implying a global wall-clock deadline.

README's recovery contract bounds attempts independently of scan budgets. The
elapsed bounds below apply to scripted one-symbol reads and reconnect costs;
they are not a bound for every phase of a complete protocol transaction.
"""

import signal
from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

from helianthus_vrc_explorer.transport import enhanced_tcp
from helianthus_vrc_explorer.transport.base import (
    TransportDisconnected,
    TransportRecoveryExhausted,
    TransportTimeout,
)


@pytest.fixture(autouse=True)
def deadlock_watchdog() -> Iterator[None]:
    """Interrupt a regressed loop in place; no worker can outlive the test."""

    def expired(_signum: int, _frame: object) -> None:
        raise AssertionError("transport characterization deadlock watchdog expired")

    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 3.0)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


class ScriptedConnection:
    """A fake message source whose receive/reconnect work advances virtual time."""

    def __init__(self) -> None:
        self.now = 0.0
        self.attempts = 0
        self.ticks = 0
        self.reconnects: list[int] = []
        self.success_on: int | None = None
        self.interrupt_at: str | None = None
        self.disconnect_on: set[int] = set()
        self.fail_reconnect = False

    def monotonic(self) -> float:
        return self.now

    def read_message(self) -> tuple[str, int, int]:
        self.now += 0.25
        self.ticks += 1
        if self.interrupt_at == "read" and self.attempts == 3 and self.ticks == 2:
            raise KeyboardInterrupt
        if self.attempts in self.disconnect_on:
            raise TransportDisconnected("synthetic disconnect")
        if self.attempts == self.success_on and self.ticks == 3:
            return ("data", 0x01, 0)
        return ("frame", enhanced_tcp._ENH_RES_INFO, 0)

    def reconnect(self, _seq: int, attempt: int) -> None:
        self.reconnects.append(attempt)
        self.now += 0.5
        if self.interrupt_at == "reconnect":
            raise KeyboardInterrupt
        if self.fail_reconnect:
            raise TransportTimeout("synthetic reconnect timeout")

    def send_once(
        self, transport: enhanced_tcp.EnhancedTcpTransport, admitted: Callable[[], None]
    ) -> bytes:
        admitted()
        self.attempts += 1
        self.ticks = 0
        return bytes((transport._recv_bus_symbol(),))


def run_script(
    monkeypatch: pytest.MonkeyPatch,
    connection: ScriptedConnection,
    *,
    timeout_retries: int = 1,
    reconnect_retries: int = 2,
) -> bytes:
    transport = enhanced_tcp.EnhancedTcpTransport(
        enhanced_tcp.EnhancedTcpConfig(
            timeout_s=1.0,
            timeout_max_retries=timeout_retries,
            reconnect_max_retries=reconnect_retries,
            reconnect_delay_s=0,
        )
    )
    # Replace the module reference, not the process-wide time.monotonic function.
    monkeypatch.setattr(enhanced_tcp, "time", SimpleNamespace(monotonic=connection.monotonic))
    monkeypatch.setattr(transport, "_read_message", connection.read_message)
    monkeypatch.setattr(transport, "_reconnect", connection.reconnect)
    try:
        return transport._send_with_policy(
            1, lambda admitted: connection.send_once(transport, admitted), retry_safe=True
        )
    finally:
        transport.close()


@pytest.mark.parametrize(("timeouts", "reconnects"), [(0, 0), (0, 2), (1, 2), (2, 1)])
def test_timeout_exhaustion_has_finite_aggregate_cost(
    monkeypatch: pytest.MonkeyPatch, timeouts: int, reconnects: int
) -> None:
    connection = ScriptedConnection()
    expected_attempts = (timeouts + 1) * (reconnects + 1)
    expected_error = TransportRecoveryExhausted if reconnects else TransportTimeout
    with pytest.raises(expected_error) as raised:
        run_script(monkeypatch, connection, timeout_retries=timeouts, reconnect_retries=reconnects)
    assert connection.attempts == expected_attempts
    assert connection.reconnects == list(range(1, reconnects + 1))
    assert connection.now == expected_attempts * 1.0 + reconnects * 0.5
    if isinstance(raised.value, TransportRecoveryExhausted):
        assert raised.value.request_attempts == expected_attempts
        assert raised.value.reconnect_attempts == reconnects


def test_success_near_last_attempt_deadline_retains_prior_elapsed_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = ScriptedConnection()
    connection.success_on = 6
    assert run_script(monkeypatch, connection) == b"\x01"
    assert connection.attempts == 6
    assert connection.reconnects == [1, 2]
    assert connection.now == 5 * 1.0 + 2 * 0.5 + 0.75


def test_mixed_disconnects_and_timeouts_share_reconnect_allowance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = ScriptedConnection()
    connection.disconnect_on = {1, 4}
    with pytest.raises(TransportRecoveryExhausted) as raised:
        run_script(monkeypatch, connection)
    assert connection.attempts == raised.value.request_attempts == 4
    assert connection.reconnects == [1, 2]
    assert connection.now == 2 * 0.25 + 2 * 1.0 + 2 * 0.5


def test_failed_reconnects_consume_allowance_without_new_request_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = ScriptedConnection()
    connection.fail_reconnect = True
    with pytest.raises(TransportRecoveryExhausted) as raised:
        run_script(monkeypatch, connection)
    assert raised.value.phase == "reconnect"
    assert connection.attempts == raised.value.request_attempts == 2
    assert connection.reconnects == [1, 2]
    assert connection.now == 3.0


@pytest.mark.parametrize("phase", ["read", "reconnect"])
def test_keyboard_cancellation_propagates_without_further_retry(
    monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    # Synchronous transport has no cancellation-token API; characterize interruption.
    connection = ScriptedConnection()
    connection.interrupt_at = phase
    with pytest.raises(KeyboardInterrupt):
        run_script(monkeypatch, connection)
    assert connection.attempts == (3 if phase == "read" else 2)
    assert connection.reconnects == [1]
    assert connection.now == (3.0 if phase == "read" else 2.5)
