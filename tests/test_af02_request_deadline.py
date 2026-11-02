"""Nonrenewable request deadline primitive and zero-attempt recovery diagnostics.

Every clock and sleeper is a synthetic in-memory script; no wall clock, real
sleep, socket or transport I/O is used.  The primitive is not yet wired into a
transport entry point, so nothing here claims a deadline for a public call.
"""

from __future__ import annotations

import math
from collections.abc import Callable

import pytest

from helianthus_vrc_explorer.transport import request_deadline as module
from helianthus_vrc_explorer.transport.base import TransportError, TransportRecoveryExhausted
from helianthus_vrc_explorer.transport.request_deadline import (
    RequestDeadline,
    RequestDeadlineExpired,
    validate_budget_seconds,
)


class VirtualClock:
    """Monotonic virtual time that only moves when a test or sleeper moves it.

    Boundary tests use binary-exact steps so equality is not a rounding accident.
    """

    def __init__(self, now: float = 100.0) -> None:
        self.now = now
        self.reads = 0
        self.slept: list[float] = []

    def __call__(self) -> float:
        self.reads += 1
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def sleeper(self, fraction: float = 1.0) -> Callable[[float], None]:
        def sleep(seconds: float) -> None:
            self.slept.append(seconds)
            self.now += seconds * fraction

        return sleep


# --- validate_budget_seconds ---------------------------------------------------


@pytest.mark.parametrize("value", [0.001, 1, 30.0, 3600])
def test_validate_budget_accepts_finite_positive_numbers(value: float) -> None:
    result = validate_budget_seconds(value)
    assert result == float(value)
    assert type(result) is float


@pytest.mark.parametrize("value", [True, False, "30", None, b"\x1e"])
def test_validate_budget_rejects_bool_and_non_numbers(value: object) -> None:
    with pytest.raises(TypeError):
        validate_budget_seconds(value)


@pytest.mark.parametrize("value", [0, 0.0, -0.0, -1.0, math.nan, math.inf, -math.inf])
def test_validate_budget_rejects_zero_negative_nan_and_infinities(value: float) -> None:
    with pytest.raises(ValueError):
        validate_budget_seconds(value)


@pytest.mark.parametrize("value", [True, 0.0, -1.0, math.nan, math.inf, -math.inf])
def test_constructor_rejects_invalid_budget_without_creating_a_deadline(value: object) -> None:
    clock = VirtualClock()
    with pytest.raises((TypeError, ValueError)):
        RequestDeadline(value, clock=clock)


def test_module_captures_no_default_clock_or_sleeper() -> None:
    assert not hasattr(module, "time")
    assert not hasattr(module, "monotonic")
    with pytest.raises(TypeError):
        RequestDeadline(30.0)  # type: ignore[call-arg]


# --- remaining_s boundaries ----------------------------------------------------


def test_deadline_is_captured_once_from_the_injected_clock() -> None:
    clock = VirtualClock(now=100.0)
    deadline = RequestDeadline(1.0, clock=clock)
    assert clock.reads == 1
    assert deadline.budget_s == 1.0
    assert deadline.remaining_s() == pytest.approx(1.0)


def test_positive_remaining_time_before_deadline() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(0.4)
    assert deadline.remaining_s() == pytest.approx(0.6)


def test_exact_equality_is_expired() -> None:
    clock = VirtualClock(now=0.0)
    deadline = RequestDeadline(0.5, clock=clock)
    clock.advance(0.5)
    with pytest.raises(RequestDeadlineExpired):
        deadline.remaining_s()


def test_overrun_is_expired() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(7.0)
    with pytest.raises(RequestDeadlineExpired) as excinfo:
        deadline.remaining_s()
    assert excinfo.value.budget_s == 1.0


def test_progress_does_not_renew_deadline() -> None:
    """Catches a mutation that recomputes the deadline from the latest reading."""

    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    for _ in range(4):
        clock.advance(0.125)
        deadline.remaining_s()
        deadline.io_timeout_s(5.0)
    assert deadline.remaining_s() == 0.5
    clock.advance(0.5)
    with pytest.raises(RequestDeadlineExpired):
        deadline.remaining_s()


def test_nested_helper_calls_and_nested_deadlines_do_not_renew_outer() -> None:
    clock = VirtualClock()
    outer = RequestDeadline(1.0, clock=clock)
    clock.advance(0.5)
    inner = RequestDeadline(10.0, clock=clock)
    outer.sleep(0.125, sleep=clock.sleeper())
    assert inner.remaining_s() == 9.875
    assert outer.remaining_s() == 0.375
    clock.advance(0.375)
    with pytest.raises(RequestDeadlineExpired):
        outer.remaining_s()
    assert inner.remaining_s() == 9.5


def test_clock_stepping_backwards_cannot_extend_deadline() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(0.8)
    assert deadline.remaining_s() == pytest.approx(0.2)
    clock.advance(-5.0)
    assert deadline.remaining_s() == pytest.approx(0.2)


def test_non_finite_clock_reading_fails_closed() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.now = math.nan
    with pytest.raises(RequestDeadlineExpired):
        deadline.remaining_s()
    with pytest.raises(ValueError):
        RequestDeadline(1.0, clock=clock)


def test_separate_operations_get_fresh_deadlines() -> None:
    clock = VirtualClock()
    first = RequestDeadline(1.0, clock=clock)
    clock.advance(1.0)
    with pytest.raises(RequestDeadlineExpired):
        first.remaining_s()
    second = RequestDeadline(1.0, clock=clock)
    assert second.remaining_s() == pytest.approx(1.0)
    with pytest.raises(RequestDeadlineExpired):
        first.remaining_s()


def test_expired_signal_is_internal_not_a_transport_error() -> None:
    assert not issubclass(RequestDeadlineExpired, TransportError)


# --- io_timeout_s ----------------------------------------------------------------


def test_shorter_local_timeout_wins() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(30.0, clock=clock)
    assert deadline.io_timeout_s(2.5) == pytest.approx(2.5)


def test_shorter_remaining_budget_wins_over_local_timeout() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(0.4)
    assert deadline.io_timeout_s(2.5) == pytest.approx(0.6)


def test_io_timeout_at_equality_raises() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(1.0)
    with pytest.raises(RequestDeadlineExpired):
        deadline.io_timeout_s(2.5)


@pytest.mark.parametrize("local", [True, 0.0, -1.0, math.nan, math.inf])
def test_io_timeout_rejects_invalid_local_limit(local: object) -> None:
    deadline = RequestDeadline(1.0, clock=VirtualClock())
    with pytest.raises((TypeError, ValueError)):
        deadline.io_timeout_s(local)


# --- sleep -----------------------------------------------------------------------


def test_long_sleep_is_clamped_to_remaining() -> None:
    """Catches a mutation that passes the full requested delay to the sleeper."""

    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(0.75)
    with pytest.raises(RequestDeadlineExpired):
        deadline.sleep(15.0, sleep=clock.sleeper())
    assert clock.slept == [0.25]


def test_clamped_sleep_returns_when_sleeper_wakes_before_deadline() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(0.75)
    deadline.sleep(15.0, sleep=clock.sleeper(fraction=0.5))
    assert clock.slept == [0.25]
    assert deadline.remaining_s() == 0.125


def test_short_sleep_uses_requested_delay() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    deadline.sleep(0.25, sleep=clock.sleeper())
    assert clock.slept == [pytest.approx(0.25)]
    assert deadline.remaining_s() == pytest.approx(0.75)


def test_expiry_after_sleep_is_raised() -> None:
    """A sleeper that overruns its clamp still cannot let the caller continue."""

    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)

    def oversleep(seconds: float) -> None:
        clock.slept.append(seconds)
        clock.advance(seconds + 3.0)

    with pytest.raises(RequestDeadlineExpired):
        deadline.sleep(0.1, sleep=oversleep)
    assert clock.slept == [pytest.approx(0.1)]


def test_sleep_is_not_started_after_expiry() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(1.0)
    with pytest.raises(RequestDeadlineExpired):
        deadline.sleep(0.5, sleep=clock.sleeper())
    assert clock.slept == []


def test_zero_delay_is_allowed_before_expiry() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    deadline.sleep(0, sleep=clock.sleeper())
    assert clock.slept == []
    assert deadline.remaining_s() == pytest.approx(1.0)


def test_zero_delay_cannot_bypass_expiry() -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    clock.advance(1.0)
    with pytest.raises(RequestDeadlineExpired):
        deadline.sleep(0.0, sleep=clock.sleeper())


@pytest.mark.parametrize("delay", [True, -0.1, math.nan, math.inf, "1"])
def test_sleep_rejects_invalid_delay_without_sleeping(delay: object) -> None:
    clock = VirtualClock()
    deadline = RequestDeadline(1.0, clock=clock)
    with pytest.raises((TypeError, ValueError)):
        deadline.sleep(delay, sleep=clock.sleeper())
    assert clock.slept == []


# --- TransportRecoveryExhausted diagnostics ---------------------------------------


def test_recovery_exhausted_accepts_zero_admitted_attempts() -> None:
    exc = TransportRecoveryExhausted(
        cause="timeout", phase="transaction", request_attempts=0, reconnect_attempts=0
    )
    assert exc.request_attempts == 0
    assert exc.retry_count == 0
    assert exc.reconnect_attempts == 0
    assert str(exc) == (
        "transport recovery exhausted: cause=timeout phase=transaction "
        "request_attempts=0 retry_count=0 reconnect_attempts=0"
    )


def test_recovery_exhausted_zero_attempts_with_begun_reconnects() -> None:
    exc = TransportRecoveryExhausted(
        cause="timeout", phase="transaction", request_attempts=0, reconnect_attempts=2
    )
    assert (exc.request_attempts, exc.retry_count, exc.reconnect_attempts) == (0, 0, 2)


def test_recovery_exhausted_negative_counts_are_nonnegative() -> None:
    exc = TransportRecoveryExhausted(
        cause="timeout", phase="transaction", request_attempts=-3, reconnect_attempts=-1
    )
    assert (exc.request_attempts, exc.retry_count, exc.reconnect_attempts) == (0, 0, 0)


@pytest.mark.parametrize(
    ("cause", "phase", "attempts", "reconnects", "expected"),
    [
        ("timeout", "transaction", 1, 0, ("timeout", "transaction", 1, 0, 0)),
        ("timeout", "transaction", 3, 0, ("timeout", "transaction", 3, 2, 0)),
        ("timeout", "transaction", 3, 4, ("timeout", "transaction", 3, 2, 4)),
        ("disconnected", "transaction", 3, 4, ("disconnected", "transaction", 3, 2, 4)),
        ("timeout", "receive", 3, 4, ("timeout", "receive", 3, 2, 4)),
    ],
)
def test_recovery_exhausted_positive_counts_unchanged(
    cause: str,
    phase: str,
    attempts: int,
    reconnects: int,
    expected: tuple[str, str, int, int, int],
) -> None:
    exc = TransportRecoveryExhausted(
        cause=cause, phase=phase, request_attempts=attempts, reconnect_attempts=reconnects
    )
    assert (
        exc.cause,
        exc.phase,
        exc.request_attempts,
        exc.retry_count,
        exc.reconnect_attempts,
    ) == expected
    assert str(exc) == (
        f"transport recovery exhausted: cause={expected[0]} phase={expected[1]} "
        f"request_attempts={expected[2]} retry_count={expected[3]} "
        f"reconnect_attempts={expected[4]}"
    )


def test_recovery_exhausted_sanitizes_unknown_cause_and_phase() -> None:
    raw_cause = "connect to 192.0.2.10:9999 refused"
    raw_phase = "dns example.invalid"
    exc = TransportRecoveryExhausted(
        cause=raw_cause, phase=raw_phase, request_attempts=0, reconnect_attempts=1
    )
    assert exc.cause == "transport_error"
    assert exc.phase == "transaction"
    assert raw_cause not in str(exc)
    assert raw_phase not in str(exc)
    assert str(exc) == (
        "transport recovery exhausted: cause=transport_error phase=transaction "
        "request_attempts=0 retry_count=0 reconnect_attempts=1"
    )


def test_recovery_exhausted_zero_attempts_retains_partial_evidence_fields() -> None:
    exc = TransportRecoveryExhausted(
        cause="timeout", phase="transaction", request_attempts=0, reconnect_attempts=0
    )
    assert exc.selector is None
    assert exc.entry is None
    assert exc.system_information == []
    assert exc.system_information_diagnostics == {}
    assert exc.parameter_description is None

    selector = {"opcode": "0x02", "group": "0x03", "instance": "0x01", "register": "0x0010"}
    entry = {"raw_hex": "00aa", "error": None}
    system_information = [(0x01, 1.5, "synthetic")]
    diagnostics: dict[int, dict[str, str | int | None]] = {0x01: {"status": "ok", "count": 1}}
    description = {"name": "synthetic_parameter"}
    exc.selector = selector
    exc.entry = entry
    exc.system_information = system_information
    exc.system_information_diagnostics = diagnostics
    exc.parameter_description = description

    assert exc.selector is selector
    assert exc.entry is entry
    assert exc.system_information is system_information
    assert exc.system_information_diagnostics is diagnostics
    assert exc.parameter_description is description
    assert (exc.request_attempts, exc.retry_count) == (0, 0)
