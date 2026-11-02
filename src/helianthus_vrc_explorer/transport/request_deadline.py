"""Nonrenewable elapsed deadline shared by one logical transport operation.

A ``RequestDeadline`` captures one absolute deadline from an injected monotonic
clock.  Attempts, reconnects, backoff, framing and response phases of the same
operation share it; nothing here renews or resets it.  A new independent
operation constructs a new instance.

This is a software budget for transport-controlled waits.  It cannot interrupt
DNS resolution, caller hooks, file I/O, OS scheduling or libraries that ignore
timeouts; callers check expiry before and after such work instead.

The module deliberately has no default clock or sleeper: consuming transports
pass their own module-level references so virtual-clock tests stay isolated.
``RequestDeadlineExpired`` is internal and is not a ``TransportError``; the
consuming transport translates it into its terminal diagnostic before any
generic retry handling.
"""

from __future__ import annotations

import math
from collections.abc import Callable

MonotonicClock = Callable[[], float]
Sleeper = Callable[[float], object]


class RequestDeadlineExpired(Exception):
    """Internal: the operation's elapsed budget is exhausted (``now >= deadline``)."""

    def __init__(self, budget_s: float) -> None:
        self.budget_s = budget_s
        super().__init__(f"request deadline expired: budget_s={budget_s}")


def _finite_number(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{name} must be a real number of seconds")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    return number


def validate_budget_seconds(value: object) -> float:
    """Return ``value`` as a finite positive duration in seconds.

    ``bool`` and non-numeric values raise ``TypeError``; zero, negative, NaN and
    either infinity raise ``ValueError``.  There is no unlimited sentinel.
    """

    seconds = _finite_number(value, "budget")
    if seconds <= 0.0:
        raise ValueError("budget must be positive")
    return seconds


class RequestDeadline:
    """One absolute deadline per logical operation; never renewed."""

    __slots__ = ("_budget_s", "_clock", "_deadline", "_latest")

    def __init__(self, max_command_s: object, *, clock: MonotonicClock) -> None:
        budget_s = validate_budget_seconds(max_command_s)
        start = clock()
        if not math.isfinite(start):
            raise ValueError("clock reading must be finite")
        deadline = start + budget_s
        if not math.isfinite(deadline):
            raise ValueError("deadline must be finite")
        self._budget_s = budget_s
        self._clock = clock
        self._deadline = deadline
        self._latest = start

    @property
    def budget_s(self) -> float:
        return self._budget_s

    def _expired(self) -> RequestDeadlineExpired:
        return RequestDeadlineExpired(self._budget_s)

    def remaining_s(self) -> float:
        """Return the positive time left, or raise ``RequestDeadlineExpired``.

        The budget is exhausted at equality.  The latest clock reading is kept
        so a clock that steps backwards cannot extend the deadline, and a
        non-finite reading fails closed as expired.
        """

        now = self._clock()
        if not math.isfinite(now):
            raise self._expired()
        if now > self._latest:
            self._latest = now
        remaining = self._deadline - self._latest
        if remaining <= 0.0:
            raise self._expired()
        return remaining

    def io_timeout_s(self, local_limit_s: object) -> float:
        """Return the smaller of the remaining budget and a positive local limit."""

        local_s = validate_budget_seconds(local_limit_s)
        return min(self.remaining_s(), local_s)

    def sleep(self, delay_s: object, *, sleep: Sleeper) -> None:
        """Wait at most the remaining budget, then check expiry again.

        A zero delay is allowed but still raises when the budget is exhausted.
        """

        delay = _finite_number(delay_s, "delay")
        if delay < 0.0:
            raise ValueError("delay must not be negative")
        remaining = self.remaining_s()
        if delay > 0.0:
            sleep(min(delay, remaining))
        self.remaining_s()
