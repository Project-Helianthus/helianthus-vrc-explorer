"""Bounded automatic B524 Event candidates derived from scalar topology."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..protocol.b524_schedules import (
    EVENT_PROFILES,
    EventProfileName,
    build_event_read_payload,
    build_event_setpoint_read_payload,
)
from .b524_operation_reads import B524OperationReadRequest

DEFAULT_EVENT_WEEKDAY_CODES = tuple(range(8))
_PROFILE_ORDER: tuple[EventProfileName, ...] = ("system", "dhw", "zone")


def _unique_u8(values: Sequence[int], *, name: str) -> tuple[int, ...]:
    result: list[int] = []
    seen: set[int] = set()
    for value in values:
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(f"{name} must contain only integers")
        if not 0 <= value <= 0xFF:
            raise ValueError(f"{name} value out of range: {value} (allowed 0-255)")
        if value not in seen:
            seen.add(value)
            result.append(value)
    return tuple(result)


def event_program_requests(
    profile: EventProfileName,
    *,
    instance: int,
    address: int,
    weekday_codes: Sequence[int],
) -> tuple[B524OperationReadRequest, ...]:
    """Build alternating automatic OP09/OP0B candidates for one raw program selector."""

    if profile not in EVENT_PROFILES:
        raise ValueError(f"unknown Event profile: {profile!r}")
    codes = _unique_u8(weekday_codes, name="weekday_codes")
    requests: list[B524OperationReadRequest] = []
    selector_prefix: dict[str, str | int] = {
        "profile": profile,
        "instance": instance,
        "address": address,
    }
    for weekday_code in codes:
        selector = {**selector_prefix, "weekday_code": weekday_code}
        requests.extend(
            (
                B524OperationReadRequest(
                    operation="GetEvent",
                    opcode=0x09,
                    selector=dict(selector),
                    payload=build_event_read_payload(
                        profile,
                        instance=instance,
                        address=address,
                        weekday_code=weekday_code,
                    ),
                    requires_vrc700=False,
                    automatic_event=True,
                ),
                B524OperationReadRequest(
                    operation="GetEventSetPoint",
                    opcode=0x0B,
                    selector=dict(selector),
                    payload=build_event_setpoint_read_payload(
                        profile,
                        instance=instance,
                        address=address,
                        weekday_code=weekday_code,
                    ),
                    requires_vrc700=False,
                    automatic_event=True,
                ),
            )
        )
    return tuple(requests)


def build_default_event_requests(
    *,
    instances: Mapping[EventProfileName, tuple[int, ...]],
    weekday_codes: Sequence[int] = DEFAULT_EVENT_WEEKDAY_CODES,
) -> tuple[B524OperationReadRequest, ...]:
    """Build the bounded raw candidate window for admitted scalar instances only."""

    codes = _unique_u8(weekday_codes, name="weekday_codes")
    requests: list[B524OperationReadRequest] = []
    for profile in _PROFILE_ORDER:
        profile_instances = _unique_u8(instances.get(profile, ()), name=f"instances[{profile}]")
        for instance in profile_instances:
            for address in EVENT_PROFILES[profile].addresses:
                requests.extend(
                    event_program_requests(
                        profile,
                        instance=instance,
                        address=address,
                        weekday_codes=codes,
                    )
                )
    return tuple(requests)
