from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

type EventProfileName = Literal["system", "dhw", "zone"]
type TimerChannelName = Literal[
    "ventilation",
    "noise-reduction",
    "tariff",
    "dhw",
    "circulation",
    "zone-cooling",
    "zone-heating",
]


@dataclass(frozen=True, slots=True)
class EventProfile:
    system_type: int
    addresses: tuple[int, ...]
    setpoint_kind: Literal["temperature", "dhw-state"]


EVENT_PROFILES: Final[dict[str, EventProfile]] = {
    "system": EventProfile(
        system_type=0x00,
        addresses=(0x01, 0x02, 0x03),
        setpoint_kind="temperature",
    ),
    "dhw": EventProfile(system_type=0x01, addresses=(0x01, 0x02), setpoint_kind="dhw-state"),
    "zone": EventProfile(system_type=0x03, addresses=(0x01, 0x02), setpoint_kind="temperature"),
}

TIMER_CHANNELS: Final[dict[str, tuple[int, int]]] = {
    "ventilation": (0x00, 0x01),
    "noise-reduction": (0x00, 0x02),
    "tariff": (0x00, 0x03),
    "dhw": (0x01, 0x01),
    "circulation": (0x01, 0x02),
    "zone-cooling": (0x03, 0x01),
    "zone-heating": (0x03, 0x02),
}

_DHW_SETPOINT_STATES: Final[dict[int, str]] = {
    253: "enable",
    254: "disable",
    255: "replacement",
}


@dataclass(frozen=True, slots=True)
class B524TimerSlot:
    start_raw: int
    stop_raw: int
    start_minutes: int | None
    stop_minutes: int | None
    unused: bool


@dataclass(frozen=True, slots=True)
class B524TimerResponse:
    parameter_config: int
    slots: tuple[B524TimerSlot, B524TimerSlot, B524TimerSlot]
    raw_hex: str


@dataclass(frozen=True, slots=True)
class B524EventTime:
    raw: int
    minutes: int | None


@dataclass(frozen=True, slots=True)
class B524EventResponse:
    parameter_config: int
    start1_raw: int
    starts: tuple[
        B524EventTime,
        B524EventTime,
        B524EventTime,
        B524EventTime,
        B524EventTime,
        B524EventTime,
    ]
    raw_hex: str


@dataclass(frozen=True, slots=True)
class B524EventSetPointValue:
    raw: int
    temperature_c: float | None
    state: str | None


@dataclass(frozen=True, slots=True)
class B524EventSetPointResponse:
    parameter_config: int
    values: tuple[
        B524EventSetPointValue,
        B524EventSetPointValue,
        B524EventSetPointValue,
        B524EventSetPointValue,
        B524EventSetPointValue,
        B524EventSetPointValue,
        B524EventSetPointValue,
    ]
    raw_hex: str


@dataclass(frozen=True, slots=True)
class B524VR91Response:
    binding_zone: int
    special_function_status: int
    heating_operating_mode: int
    cooling_operating_mode: int
    status_info: int
    frost_protection: int
    heating_temperature_raw: int
    cooling_temperature_raw: int
    raw_hex: str


def _validate_u8(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be in range 0..255, got {value}")
    return value


def _event_profile(profile: str) -> EventProfile:
    try:
        return EVENT_PROFILES[profile]
    except KeyError as exc:
        choices = ", ".join(EVENT_PROFILES)
        raise ValueError(f"event profile must be one of {choices}, got {profile!r}") from exc


def _event_selector(
    opcode: int,
    profile: str,
    *,
    instance: int,
    address: int,
    weekday_code: int,
) -> bytes:
    selected = _event_profile(profile)
    _validate_u8("instance", instance)
    _validate_u8("address", address)
    _validate_u8("weekday_code", weekday_code)
    if address not in selected.addresses:
        choices = ", ".join(f"0x{item:02X}" for item in selected.addresses)
        raise ValueError(
            f"address 0x{address:02X} is not documented for {profile}; choose {choices}"
        )
    return bytes((opcode, selected.system_type, instance, address, weekday_code))


def build_event_read_payload(
    profile: EventProfileName,
    *,
    instance: int,
    address: int,
    weekday_code: int,
) -> bytes:
    return _event_selector(
        0x09,
        profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
    )


def build_event_write_payload(
    profile: EventProfileName,
    *,
    instance: int,
    address: int,
    weekday_code: int,
    values: tuple[int, int, int, int, int, int, int],
) -> bytes:
    selector = _event_selector(
        0x0A,
        profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
    )
    return selector + _seven_values(values)


def build_event_setpoint_read_payload(
    profile: EventProfileName,
    *,
    instance: int,
    address: int,
    weekday_code: int,
) -> bytes:
    return _event_selector(
        0x0B,
        profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
    )


def build_event_setpoint_write_payload(
    profile: EventProfileName,
    *,
    instance: int,
    address: int,
    weekday_code: int,
    values: tuple[int, int, int, int, int, int, int],
) -> bytes:
    selector = _event_selector(
        0x0C,
        profile,
        instance=instance,
        address=address,
        weekday_code=weekday_code,
    )
    return selector + _seven_values(values)


def _seven_values(values: tuple[int, int, int, int, int, int, int]) -> bytes:
    if len(values) != 7:
        raise ValueError(f"exactly 7 values are required, got {len(values)}")
    return bytes(_validate_u8(f"value{index}", value) for index, value in enumerate(values, 1))


def _timer_selector(channel: str, *, instance: int, weekday: int) -> bytes:
    try:
        system_type, address = TIMER_CHANNELS[channel]
    except KeyError as exc:
        choices = ", ".join(TIMER_CHANNELS)
        raise ValueError(f"timer channel must be one of {choices}, got {channel!r}") from exc
    _validate_u8("instance", instance)
    if not 0 <= weekday <= 6:
        raise ValueError(f"weekday must be in range 0..6, got {weekday}")
    if not channel.startswith("zone-") and instance != 0:
        raise ValueError(f"timer channel {channel} requires instance 0")
    return bytes((system_type, instance, address, weekday))


def build_timer_read_payload(channel: TimerChannelName, *, instance: int, weekday: int) -> bytes:
    return b"\x03" + _timer_selector(channel, instance=instance, weekday=weekday)


def build_timer_write_payload(
    channel: TimerChannelName,
    *,
    instance: int,
    weekday: int,
    slots: tuple[
        tuple[int, int] | None,
        tuple[int, int] | None,
        tuple[int, int] | None,
    ],
) -> bytes:
    if len(slots) != 3:
        raise ValueError(f"exactly 3 timer slots are required, got {len(slots)}")
    payload = bytearray(b"\x04" + _timer_selector(channel, instance=instance, weekday=weekday))
    for index, slot in enumerate(slots, 1):
        if slot is None:
            payload.extend((0x90, 0x90))
            continue
        if len(slot) != 2:
            raise ValueError(f"slot {index} must contain start and stop codes")
        start, stop = slot
        _validate_timer_pair(start, stop, label=f"slot {index}")
        payload.extend((start, stop))
    return bytes(payload)


def _validate_timer_pair(start: int, stop: int, *, label: str) -> None:
    _validate_u8(f"{label} start", start)
    _validate_u8(f"{label} stop", stop)
    if start >= 0x90:
        raise ValueError(f"{label} start code must be 0x00..0x8F")
    if stop > 0x90:
        raise ValueError(f"{label} stop code must be 0x00..0x90")
    if start >= stop:
        raise ValueError(f"{label} start code must be less than stop code")


def parse_timer_response(payload: bytes) -> B524TimerResponse:
    blob = bytes(payload)
    if len(blob) != 7:
        raise ValueError(f"ReadTimer response must be 7 bytes, got {len(blob)}")
    slots: list[B524TimerSlot] = []
    for offset in (1, 3, 5):
        start, stop = blob[offset], blob[offset + 1]
        if start == stop == 0x90:
            slots.append(
                B524TimerSlot(
                    start_raw=start,
                    stop_raw=stop,
                    start_minutes=None,
                    stop_minutes=None,
                    unused=True,
                )
            )
            continue
        _validate_timer_pair(start, stop, label=f"slot {(offset + 1) // 2}")
        slots.append(
            B524TimerSlot(
                start_raw=start,
                stop_raw=stop,
                start_minutes=start * 10,
                stop_minutes=stop * 10,
                unused=False,
            )
        )
    return B524TimerResponse(
        parameter_config=blob[0],
        slots=(slots[0], slots[1], slots[2]),
        raw_hex=blob.hex(),
    )


def parse_event_response(payload: bytes) -> B524EventResponse:
    blob = bytes(payload)
    if len(blob) != 8:
        raise ValueError(f"GetEvent response must be 8 bytes, got {len(blob)}")
    starts = tuple(
        B524EventTime(raw=value, minutes=value * 10 if value <= 0x90 else None)
        for value in blob[2:]
    )
    return B524EventResponse(
        parameter_config=blob[0],
        start1_raw=blob[1],
        starts=(starts[0], starts[1], starts[2], starts[3], starts[4], starts[5]),
        raw_hex=blob.hex(),
    )


def parse_event_setpoint_response(
    payload: bytes, profile: EventProfileName
) -> B524EventSetPointResponse:
    blob = bytes(payload)
    if len(blob) != 8:
        raise ValueError(f"GetEventSetPoint response must be 8 bytes, got {len(blob)}")
    selected = _event_profile(profile)
    if selected.setpoint_kind == "temperature":
        values = tuple(
            B524EventSetPointValue(raw=value, temperature_c=value / 2.0, state=None)
            for value in blob[1:]
        )
    else:
        values = tuple(
            B524EventSetPointValue(
                raw=value,
                temperature_c=None,
                state=_DHW_SETPOINT_STATES.get(value),
            )
            for value in blob[1:]
        )
    return B524EventSetPointResponse(
        parameter_config=blob[0],
        values=(values[0], values[1], values[2], values[3], values[4], values[5], values[6]),
        raw_hex=blob.hex(),
    )


def build_vr91_read_payload() -> bytes:
    return b"\x08"


def parse_vr91_response(payload: bytes) -> B524VR91Response:
    blob = bytes(payload)
    if len(blob) != 8:
        raise ValueError(f"ReadVR91 response must be 8 bytes, got {len(blob)}")
    return B524VR91Response(
        binding_zone=blob[0],
        special_function_status=blob[1],
        heating_operating_mode=blob[2],
        cooling_operating_mode=blob[3],
        status_info=blob[4],
        frost_protection=blob[5],
        heating_temperature_raw=blob[6],
        cooling_temperature_raw=blob[7],
        raw_hex=blob.hex(),
    )
