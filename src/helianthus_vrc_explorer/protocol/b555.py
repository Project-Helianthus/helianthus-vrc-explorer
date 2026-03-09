from __future__ import annotations

from dataclasses import dataclass

_DAY_NAMES: tuple[str, ...] = (
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
)


def _validate_u8(name: str, value: int) -> int:
    if not (0x00 <= value <= 0xFF):
        raise ValueError(f"{name} out of range 0x00..0xFF: 0x{value:02X}")
    return value


def build_b555_slots_read_payload(zone: int, hc: int) -> bytes:
    return bytes((0xA4, _validate_u8("zone", zone), _validate_u8("hc", hc)))


def build_b555_config_read_payload(zone: int, hc: int) -> bytes:
    return bytes((0xA3, _validate_u8("zone", zone), _validate_u8("hc", hc)))


def build_b555_timer_read_payload(zone: int, hc: int, day: int, slot: int) -> bytes:
    if not (0x00 <= day <= 0x06):
        raise ValueError(f"day out of range 0x00..0x06: 0x{day:02X}")
    return bytes(
        (
            0xA5,
            _validate_u8("zone", zone),
            _validate_u8("hc", hc),
            day,
            _validate_u8("slot", slot),
        )
    )


@dataclass(frozen=True, slots=True)
class B555ConfigRead:
    status: int
    max_slots: int
    time_resolution_min: int
    min_duration_min: int
    has_temperature: bool
    temp_slots: int
    min_temp_c: int | None
    max_temp_c: int | None
    padding: int

    @property
    def available(self) -> bool:
        return self.status == 0x00


@dataclass(frozen=True, slots=True)
class B555SlotsRead:
    status: int
    slot_counts: tuple[int, int, int, int, int, int, int]
    padding: int

    @property
    def available(self) -> bool:
        return self.status == 0x00

    def as_day_map(self) -> dict[str, int]:
        return dict(zip(_DAY_NAMES, self.slot_counts, strict=True))


@dataclass(frozen=True, slots=True)
class B555TimerRead:
    status: int
    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int
    temperature_raw_u16: int

    @property
    def temperature_c(self) -> float | None:
        if self.temperature_raw_u16 == 0xFFFF:
            return None
        return self.temperature_raw_u16 / 10.0


def parse_b555_config_read_response(payload: bytes) -> B555ConfigRead:
    blob = bytes(payload)
    if len(blob) != 9:
        raise ValueError(f"B555 A3 response must be 9 bytes, got {len(blob)}")
    min_temp = None if blob[6] == 0xFF else blob[6]
    max_temp = None if blob[7] == 0xFF else blob[7]
    return B555ConfigRead(
        status=blob[0],
        max_slots=blob[1],
        time_resolution_min=blob[2],
        min_duration_min=blob[3],
        has_temperature=blob[4] != 0x00,
        temp_slots=blob[5],
        min_temp_c=min_temp,
        max_temp_c=max_temp,
        padding=blob[8],
    )


def parse_b555_slots_read_response(payload: bytes) -> B555SlotsRead:
    blob = bytes(payload)
    if len(blob) != 9:
        raise ValueError(f"B555 A4 response must be 9 bytes, got {len(blob)}")
    return B555SlotsRead(
        status=blob[0],
        slot_counts=(
            blob[1],
            blob[2],
            blob[3],
            blob[4],
            blob[5],
            blob[6],
            blob[7],
        ),
        padding=blob[8],
    )


def parse_b555_timer_read_response(payload: bytes) -> B555TimerRead:
    blob = bytes(payload)
    if len(blob) != 7:
        raise ValueError(f"B555 A5 response must be 7 bytes, got {len(blob)}")
    return B555TimerRead(
        status=blob[0],
        start_hour=blob[1],
        start_minute=blob[2],
        end_hour=blob[3],
        end_minute=blob[4],
        temperature_raw_u16=int.from_bytes(blob[5:7], byteorder="little", signed=False),
    )


def b555_status_label(status: int) -> str:
    if status == 0x00:
        return "available"
    if status == 0x03:
        return "unavailable"
    return f"0x{status:02x}"


def format_b555_time(hour: int, minute: int) -> str:
    return f"{hour:02d}:{minute:02d}"
