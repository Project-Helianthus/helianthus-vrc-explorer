from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, cast


class B524Error(Exception):
    """Base class for B524 protocol errors."""


class B524IdParseError(B524Error, ValueError):
    """Raised when parsing an ebusd CSV `b524` id selector fails."""


class B524IdHexError(B524IdParseError):
    """Raised when the id field is not valid hex."""


class B524IdLengthError(B524IdParseError):
    """Raised when the id field has an unexpected byte length for its opcode family."""


class B524UnknownOpcodeError(B524IdParseError):
    """Raised when the selector opcode is not recognized."""


type RegisterOpcode = Literal[0x02, 0x06]
type TimerOpcode = Literal[0x03, 0x04]
type DirectoryOpcode = Literal[0x00]
type ConstraintOpcode = Literal[0x01]


@dataclass(frozen=True, slots=True)
class B524DirectorySelector:
    """B524 directory probe selector (`00 <GG> 00`).

    This opcode family is not expected to appear in ebusd's CSV id column, but the
    parsing logic supports it for completeness.
    """

    opcode: DirectoryOpcode
    group: int


@dataclass(frozen=True, slots=True)
class B524ConstraintSelector:
    """B524 constraint selector (`01 <GG> <RR>`)."""

    opcode: ConstraintOpcode
    group: int
    register: int


@dataclass(frozen=True, slots=True)
class B524RegisterSelector:
    """B524 register selector for local (0x02) or remote (0x06) register spaces.

    Payload structure (`<RR>` is a little-endian u16):

        <opcode> <optype> <GG> <II> <RR_LO> <RR_HI>

    Where:
    - opcode: 0x02 (local) or 0x06 (remote)
    - optype: 0x00 (read) or 0x01 (write)
    - GG: group
    - II: instance
    - RR: register id
    """

    opcode: RegisterOpcode
    optype: Literal[0x00, 0x01]
    group: int
    instance: int
    register: int


@dataclass(frozen=True, slots=True)
class B524TimerSelector:
    """B524 timer selector for read (0x03) or write (0x04) timer schedules.

    Payload structure:

        <opcode> <SEL1> <SEL2> <SEL3> <WEEKDAY>

    Where:
    - opcode: 0x03 (read timer) or 0x04 (write timer)
    - SEL1..SEL3: selector tuple bytes
    - WEEKDAY: 0x00..0x06 (Monday..Sunday)
    """

    opcode: TimerOpcode
    selector: tuple[int, int, int]
    weekday: int


type B524IdSelector = (
    B524DirectorySelector | B524RegisterSelector | B524TimerSelector | B524ConstraintSelector
)

_REGISTER_SELECTOR_LEN: Final[int] = 6
_TIMER_SELECTOR_LEN: Final[int] = 5
_DIRECTORY_SELECTOR_LEN: Final[int] = 3
_CONSTRAINT_SELECTOR_LEN: Final[int] = 3


def parse_b524_id(id_hex: str) -> B524IdSelector:
    """Parse an ebusd CSV `b524` id selector into a structured representation.

    The CSV `id` field encodes the *raw* B524 request payload bytes as hex (no ebus
    framing). The payload is dispatched by opcode family:

    - 0x02 / 0x06: register selectors (6 bytes)
    - 0x03 / 0x04: timer selectors (5 bytes)
    - 0x00: directory probe selector (3 bytes, not expected in CSV)
    - 0x01: constraint selector (3 bytes: opcode, group, register)

    Examples:
    - ``b524,020003001600`` -> opcode=0x02, optype=0x00, group=0x03, instance=0x00, register=0x0016
    - ``b524,060009010700`` -> opcode=0x06, optype=0x00, group=0x09, instance=0x01, register=0x0007
    - ``b524,0300000100``   -> opcode=0x03, selector=(0x00,0x00,0x01), weekday=0x00

    Args:
        id_hex: Hex-encoded payload bytes (e.g. ``"020003001600"``). A leading
            ``b524,`` (as found in ebusd CSV exports) and/or ``0x`` prefix is accepted.

    Returns:
        A typed selector dataclass corresponding to the opcode family.

    Raises:
        B524IdHexError: If ``id_hex`` is not valid hex.
        B524IdLengthError: If payload length doesn't match the opcode family.
        B524UnknownOpcodeError: If the selector opcode is not recognized.
    """

    normalized = id_hex.strip()
    if normalized.lower().startswith("b524,"):
        normalized = normalized[5:].strip()
    if normalized.startswith(("0x", "0X")):
        normalized = normalized[2:]

    try:
        payload = bytes.fromhex(normalized)
    except ValueError as exc:
        raise B524IdHexError(f"Invalid B524 id hex: {id_hex!r}") from exc

    if not payload:
        raise B524IdLengthError("B524 id payload is empty")

    opcode = payload[0]

    match opcode:
        case 0x00:
            if len(payload) != _DIRECTORY_SELECTOR_LEN:
                raise B524IdLengthError(
                    f"Opcode 0x00 expects {_DIRECTORY_SELECTOR_LEN} bytes, got {len(payload)}"
                )
            if payload[2] != 0x00:
                raise B524IdParseError(
                    f"Opcode 0x00 expects final byte 0x00, got 0x{payload[2]:02X}"
                )
            return B524DirectorySelector(opcode=0x00, group=payload[1])

        case 0x02 | 0x06:
            if len(payload) != _REGISTER_SELECTOR_LEN:
                raise B524IdLengthError(
                    f"Opcode 0x{opcode:02X} expects {_REGISTER_SELECTOR_LEN} bytes, "
                    f"got {len(payload)}"
                )
            optype = payload[1]
            if optype not in {0x00, 0x01}:
                raise B524IdParseError(
                    f"Opcode 0x{opcode:02X} expects optype 0x00 (read) or 0x01 (write), "
                    f"got 0x{optype:02X}"
                )
            optype_lit = cast(Literal[0x00, 0x01], optype)
            register = int.from_bytes(payload[4:6], byteorder="little", signed=False)
            return B524RegisterSelector(
                opcode=opcode,
                optype=optype_lit,
                group=payload[2],
                instance=payload[3],
                register=register,
            )

        case 0x03 | 0x04:
            if len(payload) != _TIMER_SELECTOR_LEN:
                raise B524IdLengthError(
                    f"Opcode 0x{opcode:02X} expects {_TIMER_SELECTOR_LEN} bytes, got {len(payload)}"
                )
            weekday = payload[4]
            if weekday > 0x06:
                raise B524IdParseError(
                    f"Timer selector weekday must be 0x00..0x06, got 0x{weekday:02X}"
                )
            return B524TimerSelector(
                opcode=opcode,
                selector=(payload[1], payload[2], payload[3]),
                weekday=weekday,
            )

        case 0x01:
            if len(payload) != _CONSTRAINT_SELECTOR_LEN:
                raise B524IdLengthError(
                    f"Opcode 0x{opcode:02X} expects {_CONSTRAINT_SELECTOR_LEN} bytes, "
                    f"got {len(payload)}"
                )
            return B524ConstraintSelector(
                opcode=0x01,
                group=payload[1],
                register=payload[2],
            )

        case _:
            raise B524UnknownOpcodeError(f"Unknown B524 opcode: 0x{opcode:02X}")


def _validate_u8(field_name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}")
    if not (0x00 <= value <= 0xFF):
        raise ValueError(f"{field_name} must be in range 0..255, got {value}")


def _validate_u16(field_name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}")
    if not (0x0000 <= value <= 0xFFFF):
        raise ValueError(f"{field_name} must be in range 0..65535, got {value}")


def build_directory_probe_payload(group: int) -> bytes:
    """Build a raw B524 directory probe payload.

    Payload structure:

        <opcode> <GG> 0x00

    Where:
    - opcode: 0x00
    - GG: group
    """

    _validate_u8("group", group)
    return bytes((0x00, group, 0x00))


def build_constraint_probe_payload(group: int, register: int) -> bytes:
    """Build a raw B524 constraint dictionary probe payload.

    Payload structure:

        <opcode> <GG> <RR>

    Where:
    - opcode: 0x01
    - GG: group
    - RR: register id (u8)
    """

    _validate_u8("group", group)
    _validate_u8("register", register)
    return bytes((0x01, group, register))


def build_register_read_payload(
    opcode: RegisterOpcode, group: int, instance: int, register: int
) -> bytes:
    """Build a raw B524 register read payload.

    Payload structure (`<RR>` is a little-endian u16):

        <opcode> <optype> <GG> <II> <RR_LO> <RR_HI>

    Where:
    - opcode: 0x02 (local) or 0x06 (remote)
    - optype: 0x00 (read)
    - GG: group
    - II: instance
    - RR: register id
    """

    if opcode not in (0x02, 0x06):
        raise ValueError(f"opcode must be 0x02 or 0x06, got 0x{opcode:02X}")

    _validate_u8("group", group)
    _validate_u8("instance", instance)
    _validate_u16("register", register)

    return bytes((opcode, 0x00, group, instance)) + register.to_bytes(
        2, byteorder="little", signed=False
    )
