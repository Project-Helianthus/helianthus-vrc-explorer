import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    B524ConstraintSelector,
    B524IdHexError,
    B524IdLengthError,
    B524RegisterSelector,
    B524TimerSelector,
    B524UnknownOpcodeError,
    parse_b524_id,
)


def test_parse_b524_id_local_register_examples() -> None:
    assert parse_b524_id("020003001600") == B524RegisterSelector(
        opcode=0x02,
        optype=0x00,
        group=0x03,
        instance=0x00,
        register=0x0016,
    )
    assert parse_b524_id("b524,020003001600") == B524RegisterSelector(
        opcode=0x02,
        optype=0x00,
        group=0x03,
        instance=0x00,
        register=0x0016,
    )

    assert parse_b524_id("020002000f00") == B524RegisterSelector(
        opcode=0x02,
        optype=0x00,
        group=0x02,
        instance=0x00,
        register=0x000F,
    )
    assert parse_b524_id("B524,020002000f00") == B524RegisterSelector(
        opcode=0x02,
        optype=0x00,
        group=0x02,
        instance=0x00,
        register=0x000F,
    )


def test_parse_b524_id_remote_register_examples() -> None:
    assert parse_b524_id("060009010700") == B524RegisterSelector(
        opcode=0x06,
        optype=0x00,
        group=0x09,
        instance=0x01,
        register=0x0007,
    )
    assert parse_b524_id("b524,060009010700") == B524RegisterSelector(
        opcode=0x06,
        optype=0x00,
        group=0x09,
        instance=0x01,
        register=0x0007,
    )

    assert parse_b524_id("06000a010f00") == B524RegisterSelector(
        opcode=0x06,
        optype=0x00,
        group=0x0A,
        instance=0x01,
        register=0x000F,
    )
    assert parse_b524_id("  b524,06000a010f00  ") == B524RegisterSelector(
        opcode=0x06,
        optype=0x00,
        group=0x0A,
        instance=0x01,
        register=0x000F,
    )


def test_parse_b524_id_timer_examples() -> None:
    assert parse_b524_id("0300000100") == B524TimerSelector(
        opcode=0x03,
        selector=(0x00, 0x00, 0x01),
        weekday=0x00,
    )
    assert parse_b524_id("b524,0300000100") == B524TimerSelector(
        opcode=0x03,
        selector=(0x00, 0x00, 0x01),
        weekday=0x00,
    )

    assert parse_b524_id("0400000106") == B524TimerSelector(
        opcode=0x04,
        selector=(0x00, 0x00, 0x01),
        weekday=0x06,
    )
    assert parse_b524_id("B524,0x0400000106") == B524TimerSelector(
        opcode=0x04,
        selector=(0x00, 0x00, 0x01),
        weekday=0x06,
    )


def test_parse_b524_id_constraint_example() -> None:
    assert parse_b524_id("010000") == B524ConstraintSelector(
        opcode=0x01,
        legacy_incomplete=True,
        group=0x00,
        register=0x00,
    )
    assert parse_b524_id("b524,010a01") == B524ConstraintSelector(
        opcode=0x01,
        legacy_incomplete=True,
        group=0x0A,
        register=0x01,
    )


@pytest.mark.parametrize(
    ("id_hex", "exc_type"),
    [
        ("", B524IdLengthError),
        ("0200030016", B524IdLengthError),  # opcode 0x02 expects 6 bytes
        ("03000001", B524IdLengthError),  # opcode 0x03 expects 5 bytes
        ("ff0000", B524UnknownOpcodeError),
        ("zz", B524IdHexError),
    ],
)
def test_parse_b524_id_errors(id_hex: str, exc_type: type[Exception]) -> None:
    with pytest.raises(exc_type):
        parse_b524_id(id_hex)
