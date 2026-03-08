import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    build_constraint_probe_payload,
    build_directory_probe_payload,
    build_register_read_payload,
)


@pytest.mark.parametrize(
    ("group", "expected_hex"),
    [
        (0x03, "000300"),
        (0x0A, "000a00"),
    ],
)
def test_build_directory_probe_payload(group: int, expected_hex: str) -> None:
    assert build_directory_probe_payload(group) == bytes.fromhex(expected_hex)


@pytest.mark.parametrize(
    ("opcode", "group", "instance", "register", "expected_hex"),
    [
        (0x02, 0x03, 0x00, 0x0016, "020003001600"),
        (0x02, 0x02, 0x00, 0x000F, "020002000f00"),
        (0x02, 0x08, 0x00, 0x0004, "020008000400"),
        (0x06, 0x08, 0x01, 0x0004, "060008010400"),
        (0x06, 0x09, 0x01, 0x0007, "060009010700"),
        (0x06, 0x0A, 0x01, 0x000F, "06000a010f00"),
    ],
)
def test_build_register_read_payload_known_selectors(
    opcode: int,
    group: int,
    instance: int,
    register: int,
    expected_hex: str,
) -> None:
    assert build_register_read_payload(opcode, group, instance, register) == bytes.fromhex(
        expected_hex
    )


@pytest.mark.parametrize("group", [-1, 256])
def test_build_directory_probe_payload_range_validation(group: int) -> None:
    with pytest.raises(ValueError, match=r"group must be in range 0\.\.255"):
        build_directory_probe_payload(group)


@pytest.mark.parametrize(
    ("group", "register", "expected_hex"),
    [
        (0x00, 0x00, "010000"),
        (0x0A, 0x01, "010a01"),
    ],
)
def test_build_constraint_probe_payload(
    group: int,
    register: int,
    expected_hex: str,
) -> None:
    assert build_constraint_probe_payload(group, register) == bytes.fromhex(expected_hex)


@pytest.mark.parametrize(
    ("group", "instance", "register"),
    [
        (-1, 0, 0),
        (0, -1, 0),
        (0, 0, -1),
        (256, 0, 0),
        (0, 256, 0),
        (0, 0, 65536),
    ],
)
def test_build_register_read_payload_range_validation(
    group: int, instance: int, register: int
) -> None:
    with pytest.raises(ValueError):
        build_register_read_payload(0x02, group, instance, register)


def test_build_register_read_payload_opcode_validation() -> None:
    with pytest.raises(ValueError, match=r"opcode must be 0x02 or 0x06"):
        build_register_read_payload(0x03, 0x01, 0x00, 0x0000)
