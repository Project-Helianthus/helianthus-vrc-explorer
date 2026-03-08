import pytest

from helianthus_vrc_explorer.protocol.parser import (
    ValueEncodeError,
    encode_typed_value,
    parse_typed_value,
)


def test_encode_uin_roundtrips() -> None:
    data = encode_typed_value("UIN", 0x1234)
    assert data.hex() == "3412"
    assert parse_typed_value("UIN", data) == 0x1234


def test_encode_uch_roundtrips() -> None:
    data = encode_typed_value("UCH", 0x7F)
    assert data.hex() == "7f"
    assert parse_typed_value("UCH", data) == 0x7F


def test_encode_bool_roundtrips() -> None:
    assert encode_typed_value("BOOL", True).hex() == "01"
    assert encode_typed_value("BOOL", False).hex() == "00"
    assert parse_typed_value("BOOL", encode_typed_value("BOOL", True)) is True
    assert parse_typed_value("BOOL", encode_typed_value("BOOL", False)) is False


def test_encode_exp_roundtrips() -> None:
    data = encode_typed_value("EXP", 1.0)
    assert parse_typed_value("EXP", data) == 1.0


def test_encode_str_roundtrips() -> None:
    data = encode_typed_value("STR:*", "Etaj")
    assert data.endswith(b"\x00")
    assert parse_typed_value("STR:*", data) == "Etaj"


def test_encode_hda3_roundtrips() -> None:
    data = encode_typed_value("HDA:3", "2026-02-06")
    assert parse_typed_value("HDA:3", data) == "2026-02-06"


def test_encode_hti_roundtrips() -> None:
    data = encode_typed_value("HTI", "23:59:58")
    assert parse_typed_value("HTI", data) == "23:59:58"


def test_encode_fw_roundtrips() -> None:
    data = encode_typed_value("FW", "08.05.00")
    assert data.hex() == "080500"
    assert parse_typed_value("FW", data) == "08.05.00"


@pytest.mark.parametrize("value", ["8.05.00", "08.5.00", "08.05", "08.05.000", "ab.05.00"])
def test_encode_fw_rejects_non_canonical_strings(value: str) -> None:
    with pytest.raises(ValueEncodeError, match=r"FW expects MM\.mm\.pp"):
        encode_typed_value("FW", value)


def test_encode_hex_enforces_length() -> None:
    assert encode_typed_value("HEX:2", "0x3412").hex() == "3412"
    with pytest.raises(ValueEncodeError):
        encode_typed_value("HEX:2", "0x00")


def test_encode_unknown_type_raises() -> None:
    with pytest.raises(ValueEncodeError, match=r"Unknown type spec"):
        encode_typed_value("NOPE", 1)
