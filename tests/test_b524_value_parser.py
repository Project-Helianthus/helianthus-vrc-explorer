import pytest

from helianthus_vrc_explorer.protocol.parser import ValueParseError, parse_typed_value


def test_parse_exp_float32le() -> None:
    assert parse_typed_value("EXP", bytes.fromhex("0000803f")) == 1.0


def test_parse_exp_nan_is_none() -> None:
    # Quiet NaN (0x7FC00000) encoded as float32 little-endian.
    assert parse_typed_value("EXP", bytes.fromhex("0000c07f")) is None


def test_parse_uin_u16le() -> None:
    assert parse_typed_value("UIN", bytes.fromhex("3412")) == 0x1234


def test_parse_uch_u8() -> None:
    assert parse_typed_value("UCH", bytes.fromhex("7f")) == 0x7F


def test_parse_i8_i16_i32_and_u32() -> None:
    assert parse_typed_value("I8", bytes.fromhex("ff")) == -1
    assert parse_typed_value("I16", bytes.fromhex("ffff")) == -1
    assert parse_typed_value("U32", bytes.fromhex("01000000")) == 1
    assert parse_typed_value("I32", bytes.fromhex("ffffffff")) == -1


def test_parse_bool_u8_to_bool() -> None:
    assert parse_typed_value("BOOL", bytes.fromhex("00")) is False
    assert parse_typed_value("BOOL", bytes.fromhex("01")) is True
    assert parse_typed_value("BOOL", bytes.fromhex("02")) is True


def test_parse_hex_n_preserves_byte_order() -> None:
    assert parse_typed_value("HEX:2", bytes.fromhex("3412")) == "0x3412"
    assert parse_typed_value("hex:4", bytes.fromhex("01020304")) == "0x01020304"


def test_parse_str_cstring_strips_trailing_nuls_and_decodes_latin1() -> None:
    assert parse_typed_value(" str:* ", b"hello\x00\x00") == "hello"


def test_parse_str_cstring_empty_string() -> None:
    assert parse_typed_value("STR:*", b"\x00\x00") == ""


def test_parse_str_cstring_stops_at_first_nul() -> None:
    assert parse_typed_value("STR:*", b"zone\x00junk\x00") == "zone"


def test_parse_hda3_date_u24le_ddmmyy() -> None:
    assert parse_typed_value("HDA:3", bytes.fromhex("060226")) == "2026-02-06"


def test_parse_hti_time_u24le_hhmmss() -> None:
    assert parse_typed_value("HTI", bytes.fromhex("235958")) == "23:59:58"


def test_parse_fw_valid() -> None:
    assert parse_typed_value("FW", bytes.fromhex("080500")) == "08.05.00"
    assert parse_typed_value("FW", bytes.fromhex("021703")) == "02.17.03"


@pytest.mark.parametrize(
    ("type_spec", "data_hex"),
    [
        ("EXP", ""),
        ("EXP", "000080"),
        ("UIN", ""),
        ("UIN", "00"),
        ("UIN", "000000"),
        ("UCH", ""),
        ("UCH", "0000"),
        ("HDA:3", ""),
        ("HDA:3", "01020304"),
        ("HTI", ""),
        ("HTI", "0102"),
        ("HTI", "01020304"),
        ("FW", "0805"),
        ("FW", "08050000"),
        ("HEX:2", "00"),
        ("HEX:4", "00"),
        ("I16", "00"),
        ("I32", "0000"),
    ],
)
def test_parse_wrong_lengths_raise(type_spec: str, data_hex: str) -> None:
    with pytest.raises(ValueParseError):
        parse_typed_value(type_spec, bytes.fromhex(data_hex))


@pytest.mark.parametrize(
    ("type_spec", "data_hex"),
    [
        ("HDA:3", "320226"),  # day=32
        ("HDA:3", "310226"),  # day=31 in Feb
        ("HDA:3", "063b26"),  # invalid BCD month (0x3B)
        ("HTI", "240000"),  # hour=24
        ("HTI", "006000"),  # minute=60
        ("HTI", "000060"),  # second=60
        ("HTI", "23593a"),  # invalid BCD second (0x3A)
        ("FW", "aa0000"),  # invalid BCD major (0xAA)
    ],
)
def test_parse_malformed_values_raise(type_spec: str, data_hex: str) -> None:
    with pytest.raises(ValueParseError):
        parse_typed_value(type_spec, bytes.fromhex(data_hex))


def test_parse_unknown_type_raises() -> None:
    with pytest.raises(ValueParseError, match=r"Unknown type spec"):
        parse_typed_value("FOO", b"")
