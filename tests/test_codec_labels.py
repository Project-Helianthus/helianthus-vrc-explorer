from __future__ import annotations

from helianthus_vrc_explorer.protocol.parser import parse_typed_value
from helianthus_vrc_explorer.schema.b524_codec_labels import (
    b524_codec_label,
    bundled_b524_codec_labels,
)

# Every fixed codec spec accepted by parse_typed_value's match statement, plus
# the two parameterized families (STR:n, HEX:n) represented by their family
# token. Mirrors the set parsed in browse_textual._parse_new_value.
_KNOWN_CODECS = (
    "BOOL",
    "UCH",
    "UIN",
    "I8",
    "I16",
    "U32",
    "I32",
    "EXP",
    "HDA:3",
    "HTI",
    "FW",
    "FWU",
)


def test_every_parser_accepted_codec_has_a_label_row() -> None:
    labels = bundled_b524_codec_labels()
    for codec in _KNOWN_CODECS:
        assert codec in labels, f"missing codec label row for {codec!r}"
        assert labels[codec].raw_shape
        assert labels[codec].interpreted_shape


def test_str_and_hex_families_have_representative_rows() -> None:
    labels = bundled_b524_codec_labels()
    assert "STR:n" in labels
    assert "HEX:n" in labels


def test_b524_codec_label_resolves_family_tokens_for_parameterized_specs() -> None:
    assert b524_codec_label("STR:16") is not None
    assert b524_codec_label("STR:16").interpreted_shape == "text"
    assert b524_codec_label("HEX:3") is not None
    assert b524_codec_label("hex:3").interpreted_shape == "uninterpreted bytes"


def test_unknown_codec_degrades_to_type_verbatim_with_byte_count() -> None:
    assert b524_codec_label("WIDGET:7") is None


def test_parser_actually_accepts_every_fixed_codec_in_the_table() -> None:
    # Smoke-test that the label table has not drifted from the parser: every
    # fixed codec we claim to label must actually decode a correctly sized,
    # all-zero payload without raising (content correctness is parser.py's
    # own test responsibility, not this table's).
    payloads = {
        "BOOL": bytes(1),
        "UCH": bytes(1),
        "UIN": bytes(2),
        "I8": bytes(1),
        "I16": bytes(2),
        "U32": bytes(4),
        "I32": bytes(4),
        "EXP": bytes(4),
        "HDA:3": bytes((1, 1, 0)),
        "HTI": bytes(3),
        "FW": bytes(3),
        "FWU": bytes(3),
    }
    for codec, payload in payloads.items():
        parse_typed_value(codec, payload)
