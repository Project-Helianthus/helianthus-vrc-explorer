from __future__ import annotations

from pathlib import Path

import pytest

from helianthus_vrc_explorer.schema.regulator_identity import (
    load_regulator_identity_catalog,
    lookup_regulator_identity,
    normalize_spn,
    spn_from_sw,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_catalog_contains_all_exact_eid_spn_pairs() -> None:
    catalog = load_regulator_identity_catalog()

    assert len(catalog) == 39
    assert {(entry.eid, entry.spn_hex) for entry in catalog} == {
        ("70000", "0141"),
        ("70000", "0155"),
        ("70000", "015A"),
        ("70000", "016C"),
        ("70000", "0171"),
        ("70000", "01D8"),
        ("72000", "0179"),
        ("B7V00", "0163"),
        ("BASS0", "0184"),
        ("BASS0", "0193"),
        ("BASS2", "01A1"),
        ("BASS2", "01CF"),
        ("BASS3", "01B0"),
        ("BASS3", "01BB"),
        ("BASS3", "01D0"),
        ("BASS3", "01D9"),
        ("BASV0", "0184"),
        ("BASV0", "0193"),
        ("BASV2", "01A1"),
        ("BASV2", "01CF"),
        ("BASV3", "01B0"),
        ("BASV3", "01BB"),
        ("BASV3", "01D0"),
        ("BASV3", "01D9"),
        ("CTLS0", "0188"),
        ("CTLS0", "0189"),
        ("CTLS2", "019D"),
        ("CTLS3", "01AF"),
        ("CTLS3", "01B6"),
        ("CTLS3", "01E1"),
        ("CTLV0", "0187"),
        ("CTLV2", "019B"),
        ("CTLV3", "01AE"),
        ("CTLV3", "01B5"),
        ("CTLV3", "01DC"),
        ("CTLV3", "01E0"),
        ("CTLX0", "007F"),
        ("CTLX0", "0194"),
        ("EMM00", "0181"),
    }
    for entry in catalog:
        assert lookup_regulator_identity(entry.eid, entry.spn) == entry


@pytest.mark.parametrize(
    ("eid", "spn", "model_name", "protocol_family"),
    [
        ("bass0", "0x0184", "VRC720", "VRC720"),
        ("BASS0", "0193", "VRT380", "VRC720"),
        ("70000", 0x0141, "VRC700 R1", "VRC700"),
    ],
)
def test_lookup_requires_an_exact_eid_spn_pair(
    eid: str, spn: int | str, model_name: str, protocol_family: str
) -> None:
    result = lookup_regulator_identity(eid, spn)

    assert result is not None
    assert result.model_name == model_name
    assert result.protocol_family == protocol_family


def test_shared_eid_never_selects_a_model_without_the_matching_spn() -> None:
    assert lookup_regulator_identity("BASS0", "0184").model_name == "VRC720"  # type: ignore[union-attr]
    assert lookup_regulator_identity("BASS0", "0193").model_name == "VRT380"  # type: ignore[union-attr]
    assert lookup_regulator_identity("BASS0", "0185") is None
    assert lookup_regulator_identity("BASS0", None) is None


@pytest.mark.parametrize("value", [True, -1, 0x10000, "184", "0x184", "01GG", " 0184"])
def test_spn_requires_u16_or_canonical_four_hex_digits(value: object) -> None:
    with pytest.raises(ValueError):
        normalize_spn(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("sw", "expected_spn"),
    [("0417", 0x01A1), ("0463", 0x01CF), ("0507", 0x01FB)],
)
def test_spn_from_sw_decodes_four_digit_bcd_as_a_decimal_pin(sw: str, expected_spn: int) -> None:
    assert spn_from_sw(sw) == expected_spn


@pytest.mark.parametrize("sw", [None, True, 417, "417", "04A7", "05F7", " 0417"])
def test_spn_from_sw_rejects_non_bcd_or_noncanonical_raw_sw(sw: object) -> None:
    assert spn_from_sw(sw) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "eid", [True, 70000, "BASS", "BASS00", "B\u00c4SS0", "ba\u00df0", "CT\tV3"]
)
def test_lookup_rejects_invalid_eid(eid: object) -> None:
    with pytest.raises(ValueError):
        lookup_regulator_identity(eid, "0184")  # type: ignore[arg-type]


def test_packaged_catalog_matches_canonical_copy() -> None:
    root = _repo_root()
    assert (root / "data/regulator_eid_spn.csv").read_text(encoding="utf-8") == (
        root / "src/helianthus_vrc_explorer/data/regulator_eid_spn.csv"
    ).read_text(encoding="utf-8")


def test_catalog_rejects_duplicate_eid_spn_pairs(tmp_path: Path) -> None:
    duplicate_catalog = tmp_path / "duplicate.csv"
    duplicate_catalog.write_text(
        "eid,spn,model_name,protocol_family\nBASS0,0184,VRC720,VRC720\nBASS0,0184,VRT380,VRC720\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate EID/SPN pair"):
        load_regulator_identity_catalog(duplicate_catalog)
