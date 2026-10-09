"""Pair-only regulator identity catalog backed by public CSV data."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import IO, Final

CATALOG_HEADER: Final = ["eid", "spn", "model_name", "protocol_family"]
SUPPORTED_PROTOCOL_FAMILIES: Final = frozenset({"VRC700", "VRC720"})


@dataclass(frozen=True, slots=True)
class RegulatorIdentity:
    """A catalog entry selected only by its exact EID and SPN pair."""

    eid: str
    spn: int
    model_name: str
    protocol_family: str

    @property
    def spn_hex(self) -> str:
        """Canonical four-digit uppercase hexadecimal SPN representation."""

        return f"{self.spn:04X}"


def normalize_eid(eid: str) -> str:
    """Validate and uppercase a five-character ASCII device EID."""

    if not isinstance(eid, str):
        raise ValueError("eid must be a string")
    if len(eid) != 5 or not eid.isascii() or not eid.isalnum():
        raise ValueError("eid must be exactly five ASCII alphanumeric characters")
    return eid.upper()


def normalize_spn(spn: int | str | None) -> int | None:
    """Validate an explicit u16 SPN or its canonical four-hex-digit spelling."""

    if spn is None:
        return None
    if isinstance(spn, bool):
        raise ValueError("spn must be a u16 integer or four hexadecimal digits")
    if isinstance(spn, int):
        if 0 <= spn <= 0xFFFF:
            return spn
        raise ValueError("spn integer must be in range 0..65535")
    if not isinstance(spn, str):
        raise ValueError("spn must be a u16 integer or four hexadecimal digits")
    digits = spn[2:] if spn.startswith("0x") else spn
    if len(digits) != 4 or any(character not in "0123456789abcdefABCDEF" for character in digits):
        raise ValueError(
            "spn string must be exactly four hexadecimal digits, optionally prefixed 0x"
        )
    return int(digits, 16)


def spn_from_sw(sw: str) -> int | None:
    """Decode an exact four-digit BCD software PIN into the catalog SPN value.

    This conversion is intentionally distinct from :func:`normalize_spn`: the
    wire software value is decimal BCD, while catalog SPNs are hexadecimal
    numeric values.
    """

    if not isinstance(sw, str) or len(sw) != 4 or not sw.isascii():
        return None
    if any(character not in "0123456789" for character in sw):
        return None
    return int(sw, 10)


def load_regulator_identity_catalog(path: Path | None = None) -> tuple[RegulatorIdentity, ...]:
    """Load and validate the packaged regulator EID/SPN catalog."""

    if path is None:
        resource = resources.files("helianthus_vrc_explorer.data").joinpath("regulator_eid_spn.csv")
        with resource.open("r", encoding="utf-8") as catalog_file:
            return _read_catalog(catalog_file)
    with path.open(newline="", encoding="utf-8") as catalog_file:
        return _read_catalog(catalog_file)


def _read_catalog(catalog_file: IO[str]) -> tuple[RegulatorIdentity, ...]:
    reader = csv.DictReader(catalog_file)
    if reader.fieldnames != CATALOG_HEADER:
        raise ValueError(f"Unexpected regulator identity CSV header: {reader.fieldnames}")

    entries: list[RegulatorIdentity] = []
    seen_pairs: set[tuple[str, int]] = set()
    for row_number, raw_row in enumerate(reader, start=2):
        row = {key: (raw_row.get(key) or "").strip() for key in CATALOG_HEADER}
        eid = normalize_eid(row["eid"])
        spn = normalize_spn(row["spn"])
        assert spn is not None
        if row["eid"] != eid or row["spn"] != f"{spn:04X}":
            raise ValueError(f"Non-canonical EID or SPN at catalog row {row_number}")
        if not row["model_name"]:
            raise ValueError(f"Missing model_name at catalog row {row_number}")
        if row["protocol_family"] not in SUPPORTED_PROTOCOL_FAMILIES:
            raise ValueError(f"Unsupported protocol_family at catalog row {row_number}")
        pair = (eid, spn)
        if pair in seen_pairs:
            raise ValueError(f"Duplicate EID/SPN pair at catalog row {row_number}")
        seen_pairs.add(pair)
        entries.append(
            RegulatorIdentity(
                eid=eid,
                spn=spn,
                model_name=row["model_name"],
                protocol_family=row["protocol_family"],
            )
        )
    return tuple(entries)


def lookup_regulator_identity(eid: str, spn: int | str | None) -> RegulatorIdentity | None:
    """Return an exact catalog match; absent or unmatched SPN assigns no model."""

    normalized_eid = normalize_eid(eid)
    normalized_spn = normalize_spn(spn)
    if normalized_spn is None:
        return None
    for entry in load_regulator_identity_catalog():
        if (entry.eid, entry.spn) == (normalized_eid, normalized_spn):
            return entry
    return None
