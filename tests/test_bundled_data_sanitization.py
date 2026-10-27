"""Guard: bundled scan observations carry no identifier, clock, free text or raw bytes.

The committed observation data comes from a private scan through the repository's own
projections: `scripts/export_controller_observations.py` (fixture inventory),
`scripts/import_b524_descriptions.py` (description baseline) and the importer's
installation-observation export (catalogue blocks). The exporter documents what it omits;
this test keeps the committed files within that contract, and proves it can fail by
running the same checks on deliberately poisoned copies.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections.abc import Iterator
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "src/helianthus_vrc_explorer/data"
CATALOG = DATA / "b524_description_profiles.json"
BASELINE = DATA / "b524_parameter_descriptions.json"
INVENTORY = ROOT / "tests/fixtures/basv2_full_scan_inventory.json"
EXPORTER = ROOT / "scripts/export_controller_observations.py"
FILES = {"catalog": CATALOG, "baseline": BASELINE, "inventory": INVENTORY}

LONG_DIGITS = re.compile(r"\d{20,}")
# Names the exporter documents as omitted (identifiers, clocks, free text, raw bytes,
# metadata), plus the artifact keys that carry them. Matched as whole key names.
OMITTED_KEYS = frozenset(
    {
        "serial",
        "esn",
        "address",
        "locator",
        "timestamp",
        "scan_timestamp",
        "contributor",
        "metadata",
        "name",
        "designation",
        "description",
        "value",
        "current_value",
        "clock",
        "note",
        "host",
        "ebusd_host",
        "ebusd_port",
        "raw_hex",
        "reply_hex",
        "raw_description_hex",
    }
)
# The catalogue predates this check and keeps one retained raw description per BASV0 row
# (public local-constraint evidence, documented in docs/basv0-metadata.md).
RAW_DESCRIPTION_SOURCE = "sanitized_read_only_basv0_observation"
IMPORTER_SOURCE = "read_only_observed_baseline"

HEX2 = re.compile(r"0x[0-9a-f]{2}")
HEX4 = re.compile(r"0x[0-9a-f]{4}")
BLOCK_VALUES: dict[str, re.Pattern[str]] = {
    "observed_instance_qualification": re.compile(r"installation_observation_not_profile_limit"),
    "read_opcode": re.compile(r"0x0[26]"),
    "group": HEX2,
    "instance": HEX2,
    "identifier": HEX4,
    "semantics": re.compile(r"capacity|expected_population"),
    "device_class_raw": re.compile(r"[0-9a-f]{2}"),
    "device_firmware_raw": re.compile(r"[0-9a-f]{6}"),
}
BLOCK_NUMBERS = frozenset({"capacity", "expected", "observed"})

ROW_KEYS = frozenset(
    {
        "codec_migration",
        "codec_provenance",
        "decoder_revision",
        "description_opcode",
        "group",
        "instance",
        "max",
        "min",
        "profile",
        "read_opcode",
        "register",
        "source",
        "step",
        "step_qualification",
        "type",
        "validation_scope",
        "width",
    }
)
PROFILE_KEYS = frozenset(
    {
        "api_revision",
        "api_revision_raw",
        "api_version",
        "api_version_raw",
        "controller_class_raw",
        "controller_firmware_raw",
        "device_class_raw",
        "device_firmware_raw",
        "device_identity_required",
        "eid",
        "firmware",
        "hardware_raw_hex",
        "model",
        "profile",
        "profile_id",
        "software_raw_hex",
    }
)
# Format bounds of the date/time codecs; they are limits, not readings of a clock.
CLOCK_LIMITS = {
    "DATE_DMY_U8X3": re.compile(r"\d{4}-\d{2}-\d{2}"),
    "TIME_HMS_U8X3": re.compile(r"\d{2}:\d{2}:\d{2}"),
}
FIXTURE_KEYS = frozenset(
    {
        "current_values",
        "derivation",
        "family",
        "kind",
        "native_profile_input",
        "observations",
        "qualification",
        "raw_descriptions",
        "schema_version",
        "write_bound_evidence",
    }
)
OBSERVATION_KEYS = frozenset(
    {"decoded_observation", "evidence_grade", "raw_description", "response_state", "selector"}
)
DECODED_KEYS = frozenset(
    {
        "codec_provenance",
        "evidence_grade",
        "max",
        "min",
        "qualification",
        "step",
        "step_qualification",
        "type",
        "width",
    }
)


def _exporter() -> Any:
    spec = importlib.util.spec_from_file_location("controller_export", EXPORTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _keys(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from _keys(item)


def long_digit_violations(text: str) -> list[str]:
    return [f"{len(m.group())}-digit sequence" for m in LONG_DIGITS.finditer(text)]


def omitted_key_violations(document: dict[str, Any]) -> list[str]:
    """Omitted key names anywhere, except the documented BASV0 raw descriptions."""

    found: list[str] = []
    rows = document.get("descriptions")
    if isinstance(rows, list):
        for row in rows:
            allowed = (
                {"raw_description_hex"} if row.get("source") == RAW_DESCRIPTION_SOURCE else set()
            )
            found += [key for key in _keys(row) if key in OMITTED_KEYS - allowed]
        rest = {key: value for key, value in document.items() if key != "descriptions"}
        return found + [key for key in _keys(rest) if key in OMITTED_KEYS]
    return [key for key in _keys(document) if key in OMITTED_KEYS]


def block_violations(profile: dict[str, Any]) -> list[str]:
    """Every field of the two observation blocks must be a number or an allowlisted token."""

    found: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, key)
        elif isinstance(node, list):
            for item in node:
                walk(item, path)
        elif node is None:
            return
        elif path in BLOCK_NUMBERS:
            if type(node) is not int or not 0 <= node <= 0xFF:
                found.append(f"{path}={node!r}")
        elif path in BLOCK_VALUES:
            if not isinstance(node, str) or BLOCK_VALUES[path].fullmatch(node) is None:
                found.append(f"{path}={node!r}")
        else:
            found.append(f"unexpected field {path}")

    for key in ("instance_observations", "remote_device_observations"):
        if key in profile:
            walk(profile[key], key)
    return found


def importer_row_violations(document: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for row in document["descriptions"]:
        if row.get("source") != IMPORTER_SOURCE:
            continue
        found += [f"row key {key}" for key in row if key not in ROW_KEYS]
        found += [f"profile key {key}" for key in row["profile"] if key not in PROFILE_KEYS]
        for limit in ("min", "max", "step"):
            value = row[limit]
            if isinstance(value, str):
                pattern = CLOCK_LIMITS.get(row["type"])
                if pattern is None or pattern.fullmatch(value) is None:
                    found.append(f"{limit}={value!r} on {row['type']}")
    return found


def fixture_violations(document: dict[str, Any]) -> list[str]:
    exporter = _exporter()
    found = [f"key {key}" for key in document if key not in FIXTURE_KEYS]
    for row in document["observations"]:
        if set(row) != OBSERVATION_KEYS or set(row["decoded_observation"]) != DECODED_KEYS:
            found.append("observation shape")
            continue
        if row["raw_description"] not in {"omitted", "unknown"}:
            found.append(f"raw_description={row['raw_description']!r}")
        if row["response_state"] not in exporter.STATES | {"unknown"}:
            found.append(f"response_state={row['response_state']!r}")
        for grade in (row["evidence_grade"], row["decoded_observation"]["evidence_grade"]):
            if grade not in exporter.GRADES | {"unspecified"}:
                found.append(f"evidence_grade={grade!r}")
        selector = row["selector"]
        if set(selector) != {"opcode", "group", "instance", "register"}:
            found.append("selector shape")
        elif not (
            HEX2.fullmatch(selector["opcode"])
            and HEX2.fullmatch(selector["group"])
            and HEX2.fullmatch(selector["instance"])
            and HEX4.fullmatch(selector["register"])
        ):
            found.append(f"selector={selector!r}")
        decoded = row["decoded_observation"]
        for key in ("type", "qualification", "step_qualification", "codec_provenance"):
            if not isinstance(decoded[key], str):
                found.append(f"{key} is not a token")
        for key in ("min", "max", "step", "width"):
            if isinstance(decoded[key], str) and decoded[key] != "unknown":
                found.append(f"{key}={decoded[key]!r}")
    return found


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# --- the committed files ----------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(FILES))
def test_no_twenty_digit_sequence_in_the_bundled_observation_data(name: str) -> None:
    assert long_digit_violations(FILES[name].read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("name", sorted(FILES))
def test_no_key_the_exporter_omits_in_the_bundled_observation_data(name: str) -> None:
    assert omitted_key_violations(_load(FILES[name])) == []


def test_catalogue_observation_blocks_hold_only_numbers_and_allowlisted_tokens() -> None:
    profiles = _load(CATALOG)["profiles"]

    assert [p["id"] for p in profiles if "instance_observations" in p] == [
        "basv2_sw0507_hw1704_api1"
    ]
    for profile in profiles:
        assert block_violations(profile) == []


def test_baseline_rows_from_the_importer_carry_only_the_allowlisted_fields() -> None:
    document = _load(BASELINE)

    assert importer_row_violations(document) == []
    imported = [r for r in document["descriptions"] if r["source"] == IMPORTER_SOURCE]
    assert len(imported) >= 125  # the rows this guard is about are really being checked


def test_inventory_fixture_is_exporter_output_without_values_or_raw_bytes() -> None:
    document = _load(INVENTORY)

    assert fixture_violations(document) == []
    assert document["current_values"] == "omitted"
    assert document["raw_descriptions"] == "omitted"
    assert document["kind"] == "observation-only"
    assert document["native_profile_input"] is False
    assert document["write_bound_evidence"] is False


def test_exporter_still_documents_what_it_omits() -> None:
    doc = " ".join((_exporter().__doc__ or "").split())

    assert (
        "Current values (including text, clocks and identifiers), raw bytes, names and "
        "arbitrary metadata are omitted." in doc
    )


# --- the guard can fail ------------------------------------------------------------------


def test_the_checks_reject_poisoned_copies() -> None:
    assert long_digit_violations('{"id": "x", "n": "' + "1" * 20 + '"}') == ["20-digit sequence"]
    assert long_digit_violations("1" * 19 + " " + "1" * 19) == []

    catalog = _load(CATALOG)
    for key in ("serial", "esn", "raw_hex", "reply_hex", "scan_timestamp", "designation"):
        poisoned = deepcopy(catalog)
        poisoned["profiles"][1]["remote_device_observations"]["devices"][0][key] = "x"
        assert key in omitted_key_violations(poisoned)

    for field, value in (
        ("device_class_raw", "Boiler"),
        ("device_firmware_raw", "0c01"),
        ("group", "0x1"),
        ("capacity", "3"),
        ("observed", 1000),
        ("serial", "x"),
    ):
        poisoned = deepcopy(catalog)
        profile = poisoned["profiles"][1]
        target = (
            profile["instance_observations"]["groups"][0]
            if field in {"capacity", "observed"}
            else profile["remote_device_observations"]["devices"][0]
        )
        target[field] = value
        assert block_violations(profile) != []

    baseline = deepcopy(_load(BASELINE))
    row = next(r for r in baseline["descriptions"] if r["source"] == IMPORTER_SOURCE)
    row["raw_description_hex"] = "00"
    assert "raw_description_hex" in omitted_key_violations(baseline)
    assert importer_row_violations(baseline) == ["row key raw_description_hex"]
    row.pop("raw_description_hex")
    row["profile"]["serial"] = "x"
    assert importer_row_violations(baseline) == ["profile key serial"]
    row["profile"].pop("serial")
    row["type"], row["min"] = "EXP", "2001-01-01"
    assert importer_row_violations(baseline) == ["min='2001-01-01' on EXP"]

    inventory = deepcopy(_load(INVENTORY))
    inventory["observations"][0]["current_value"] = "x"
    assert fixture_violations(inventory) == ["observation shape"]
    inventory = deepcopy(_load(INVENTORY))
    inventory["observations"][0]["evidence_grade"] = "Proven but see serial"
    assert fixture_violations(inventory) == ["evidence_grade='Proven but see serial'"]
    inventory = deepcopy(_load(INVENTORY))
    inventory["serial"] = "x"
    assert fixture_violations(inventory) == ["key serial"]
    assert "serial" in omitted_key_violations(inventory)
