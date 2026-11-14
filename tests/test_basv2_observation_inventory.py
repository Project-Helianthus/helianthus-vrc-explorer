"""The published BASV2 observation inventory is the exporter's projection of committed data.

`fixtures/b524-basv2-observation-inventory-v1.json` must equal the output of
`scripts/export_controller_observations.py` over an operations-first artifact assembled
only from committed files: the BASV2 rows of the bundled description baseline and the
sanitized BASV2 Full-scan selector inventory under `tests/fixtures/`. Nothing is scanned.
Every observation is graded Hypothesis, no raw description is committed so each one is
Unknown, and the document carries the controller family only. Each privacy check is also
run on a deliberately poisoned copy to prove it can fail.
"""

from __future__ import annotations

import importlib.util
import json
import re
from collections.abc import Iterator
from copy import deepcopy
from functools import cache
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLISHED = ROOT / "fixtures/b524-basv2-observation-inventory-v1.json"
BASELINE = ROOT / "src/helianthus_vrc_explorer/data/b524_parameter_descriptions.json"
SELECTOR_INVENTORY = ROOT / "tests/fixtures/basv2_full_scan_inventory.json"
EXPORTER = ROOT / "scripts/export_controller_observations.py"

CONTROLLER_EID = "BASV2"
SELECTOR_FIELDS = ("opcode", "group", "instance", "register")
BASELINE_FIELDS = ("read_opcode", "group", "instance", "register")
# Decoded description fields copied from committed rows; everything else stays behind.
DESCRIPTION_FIELDS = (
    "type",
    "min",
    "max",
    "step",
    "width",
    "qualification",
    "step_qualification",
    "codec_provenance",
)
ABSENT_TOKENS = frozenset({"unknown", "unspecified"})

DOCUMENT_KEYS = frozenset(
    {
        "current_values",
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
NUMERIC_KEYS = frozenset({"min", "max", "step", "width"})
# Every string the document may carry: fixed exporter vocabulary and selector encodings.
TOKENS = frozenset(
    {
        "controller-observations/1",
        "observation-only",
        "omitted",
        "unknown",
        "unspecified",
        "VRC720",
        "Hypothesis",
        "active",
        "matched",
        "unqualified",
        "unavailable",
        "bundled",
        "profile_qualified",
        "qualified",
        "decoded",
        "selector_qualified",
        "length_inferred",
        "UCH",
        "BOOL",
        "I8",
        "UIN",
        "I16",
        "U32",
        "I32",
        "EXP",
        "DATE_DMY_U8X3",
        "TIME_HMS_U8X3",
    }
)
SELECTOR_PATTERNS = {
    "opcode": re.compile(r"0x0[26]"),
    "group": re.compile(r"0x[0-9a-f]{2}"),
    "instance": re.compile(r"0x[0-9a-f]{2}"),
    "register": re.compile(r"0x[0-9a-f]{4}"),
}
CLOCK_TEXT = re.compile(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}(:\d{2})?")
# Integer digit runs only: float32 fractions such as 0.10000000149011612 are decoded steps.
LONG_DIGITS = re.compile(r"(?<![\d.])\d{9,}")


def _exporter() -> Any:
    spec = importlib.util.spec_from_file_location("controller_export", EXPORTER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@cache
def baseline_rows() -> dict[tuple[str, ...], dict[str, Any]]:
    rows = _load(BASELINE)["descriptions"]
    return {
        tuple(row[field] for field in BASELINE_FIELDS): row
        for row in rows
        if row["profile"]["eid"] == CONTROLLER_EID
    }


@cache
def selector_inventory() -> dict[str, Any]:
    return _load(SELECTOR_INVENTORY)


@cache
def inventory_rows() -> dict[tuple[str, ...], dict[str, Any]]:
    return {
        tuple(row["selector"][field] for field in SELECTOR_FIELDS): row
        for row in selector_inventory()["observations"]
    }


def _description(selector: tuple[str, ...]) -> dict[str, Any]:
    """Committed decoded fields: baseline first, the selector inventory fills the gaps."""

    description: dict[str, Any] = {}
    row = baseline_rows().get(selector)
    if row is not None:
        description.update({key: row[key] for key in DESCRIPTION_FIELDS if key in row})
    observed = inventory_rows().get(selector)
    if observed is not None:
        for key in DESCRIPTION_FIELDS:
            value = observed["decoded_observation"].get(key)
            if key not in description and value not in ABSENT_TOKENS:
                description[key] = value
    description["evidence_grade"] = "Hypothesis"
    return description


def committed_artifact() -> dict[str, Any]:
    """An operations-first artifact holding only committed BASV2 observation data."""

    inventory = inventory_rows()
    operations: dict[str, Any] = {}
    for selector in sorted(set(baseline_rows()) | set(inventory)):
        opcode, group, instance, register = selector
        entry: dict[str, Any] = {
            "read_opcode": opcode,
            "evidence_grade": "Hypothesis",
            "parameter_description": _description(selector),
        }
        if selector in inventory:
            entry["response_state"] = inventory[selector]["response_state"]
        groups = operations.setdefault(opcode, {"groups": {}})["groups"]
        instances = groups.setdefault(group, {"instances": {}})["instances"]
        instances.setdefault(instance, {"registers": {}})["registers"][register] = entry
    return {
        "schema_version": "2.5",
        "meta": {"identity": {"protocol_family": selector_inventory()["family"]}},
        "operations": operations,
    }


def expected_text() -> str:
    """The exporter's command-line serialization of the committed artifact."""

    document = _exporter().export_observations(committed_artifact())
    return json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"


def published() -> dict[str, Any]:
    return _load(PUBLISHED)


def _strings(node: object, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str]]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(value, (*path, key))
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item, path)
    elif isinstance(node, str):
        yield path, node


def shape_violations(document: dict[str, Any]) -> list[str]:
    """Fixed key sets: no value, reply byte, status flag, name, identifier or clock field."""

    found = [f"document key {key}" for key in set(document) ^ DOCUMENT_KEYS]
    for row in document.get("observations", []):
        found += [f"observation key {key}" for key in set(row) ^ OBSERVATION_KEYS]
        decoded = row.get("decoded_observation", {})
        found += [f"decoded key {key}" for key in set(decoded) ^ DECODED_KEYS]
        selector = set(row.get("selector", {}))
        found += [f"selector key {key}" for key in selector ^ set(SELECTOR_FIELDS)]
        for key in NUMERIC_KEYS & set(decoded):
            if not isinstance(decoded[key], int | float) and decoded[key] != "unknown":
                found.append(f"non-numeric {key}")
    return found


def identity_violations(document: dict[str, Any]) -> list[str]:
    """Only the controller family; every other string is fixed vocabulary or a selector."""

    found = [] if document.get("family") == "VRC720" else ["family"]
    for path, text in _strings(document):
        if path and path[-2:-1] == ("selector",):
            if not SELECTOR_PATTERNS[path[-1]].fullmatch(text):
                found.append(f"selector text at {'/'.join(path)}")
        elif text not in TOKENS:
            found.append(f"free text at {'/'.join(path)}")
    return found


def grade_violations(document: dict[str, Any]) -> list[str]:
    found = []
    for row in document["observations"]:
        if row["evidence_grade"] != "Hypothesis":
            found.append("observation grade")
        if row["decoded_observation"]["evidence_grade"] != "Hypothesis":
            found.append("decoded grade")
        if row["raw_description"] != "unknown":
            found.append("raw description")
    return found


def leak_violations(text: str) -> list[str]:
    """Serials and identifiers as long digit runs; capture times as date or clock text."""

    return [f"long digit run {m.group()}" for m in LONG_DIGITS.finditer(text)] + [
        "clock text" for _ in CLOCK_TEXT.finditer(text)
    ]


def selector_violations(document: dict[str, Any]) -> list[str]:
    expected = set(baseline_rows()) | set(inventory_rows())
    rows = document["observations"]
    actual = [tuple(row["selector"][field] for field in SELECTOR_FIELDS) for row in rows]
    found = [] if len(actual) == len(set(actual)) else ["duplicate selector"]
    return found + [f"selector {selector}" for selector in set(actual) ^ expected]


def test_published_inventory_is_the_exporter_output_of_committed_data() -> None:
    assert PUBLISHED.read_text(encoding="utf-8") == expected_text()


def test_published_inventory_covers_every_committed_selector_once() -> None:
    document = published()
    assert selector_violations(document) == []
    assert len(document["observations"]) == len(set(baseline_rows()) | set(inventory_rows()))


def test_published_inventory_keeps_committed_decoded_ranges() -> None:
    rows = baseline_rows()
    for row in published()["observations"]:
        selector = tuple(row["selector"][field] for field in SELECTOR_FIELDS)
        if selector not in rows:
            continue
        decoded, source = row["decoded_observation"], rows[selector]
        assert decoded["type"] == source["type"]
        for key in ("min", "max", "step", "width"):
            # Date and time bounds are format text, never copied; they stay unknown.
            expected = source[key] if isinstance(source[key], int | float) else "unknown"
            assert decoded[key] == expected


def test_published_inventory_is_observation_only() -> None:
    document = published()
    assert document["kind"] == "observation-only"
    assert document["native_profile_input"] is False
    assert document["write_bound_evidence"] is False
    assert document["qualification"] == "unknown"
    assert document["current_values"] == "omitted"


def test_published_inventory_carries_family_identity_only() -> None:
    assert identity_violations(published()) == []


def test_every_observation_is_hypothesis_with_unknown_raw_description() -> None:
    assert grade_violations(published()) == []


def test_published_inventory_has_no_value_serial_address_or_capture_time() -> None:
    document = published()
    assert shape_violations(document) == []
    assert leak_violations(PUBLISHED.read_text(encoding="utf-8")) == []


def _poison(document: dict[str, Any], change: str) -> dict[str, Any]:
    poisoned = deepcopy(document)
    row = poisoned["observations"][0]
    if change == "reply byte":
        row["reply_hex"] = "00"
    elif change == "value":
        row["decoded_observation"]["value"] = 21.5
    elif change == "model":
        poisoned["family"] = "controller model text"
    elif change == "controller identity":
        poisoned["eid"] = CONTROLLER_EID
    elif change == "selector text":
        row["selector"]["group"] = "group two"
    elif change == "non-numeric bound":
        row["decoded_observation"]["max"] = "fifty"
    return poisoned


@pytest.mark.parametrize(
    ("change", "check"),
    [
        ("reply byte", shape_violations),
        ("value", shape_violations),
        ("non-numeric bound", shape_violations),
        ("controller identity", shape_violations),
        ("model", identity_violations),
        ("selector text", identity_violations),
    ],
)
def test_privacy_checks_reject_poisoned_copies(change: str, check: Any) -> None:
    assert check(_poison(published(), change))


@pytest.mark.parametrize(
    ("location", "grade"),
    [("evidence_grade", "Proven"), ("decoded_observation", "Unknown"), ("raw", "omitted")],
)
def test_grade_check_rejects_poisoned_copies(location: str, grade: str) -> None:
    poisoned = deepcopy(published())
    row = poisoned["observations"][-1]
    if location == "decoded_observation":
        row["decoded_observation"]["evidence_grade"] = grade
    elif location == "raw":
        row["raw_description"] = grade
    else:
        row[location] = grade
    assert grade_violations(poisoned)


@pytest.mark.parametrize("text", ['"serial": 123456789012', '"captured": "2026-01-02"', "12:34"])
def test_leak_check_rejects_poisoned_text(text: str) -> None:
    assert leak_violations(PUBLISHED.read_text(encoding="utf-8") + text)


@pytest.mark.parametrize("field", SELECTOR_FIELDS)
def test_selector_check_rejects_each_changed_selector_field(field: str) -> None:
    poisoned = deepcopy(published())
    selector = poisoned["observations"][0]["selector"]
    selector[field] = {"opcode": "0x06", "register": "0xfff0"}.get(field, "0xf0")
    assert selector_violations(poisoned)
