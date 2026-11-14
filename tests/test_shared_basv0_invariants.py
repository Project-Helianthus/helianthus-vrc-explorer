"""Shared BASV0 native invariants over the public and packaged fixture copies.

The vendored docs schemas and semantic validator are the reference. Every fault
below is a synthetic mutation of a loaded copy; no committed file is modified.
"""

import base64
import importlib.util
import json
import shutil
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from helianthus_vrc_explorer.evidence_export import (
    OVERLAY,
    build_native_evidence,
    serialize_native_evidence,
    validate_scope_overlay,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "shared_basv0_invariants", ROOT / "scripts/check_shared_b524_fixtures.py"
)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

COPIES = {
    "public": ROOT / "fixtures",
    "packaged": ROOT / "src/helianthus_vrc_explorer/fixtures",
}
NAMES = (checker.DESCRIPTION, checker.OBSERVATIONS)
MANIFEST = json.loads((checker.DEFAULT_ROOT / "manifest.json").read_text())
IDENTITY_MANIFEST = json.loads(
    (ROOT / "src/helianthus_vrc_explorer/data/b524_description_profiles.json").read_text()
)
SELECTOR_FIELDS = ("operation", "group", "instance", "register")
DHW_SELECTOR = {"operation": "02", "group": "00", "instance": "00", "register": "0001"}


def pinned_hex(name):
    """The page-cited pin, carried in the vendored manifest as Base64."""
    return base64.b64decode(MANIFEST["digests_base64"][name]).hex()


@pytest.fixture(scope="module")
def validator():
    module = checker.load_validator(checker.DEFAULT_ROOT / checker.VALIDATOR)
    module.REGISTER_MAP = checker.DEFAULT_ROOT / checker.REGISTER_MAP
    module.CALENDAR_CLOCK_CSV = checker.DEFAULT_ROOT / checker.CALENDAR
    return module


@pytest.fixture(scope="module")
def documents():
    return {
        label: tuple(json.loads((path / name).read_text()) for name in NAMES)
        for label, path in COPIES.items()
    }


def public_pair(documents):
    return deepcopy(documents["public"])


def overlay_for(description, observations):
    return build_native_evidence(description, observations, IDENTITY_MANIFEST)[OVERLAY]


@pytest.mark.parametrize("copy", sorted(COPIES))
def test_copy_bytes_match_the_pinned_docs_pair(copy):
    for name in NAMES:
        data = (COPIES[copy] / name).read_bytes()
        assert sha256(data).hexdigest() == pinned_hex(name), f"{copy}/{name}"
        assert data == (checker.DEFAULT_ROOT / checker.NATIVE / name).read_bytes()


def test_public_and_packaged_copies_are_identical():
    for name in NAMES:
        assert (COPIES["public"] / name).read_bytes() == (COPIES["packaged"] / name).read_bytes()


@pytest.mark.parametrize("copy", sorted(COPIES))
def test_copy_passes_docs_schemas_and_semantic_validator(copy, documents, validator):
    description, observations = deepcopy(documents[copy])
    checker.validate_documents(checker.DEFAULT_ROOT, description, observations)
    overlay = overlay_for(description, observations)
    validator.validate_documents(description, observations, checker.DESCRIPTION, overlay)
    validate_scope_overlay(description, overlay)
    assert observations["current_values"] == "omitted"
    assert observations["native_headers"] == "omitted"
    assert observations["response_payloads"] == "omitted"
    assert all("validation_scope" not in record for record in description["records"])


@pytest.mark.parametrize("copy", sorted(COPIES))
def test_native_export_of_copy_reproduces_its_bytes(copy, documents):
    description, observations = deepcopy(documents[copy])
    encoded = serialize_native_evidence(
        build_native_evidence(description, observations, IDENTITY_MANIFEST)
    )
    for name in NAMES:
        assert encoded[name] == (COPIES[copy] / name).read_bytes()


def test_checker_rejects_a_copy_differing_from_the_pinned_pair(tmp_path):
    copies = []
    for label, path in COPIES.items():
        shutil.copytree(path, tmp_path / label, ignore=shutil.ignore_patterns("*.py"))
        copies.append(tmp_path / label)
    checker.validate_published_copies(checker.DEFAULT_ROOT, copies)
    damaged = copies[1] / checker.DESCRIPTION
    damaged.write_bytes(damaged.read_bytes().rstrip(b"\n"))
    with pytest.raises(ValueError, match="digest"):
        checker.validate_published_copies(checker.DEFAULT_ROOT, copies)


def test_publish_copies_writes_pinned_bytes_and_fails_closed(tmp_path):
    root = tmp_path / "bundle"
    shutil.copytree(checker.DEFAULT_ROOT, root)
    copies = [tmp_path / "public", tmp_path / "packaged"]
    for directory in copies:
        directory.mkdir()
        for name in NAMES:
            (directory / name).write_text("last-known-good")
    checker.publish_copies(root, copies)
    for directory in copies:
        for name in NAMES:
            assert sha256((directory / name).read_bytes()).hexdigest() == pinned_hex(name)
        (directory / checker.DESCRIPTION).write_text("last-known-good")
    vendored = root / checker.NATIVE / checker.OBSERVATIONS
    vendored.write_bytes(vendored.read_bytes().rstrip(b"\n"))
    with pytest.raises(ValueError, match="digest"):
        checker.publish_copies(root, copies)
    for directory in copies:
        assert (directory / checker.DESCRIPTION).read_text() == "last-known-good"
        assert sorted(path.name for path in directory.iterdir()) == sorted(NAMES)


@pytest.mark.parametrize(
    "marker", ["current_values", "native_headers", "response_payloads", "nonclaims"]
)
def test_omission_markers_and_nonclaims_are_required(marker, documents):
    description, observations = public_pair(documents)
    observations.pop(marker)
    with pytest.raises(ValueError, match=marker):
        checker.validate_documents(checker.DEFAULT_ROOT, description, observations)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("eid", "UNKNOWN"),
        ("software_raw", "0218"),
        ("hardware_raw", "8804"),
        ("api_version_raw", "2"),
        ("api_revision_raw", "2"),
    ],
)
def test_every_local_profile_identity_field_is_checked(field, value, documents, validator):
    description, observations = public_pair(documents)
    description["local_profile"][field] = value
    with pytest.raises(validator.ValidationError, match="local_profile"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


def _qualified_family(records, codec):
    """First family with at least two described instances qualified for ``codec``."""
    families = {}
    for record in records:
        decoded = record["decoded"]
        if decoded and decoded["qualification"] == "qualified" and decoded["codec"] == codec:
            selector = record["selector"]
            key = (selector["operation"], selector["group"], selector["register"])
            families.setdefault(key, []).append(record)
    return next(members for members in families.values() if len(members) > 1)


def test_cross_instance_range_must_be_identical(documents, validator):
    description, observations = public_pair(documents)
    member = _qualified_family(description["records"], "UCH")[1]
    # Keep the record self-consistent: only the family comparison can catch this.
    step = (int(member["raw_limits"]["step_hex"], 16) + 1) % 256 or 1
    member["raw_limits"]["step_hex"] = f"{step:02X}"
    member["raw_description_hex"] = member["raw_description_hex"][:-2] + f"{step:02X}"
    member["decoded"]["step"] = step
    with pytest.raises(validator.ValidationError, match="described instances differ"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


def test_cross_instance_qualified_codec_must_be_identical(documents, validator):
    description, _ = public_pair(documents)
    member = _qualified_family(description["records"], "EXP")[1]
    member["decoded"]["codec"] = "U32"
    with pytest.raises(validator.ValidationError, match="conflicting qualified codecs"):
        validator._validate_family_invariance(description["records"])


def _remote_slot(records):
    slots = {}
    for record in records:
        identity = record["remote_identity"]
        if identity and identity["qualification"] == "observed_remote_header":
            selector = record["selector"]
            slots.setdefault((selector["group"], selector["instance"]), []).append(record)
    return next(members for members in slots.values() if len(members) > 1)


@pytest.mark.parametrize(
    ("field", "change", "message"),
    [
        ("address_raw", "consistency", "one slot retains one identity"),
        ("firmware_raw", "consistency", "one slot retains one identity"),
        ("group", "consistency", "group disagrees with selector"),
        ("qualification", "consistency", "one slot retains one qualification"),
        ("address_raw", "width", "must be 1 bytes"),
        ("firmware_raw", "width", "must be 3 bytes"),
        ("group", "width", "must be 1 bytes"),
    ],
)
def test_remote_slot_identity_is_consistent_and_sized(field, change, message, documents, validator):
    description, observations = public_pair(documents)
    record = _remote_slot(description["records"])[1]
    identity = record["remote_identity"]
    if change == "width":
        identity[field] += "00"
    elif field == "qualification":
        # Keep the record's own presence consistent; only the slot comparison differs.
        identity[field] = "unqualified"
        record["presence_state"] = "remote_identity_unqualified"
    else:
        identity[field] = "".join(
            f"{(int(identity[field][i : i + 2], 16) + 1) % 256:02X}"
            for i in range(0, len(identity[field]), 2)
        )
    with pytest.raises(validator.ValidationError, match=message):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


def _linked_local_row(observations):
    rows = observations["records"]
    taken = {tuple(row["selector"][field] for field in SELECTOR_FIELDS) for row in rows}
    remote_slots = {
        (row["selector"]["group"], row["selector"]["instance"])
        for row in rows
        if row["selector"]["operation"] == "06"
    }
    for row in rows:
        selector = row["selector"]
        if (
            selector["operation"] == "02"
            and row["description"]
            and row["description"]["acquisition_state"] == "matched"
            and ("06", selector["group"], selector["instance"], selector["register"]) not in taken
            and (selector["group"], selector["instance"]) not in remote_slots
        ):
            return row, taken
    raise AssertionError("no linked local observation without a remote counterpart")


@pytest.mark.parametrize("field", SELECTOR_FIELDS)
def test_linked_observation_must_match_every_selector_field(field, documents, validator):
    description, observations = public_pair(documents)
    row, taken = _linked_local_row(observations)
    if field == "operation":
        row["selector"]["operation"] = "06"
        row["identity_scope"] = "remote"
    else:
        width = 4 if field == "register" else 2
        row["selector"][field] = next(
            candidate
            for candidate in (f"{value:0{width}X}" for value in range(16**width - 1, 0, -1))
            if tuple(candidate if key == field else row["selector"][key] for key in SELECTOR_FIELDS)
            not in taken
        )
    with pytest.raises(validator.ValidationError, match="description selector mismatch"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


def test_linked_observation_opcode_must_match_identity_scope(documents, validator):
    description, observations = public_pair(documents)
    row, _ = _linked_local_row(observations)
    row["identity_scope"] = "remote"
    with pytest.raises(validator.ValidationError, match="request opcode corroboration failed"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


@pytest.mark.parametrize("side", ["observation", "description"])
def test_linked_access_flags_must_agree(side, documents, validator):
    description, observations = public_pair(documents)
    # Skip the published DHW record: its own pin would fire before the link check.
    row = next(
        row
        for row in observations["records"]
        if row["description"]
        and row["response_state"] == "echo_payload"
        and row["selector"] != DHW_SELECTOR
    )
    target = (
        row if side == "observation" else description["records"][row["description"]["record_index"]]
    )
    target["access_flags"] = {"00": "01", "01": "02", "02": "03", "03": "00"}[
        target["access_flags"]
    ]
    with pytest.raises(validator.ValidationError, match="access flags disagree"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


def test_remote_slot_retains_one_presence_state(documents, validator):
    description, observations = public_pair(documents)
    slots = {}
    for row in observations["records"]:
        selector = row["selector"]
        if selector["operation"] == "06":
            slots.setdefault((selector["group"], selector["instance"]), []).append(row)
    members = next(rows for rows in slots.values() if len(rows) > 1)
    states = ["observed_present", "observed_inactive", "unknown", "remote_identity_unqualified"]
    members[1]["presence_state"] = next(
        state for state in states if state != members[0]["presence_state"]
    )
    with pytest.raises(validator.ValidationError, match="one remote slot retains one presence"):
        validator.validate_documents(description, observations, checker.DESCRIPTION)


@pytest.mark.parametrize(
    "fault",
    ["duplicate", "missing", "wrong_scope", *(f"orphan_{field}" for field in SELECTOR_FIELDS)],
)
def test_overlay_is_a_bijection_over_description_selectors(fault, documents, validator):
    description, observations = public_pair(documents)
    overlay = overlay_for(description, observations)
    rows = overlay["records"]
    if fault == "duplicate":
        rows.append(deepcopy(rows[0]))
    elif fault == "missing":
        rows.pop()
    elif fault == "wrong_scope":
        rows[0]["validation_scope"] = "display_only"
    else:
        field = fault.removeprefix("orphan_")
        rows[0]["selector"][field] = {
            "operation": "06" if rows[0]["selector"]["operation"] == "02" else "02",
            "group": "FF",
            "instance": "FF",
            "register": "FFFF",
        }[field]
        assert rows[0]["selector"] not in [record["selector"] for record in description["records"]]
    with pytest.raises(validator.ValidationError):
        validator.validate_documents(description, observations, checker.DESCRIPTION, overlay)
    with pytest.raises(ValueError):
        validate_scope_overlay(description, overlay)
