from __future__ import annotations

import re
from copy import deepcopy
from io import StringIO
from typing import Any

import pytest
from rich.console import Console

from helianthus_vrc_explorer.ui.viewer import (
    _build_sheets,
    _render,
    _State,
    apply_row_type_override,
)


def _artifact(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "2.3",
        "operations": {
            "0x02": {"groups": {"0x01": {"instances": {"0x00": {"registers": {"0x0005": entry}}}}}}
        },
    }


def _entry() -> dict[str, Any]:
    return {
        "raw_hex": "0100",
        "type": "UIN",
        "value": 1,
        "error": None,
        "parameter_description": {
            "qualification": "matched",
            "codec_provenance": "selector_qualified",
            "target_profile_match": True,
        },
    }


def _view(artifact: dict[str, Any]) -> str:
    output = StringIO()
    console = Console(file=output, width=140, height=40, color_system=None)
    console.print(_render(console, artifact, _State(sheets=_build_sheets(artifact))))
    return output.getvalue()


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown"])
def test_explicit_grade_is_separate_from_acceptance_and_profile(grade: str) -> None:
    entry = _entry()
    entry["evidence_grade"] = grade
    artifact = _artifact(entry)
    before = deepcopy(artifact)

    view = _view(artifact)

    assert f"Entry evidence: {grade}" in view
    assert "Decoded value: Hypothesis" in view
    assert "Decoded value: Proven" not in view
    assert "manual type override" not in view
    assert "Codec acceptance: matched (codec_provenance=selector_qualified)" in view
    assert "Controller-profile match: True" in view
    assert "raw_hex=0100" in view
    assert "Space cycle row type" in view
    assert artifact == before


@pytest.mark.parametrize("grade", [None, "qualified", "proven", "Proven ", True, 1, [], {}])
def test_unsupported_grade_is_unknown_despite_successful_decode(grade: object) -> None:
    entry = _entry()
    entry["evidence_grade"] = grade
    artifact = _artifact(entry)
    before = deepcopy(artifact)

    view = _view(artifact)

    assert "Entry evidence: Unknown" in view
    assert "Entry evidence: Proven" not in view
    assert "Decoded value: Proven" not in view
    assert artifact == before


@pytest.mark.parametrize("legacy", [False, True])
def test_missing_grade_is_unknown_including_legacy_metadata(legacy: bool) -> None:
    entry = _entry()
    artifact = _artifact(entry)
    if legacy:
        del artifact["schema_version"]
        del entry["parameter_description"]
    before = deepcopy(artifact)

    view = _view(artifact)

    assert "Entry evidence: Unknown" in view
    assert "Entry evidence: Proven" not in view
    assert "Decoded value: Proven" not in view
    if legacy:
        assert "Codec acceptance: Unknown (codec_provenance=Unknown)" in view
        assert "Controller-profile match: Unknown" in view
    assert artifact == before


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown", None])
def test_override_is_view_hypothesis_without_regrading_native_evidence(grade: str | None) -> None:
    entry = _entry()
    if grade is not None:
        entry["evidence_grade"] = grade
    artifact = _artifact(entry)
    description = deepcopy(entry["parameter_description"])
    apply_row_type_override(
        artifact, group_key="0x01", rr_key="0x0005", type_spec="HEX:2", op_key="0x02"
    )
    before_render = deepcopy(artifact)

    view = _view(artifact)

    shown = grade if grade is not None else "Unknown"
    assert re.search(rf"Entry evidence: {shown}\s*│", view)
    assert "Decoded value: Hypothesis (manual type override; view only)" in view
    # The override form replaces the plain decoded-value line rather than adding to it.
    assert not re.search(r"Decoded value: Hypothesis\s*│", view)
    assert "Decoded value: Proven" not in view
    assert entry["raw_hex"] == "0100"
    assert entry["value"] == "0x0100"
    assert entry.get("evidence_grade") == grade
    assert ("evidence_grade" in entry) is (grade is not None)
    assert entry["parameter_description"] == description
    assert artifact == before_render


def test_grade_does_not_imply_accepted_codec_or_matching_profile() -> None:
    entry = _entry()
    entry["evidence_grade"] = "Proven"
    entry["parameter_description"].update(
        qualification="unqualified", codec_provenance="length_inferred", target_profile_match=False
    )

    view = _view(_artifact(entry))

    assert "Entry evidence: Proven" in view
    assert "Decoded value: Hypothesis" in view
    assert "Decoded value: Proven" not in view
    assert "Codec acceptance: unqualified (codec_provenance=length_inferred)" in view
    assert "Controller-profile match: False" in view


@pytest.mark.parametrize("override_key", ["operations", "namespaces", None])
def test_saved_override_is_hypothesis_without_altering_retained_entry(
    override_key: str | None,
) -> None:
    entry = _entry()
    entry["evidence_grade"] = "Proven"
    artifact = _artifact(entry)
    overrides = (
        {override_key: {"0x02": {"0x0005": "HEX:2"}}}
        if override_key is not None
        else {"0x0005": "HEX:2"}
    )
    artifact["meta"] = {"type_overrides": {"0x01": overrides}, "incomplete": True}
    before = deepcopy(artifact)

    view = _view(artifact)

    assert re.search(r"Entry evidence: Proven\s*│", view)
    assert "Decoded value: Hypothesis (manual type override; view only)" in view
    assert "Decoded value: Proven" not in view
    assert "raw_hex=0100" in view
    assert artifact == before


def test_row_override_does_not_grade_instance_without_entry() -> None:
    artifact = _artifact(_entry())
    instances = artifact["operations"]["0x02"]["groups"]["0x01"]["instances"]
    instances["0x01"] = {"registers": {}}
    apply_row_type_override(
        artifact, group_key="0x01", rr_key="0x0005", type_spec="HEX:2", op_key="0x02"
    )
    output = StringIO()
    console = Console(file=output, width=140, height=40, color_system=None)
    state = _State(sheets=_build_sheets(artifact))
    state.col_idx = 1
    console.print(_render(console, artifact, state))
    view = output.getvalue()

    assert "II=0x01" in view
    assert "Entry evidence: Unknown" in view
    assert re.search(r"Decoded value: Unknown\s*│", view)
    assert "manual type override" not in view


def test_entry_level_codec_provenance_is_used_without_description() -> None:
    entry = _entry()
    del entry["parameter_description"]
    entry["codec_provenance"] = "length_inferred"

    view = _view(_artifact(entry))

    assert "(codec_provenance=length_inferred)" in view


@pytest.mark.parametrize("value", [None, 1])
def test_decoded_value_is_unknown_without_a_decode_and_hypothesis_with_one(
    value: int | None,
) -> None:
    entry = _entry()
    entry["evidence_grade"] = "Proven"
    entry["value"] = value
    if value is None:
        entry["error"] = "parse_error: short payload"

    view = _view(_artifact(entry))

    expected = "Hypothesis" if value is not None else "Unknown"
    assert re.search(rf"Decoded value: {expected}\s*│", view)
    assert "Entry evidence: Proven" in view
    assert "Decoded value: Proven" not in view
