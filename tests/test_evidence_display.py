"""The shared evidence display rules, and that every surface applies them identically."""

from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from io import StringIO
from typing import Any, NamedTuple

import pytest
from rich.console import Console

from helianthus_vrc_explorer.ui import evidence_display
from helianthus_vrc_explorer.ui.browse_detail import register_detail_sections
from helianthus_vrc_explorer.ui.browse_models import RegisterAddress, RegisterRow
from helianthus_vrc_explorer.ui.evidence_display import (
    OVERRIDE_TEXT,
    entry_codec_provenance,
    entry_evidence_display,
    entry_evidence_grade,
    entry_has_decoded_value,
    get_row_type_override,
    manual_override_applies,
    observed_description,
)
from helianthus_vrc_explorer.ui.html_report import render_html_report
from helianthus_vrc_explorer.ui.viewer import _build_sheets, _render, _State


class Case(NamedTuple):
    name: str
    entry: dict[str, Any] | None
    override: str | None  # saved row override
    grade: str  # "Entry evidence"
    decoded: str  # "Decoded value" as shown (override form included)
    provenance: str  # "Codec provenance"
    overridden: bool


def _entry(**extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "raw_hex": "0100",
        "type": "UIN",
        "value": 1,
        "error": None,
        "flags": 3,
        "flags_access": "writable_visible",
        "parameter_description": {
            "qualification": "matched",
            "codec_provenance": "selector_qualified",
        },
    }
    entry.update(extra)
    return entry


def _no_description(**extra: Any) -> dict[str, Any]:
    entry = _entry(**extra)
    del entry["parameter_description"]
    return entry


def _undecoded(**extra: Any) -> dict[str, Any]:
    return _entry(value=None, error="parse_error: short payload", **extra)


CASES: list[Case] = [
    Case(
        "proven-grade-unqualified-codec",
        _entry(
            evidence_grade="Proven",
            parameter_description={
                "qualification": "unqualified",
                "codec_provenance": "length_inferred",
            },
        ),
        None,
        "Proven",
        "Hypothesis",
        "length_inferred",
        False,
    ),
    Case(
        "hypothesis-grade",
        _entry(evidence_grade="Hypothesis"),
        None,
        "Hypothesis",
        "Hypothesis",
        "selector_qualified",
        False,
    ),
    Case(
        "override-on-proven-cell",
        _entry(evidence_grade="Proven"),
        "HEX:2",
        "Proven",
        OVERRIDE_TEXT,
        "selector_qualified",
        True,
    ),
    Case(
        "override-on-ungraded-cell",
        _entry(),
        "HEX:2",
        "Unknown",
        OVERRIDE_TEXT,
        "selector_qualified",
        True,
    ),
    Case(
        "override-recovers-a-failed-decode",
        _undecoded(evidence_grade="Proven"),
        "HEX:2",
        "Proven",
        OVERRIDE_TEXT,
        "selector_qualified",
        True,
    ),
    Case("sparse-cell", None, None, "Unknown", "Unknown", "Unknown", False),
    Case("sparse-cell-with-row-override", None, "HEX:2", "Unknown", "Unknown", "Unknown", False),
    Case(
        "entry-without-a-decoded-value",
        _undecoded(evidence_grade="Proven"),
        None,
        "Proven",
        "Unknown",
        "selector_qualified",
        False,
    ),
    Case(
        "entry-level-provenance-fallback",
        _no_description(codec_provenance="length_inferred"),
        None,
        "Unknown",
        "Hypothesis",
        "length_inferred",
        False,
    ),
    Case(
        "no-provenance-anywhere",
        _no_description(),
        None,
        "Unknown",
        "Hypothesis",
        "Unknown",
        False,
    ),
    Case(
        "description-provenance-wins",
        _entry(codec_provenance="length_inferred"),
        None,
        "Unknown",
        "Hypothesis",
        "selector_qualified",
        False,
    ),
    Case(
        "unsupported-grade",
        _entry(evidence_grade="proven"),
        None,
        "Unknown",
        "Hypothesis",
        "selector_qualified",
        False,
    ),
]


def _artifact(entry: dict[str, Any] | None, override: str | None) -> dict[str, Any]:
    registers: dict[str, Any] = {} if entry is None else {"0x0005": entry}
    artifact: dict[str, Any] = {
        "schema_version": "2.3",
        "operations": {
            "0x02": {
                "groups": {
                    "0x01": {
                        "instances": {
                            # A neighbouring instance keeps the row visible when the selected
                            # cell is sparse; its entry must never leak into the selected cell.
                            "0x00": {
                                "registers": {
                                    "0x0005": _entry(
                                        evidence_grade="Hypothesis", codec_provenance="neighbour"
                                    )
                                }
                            },
                            "0x01": {"registers": registers},
                        }
                    }
                }
            }
        },
    }
    if override is not None:
        artifact["meta"] = {
            "type_overrides": {"0x01": {"operations": {"0x02": {"0x0005": override}}}}
        }
    return artifact


def _viewer_text(artifact: dict[str, Any]) -> str:
    output = StringIO()
    console = Console(file=output, width=140, height=40, color_system=None)
    state = _State(sheets=_build_sheets(artifact))
    state.col_idx = 1  # instance 0x01
    console.print(_render(console, artifact, state))
    return output.getvalue()


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_helper_resolves_each_case(case: Case) -> None:
    before = deepcopy(case.entry)

    display = entry_evidence_display(case.entry, type_override=case.override)

    assert (
        display.grade,
        display.decoded_text,
        display.codec_provenance,
        display.override_applies,
    ) == (case.grade, case.decoded, case.provenance, case.overridden)
    assert case.entry == before


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_viewer_and_helper_agree(case: Case) -> None:
    artifact = _artifact(case.entry, case.override)
    selected = artifact["operations"]["0x02"]["groups"]["0x01"]["instances"]["0x01"]["registers"]
    display = entry_evidence_display(
        selected.get("0x0005"),
        type_override=get_row_type_override(
            artifact, group_key="0x01", rr_key="0x0005", op_key="0x02"
        ),
    )

    view = _viewer_text(artifact)

    assert "II=0x01" in view
    assert f"Entry evidence: {display.grade}" in view
    assert f"Decoded value: {display.decoded_text}" in view
    assert f"(codec_provenance={display.codec_provenance})" in view
    assert ("manual type override" in view) is display.override_applies
    assert "Decoded value: Proven" not in view
    # ... and the helper's verdict is the expected one, so the viewer's output is as well.
    assert (display.grade, display.decoded_text, display.codec_provenance) == (
        case.grade,
        case.decoded,
        case.provenance,
    )


def _row() -> RegisterRow:
    address = RegisterAddress(
        protocol="b524",
        group_key="0x01",
        namespace_key="0x02",
        namespace_label=None,
        instance_key="0x01",
        register_key="0x0005",
        read_opcode="0x02",
    )
    return RegisterRow(
        row_id="row",
        protocol="b524",
        group_key="0x01",
        namespace_key="0x02",
        namespace_label=None,
        section_key=None,
        group_name="Group",
        instance_key="0x01",
        register_key="0x0005",
        name="0x0005",
        myvaillant_name="name",
        ebusd_name="",
        path="path",
        tab="config",
        address=address,
        value_text="1",
        raw_hex="0100",
        unit="n/a",
        access_flags="writable_visible",
        last_update_text="",
        age_text="",
        change_indicator="-",
        search_blob="",
    )


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_browser_rows_agree_with_the_helper(case: Case) -> None:
    sections = register_detail_sections(
        row=_row(), entry=case.entry, description=None, type_override=case.override
    )

    rows = {row.label: row for section in sections for row in section.rows}
    assert rows["Entry evidence"].value == case.grade
    decoded = rows["Decoded value"]
    assert (f"{decoded.value} ({decoded.note})" if decoded.note else decoded.value) == case.decoded
    assert bool(decoded.note) is case.overridden
    assert rows["Codec provenance"].value == case.provenance
    assert "Decoded evidence" not in rows and "Decoded interpretation" not in rows


def _html_cell_evidence(cases: list[Case]) -> list[dict[str, Any]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated HTML agreement check")
    artifact = _artifact(None, None)
    registers = artifact["operations"]["0x02"]["groups"]["0x01"]["instances"]
    # One register per case, all on the selected instance 0x01; sparse cases leave it out.
    registers["0x01"]["registers"] = {}
    calls = []
    for index, case in enumerate(cases):
        register = f"0x{0x0100 + index:04x}"
        if case.entry is not None:
            registers["0x01"]["registers"][register] = case.entry
        calls.append(["0x02", "0x01", "0x01", register, case.entry is not None, case.override])
    html = render_html_report(artifact)
    start = html.index("const B524_ENTRY_EVIDENCE_LABELS")
    end = html.index("function b524CorrespondenceSecondaryText", start)
    script = html[start:end] + (
        "const calls = "
        + json.dumps(calls)
        + ";console.log(JSON.stringify(calls.map(([op, gg, ii, rr, has, override]) => "
        + "b524EntryEvidence(op, gg, ii, rr, has ? {} : null, override))));"
    )
    result = subprocess.run(
        [node, "-e", script], check=True, text=True, capture_output=True, timeout=10
    )
    return json.loads(result.stdout)  # type: ignore[no-any-return]


def test_html_report_agrees_with_the_helper_for_every_case() -> None:
    results = _html_cell_evidence(CASES)

    for case, result in zip(CASES, results, strict=True):
        assert (result["grade"], result["provenance"], result["overridden"]) == (
            case.grade,
            case.provenance,
            case.overridden,
        ), case.name
        assert result["lines"] == [
            f"Entry evidence: {case.grade}",
            f"Decoded value: {case.decoded}",
            f"Codec provenance: {case.provenance}",
        ], case.name


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown"])
def test_grade_accepts_exactly_the_three_case_sensitive_values(grade: str) -> None:
    assert entry_evidence_grade({"evidence_grade": grade}) == grade


@pytest.mark.parametrize(
    "grade", [None, "", "proven", "PROVEN", "Proven ", "qualified", "matched", True, 1, 0.5, [], {}]
)
def test_grade_rejects_everything_else_as_unknown(grade: object) -> None:
    assert entry_evidence_grade({"evidence_grade": grade}) == "Unknown"
    assert entry_evidence_grade({}) == "Unknown"
    assert entry_evidence_grade(None) == "Unknown"


def test_qualification_and_profile_match_never_supply_a_grade() -> None:
    entry = _entry()
    entry["parameter_description"]["target_profile_match"] = True
    entry["selector_qualified"] = True
    entry["qualified"] = True

    assert entry_evidence_grade(entry) == "Unknown"


def test_codec_provenance_precedence() -> None:
    both = _entry(codec_provenance="entry_level")
    assert entry_codec_provenance(both) == "selector_qualified"
    assert entry_codec_provenance(_no_description(codec_provenance="entry_level")) == "entry_level"
    # An empty description that names no provenance still falls back.
    assert entry_codec_provenance(_entry(parameter_description={}, codec_provenance="x")) == "x"
    assert entry_codec_provenance(_entry(parameter_description="bad", codec_provenance="x")) == "x"
    assert entry_codec_provenance(_no_description()) == "Unknown"
    assert entry_codec_provenance({}) == "Unknown"
    assert entry_codec_provenance(None) == "Unknown"


def test_override_applies_only_to_a_cell_that_holds_an_entry() -> None:
    assert manual_override_applies(_entry(), "HEX:2") is True
    assert manual_override_applies(_entry(), None) is False
    assert manual_override_applies(None, "HEX:2") is False
    assert manual_override_applies({}, "HEX:2") is False


def test_override_never_changes_the_retained_grade_or_provenance() -> None:
    entry = _entry(evidence_grade="Proven")

    plain = entry_evidence_display(entry)
    overridden = entry_evidence_display(entry, type_override="HEX:2")

    assert (plain.grade, plain.codec_provenance) == (overridden.grade, overridden.codec_provenance)
    assert (plain.override_applies, overridden.override_applies) == (False, True)


def test_observed_description_is_empty_unless_a_dict() -> None:
    assert observed_description(_entry()) == _entry()["parameter_description"]
    assert observed_description(_entry(parameter_description=None)) == {}
    assert observed_description(_entry(parameter_description=[1])) == {}
    assert observed_description(None) == {}


def test_viewer_keeps_exposing_the_override_lookup_it_always_had() -> None:
    from helianthus_vrc_explorer.ui import viewer

    assert viewer.get_row_type_override is evidence_display.get_row_type_override


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        (_entry(value=1), True),
        (_entry(value=0), True),
        (_entry(value=""), True),
        (_entry(value=False), True),
        (_entry(value=None), False),
        (_entry(value=None, error="parse_error: x"), False),
        ({"raw_hex": "0100"}, False),
        ({}, False),
        (None, False),
    ],
)
def test_a_decoded_value_is_any_value_that_is_not_missing(
    entry: dict[str, Any] | None, expected: bool
) -> None:
    assert entry_has_decoded_value(entry) is expected


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown", "proven", None])
@pytest.mark.parametrize("value", [None, 0, 1])
@pytest.mark.parametrize("override", [None, "HEX:2"])
def test_a_decoded_value_is_never_better_than_hypothesis(
    grade: str | None, value: int | None, override: str | None
) -> None:
    entry = _entry(value=value)
    if grade is not None:
        entry["evidence_grade"] = grade

    display = entry_evidence_display(entry, type_override=override)

    assert display.decoded_value in {"Hypothesis", "Unknown"}
    assert not display.decoded_text.startswith("Proven")
