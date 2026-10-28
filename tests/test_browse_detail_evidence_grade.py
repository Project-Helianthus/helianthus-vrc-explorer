"""Browser detail pane: entry-level evidence grade and codec provenance rows.

The rows follow the rules the results viewer applies (``ui/evidence_display.py``): the
retained grade is shown as stored, a manual override adds a separate Hypothesis row and only
for a selected cell that holds an entry, a cell without an entry is Unknown, and the codec
provenance falls back to the entry-level field when the parameter description has none.
"""

from __future__ import annotations

import asyncio
import io
import re
from copy import deepcopy
from dataclasses import replace
from typing import Any

import pytest
from rich.console import Console
from textual.widgets import DataTable, Static, Tree

from helianthus_vrc_explorer.ui import browse_textual
from helianthus_vrc_explorer.ui.browse_detail import (
    DetailRow,
    DetailSection,
    register_detail_sections,
)
from helianthus_vrc_explorer.ui.browse_models import RegisterAddress, RegisterRow

OVERRIDE_NOTE = "manual type override; view only"


def _row() -> RegisterRow:
    address = RegisterAddress(
        protocol="b524",
        group_key="0x09",
        namespace_key="0x02",
        namespace_label=None,
        instance_key="0x01",
        register_key="0x0002",
        read_opcode="0x02",
    )
    return RegisterRow(
        row_id="row:0x0002",
        protocol="b524",
        group_key="0x09",
        namespace_key="0x02",
        namespace_label=None,
        section_key=None,
        group_name="Ventilation",
        instance_key="0x01",
        register_key="0x0002",
        name="0x0002",
        myvaillant_name="operating_mode",
        ebusd_name="",
        path="B524/op02/ventilation/0x01/operating_mode",
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


def _entry(**extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "UIN",
        "value": 1,
        "raw_hex": "0100",
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


def _value_rows(sections: tuple[DetailSection, ...]) -> list[DetailRow]:
    value = next(section for section in sections if section.title == "VALUE")
    return list(value.rows)


def _by_label(rows: list[DetailRow]) -> dict[str, DetailRow]:
    return {row.label: row for row in rows}


def _all_rows(sections: tuple[DetailSection, ...]) -> list[DetailRow]:
    return [row for section in sections for row in section.rows]


def _rendered(sections: tuple[DetailSection, ...]) -> str:
    console = Console(file=io.StringIO(), width=160, legacy_windows=False)
    console.print(browse_textual._render_detail_sections(sections))
    return console.file.getvalue()  # type: ignore[attr-defined,no-any-return]


def test_proven_retained_grade_is_shown_as_stored_beside_the_unqualified_codec() -> None:
    entry = _entry(evidence_grade="Proven")
    entry["parameter_description"] = {
        "qualification": "unqualified",
        "codec_provenance": "length_inferred",
    }
    before = deepcopy(entry)

    sections = register_detail_sections(row=_row(), entry=entry, description=None)

    rows = _value_rows(sections)
    assert [row.label for row in rows[:5]] == [
        "Interpreted",
        "RAW",
        "Entry evidence",
        "Decoded value",
        "Codec provenance",
    ]
    by_label = _by_label(rows)
    assert by_label["Entry evidence"].value == "Proven"
    # The retained bytes may be Proven; the decoded value never is.
    assert by_label["Decoded value"] == DetailRow("Decoded value", "Hypothesis")
    assert by_label["Codec provenance"].value == "length_inferred"
    assert entry == before
    text = _rendered(sections)
    assert "Entry evidence:" in text and "Proven" in text
    assert re.search(r"Decoded value:\s+Hypothesis", text)
    assert not re.search(r"Decoded value:\s+Proven", text)
    assert "Codec provenance:" in text and "length_inferred" in text


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown"])
def test_explicit_grade_is_shown_verbatim_without_qualification_changing_it(grade: str) -> None:
    entry = _entry(evidence_grade=grade)

    rows = _by_label(_value_rows(register_detail_sections(row=_row(), entry=entry, description={})))

    assert rows["Entry evidence"].value == grade
    assert rows["Decoded value"].value == "Hypothesis"
    assert rows["Codec provenance"].value == "selector_qualified"


@pytest.mark.parametrize("grade", [None, "qualified", "proven", "Proven ", True, 1, [], {}])
def test_missing_or_unsupported_grade_is_unknown_despite_a_qualified_codec(grade: object) -> None:
    entry = _entry(evidence_grade=grade)
    description = {"qualification": "matched", "codec_provenance": "selector_qualified"}

    rows = _by_label(
        _value_rows(register_detail_sections(row=_row(), entry=entry, description=description))
    )

    assert rows["Entry evidence"].value == "Unknown"
    assert rows["Decoded value"].value == "Hypothesis"


@pytest.mark.parametrize("grade", ["Proven", "Hypothesis", "Unknown", None])
def test_manual_override_on_the_selected_cell_replaces_the_decoded_value_with_its_override_form(
    grade: str | None,
) -> None:
    entry = _entry()
    if grade is not None:
        entry["evidence_grade"] = grade
    before = deepcopy(entry)

    sections = register_detail_sections(
        row=_row(), entry=entry, description=None, type_override="HEX:2"
    )

    rows = _value_rows(sections)
    by_label = _by_label(rows)
    assert by_label["Entry evidence"].value == (grade or "Unknown")
    assert by_label["Decoded value"] == DetailRow("Decoded value", "Hypothesis", note=OVERRIDE_NOTE)
    labels = [row.label for row in rows]
    assert labels.count("Decoded value") == 1
    assert labels.index("Entry evidence") + 1 == labels.index("Decoded value")
    assert entry == before
    assert "Decoded value:" in _rendered(sections)
    assert f"Hypothesis ({OVERRIDE_NOTE})" in _rendered(sections)


def test_override_note_is_absent_without_one() -> None:
    sections = register_detail_sections(row=_row(), entry=_entry(), description=None)

    assert _by_label(_value_rows(sections))["Decoded value"].note == ""
    assert "manual type override" not in _rendered(sections)


def test_entry_without_a_decoded_value_reads_unknown_for_the_decoded_value() -> None:
    entry = _entry(evidence_grade="Proven", value=None, error="parse_error: short payload")

    rows = _by_label(
        _value_rows(register_detail_sections(row=_row(), entry=entry, description=None))
    )

    assert rows["Entry evidence"].value == "Proven"
    assert rows["Decoded value"].value == "Unknown"


@pytest.mark.parametrize("type_override", [None, "HEX:2"])
def test_sparse_cell_is_unknown_and_never_overridden(type_override: str | None) -> None:
    # A row override applies to the whole row, but a cell with no entry holds no overridden decode.
    sections = register_detail_sections(
        row=_row(), entry=None, description=None, type_override=type_override
    )

    rows = _by_label(_all_rows(sections))
    assert rows["Note"].value == "No artifact entry for this row."
    assert rows["Entry evidence"].value == "Unknown"
    assert rows["Decoded value"] == DetailRow("Decoded value", "Unknown")
    assert rows["Codec provenance"].value == "Unknown"
    text = _rendered(sections)
    assert "Entry evidence:" in text and "Decoded value:" in text and "Unknown" in text
    assert "manual type override" not in text


def test_entry_level_codec_provenance_is_the_fallback_without_a_description() -> None:
    entry = _entry(codec_provenance="length_inferred")
    del entry["parameter_description"]

    rows = _by_label(
        _value_rows(register_detail_sections(row=_row(), entry=entry, description=None))
    )

    assert rows["Codec provenance"].value == "length_inferred"
    assert rows["Entry evidence"].value == "Unknown"


def test_description_codec_provenance_wins_over_the_entry_level_value() -> None:
    entry = _entry(codec_provenance="length_inferred")

    rows = _by_label(
        _value_rows(register_detail_sections(row=_row(), entry=entry, description=None))
    )

    assert rows["Codec provenance"].value == "selector_qualified"


def test_entry_without_any_provenance_reads_unknown() -> None:
    entry = _entry()
    del entry["parameter_description"]

    rows = _by_label(
        _value_rows(register_detail_sections(row=_row(), entry=entry, description=None))
    )

    assert rows["Codec provenance"].value == "Unknown"


def test_grade_rows_are_not_added_to_rows_that_carry_no_artifact_entry_by_design() -> None:
    row = replace(_row(), protocol="b516", group_key=None, instance_key=None)

    sections = register_detail_sections(row=row, entry=None, description=None)

    labels = _by_label(_all_rows(sections))
    assert "Entry evidence" not in labels and "Decoded value" not in labels


def _app_artifact(
    *, meta_overrides: dict[str, Any] | None = None, grade: str | None = "Proven"
) -> dict[str, Any]:
    entry = _entry()
    entry["read_opcode"] = "0x02"
    entry["response_state"] = "active"
    if grade is not None:
        entry["evidence_grade"] = grade
    artifact: dict[str, Any] = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "identity": {"eid": "BASV2", "sw": "0507", "hw": "1704"},
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "Ventilation",
                        "instances": {
                            "0x01": {"present": True, "registers": {"0x0002": entry}},
                            "0x02": {
                                "present": True,
                                "registers": {"0x0002": _entry(value=2, raw_hex="0200")},
                            },
                        },
                    }
                }
            }
        },
    }
    if meta_overrides is not None:
        artifact["meta"]["type_overrides"] = meta_overrides
    return artifact


def _detail_text(app: Any) -> str:
    content = app.query_one("#detail-content", Static).content
    console = Console(file=io.StringIO(), width=160, legacy_windows=False)
    console.print(content)
    return console.file.getvalue()  # type: ignore[no-any-return]


async def _select_instance(app: Any, pilot: Any, instance_key: str) -> None:
    node = next(
        item
        for item in app._store.tree_nodes
        if item.level == "instance"
        and item.namespace_key == "0x02"
        and item.group_key == "0x09"
        and item.instance_key == instance_key
    )
    app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[node.node_id])
    await pilot.pause()
    app._selected_node_id = node.node_id
    app.action_tab_config()
    await pilot.pause()
    app._refresh_table()
    await pilot.pause()
    table = app.query_one("#browse-table", DataTable)
    table.focus()
    table.move_cursor(row=0)
    await pilot.pause()


def _detail_for(artifact: dict[str, Any], instance_key: str) -> str:
    async def exercise() -> str:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_instance(app, pilot, instance_key)
            return _detail_text(app)

    return asyncio.run(exercise())


def test_browser_pane_shows_the_stored_grade_and_provenance_for_the_selected_entry() -> None:
    text = _detail_for(_app_artifact(), "0x01")

    assert "Entry evidence:" in text
    assert "Proven" in text
    assert "Decoded value:" in text
    assert "Decoded value: Proven" not in text
    assert "Codec provenance:" in text
    assert "selector_qualified" in text
    assert "manual type override" not in text


def test_browser_pane_applies_a_saved_row_override_to_the_selected_entry() -> None:
    overrides = {"0x09": {"operations": {"0x02": {"0x0002": "HEX:2"}}}}
    artifact = _app_artifact(meta_overrides=overrides)
    before = deepcopy(artifact)

    text = _detail_for(artifact, "0x01")

    assert "Entry evidence:" in text and "Proven" in text
    assert "Decoded value:" in text
    assert f"Hypothesis ({OVERRIDE_NOTE})" in text
    assert artifact == before


def test_browser_pane_does_not_borrow_a_neighbouring_instances_grade() -> None:
    # Instance 0x01 is graded Proven; the selected instance 0x02 entry carries no grade.
    text = _detail_for(_app_artifact(grade="Proven"), "0x02")

    assert "Entry evidence:" in text
    assert "Unknown" in text
    assert "Proven" not in text


def _override_tree(selector: tuple[str, str, str], spec: str) -> dict[str, Any]:
    group, operation, register = selector
    return {group: {"operations": {operation: {register: spec}}}}


# Selector of _row(): group 0x09, operation 0x02, register 0x0002. Each neighbour differs from
# it in exactly one field of the key the saved override is looked up by.
_ROW_SELECTOR = ("0x09", "0x02", "0x0002")
_NEIGHBOURS = {
    "group": ("0x0a", "0x02", "0x0002"),
    "operation": ("0x09", "0x06", "0x0002"),
    "register": ("0x09", "0x02", "0x0003"),
}


def _override_for(overrides: dict[str, Any]) -> str | None:
    artifact = {"schema_version": "2.3", "meta": {"type_overrides": overrides}, "operations": {}}
    app = browse_textual._BrowseApp(artifact, allow_write=False)
    return app._type_override_for_row(_row())  # type: ignore[attr-defined,no-any-return]


@pytest.mark.parametrize("field", sorted(_NEIGHBOURS))
def test_saved_override_of_a_neighbouring_selector_does_not_apply(field: str) -> None:
    assert _override_for(_override_tree(_NEIGHBOURS[field], "HEX:2")) is None


def test_saved_override_is_chosen_by_group_operation_and_register() -> None:
    overrides: dict[str, Any] = {}
    selectors = [*_NEIGHBOURS.values(), _ROW_SELECTOR]
    for group, operation, register in selectors:
        spec = "UIN" if (group, operation, register) == _ROW_SELECTOR else f"HEX:{register}{group}"
        operations = overrides.setdefault(group, {}).setdefault("operations", {})
        operations.setdefault(operation, {})[register] = spec

    assert _override_for(overrides) == "UIN"
    del overrides["0x09"]["operations"]["0x02"]["0x0002"]
    assert _override_for(overrides) is None


def test_rows_of_other_protocols_have_no_saved_override() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {"type_overrides": _override_tree(_ROW_SELECTOR, "UIN")},
        "operations": {},
    }
    app = browse_textual._BrowseApp(artifact, allow_write=False)
    other = replace(_row(), protocol="b516")

    assert app._type_override_for_row(other) is None  # type: ignore[attr-defined]
