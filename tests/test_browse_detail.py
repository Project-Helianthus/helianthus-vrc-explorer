from __future__ import annotations

from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
    B524RegisterNameCorrespondence,
)
from helianthus_vrc_explorer.ui.b524_operation_reads import OperationReadView
from helianthus_vrc_explorer.ui.browse_detail import (
    DetailSection,
    node_detail_sections,
    register_detail_sections,
)
from helianthus_vrc_explorer.ui.browse_models import RegisterAddress, RegisterRow, TreeNodeRef


def _row(
    *,
    read_opcode: str | None = "0x02",
    group_key: str | None = "0x09",
    instance_key: str | None = "0x01",
    register_key: str = "0x0002",
    unit: str = "n/a",
    ebusd_name: str = "",
    myvaillant_name: str = "operating_mode",
) -> RegisterRow:
    address = RegisterAddress(
        protocol="b524",
        group_key=group_key,
        namespace_key=read_opcode,
        namespace_label=None,
        instance_key=instance_key,
        register_key=register_key,
        read_opcode=read_opcode,
    )
    return RegisterRow(
        row_id=f"row:{register_key}",
        protocol="b524",
        group_key=group_key,
        namespace_key=read_opcode,
        namespace_label=None,
        section_key=None,
        group_name="Ventilation",
        instance_key=instance_key,
        register_key=register_key,
        name=register_key,
        myvaillant_name=myvaillant_name,
        ebusd_name=ebusd_name,
        path="B524/op02/ventilation/0x01/operating_mode",
        tab="config",
        address=address,
        value_text="NORMAL (2)",
        raw_hex="02",
        unit=unit,
        access_flags="writable_visible",
        last_update_text="2026-10-09T12:00:00Z",
        age_text="1.0s",
        change_indicator="-",
        search_blob="",
    )


def _section(sections: tuple[DetailSection, ...], title: str) -> DetailSection | None:
    for section in sections:
        if section.title == title:
            return section
    return None


def test_header_and_value_sections_render_name_address_status_and_raw() -> None:
    row = _row()
    entry = {
        "read_opcode": "0x02",
        "type": "UCH",
        "value": 2,
        "raw_hex": "02",
        "flags": 3,
        "flags_access": "writable_visible",
        "response_state": "active",
    }
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)

    header = sections[0]
    assert header.title == ""
    header_text = " ".join(f"{r.label} {r.value}" for r in header.rows)
    assert "operating_mode" in header_text
    assert row.address.label in header_text
    assert "OK" in header_text

    value = _section(sections, "VALUE")
    assert value is not None
    value_text = " ".join(f"{r.label} {r.value}" for r in value.rows)
    assert "NORMAL (2)" in value_text
    assert "02" in value_text


def test_type_section_uses_codec_label_table() -> None:
    row = _row()
    entry = {"type": "EXP", "raw_hex": "0000a040", "value": 5.0, "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    type_section = _section(sections, "TYPE")
    assert type_section is not None
    text = " ".join(f"{r.label} {r.value}" for r in type_section.rows)
    assert "EXP" in text
    assert "decimal number" in text


def test_type_section_degrades_unknown_codec_to_verbatim_and_byte_count() -> None:
    row = _row()
    entry = {"type": "WIDGET:7", "raw_hex": "0011223344", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    type_section = _section(sections, "TYPE")
    assert type_section is not None
    text = " ".join(f"{r.label} {r.value}" for r in type_section.rows)
    assert "WIDGET:7" in text
    assert "5 bytes" in text
    assert "unknown" in text


def test_limits_section_omitted_when_no_description_and_no_catalog_evidence() -> None:
    row = _row()
    entry = {"type": "EXP", "raw_hex": "00000000", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    assert _section(sections, "LIMITS") is None


def test_limits_section_states_source_and_incompleteness() -> None:
    row = _row()
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    description = {
        "type": "UCH",
        "min": 0,
        "max": 5,
        "step": None,
        "step_qualification": "unknown",
        "qualification": "matched",
        "source": "live",
    }
    sections = register_detail_sections(
        row=row, entry=entry, description=description, correspondence=None
    )
    limits = _section(sections, "LIMITS")
    assert limits is not None
    text = " ".join(f"{r.label} {r.value} {r.note}" for r in limits.rows)
    assert "min=0" in text
    assert "max=5" in text
    assert "incomplete" in text
    assert "live" in text


def test_limits_section_shows_catalog_evidence_as_unqualified() -> None:
    row = _row()
    entry = {
        "type": "EXP",
        "raw_hex": "00000000",
        "flags_access": "writable_visible",
        "constraint_type": "f32_range",
        "constraint_min": 0,
        "constraint_max": 40,
        "constraint_step": 0.5,
    }
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    limits = _section(sections, "LIMITS")
    assert limits is not None
    text = " ".join(f"{r.label} {r.value} {r.note}" for r in limits.rows)
    assert "catalog evidence" in text.lower()
    assert "unqualified" in text.lower()


def test_unknown_register_shows_fallback_name_flags_and_raw_unqualified_description() -> None:
    row = _row(register_key="0x0075", myvaillant_name="")
    entry = {
        "type": "UCH",
        "raw_hex": "00",
        "flags": 0,
        "flags_access": "read_only_not_visible",
        "parameter_description": {
            "qualification": "matched",
            "codec_provenance": "length_inferred",
            "reply_hex": "007500000101",
            "type": "UCH",
            "min": 0,
            "max": 1,
            "step": 1,
        },
    }
    sections = register_detail_sections(row=row, entry=entry, description=None)
    header = _section(sections, "")
    limits = _section(sections, "LIMITS")
    flags = _section(sections, "FLAGS")
    gates = _section(sections, "GATES")
    assert header is not None and header.rows[0].value == "0x0075"
    assert limits is not None and "raw_description_evidence" in limits.rows[0].note
    assert flags is not None and "0 → read_only_not_visible" in flags.rows[0].value
    assert gates is not None and any(row.value == "unqualified" for row in gates.rows)


def test_flags_section_splits_access_into_two_facets() -> None:
    row = _row()
    entry = {"type": "UCH", "raw_hex": "02", "flags": 3, "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    flags = _section(sections, "FLAGS")
    assert flags is not None
    text = " ".join(f"{r.label} {r.value}" for r in flags.rows)
    assert "writable" in text
    assert "visible" in text
    assert "no role, volatility, persistence or connected-device state" in flags.note


def test_gates_section_g1_flags_legacy_access_label_as_unknown_not_read_only() -> None:
    """Pins the child_lock/user_rw observation from the plan (section 2.4): a
    legacy label must be surfaced as the real reason, never silently implied
    read-only."""
    row = _row()
    entry = {"type": "BOOL", "raw_hex": "03", "flags": 3, "flags_access": "user_rw"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    gates = _section(sections, "GATES")
    assert gates is not None
    access_row = next(r for r in gates.rows if r.label == "Write gate")
    assert access_row.value == "unknown"
    assert "user_rw" in access_row.note
    assert "not a recognised writable label" in access_row.note


def test_gates_section_reports_g1_through_g8() -> None:
    row = _row()
    entry = {
        "type": "UCH",
        "raw_hex": "02",
        "flags": 3,
        "flags_access": "writable_visible",
        "enum_options": [
            {
                "value": 2,
                "label": "NORMAL",
                "gate": {"qualification": "qualified", "state": True},
            }
        ],
    }
    description = {
        "type": "UCH",
        "min": 0,
        "max": 5,
        "step": 1,
        "qualification": "matched",
        "source": "live",
    }
    sections = register_detail_sections(
        row=row, entry=entry, description=description, correspondence=None
    )
    gates = _section(sections, "GATES")
    assert gates is not None
    labels = {r.label for r in gates.rows}
    assert {
        "Write gate",
        "Description",
        "Limits",
        "Codec",
        "Profile",
        "Enum gate",
        "Route",
    } <= labels


def test_names_section_explorer_name_is_first_and_ebusd_name_included() -> None:
    row = _row(ebusd_name="Hc1OperatingMode")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    names = _section(sections, "NAMES")
    assert names is not None
    assert names.rows[0].label == "Explorer"
    assert names.rows[0].value == "operating_mode"
    assert any(r.label == "eBUSd" and r.value == "Hc1OperatingMode" for r in names.rows)


def test_unit_section_always_present_and_not_recorded_for_b524() -> None:
    row = _row(unit="n/a")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    unit = _section(sections, "UNIT")
    assert unit is not None
    assert unit.rows[0].value == "not recorded"


def test_unit_section_shows_real_unit_for_b516() -> None:
    row = _row(unit="kWh")
    entry = {"type": "UIN", "raw_hex": "0001", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    unit = _section(sections, "UNIT")
    assert unit is not None
    assert unit.rows[0].value == "kWh"


def test_enumeration_section_absent_when_no_enum_options_and_no_bool_fallback() -> None:
    # register_key/group_key chosen to avoid the real bundled value-label
    # catalog match at (opcode=0x02, group=0x09, register=0x0002).
    row = _row(group_key="0x09", register_key="0x0099")
    entry = {"type": "EXP", "raw_hex": "00000000", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    assert _section(sections, "ENUMERATION") is None


def test_enumeration_section_present_with_gate_reason_when_enum_options_recorded() -> None:
    row = _row(register_key="0x0002")
    entry = {
        "type": "UCH",
        "raw_hex": "02",
        "flags_access": "writable_visible",
        "enum_options": [
            {"value": 1, "label": "TIME_CONTROLLED"},
            {"value": 2, "label": "NORMAL"},
        ],
    }
    description = {"min": 2, "max": 3, "step": 1}
    sections = register_detail_sections(
        row=row, entry=entry, description=description, correspondence=None
    )
    enumeration = _section(sections, "ENUMERATION")
    assert enumeration is not None
    assert "candidate" in enumeration.note
    assert "no per-code gate evidence" in enumeration.note
    values = {r.label for r in enumeration.rows}
    assert values == {"1", "2"}


def test_enumeration_section_present_for_bool_fallback_without_enum_options() -> None:
    row = _row(group_key="0x09", register_key="0x0099")
    entry = {"type": "BOOL", "raw_hex": "01", "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    enumeration = _section(sections, "ENUMERATION")
    assert enumeration is not None
    labels = sorted(r.value for r in enumeration.rows)
    assert any("OFF" in label for label in labels)
    assert any("ON" in label for label in labels)


def test_evidence_section_carries_reply_and_qualification_fields() -> None:
    row = _row()
    entry = {
        "type": "UCH",
        "raw_hex": "02",
        "flags_access": "writable_visible",
        "reply_hex": "03090200 02",
        "response_state": "active",
        "value_label_qualification": "candidate_unqualified",
    }
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    evidence = _section(sections, "EVIDENCE")
    assert evidence is not None
    text = " ".join(f"{r.label} {r.value}" for r in evidence.rows)
    assert "reply_hex" in text
    assert "candidate_unqualified" in text


def test_entry_none_renders_header_and_no_artifact_entry_note() -> None:
    row = _row()
    sections = register_detail_sections(row=row, entry=None, description=None, correspondence=None)
    text = " ".join(" ".join(f"{r.label} {r.value}" for r in s.rows) for s in sections)
    assert "No artifact entry for this row." in text


def test_non_op02_op06_row_renders_value_type_evidence_only_with_applicability_note() -> None:
    row = _row(read_opcode="0x00", group_key=None, instance_key=None, register_key="0x0001")
    entry = {"type": "UIN", "raw_hex": "0002", "value": 2, "flags_access": "read-only"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)

    assert _section(sections, "LIMITS") is None
    assert _section(sections, "GATES") is None
    assert _section(sections, "NAMES") is None
    assert _section(sections, "ENUMERATION") is None
    assert _section(sections, "VALUE") is not None
    assert _section(sections, "TYPE") is not None

    text = " ".join(" ".join(f"{r.label} {r.value}" for r in s.rows) for s in sections)
    assert "No concrete OP02/OP06 selector" in text


def test_operation_read_variant_shows_decode_qualification_and_no_limits_or_names() -> None:
    row = _row(
        read_opcode="0x03", group_key="selector-id", instance_key=None, register_key="channel"
    )
    view = OperationReadView(
        opcode_hex="0x03",
        title="OP03 ReadTimer",
        selector_key="selector-key",
        selector_label="Zone 1 Monday",
        request_payload_hex="0903020001ff",
        response_raw_hex="03ff000648908fff",
        response_state="value",
        qualification="schema_unqualified",
        selector_correlation="matches_request",
        request_attempts=1,
        fields=(("channel", "heating"), ("on_time", "06:00")),
    )
    sections = register_detail_sections(
        row=row, entry=None, description=None, correspondence=None, operation_view=view
    )
    assert _section(sections, "LIMITS") is None
    assert _section(sections, "NAMES") is None
    assert _section(sections, "ENUMERATION") is None
    decode = _section(sections, "DECODE QUALIFICATION")
    assert decode is not None
    text = " ".join(f"{r.label} {r.value}" for r in decode.rows)
    assert "schema_unqualified" in text
    assert "matches_request" in text
    value_section = _section(sections, "VALUE")
    assert value_section is not None
    value_text = " ".join(f"{r.label} {r.value}" for r in value_section.rows)
    assert "heating" in value_text
    assert "06:00" in value_text


def test_node_detail_sections_for_navigation_node_shows_hint_and_row_count() -> None:
    node = TreeNodeRef(
        node_id="b524:group:0x09", label="Ventilation", level="group", protocol="b524"
    )
    sections = node_detail_sections(node, row_count=0)
    text = " ".join(" ".join(f"{r.label} {r.value}" for r in s.rows) for s in sections)
    assert "Ventilation" in text
    assert "0" in text


def test_node_detail_sections_with_no_selection_shows_select_hint() -> None:
    sections = node_detail_sections(None, row_count=12)
    text = " ".join(" ".join(f"{r.label} {r.value}" for r in s.rows) for s in sections)
    assert "Select a register to see its details." in text


def test_names_section_includes_correspondence_rows_with_explorer_name_first() -> None:
    row = _row(group_key="0x09", instance_key="0x01", register_key="0x0002")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    correspondence = B524RegisterNameCorrespondence(
        name="operating_mode",
        vaillant_friendly_name=("Operating mode",),
        vaillant_name_vrc720=("Betriebsart",),
        vaillant_name_vrc700=(),
        myvaillant_name_vrc720=("Mode",),
        myvaillant_name_vrc700=(),
        ebusd_name=(),
    )
    sections = register_detail_sections(
        row=row, entry=entry, description=None, correspondence=correspondence
    )
    names = next(s for s in sections if s.title == "NAMES")
    assert names.rows[0].label == "Explorer"
    labels = [r.label for r in names.rows]
    assert "Vaillant friendly name" in labels
    assert "Vaillant name (VRC720)" in labels
    assert "myVaillant name (VRC720)" in labels
    # The section carries names only: every row uses one of the fixed labels.
    allowed = {
        "Explorer",
        "myvaillant_name provenance",
        "Observed-name identification",
        "docs-ebus catalog name",
        "docs-ebus previous name",
        "Vaillant friendly name",
        "Vaillant name (VRC720)",
        "Vaillant name (VRC700)",
        "myVaillant name (VRC720)",
        "myVaillant name (VRC700)",
        "eBUSd",
    }
    assert set(labels) <= allowed


def test_names_section_splits_multi_value_cells_onto_separate_rows() -> None:
    row = _row(group_key="0x09", instance_key="0x01", register_key="0x0002")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    correspondence = B524RegisterNameCorrespondence(
        name="operating_mode",
        vaillant_friendly_name=("Operating mode", "Mode of operation"),
        vaillant_name_vrc720=(),
        vaillant_name_vrc700=(),
        myvaillant_name_vrc720=(),
        myvaillant_name_vrc700=(),
        ebusd_name=(),
    )
    sections = register_detail_sections(
        row=row, entry=entry, description=None, correspondence=correspondence
    )
    names = next(s for s in sections if s.title == "NAMES")
    friendly_rows = [r for r in names.rows if r.label == "Vaillant friendly name"]
    assert {r.value for r in friendly_rows} == {"Operating mode", "Mode of operation"}


def test_names_section_substitutes_hc_and_zone_placeholders_in_ebusd_template() -> None:
    row = _row(group_key="0x09", instance_key="0x01", register_key="0x0002")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    correspondence = B524RegisterNameCorrespondence(
        name="operating_mode",
        vaillant_friendly_name=(),
        vaillant_name_vrc720=(),
        vaillant_name_vrc700=(),
        myvaillant_name_vrc720=(),
        myvaillant_name_vrc700=(),
        ebusd_name=("Hc{hc}OperatingMode",),
    )
    sections = register_detail_sections(
        row=row, entry=entry, description=None, correspondence=correspondence
    )
    names = next(s for s in sections if s.title == "NAMES")
    ebusd_rows = [r for r in names.rows if r.label == "eBUSd"]
    # instance_key "0x01" -> hc = instance + 1 = 2, per resolved_ebusd_name.
    assert any(r.value == "Hc2OperatingMode" for r in ebusd_rows)


def test_names_section_shows_template_verbatim_when_instance_is_not_concrete() -> None:
    row = _row(read_opcode="0x02", group_key="0x09", instance_key="0x01", register_key="0x0002")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    correspondence = B524RegisterNameCorrespondence(
        name="operating_mode",
        vaillant_friendly_name=(),
        vaillant_name_vrc720=(),
        vaillant_name_vrc700=(),
        myvaillant_name_vrc720=(),
        myvaillant_name_vrc700=(),
        ebusd_name=("Zone{zone}Name",),
    )
    sections = register_detail_sections(
        row=row, entry=entry, description=None, correspondence=correspondence
    )
    names = next(s for s in sections if s.title == "NAMES")
    ebusd_rows = [r for r in names.rows if r.label == "eBUSd"]
    assert any(r.value == "Zone2Name" for r in ebusd_rows)


def test_vaillant_description_row_absent_without_a_description_column() -> None:
    """The 0.6.1 correspondence loader exposes no description column (OD-1); the
    panel must omit the row rather than invent or reuse the friendly name."""
    row = _row(group_key="0x09", instance_key="0x01", register_key="0x0002")
    entry = {"type": "UCH", "raw_hex": "02", "flags_access": "writable_visible"}
    correspondence = B524RegisterNameCorrespondence(
        name="operating_mode",
        vaillant_friendly_name=("Operating mode",),
        vaillant_name_vrc720=(),
        vaillant_name_vrc700=(),
        myvaillant_name_vrc720=(),
        myvaillant_name_vrc700=(),
        ebusd_name=(),
    )
    sections = register_detail_sections(
        row=row, entry=entry, description=None, correspondence=correspondence
    )
    names = next(s for s in sections if s.title == "NAMES")
    assert not any(r.label == "Vaillant description" for r in names.rows)


def test_edit_section_editable_yes_for_writable_visible() -> None:
    from helianthus_vrc_explorer.ui.browse_detail import editable_state

    entry = {"type": "UCH", "raw_hex": "02", "flags": 3, "flags_access": "writable_visible"}
    editable, reason = editable_state(entry, tab="config")
    assert editable is True
    assert reason == ""


def test_edit_section_editable_no_for_read_only_visible() -> None:
    from helianthus_vrc_explorer.ui.browse_detail import editable_state

    entry = {"type": "UCH", "raw_hex": "01", "flags": 1, "flags_access": "read_only_visible"}
    editable, reason = editable_state(entry, tab="state")
    assert editable is False
    assert "read-only" in reason


def test_edit_section_surfaces_legacy_access_label_as_the_real_reason() -> None:
    from helianthus_vrc_explorer.ui.browse_detail import editable_state

    entry = {"type": "BOOL", "raw_hex": "03", "flags": 3, "flags_access": "user_rw"}
    editable, reason = editable_state(entry, tab="config")
    assert editable is False
    assert "user_rw" in reason
    assert "not a recognised writable label" in reason


def test_edit_section_appears_in_register_detail_sections_with_hint() -> None:
    row = _row()
    entry = {"type": "UCH", "raw_hex": "02", "flags": 3, "flags_access": "writable_visible"}
    sections = register_detail_sections(row=row, entry=entry, description=None, correspondence=None)
    edit = _section(sections, "EDIT")
    assert edit is not None
    text = " ".join(f"{r.label} {r.value} {r.note}" for r in edit.rows)
    assert "yes" in text
    assert "press e to edit" in text


def test_enumeration_rows_carry_the_reason_the_edit_dialog_disables_a_choice() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import parameter_enum_choices

    row = _row(register_key="0x0002")
    entry = {
        "type": "UCH",
        "raw_hex": "01",
        "flags_access": "writable_visible",
        "enum_options": [
            {"value": 0, "label": "OFF"},
            {"value": 1, "label": "ON"},
            {"value": 2, "label": "AUTO"},
        ],
    }
    description = {"min": 0, "max": 1, "step": 1}
    sections = register_detail_sections(
        row=row, entry=entry, description=description, correspondence=None
    )
    enumeration = _section(sections, "ENUMERATION")
    assert enumeration is not None
    shown = {r.label: r.value for r in enumeration.rows}
    assert "Outside described range" in shown["2"]
    assert "Outside described range" not in shown["1"]

    # The panel shows exactly what the edit dialog is given for the same row.
    dialog = parameter_enum_choices(
        entry, read_opcode=0x02, group=0x09, register=0x0002, description=description
    )
    assert shown == {str(choice.value): choice.display for choice in dialog}
    assert [choice.enabled for choice in dialog] == [True, True, False]


def test_operation_export_row_matches_what_the_edit_action_supports() -> None:
    from dataclasses import replace

    from helianthus_vrc_explorer.ui.b524_operation_reads import OPERATION_EXPORT_BY_SECTION

    assert "operation_08" not in OPERATION_EXPORT_BY_SECTION
    for section_key, opcode_hex in (
        ("operation_03", "0x03"),
        ("operation_08", "0x08"),
        ("operation_09", "0x09"),
        ("operation_0b", "0x0b"),
    ):
        row = replace(
            _row(
                read_opcode=opcode_hex,
                group_key="selector-id",
                instance_key=None,
                register_key="channel",
            ),
            section_key=section_key,
        )
        view = OperationReadView(
            opcode_hex=opcode_hex,
            title="operation read",
            selector_key="selector-key",
            selector_label="selector",
            request_payload_hex="00",
            response_raw_hex="00",
            response_state="value",
            qualification="schema_unqualified",
            selector_correlation="matches_request",
            request_attempts=1,
            fields=(),
        )
        sections = register_detail_sections(
            row=row, entry=None, description=None, correspondence=None, operation_view=view
        )
        decode = _section(sections, "DECODE QUALIFICATION")
        assert decode is not None
        export = next(r for r in decode.rows if r.label == "Export")
        if section_key in OPERATION_EXPORT_BY_SECTION:
            assert export.value == "offline export available with e"
        else:
            assert export.value == "no offline export for this operation"


def test_docs_catalog_names_are_labelled_secondary_provisional_annotations() -> None:
    row = _row(
        group_key="0x00", instance_key="0x01", register_key="0x0007", myvaillant_name="system_off"
    )
    sections = register_detail_sections(row=row, entry={}, description=None)
    names = _section(sections, "NAMES")
    assert names is not None
    assert names.rows[0].value == "system_off"
    labels = {item.label: item.value for item in names.rows}
    assert labels["docs-ebus catalog name (provisional)"] == "unknown_11"
    assert labels["docs-ebus previous name"] == "system_off"
    assert "Polarity unresolved" in labels["docs-ebus open question"]
    other = _row(read_opcode="0x06", group_key="0x00", register_key="0x0007")
    names = _section(register_detail_sections(row=other, entry={}, description=None), "NAMES")
    assert not any(item.label.startswith("docs-ebus") for item in names.rows)


def test_imported_app_names_render_with_family_and_hypothesis_caveat() -> None:
    from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
        b524_register_name_correspondence,
    )

    for register, family, expected in (
        (0x16, "VRC700", "operationModeVentilation"),
        (0xA2, "VRC720", "smartPhotovoltaicBufferOffset"),
    ):
        row = _row(group_key="0x00", instance_key="0x00", register_key=f"0x{register:04x}")
        correspondence = b524_register_name_correspondence(opcode=2, group=0, register=register)
        sections = register_detail_sections(
            row=row, entry={}, description=None, correspondence=correspondence
        )
        names = _section(sections, "NAMES")
        assert names is not None
        labels = {item.label: item.value for item in names.rows}
        assert labels[f"myVaillant name ({family})"] == expected
        assert "Hypothesis" in labels["Observed-name identification"]
        assert (
            "neither codec, value range nor write access" in labels["Observed-name identification"]
        )
