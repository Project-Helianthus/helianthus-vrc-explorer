"""Pure, Textual-free content model for the Browser's register detail panel.

Every function here takes already-resolved data (a ``RegisterRow``, the raw
artifact entry, an effective parameter description, an optional name
correspondence row, an optional operation-read view) and returns an ordered
tuple of :class:`DetailSection`. Nothing here touches Textual, the artifact
as a whole, or the transport layer, so it is testable without an App and
without re-deriving selector semantics — see
``ui.browse_textual._selector_for_row`` for the live equivalent this module
intentionally does not import (importing it would create a circular import,
since ``browse_textual`` imports this module for widget wiring).

Sections are omitted entirely when they have no content; an omitted section
means "this concept does not apply here", while a row reading ``not
recorded`` means "we have no observation" (see the plan's distinction).
Nothing here writes to the artifact.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from ..scanner.register import namespace_availability_contract
from ..schema.b524_codec_labels import b524_codec_label
from ..schema.b524_constraints import constraint_scope_metadata
from ..schema.b524_register_name_correspondence import B524RegisterNameCorrespondence
from ..schema.myvaillant_map import MyvaillantRegisterName
from .b524_operation_reads import OPERATION_EXPORT_BY_SECTION, OperationReadView
from .browse_models import RegisterRow, TreeNodeRef
from .parameter_editor import parameter_enum_choices, parameter_value_display
from .register_semantics import entry_display_value_text, entry_status_kind, entry_status_label

_WRITABLE_ACCESS = frozenset({"writable_not_visible", "writable_visible"})
_KNOWN_ACCESS_LABELS = frozenset(
    {
        "writable_not_visible",
        "writable_visible",
        "read_only_not_visible",
        "read_only_visible",
        "absent",
        "unknown_status",
        "unknown",
    }
)
_FLAGS_FACETS: dict[str, tuple[str, str]] = {
    "writable_not_visible": ("writable", "not-visible"),
    "writable_visible": ("writable", "visible"),
    "read_only_not_visible": ("read-only", "not-visible"),
    "read_only_visible": ("read-only", "visible"),
}
_FLAGS_CAVEAT = (
    "Profile-scoped visibility/writability hints; no role, volatility, "
    "persistence or connected-device state."
)
_NO_SELECTOR_NOTE = (
    "No concrete OP02/OP06 selector; limits, names and enumeration are not applicable."
)
_EVIDENCE_FIELDS: tuple[str, ...] = (
    "reply_hex",
    "reply_kind",
    "response_state",
    "read_opcode",
    "read_opcode_label",
    "error",
    "candidate_name",
    "candidate_evidence",
    "value_label_qualification",
    "observed_before_live_write",
)


@dataclass(frozen=True, slots=True)
class DetailRow:
    label: str
    value: str
    note: str = ""


@dataclass(frozen=True, slots=True)
class DetailSection:
    title: str
    rows: tuple[DetailRow, ...]
    note: str = ""


def _explorer_name(row: RegisterRow) -> str:
    return row.myvaillant_name or row.name or row.register_key


def _has_concrete_selector(row: RegisterRow) -> bool:
    return (
        row.address.read_opcode in {"0x02", "0x06"}
        and row.group_key is not None
        and row.instance_key is not None
    )


def _header_section(row: RegisterRow, entry: dict[str, Any] | None) -> DetailSection:
    rows = (
        DetailRow("Name", _explorer_name(row)),
        DetailRow("Address", row.address.label),
        DetailRow("Status", entry_status_label(entry)),
    )
    return DetailSection(title="", rows=rows)


def _interpreted_value_text(row: RegisterRow, entry: dict[str, Any] | None) -> str:
    """Prefer a live entry's own interpreted value over the hydrated row text.

    `row.value_text` is a snapshot taken at hydration time. When a fresher
    entry is available -- most notably the live-edit context's just-read
    baseline (see `_entry_for_detail` in browse_textual.py) -- render that
    instead, the same way `_refresh_table()` recomputes the table's Value
    cell for OP02/OP06 rows.
    """

    if entry is None:
        return row.value_text
    if row.protocol == "b524" and row.address.read_opcode in {"0x02", "0x06"}:
        try:
            opcode = int(row.address.read_opcode, 0)
            group = int(row.group_key or "0", 0)
            register = int(row.register_key, 0)
        except ValueError:
            return row.value_text
        return parameter_value_display(entry, opcode=opcode, group=group, register=register)
    return entry_display_value_text(entry)


def _value_section(row: RegisterRow, entry: dict[str, Any] | None) -> DetailSection:
    rows: list[DetailRow] = [
        DetailRow("Interpreted", _interpreted_value_text(row, entry)),
        DetailRow("RAW", (entry.get("raw_hex") if entry else None) or row.raw_hex or "—"),
    ]
    if entry is not None:
        preview = entry.get("local_edit_preview")
        if isinstance(preview, dict):
            rows.append(
                DetailRow(
                    "Offline preview",
                    f"{preview.get('value')} [offline preview, not written to the device]",
                )
            )
        if entry.get("written"):
            written_at = entry.get("written_at")
            rows.append(DetailRow("Written", str(written_at) if written_at else "yes"))
        readback = entry.get("validated_readback")
        if isinstance(readback, dict) and readback:
            rows.append(
                DetailRow("Validated readback", ", ".join(f"{k}={v}" for k, v in readback.items()))
            )
    if row.last_update_text:
        rows.append(DetailRow("Updated", row.last_update_text))
    if row.age_text:
        rows.append(DetailRow("Age", row.age_text))
    return DetailSection(title="VALUE", rows=tuple(rows))


def _type_section(entry: dict[str, Any] | None) -> DetailSection | None:
    if entry is None:
        return None
    type_spec = entry.get("type")
    if not isinstance(type_spec, str) or not type_spec:
        return None
    label = b524_codec_label(type_spec)
    if label is not None:
        rows = (
            DetailRow("RAW codec", f"{type_spec} ({label.raw_shape})"),
            DetailRow("Interpreted", label.interpreted_shape),
        )
        return DetailSection(title="TYPE", rows=rows)
    raw_hex = entry.get("raw_hex")
    byte_count = None
    if isinstance(raw_hex, str) and raw_hex:
        try:
            byte_count = len(bytes.fromhex(raw_hex))
        except ValueError:
            byte_count = None
    shape = f"{byte_count} bytes" if byte_count is not None else "unknown width"
    rows = (
        DetailRow("RAW codec", f"{type_spec} ({shape})"),
        DetailRow("Interpreted", "unknown"),
    )
    return DetailSection(title="TYPE", rows=rows)


def _limits_section(
    entry: dict[str, Any] | None, description: dict[str, Any] | None
) -> DetailSection | None:
    rows: list[DetailRow] = []
    if description is not None:
        minimum = description.get("min")
        maximum = description.get("max")
        step = description.get("step")
        step_qualification = description.get("step_qualification")
        source = description.get("source") or description.get("qualification") or "unknown"
        incomplete = any(value is None for value in (minimum, maximum, step))
        parts = [
            f"min={minimum if minimum is not None else '?'}",
            f"max={maximum if maximum is not None else '?'}",
            f"step={step if step is not None else '?'}",
        ]
        if step_qualification:
            parts.append(f"(step {step_qualification})")
        note = f"source: {source}"
        if incomplete:
            note += " — incomplete"
        rows.append(DetailRow("Described", " ".join(parts), note=note))
    if entry is not None and entry.get("constraint_type") is not None:
        constraint_type = entry.get("constraint_type")
        constraint_min = entry.get("constraint_min")
        constraint_max = entry.get("constraint_max")
        constraint_step = entry.get("constraint_step")
        scope = constraint_scope_metadata()
        rows.append(
            DetailRow(
                "Catalog evidence (unqualified)",
                f"{constraint_type} {constraint_min}..{constraint_max} step={constraint_step}",
                note=scope["applies_to"],
            )
        )
    if not rows:
        return None
    return DetailSection(title="LIMITS", rows=tuple(rows))


def _flags_section(entry: dict[str, Any] | None) -> DetailSection | None:
    if entry is None:
        return None
    flags = entry.get("flags")
    access = entry.get("flags_access")
    if flags is None and access is None:
        return None
    label = access if isinstance(access, str) else "unknown"
    facets = _FLAGS_FACETS.get(access) if isinstance(access, str) else None
    if facets is not None:
        label = f"{label} [{', '.join(facets)}]"
    flags_text = str(flags) if flags is not None else "?"
    rows = [DetailRow("Raw flags", f"{flags_text} → {label}")]
    reply_kind = entry.get("reply_kind")
    if reply_kind:
        rows.append(DetailRow("Reply kind", str(reply_kind)))
    return DetailSection(title="FLAGS", rows=tuple(rows), note=_FLAGS_CAVEAT)


def editable_state(entry: dict[str, Any] | None, *, tab: str) -> tuple[bool | None, str]:
    """Mirror browse_textual.action_edit_selected's own writability gate.

    This is a read-only duplicate for display, not a new gate: it reuses the
    exact same condition the live edit flow already enforces (flags_access
    first, then the raw FLAGS byte, then the state-tab heuristic) so the
    panel's "Editable" row can never say something the `e` key would
    contradict. It is intentionally not wired back into action_edit_selected
    to avoid touching the tested write-gate code path (OD-3).
    """

    if entry is None:
        return None, "no artifact entry for this row"
    flags = entry.get("flags")
    access = entry.get("flags_access")
    writable: bool | None
    if isinstance(access, str):
        writable = access in _WRITABLE_ACCESS
    else:
        writable_obj = entry.get("writable")
        writable = writable_obj if isinstance(writable_obj, bool) else None
    if writable is None and isinstance(flags, int) and flags in {0, 1, 2, 3}:
        writable = bool(flags & 2)

    if writable is False or (writable is None and tab == "state"):
        if isinstance(access, str) and access not in _WRITABLE_ACCESS:
            if access not in _KNOWN_ACCESS_LABELS:
                return (
                    False,
                    f"access label '{access}' is not a recognised writable label "
                    f"(raw flags={flags})",
                )
            return False, f"parameter is read-only (access={access})"
        return False, "parameter is read-only"

    type_spec = entry.get("type")
    if not isinstance(type_spec, str) or not type_spec:
        return False, "no type recorded for this register; cannot edit safely"
    if writable is None:
        return None, "writability unknown"
    return True, ""


def _edit_section(entry: dict[str, Any] | None, row: RegisterRow) -> DetailSection:
    editable, reason = editable_state(entry, tab=row.tab)
    if editable is True:
        value = "yes"
    elif editable is False:
        value = "no"
    else:
        value = "unknown"
    rows = [DetailRow("Editable", value, note=reason)]
    if editable is True:
        rows.append(
            DetailRow("Hint", "press e to edit (waits while a transport operation is running)")
        )
    return DetailSection(title="EDIT", rows=tuple(rows))


def _g1_access(entry: dict[str, Any] | None) -> DetailRow:
    if entry is None:
        return DetailRow("Write gate", "unknown", note="no artifact entry")
    access = entry.get("flags_access")
    flags = entry.get("flags")
    if isinstance(access, str) and access in _WRITABLE_ACCESS:
        return DetailRow("Write gate", "writable")
    if isinstance(access, str) and access in _KNOWN_ACCESS_LABELS:
        state = "read-only" if access.startswith("read_only") else access
        return DetailRow("Write gate", state)
    if isinstance(access, str):
        return DetailRow(
            "Write gate",
            "unknown",
            note=f"access label '{access}' is not a recognised writable label (raw flags={flags})",
        )
    return DetailRow("Write gate", "unknown")


def _gates_section(
    row: RegisterRow, entry: dict[str, Any] | None, description: dict[str, Any] | None
) -> DetailSection | None:
    rows: list[DetailRow] = [_g1_access(entry)]

    if description is not None:
        qualification = description.get("qualification")
        source = description.get("source") or qualification or "none"
        rows.append(DetailRow("Description", str(source)))
        incomplete = any(description.get(k) is None for k in ("min", "max", "step"))
        rows.append(DetailRow("Limits", "incomplete" if incomplete else "complete"))
        exact_qualifications = {"matched", "profile_qualified"}
        profile_state = "exact" if qualification in exact_qualifications else "unqualified"
        rows.append(DetailRow("Profile", profile_state))
    else:
        rows.append(DetailRow("Description", "none"))

    if entry is not None:
        type_spec = entry.get("type")
        if isinstance(type_spec, str) and type_spec:
            known = b524_codec_label(type_spec) is not None
            rows.append(
                DetailRow(
                    "Codec",
                    "ok" if known else "unsupported",
                    note="" if known else f"{type_spec} is not a recognised codec",
                )
            )

    if row.group_key is not None and row.address.read_opcode in {"0x02", "0x06"}:
        try:
            group_int = int(row.group_key, 0)
            opcode_int = int(row.address.read_opcode, 0)
            contract = namespace_availability_contract(group=group_int, opcode=opcode_int)  # type: ignore[arg-type]
        except (ValueError, KeyError):
            contract = None
        if contract is not None:
            if entry is None:
                presence = "unknown"
            else:
                presence = "absent" if entry_status_kind(entry) == "absent" else "present"
            rows.append(DetailRow("Instance", presence, note=contract.description))

    if entry is not None:
        enum_options = entry.get("enum_options")
        if isinstance(enum_options, list) and enum_options:
            has_gate = any(
                isinstance(option, dict) and isinstance(option.get("gate"), dict)
                for option in enum_options
            )
            rows.append(
                DetailRow(
                    "Enum gate",
                    "recorded" if has_gate else "no per-code gate evidence",
                )
            )

    if _has_concrete_selector(row):
        rows.append(DetailRow("Route", "concrete selector"))
    else:
        rows.append(DetailRow("Route", "no concrete OP02/OP06 selector"))

    return DetailSection(title="GATES", rows=tuple(rows))


def _substitute_ebusd_template(
    template: str, *, group: int | None, instance: int | None, register: int | None
) -> str:
    if group is None or instance is None or register is None:
        return f"{template} (template)"
    helper = MyvaillantRegisterName(leaf="", ebusd_name=template)
    resolved = helper.resolved_ebusd_name(group=group, instance=instance, register=register)
    return resolved if resolved is not None else f"{template} (template)"


def _names_section(
    row: RegisterRow,
    correspondence: B524RegisterNameCorrespondence | None,
) -> DetailSection:
    rows: list[DetailRow] = [DetailRow("Explorer", _explorer_name(row))]

    if correspondence is not None:
        try:
            group_int = int(row.group_key, 0) if row.group_key is not None else None
            instance_int = int(row.instance_key, 0) if row.instance_key is not None else None
            register_int = int(row.register_key, 0)
        except ValueError:
            group_int = instance_int = register_int = None

        for label, values in (
            ("Vaillant friendly name", correspondence.vaillant_friendly_name),
            ("Vaillant name (VRC720)", correspondence.vaillant_name_vrc720),
            ("Vaillant name (VRC700)", correspondence.vaillant_name_vrc700),
            ("myVaillant name (VRC720)", correspondence.myvaillant_name_vrc720),
            ("myVaillant name (VRC700)", correspondence.myvaillant_name_vrc700),
        ):
            for value in values:
                rows.append(DetailRow(label, value))

        for template in correspondence.ebusd_name:
            rows.append(
                DetailRow(
                    "eBUSd",
                    _substitute_ebusd_template(
                        template, group=group_int, instance=instance_int, register=register_int
                    ),
                )
            )

    if row.ebusd_name and not any(r.label == "eBUSd" for r in rows):
        rows.append(DetailRow("eBUSd", row.ebusd_name))

    return DetailSection(title="NAMES", rows=tuple(rows))


def _unit_section(row: RegisterRow) -> DetailSection:
    unit = row.unit.strip() if row.unit else ""
    if not unit or unit == "n/a":
        unit = "not recorded"
    return DetailSection(title="UNIT", rows=(DetailRow("Unit", unit),))


def _enumeration_section(
    row: RegisterRow, entry: dict[str, Any] | None, description: dict[str, Any] | None
) -> DetailSection | None:
    if entry is None or not _has_concrete_selector(row):
        return None
    type_spec = entry.get("type")
    if not isinstance(type_spec, str) or not type_spec:
        return None
    try:
        opcode = int(row.address.read_opcode or "0", 0)
        group = int(row.group_key or "0", 0)
        register = int(row.register_key, 0)
    except ValueError:
        return None
    # Same call the edit dialog makes, so a choice it disables is shown here
    # with the same reason.
    choices = parameter_enum_choices(
        entry, read_opcode=opcode, group=group, register=register, description=description
    )
    if not choices:
        return None
    rows = tuple(DetailRow(str(choice.value), choice.display) for choice in choices)
    note = "candidate labels, unqualified"
    enum_options = entry.get("enum_options")
    has_gate = isinstance(enum_options, list) and any(
        isinstance(option, dict) and isinstance(option.get("gate"), dict) for option in enum_options
    )
    if not has_gate:
        note += " — no per-code gate evidence recorded"
    return DetailSection(title="ENUMERATION", rows=rows, note=note)


def _evidence_section(
    entry: dict[str, Any] | None, description: dict[str, Any] | None
) -> DetailSection | None:
    if entry is None:
        return None
    rows: list[DetailRow] = []
    for field in _EVIDENCE_FIELDS:
        value = entry.get(field)
        if value in (None, ""):
            continue
        rows.append(DetailRow(field, str(value)))
    if description is not None:
        for field in ("qualification", "verification", "source"):
            value = description.get(field)
            if value:
                rows.append(DetailRow(f"description {field}", str(value)))
    if not rows:
        return None
    return DetailSection(title="EVIDENCE", rows=tuple(rows))


def _operation_detail_sections(
    row: RegisterRow, view: OperationReadView
) -> tuple[DetailSection, ...]:
    header = DetailSection(
        title="",
        rows=(
            DetailRow("Name", view.title),
            DetailRow("Selector", view.selector_label),
        ),
    )
    value_rows = [DetailRow(name, value) for name, value in view.fields]
    if view.response_raw_hex:
        value_rows.append(DetailRow("RAW", view.response_raw_hex))
    value_section = DetailSection(title="VALUE", rows=tuple(value_rows))
    decode_rows = [
        DetailRow("Qualification", view.qualification),
        DetailRow("Response state", view.response_state),
        DetailRow("Selector correlation", view.selector_correlation),
    ]
    if view.request_attempts is not None:
        decode_rows.append(DetailRow("Request attempts", str(view.request_attempts)))
    if (row.section_key or "") in OPERATION_EXPORT_BY_SECTION:
        decode_rows.append(DetailRow("Export", "offline export available with e"))
    else:
        decode_rows.append(DetailRow("Export", "no offline export for this operation"))
    decode_section = DetailSection(title="DECODE QUALIFICATION", rows=tuple(decode_rows))
    return (header, value_section, decode_section)


def register_detail_sections(
    *,
    row: RegisterRow,
    entry: dict[str, Any] | None,
    description: dict[str, Any] | None,
    correspondence: B524RegisterNameCorrespondence | None = None,
    operation_view: OperationReadView | None = None,
) -> tuple[DetailSection, ...]:
    """Build the ordered, omit-when-empty detail sections for one register row."""

    if operation_view is not None:
        return _operation_detail_sections(row, operation_view)

    if description is None and isinstance(entry, dict):
        observed = entry.get("parameter_description")
        if isinstance(observed, dict):
            description = deepcopy(observed)
            # Reaching this fallback means the resolver rejected the observed
            # description as an effective live or exact-profile description.
            # A selector-qualified codec describes only the scalar decode; it
            # does not qualify the profile that the resolver could not match.
            description["qualification"] = "unqualified"
            description["source"] = "raw_description_evidence"

    # A missing entry only signals an anomaly for a B524 row (every B524
    # register is supposed to resolve through the operations/groups/
    # instances/registers tree). B555/B516/B509 rows carry their value
    # directly on the RegisterRow instead of an "entry" dict, so entry is
    # always None for them -- that is normal, not an absent observation.
    if entry is None and row.protocol == "b524":
        header = _header_section(row, entry)
        note_section = DetailSection(
            title="",
            rows=(
                DetailRow("Note", "No artifact entry for this row."),
                DetailRow("Address", row.address.label),
                DetailRow("Path", row.path),
            ),
        )
        return (header, note_section)

    sections: list[DetailSection] = [_header_section(row, entry), _value_section(row, entry)]
    type_section = _type_section(entry)
    if type_section is not None:
        sections.append(type_section)

    if not _has_concrete_selector(row):
        sections.append(DetailSection(title="", rows=(DetailRow("Note", _NO_SELECTOR_NOTE),)))
        # UNIT is not part of the "not applicable" set (LIMITS/GATES/NAMES/
        # ENUMERATION): it is the one place a non-B524 protocol (B516) carries
        # a real, already-hardcoded unit (see the plan's section 3.5).
        sections.append(_unit_section(row))
        evidence = _evidence_section(entry, description)
        if evidence is not None:
            sections.append(evidence)
        return tuple(sections)

    limits = _limits_section(entry, description)
    if limits is not None:
        sections.append(limits)

    flags = _flags_section(entry)
    if flags is not None:
        sections.append(flags)

    gates = _gates_section(row, entry, description)
    if gates is not None:
        sections.append(gates)

    sections.append(_edit_section(entry, row))
    sections.append(_names_section(row, correspondence))
    sections.append(_unit_section(row))

    enumeration = _enumeration_section(row, entry, description)
    if enumeration is not None:
        sections.append(enumeration)

    evidence = _evidence_section(entry, description)
    if evidence is not None:
        sections.append(evidence)

    return tuple(sections)


def node_detail_sections(node: TreeNodeRef | None, *, row_count: int) -> tuple[DetailSection, ...]:
    """Build detail sections for a non-register tree selection (or no selection)."""

    if node is None:
        return (
            DetailSection(
                title="",
                rows=(
                    DetailRow("Note", "Select a register to see its details."),
                    DetailRow("Rows", str(row_count)),
                ),
            ),
        )

    rows: list[DetailRow] = [
        DetailRow("Note", "Select a register to see its details."),
        DetailRow("Label", node.label),
        DetailRow("Level", node.level),
    ]
    if node.protocol:
        rows.append(DetailRow("Protocol", node.protocol))
    if node.section_key:
        rows.append(DetailRow("Section", node.section_key))
    if node.group_key:
        rows.append(DetailRow("Group", node.group_key))
    if node.namespace_key:
        rows.append(DetailRow("Namespace", node.namespace_label or node.namespace_key))
    if node.instance_key:
        rows.append(DetailRow("Instance", node.instance_key))
    rows.append(DetailRow("Rows", str(row_count)))
    return (DetailSection(title="", rows=tuple(rows)),)
