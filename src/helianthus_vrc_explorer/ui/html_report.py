from __future__ import annotations

import json
import re
from functools import cache
from html import escape as _escape_html
from importlib.resources import files
from typing import Any

from ..artifact_schema import iter_register_entries, migrate_artifact_schema
from ..scanner.director import group_name_for_opcode
from ..schema.b524_register_name_correspondence import (
    OBSERVED_NAME_CAVEAT,
    b524_docs_catalog_correspondence,
    bundled_b524_register_name_correspondence,
)
from ..schema.b524_register_names import apply_b524_canonical_register_names
from ..schema.b524_value_labels import apply_b524_value_labels
from ..schema.parameter_descriptions import attach_bundled_descriptions, description_profile
from . import report_assets
from .emphasis import html_star_bold
from .evidence_display import (
    DECODED_GRADE,
    DECODED_LABEL,
    ENTRY_LABEL,
    EVIDENCE_GRADES,
    OVERRIDE_TEXT,
    PROVENANCE_LABEL,
    UNKNOWN,
    entry_evidence_display,
)


def _correspondence_json_map() -> dict[str, dict[str, dict[str, dict[str, list[str]]]]]:
    """Build the observed-name cross-reference table for client-side lookup.

    Purely presentational, resolved for this render only -- never written
    into the scan artifact.
    """
    table: dict[str, dict[str, dict[str, dict[str, list[str]]]]] = {}
    for (opcode, group, register), entry in bundled_b524_register_name_correspondence().items():
        opcode_key = f"0x{opcode:02x}"
        group_key = f"0x{group:02x}"
        register_key = f"0x{register:04x}"
        other_names = list(dict.fromkeys(entry.vaillant_name_vrc720 + entry.vaillant_name_vrc700))
        table.setdefault(opcode_key, {}).setdefault(group_key, {})[register_key] = {
            "vaillant_friendly_name": list(entry.vaillant_friendly_name),
            "vaillant_name": other_names,
            "ebusd_name": list(entry.ebusd_name),
            "myvaillant_name_vrc720": list(entry.myvaillant_name_vrc720),
            "myvaillant_name_vrc700": list(entry.myvaillant_name_vrc700),
        }
    return table


def _docs_catalog_json_map(artifact: dict[str, Any]) -> dict[str, dict[str, Any]]:
    table: dict[str, dict[str, Any]] = {}
    for op, gg, ii, rr, _entry in iter_register_entries(artifact):
        try:
            selector = tuple(int(value, 0) for value in (op, gg, ii, rr))
        except (ValueError, TypeError):
            continue
        entry = b524_docs_catalog_correspondence(
            opcode=selector[0],
            group=selector[1],
            instance=selector[2],
            register=selector[3],
        )
        if entry is not None:
            key = "/".join(
                f"0x{value:0{width}x}" for value, width in zip(selector, (2, 2, 2, 4), strict=True)
            )
            table[key] = {
                "name": entry.name,
                "previous_name": entry.previous_name,
                "provisional": entry.provisional,
                "open_question": entry.open_question,
            }
    return table


def _entry_evidence_rows(artifact: dict[str, Any]) -> list[list[Any]]:
    """Resolve the shared evidence rules once per entry for client-side lookup.

    Rows are ``[op, group, instance, register, entry_evidence, codec_provenance,
    decoded_value, explicit]`` using the artifact's own selector keys; ``explicit`` is
    whether the entry retains one of the three valid grades (so an explicit ``Unknown``
    is told apart from no grade). Entries that are neither explicit nor have any
    non-Unknown value are left out and read back as Unknown. Purely presentational,
    resolved for this render only -- never written into the scan artifact.
    """
    rows: list[list[Any]] = []
    for op, gg, ii, rr, entry in iter_register_entries(artifact):
        display = entry_evidence_display(entry)
        values = (display.grade, display.codec_provenance, display.decoded_value)
        grade = entry.get("evidence_grade") if isinstance(entry, dict) else None
        explicit = isinstance(grade, str) and grade in EVIDENCE_GRADES
        if explicit or any(value != UNKNOWN for value in values):
            rows.append([op, gg, ii, rr, *values, explicit])
    return rows


def _entry_evidence_labels() -> dict[str, str]:
    return {
        "entry": ENTRY_LABEL,
        "decoded": DECODED_LABEL,
        "decoded_grade": DECODED_GRADE,
        "override_text": OVERRIDE_TEXT,
        "provenance": PROVENANCE_LABEL,
        "unknown": UNKNOWN,
    }


def _json_for_html(obj: Any) -> str:
    """Dump JSON in a form that is safe to embed inside an HTML <script> tag."""

    raw = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    # Prevent `</script>` breaks and avoid HTML parser surprises.
    return (
        raw.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("'", "\\u0027")
    )


_PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")


def _substitute_template(template: str, substitutions: dict[str, str]) -> str:
    """Single-pass placeholder substitution (VE26-R3: prevents collision)."""
    return _PLACEHOLDER_RE.sub(
        lambda m: substitutions.get(m.group(0), m.group(0)),
        template,
    )


_REPORT_HEAD = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>__TITLE__</title>
    <style>
"""

_REPORT_BODY = """    </style>
  </head>
  <body>
    <header>
      <div class="title">Regulator Scan Browser</div>
      <div class="subtitle">
        This report is generated from the scan artifact.
        <span class="pill" id="metaDst"></span>
        <span class="pill" id="metaTs"></span>
        <span class="pill" id="metaIncomplete" style="display: none"></span>
      </div>
    </header>

__IDENTITY_CARD__

    <section class="sheet-card">
      <div class="tabs" id="tabs"></div>
      <div id="sheetArea"></div>
    </section>

    <script id="artifact-data" type="application/json">
__ARTIFACT_JSON__
    </script>

    <script>
"""

_REPORT_TAIL = """    </script>
  </body>
</html>
"""

_REPORT_CSS = "report.css"
_REPORT_JS = "report.js"


def _report_asset(name: str) -> str:
    """Read one packaged report asset as UTF-8 text, keeping its bytes unchanged."""
    return files(report_assets).joinpath(name).read_bytes().decode("utf-8")


@cache
def _report_template() -> str:
    """Assemble the report page; its placeholders are substituted in one pass at render time."""
    return (
        _REPORT_HEAD
        + _report_asset(_REPORT_CSS)
        + _REPORT_BODY
        + _report_asset(_REPORT_JS)
        + _REPORT_TAIL
    )


def render_html_report(artifact: dict[str, Any], *, title: str | None = None) -> str:
    # Ensure operations-first structure for consistent JS traversal.
    artifact, _migration = migrate_artifact_schema(artifact)
    # Grade and provenance are what the artifact retains: resolve them before the display passes
    # below normalise or annotate descriptions.
    entry_evidence = _entry_evidence_rows(artifact)
    apply_b524_value_labels(artifact)
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        apply_b524_canonical_register_names(operations)
    attach_bundled_descriptions(artifact)
    meta = artifact.get("meta")
    # Build group_name_map from operations-first structure
    group_name_map: dict[str, dict[str, dict[str, str]]] = {}
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        seen_groups: set[str] = set()
        for op_obj in operations.values():
            if not isinstance(op_obj, dict):
                continue
            op_groups = op_obj.get("groups")
            if isinstance(op_groups, dict):
                seen_groups.update(k for k in op_groups if isinstance(k, str))
        for group_key in seen_groups:
            try:
                group = int(group_key, 0)
            except ValueError:
                continue
            local_name = group_name_for_opcode(group, 0x02)
            local_presentation: dict[str, str] = {"name": local_name}
            if group == 0x00:
                # Presentation-only correction: scanner policy keeps its own
                # declared profile bounds and is intentionally not changed here.
                local_presentation["rr_max"] = "0x00FF"
            group_name_map[group_key] = {
                "0x02": local_presentation,
                "0x06": {"name": group_name_for_opcode(group, 0x06)},
            }
    identity_html = ""
    if isinstance(meta, dict):
        identity_obj = meta.get("identity")
        if not isinstance(identity_obj, dict):
            identity_obj = meta.get("resolved_identity")
        if isinstance(identity_obj, dict):
            rows: list[tuple[str, str]] = []
            from .regulator_identity import regulator_profile_label

            profile = regulator_profile_label(identity_obj)
            if profile:
                rows.append(("Profile", profile))
            for label, key in (
                ("Device", "device"),
                ("Model", "model"),
                ("Serial", "serial"),
                ("Firmware", "firmware"),
            ):
                value = identity_obj.get(key)
                if not isinstance(value, str):
                    continue
                text = value.strip()
                if not text or text == "n/a":
                    continue
                rows.append((label, text))
            if rows:
                cards = "".join(
                    (
                        '<div class="identity-row">'
                        f'<div class="identity-label">{_escape_html(label)}</div>'
                        f'<div class="identity-value">{html_star_bold(value)}</div>'
                        "</div>"
                    )
                    for label, value in rows
                )
                identity_html = (
                    '<section class="sheet-card identity-card">'
                    '<div class="section-title">Scan Identity</div>'
                    f'<div class="identity-grid">{cards}</div>'
                    "</section>"
                )
    page_title = title or "Regulator Scan Browser"
    return (
        _substitute_template(
            _report_template(),
            {
                "__TITLE__": _escape_html(page_title),
                "__IDENTITY_CARD__": identity_html,
                "__ARTIFACT_JSON__": _json_for_html(artifact),
                "__B524_GROUP_NAMES__": _json_for_html(group_name_map),
                "__B524_REGISTER_NAME_CORRESPONDENCE__": _json_for_html(_correspondence_json_map()),
                "__B524_DOCS_CATALOG_NAMES__": _json_for_html(_docs_catalog_json_map(artifact)),
                "__B524_ENTRY_EVIDENCE__": _json_for_html(entry_evidence),
                "__B524_ENTRY_EVIDENCE_LABELS__": _json_for_html(_entry_evidence_labels()),
                "__OBSERVED_NAME_CAVEAT__": _json_for_html(OBSERVED_NAME_CAVEAT),
                "__B524_CIRCUIT_II_MIN__": (
                    "0"
                    if description_profile(artifact).get("profile_id") == "basv2_sw0507_hw1704_api1"
                    else "1"
                ),
            },
        ).rstrip()
        + "\n"
    )
