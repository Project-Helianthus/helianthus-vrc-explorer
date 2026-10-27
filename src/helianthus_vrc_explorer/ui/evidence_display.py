"""Entry-level evidence grade, decoded-value grade and codec provenance display rules.

One place defines what the results viewer, the Browser detail pane and the HTML
report say about a selected register entry, so the three surfaces cannot drift.
Following ``docs/shared-evidence-contract.md``, the entry's evidence (facts within
its retained bytes) and its decoded value (an interpretation of them) are
different claims and are never shown under one label:

* ``Entry evidence`` is the entry's own ``evidence_grade`` exactly as retained, and
  only when it is one of the case-sensitive strings ``Proven``, ``Hypothesis`` or
  ``Unknown``. A missing, unrecognised or non-string value, and a cell that has no
  entry at all, is shown as ``Unknown``. Qualification and profile matching never
  supply or upgrade it (``docs/evidence-grades.md``).
* ``Decoded value`` is never better than ``Hypothesis``: ``Hypothesis`` when the
  entry holds a decoded value, ``Unknown`` when it holds none (a sparse cell, or an
  entry whose decode failed or was never made). A manual type override reinterprets
  the selected cell's bytes in the view only; it keeps the ``Hypothesis`` grade,
  says why, never rewrites the retained entry evidence, and applies only when the
  selected cell actually holds an entry.
* The codec provenance is the entry's retained ``parameter_description`` value,
  falling back to the entry-level ``codec_provenance`` that scan entries without a
  parameter description record directly, and ``Unknown`` when neither exists.

Everything here is pure: it reads an entry and never writes to the artifact.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..protocol.parser import ValueParseError, parse_typed_value

EVIDENCE_GRADES = frozenset({"Proven", "Hypothesis", "Unknown"})
UNKNOWN = "Unknown"

ENTRY_LABEL = "Entry evidence"
DECODED_LABEL = "Decoded value"
PROVENANCE_LABEL = "Codec provenance"

# A decoded value interprets retained bytes, so it is at most a Hypothesis.
DECODED_GRADE = "Hypothesis"
OVERRIDE_NOTE = "manual type override; view only"
OVERRIDE_TEXT = f"{DECODED_GRADE} ({OVERRIDE_NOTE})"


def get_row_type_override(
    artifact: dict[str, Any],
    *,
    group_key: str,
    rr_key: str,
    op_key: str | None = None,
) -> str | None:
    """Return the saved per-row type override from ``meta.type_overrides``, if any."""

    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        return None
    overrides = meta.get("type_overrides")
    if not isinstance(overrides, dict):
        return None
    group_overrides = overrides.get(group_key)
    if not isinstance(group_overrides, dict):
        return None
    if op_key is not None:
        for tree_key in ("operations", "namespaces"):
            ops = group_overrides.get(tree_key)
            if isinstance(ops, dict):
                op_overrides = ops.get(op_key)
                if isinstance(op_overrides, dict):
                    value = op_overrides.get(rr_key)
                    if isinstance(value, str):
                        return value
    value = group_overrides.get(rr_key)
    return value if isinstance(value, str) else None


def observed_description(entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the entry's retained ``parameter_description`` (empty when absent)."""

    description = entry.get("parameter_description") if entry else None
    return description if isinstance(description, dict) else {}


def entry_evidence_grade(entry: Mapping[str, Any] | None) -> str:
    """Return the entry's retained grade, or ``Unknown`` when it supplies no valid one."""

    grade = entry.get("evidence_grade") if entry else None
    if not isinstance(grade, str) or grade not in EVIDENCE_GRADES:
        return UNKNOWN
    return grade


def entry_codec_provenance(entry: Mapping[str, Any] | None) -> str:
    """Return the codec provenance of the entry's decode, or ``Unknown``."""

    provenance = observed_description(entry).get("codec_provenance")
    if provenance is None and entry:
        provenance = entry.get("codec_provenance")
    return UNKNOWN if provenance is None else str(provenance)


def entry_has_decoded_value(entry: Mapping[str, Any] | None) -> bool:
    """Whether the entry holds a decoded value (not a sparse cell, failed or absent decode)."""

    return entry is not None and entry.get("value") is not None


def manual_override_value(entry: Mapping[str, Any] | None, type_override: str | None) -> Any:
    """The value a row override yields from the entry's retained bytes, else ``None``.

    An entry without usable ``raw_hex`` (timeout, empty response, invalid hex) or whose
    bytes do not parse under the override has no overridden interpretation to claim, and
    neither has a parse that yields no value (an EXP NaN).
    """

    if type_override is None or not entry:
        return None
    raw_hex = entry.get("raw_hex")
    if not isinstance(raw_hex, str) or not raw_hex:
        return None
    try:
        return parse_typed_value(type_override, bytes.fromhex(raw_hex))
    except (ValueError, ValueParseError):
        return None


def manual_override_applies(entry: Mapping[str, Any] | None, type_override: str | None) -> bool:
    """A row override is shown only when it yields a value from the entry's retained bytes."""

    return manual_override_value(entry, type_override) is not None


@dataclass(frozen=True, slots=True)
class EntryEvidenceDisplay:
    grade: str
    decoded_value: str
    codec_provenance: str
    override_applies: bool

    @property
    def decoded_text(self) -> str:
        """The decoded-value line's value, in its manual-override form when one applies."""

        return OVERRIDE_TEXT if self.override_applies else self.decoded_value


def entry_evidence_display(
    entry: Mapping[str, Any] | None, *, type_override: str | None = None
) -> EntryEvidenceDisplay:
    """Resolve what to show for one selected entry (``None`` for a sparse cell)."""

    override_applies = manual_override_applies(entry, type_override)
    decoded = override_applies or entry_has_decoded_value(entry)
    return EntryEvidenceDisplay(
        grade=entry_evidence_grade(entry),
        decoded_value=DECODED_GRADE if decoded else UNKNOWN,
        codec_provenance=entry_codec_provenance(entry),
        override_applies=override_applies,
    )
