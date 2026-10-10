"""Bundled human-readable labels for B524 scalar codec specs.

Purely presentational: a short, reviewable cross-reference between a codec
spec (as used by ``protocol.parser.parse_typed_value`` and
``browse_textual._parse_new_value``) and a plain-language description of its
raw wire shape and its interpreted shape. It never changes how a value is
parsed or encoded.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from functools import cache
from importlib import resources

_EXPECTED_FIELDS = ("type", "raw_shape", "interpreted_shape")


@dataclass(frozen=True, slots=True)
class B524CodecLabel:
    """One codec's plain-language raw/interpreted shape description."""

    type: str
    raw_shape: str
    interpreted_shape: str


@cache
def bundled_b524_codec_labels() -> dict[str, B524CodecLabel]:
    """Return the bundled codec label table keyed by the exact ``type`` spec."""

    mapping: dict[str, B524CodecLabel] = {}
    resource = resources.files("helianthus_vrc_explorer.data").joinpath("b524_codec_labels.csv")
    with resource.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != _EXPECTED_FIELDS:
            raise ValueError("B524 codec-label catalog has an unexpected header")
        for row in reader:
            type_spec = (row.get("type") or "").strip()
            raw_shape = (row.get("raw_shape") or "").strip()
            interpreted_shape = (row.get("interpreted_shape") or "").strip()
            if not type_spec or not raw_shape or not interpreted_shape:
                raise ValueError(f"B524 codec-label row is incomplete: {row!r}")
            if type_spec in mapping:
                raise ValueError(f"Duplicate B524 codec-label identity: {type_spec!r}")
            mapping[type_spec] = B524CodecLabel(
                type=type_spec, raw_shape=raw_shape, interpreted_shape=interpreted_shape
            )
    return mapping


def b524_codec_label(type_spec: str) -> B524CodecLabel | None:
    """Resolve one codec's label, matching parameterized families by prefix.

    ``STR:16`` and ``HEX:3`` resolve through the family rows ``STR:n`` /
    ``HEX:n``; an unknown codec returns ``None`` so the caller can degrade to
    the type spec verbatim plus a byte count derived from the raw bytes.
    """

    normalized = type_spec.strip().upper()
    labels = bundled_b524_codec_labels()
    direct = labels.get(normalized)
    if direct is not None:
        return direct
    if normalized.startswith("STR:"):
        return labels.get("STR:n")
    if normalized.startswith("HEX:"):
        return labels.get("HEX:n")
    return None
