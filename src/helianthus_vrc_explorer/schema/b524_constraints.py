from __future__ import annotations

import csv
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_KIND_TO_TT = {
    "u8_range": 0x06,
    "u16_range": 0x09,
    "date_range": 0x0C,
    "f32_range": 0x0F,
}


@dataclass(frozen=True, slots=True)
class StaticConstraintEntry:
    tt: int
    kind: str
    min_value: int | float | str
    max_value: int | float | str
    step_value: int | float
    source: str = "static_catalog"


type StaticConstraintCatalog = dict[int, dict[int, StaticConstraintEntry]]


def _parse_hex_u8(value: str) -> int:
    parsed = int(value, 0)
    if not (0x00 <= parsed <= 0xFF):
        raise ValueError(f"u8 out of range: {value!r}")
    return parsed


def _parse_hex_u16(value: str) -> int:
    parsed = int(value, 0)
    if not (0x0000 <= parsed <= 0xFFFF):
        raise ValueError(f"u16 out of range: {value!r}")
    return parsed


def _parse_scalar(value: str) -> int | float | str:
    raw = value.strip()
    if any(ch in raw for ch in ".eE"):
        return float(raw)
    try:
        return int(raw, 0)
    except ValueError:
        return raw


def _parse_numeric(value: str) -> int | float:
    parsed = _parse_scalar(value)
    if isinstance(parsed, bool) or not isinstance(parsed, (int, float)):
        raise ValueError(f"Expected numeric constraint value, got {value!r}")
    return parsed


def load_b524_constraints_catalog_from_path(path: Path) -> StaticConstraintCatalog:
    catalog: StaticConstraintCatalog = {}

    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row:
                continue
            group_raw = (row.get("group") or "").strip()
            register_raw = (row.get("register") or "").strip()
            kind = (row.get("type") or "").strip()
            min_raw = (row.get("min") or "").strip()
            max_raw = (row.get("max") or "").strip()
            step_raw = (row.get("step") or "").strip()
            if not all((group_raw, register_raw, kind, min_raw, max_raw, step_raw)):
                continue
            tt = _KIND_TO_TT.get(kind)
            if tt is None:
                raise ValueError(f"Unsupported static constraint kind: {kind!r}")
            group = _parse_hex_u8(group_raw)
            register = _parse_hex_u16(register_raw)
            entry = StaticConstraintEntry(
                tt=tt,
                kind=kind,
                min_value=_parse_scalar(min_raw),
                max_value=_parse_scalar(max_raw),
                step_value=_parse_numeric(step_raw),
            )
            catalog.setdefault(group, {})
            if register in catalog[group]:
                raise ValueError(
                    f"Duplicate static constraint for group=0x{group:02X} register=0x{register:04X}"
                )
            catalog[group][register] = entry
    return catalog


def load_default_b524_constraints_catalog() -> tuple[StaticConstraintCatalog, str | None]:
    try:
        resource = resources.files("helianthus_vrc_explorer.data").joinpath(
            "b524_constraints_catalog.csv"
        )
        with resources.as_file(resource) as catalog_path:
            return (
                load_b524_constraints_catalog_from_path(catalog_path),
                f"static_constraints:{catalog_path.name}",
            )
    except Exception:
        fallback = Path(__file__).resolve().parents[2] / "data" / "b524_constraints_catalog.csv"
        if fallback.exists():
            try:
                return (
                    load_b524_constraints_catalog_from_path(fallback),
                    f"static_constraints:{fallback.name}",
                )
            except Exception:
                return ({}, None)
        return ({}, None)
