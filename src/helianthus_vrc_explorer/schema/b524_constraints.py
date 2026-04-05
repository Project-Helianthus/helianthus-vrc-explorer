from __future__ import annotations

import csv
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from ..scanner.identity import RegisterIdentity

_KIND_TO_TT = {
    "u8_range": 0x06,
    "u16_range": 0x09,
    "date_range": 0x0C,
    "f32_range": 0x0F,
}

_DEFAULT_STATIC_READ_OPCODES = (0x02,)

CONSTRAINT_SCOPE_DECISION = "opcode_0x02_default"
CONSTRAINT_SCOPE_PROTOCOL = "opcode_0x01"
CONSTRAINT_SCOPE_APPLIES_TO = "opcode_0x02_by_default_unless_explicitly_scoped"
CONSTRAINT_SCOPE_RATIONALE = (
    "The bundled static catalog is seeded from opcode-0x01 probe evidence, but it is "
    "only applied to opcode 0x02 by default. Remote opcode 0x06 requires explicit scope "
    "or live confirmation."
)
LIVE_PROBE_CONSTRAINT_SCOPE = "opcode_0x01_probe"


@dataclass(frozen=True, slots=True)
class StaticConstraintEntry:
    tt: int
    kind: str
    min_value: int | float | str
    max_value: int | float | str
    step_value: int | float
    source: str = "static_catalog"
    scope: str = CONSTRAINT_SCOPE_DECISION
    provenance: str = "catalog_seeded_from_opcode_0x01"
    read_opcodes: tuple[int, ...] = _DEFAULT_STATIC_READ_OPCODES


type StaticConstraintCatalog = dict[int, dict[int, StaticConstraintEntry]]


def constraint_scope_metadata() -> dict[str, str]:
    """Return canonical metadata describing the active constraint-scope decision."""

    return {
        "decision": CONSTRAINT_SCOPE_DECISION,
        "protocol": CONSTRAINT_SCOPE_PROTOCOL,
        "applies_to": CONSTRAINT_SCOPE_APPLIES_TO,
        "rationale": CONSTRAINT_SCOPE_RATIONALE,
    }


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


def _scope_derived_read_opcodes(raw_scope: str) -> tuple[int, ...] | None:
    scope = raw_scope.strip().lower()
    if not scope:
        return None
    if scope in {CONSTRAINT_SCOPE_DECISION, "opcode_0x02_only"}:
        return _DEFAULT_STATIC_READ_OPCODES
    if scope == "opcode_0x06_only":
        return (0x06,)
    if scope in {"gg_rr_invariant", "explicit_opcode_0x02_0x06"}:
        return (0x02, 0x06)
    return None


def _parse_constraint_read_opcodes(*, raw_scope: str, raw_opcodes: str) -> tuple[int, ...]:
    value = raw_opcodes.strip().lower()
    if not value:
        derived = _scope_derived_read_opcodes(raw_scope)
        if derived is not None:
            return derived
        if raw_scope.strip():
            raise ValueError(f"Unsupported constraint scope without read_opcodes: {raw_scope!r}")
        return _DEFAULT_STATIC_READ_OPCODES
    if value in {"all", "all_register_read_namespaces", "0x02+0x06"}:
        return (0x02, 0x06)

    normalized = value.replace("|", ",").replace("+", ",")
    opcodes: list[int] = []
    for token in normalized.split(","):
        candidate = token.strip()
        if not candidate:
            continue
        opcode = _parse_hex_u8(candidate)
        if opcode not in {0x02, 0x06}:
            raise ValueError(f"Unsupported constraint read opcode: {candidate!r}")
        if opcode not in opcodes:
            opcodes.append(opcode)
    if not opcodes:
        return _DEFAULT_STATIC_READ_OPCODES
    return tuple(opcodes)


def _constraint_scope_label(*, raw_scope: str, read_opcodes: tuple[int, ...]) -> str:
    if raw_scope.strip():
        return raw_scope.strip()
    if read_opcodes == _DEFAULT_STATIC_READ_OPCODES:
        return CONSTRAINT_SCOPE_DECISION
    if read_opcodes == (0x06,):
        return "opcode_0x06_only"
    if read_opcodes == (0x02, 0x06):
        return "explicit_opcode_0x02_0x06"
    return "explicit_opcode_scope"


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
            scope_raw = (row.get("scope") or "").strip()
            opcodes_raw = (row.get("read_opcodes") or "").strip()
            if not all((group_raw, register_raw, kind, min_raw, max_raw, step_raw)):
                continue
            tt = _KIND_TO_TT.get(kind)
            if tt is None:
                raise ValueError(f"Unsupported static constraint kind: {kind!r}")
            group = _parse_hex_u8(group_raw)
            register = _parse_hex_u16(register_raw)
            read_opcodes = _parse_constraint_read_opcodes(
                raw_scope=scope_raw,
                raw_opcodes=opcodes_raw,
            )
            entry = StaticConstraintEntry(
                tt=tt,
                kind=kind,
                min_value=_parse_scalar(min_raw),
                max_value=_parse_scalar(max_raw),
                step_value=_parse_numeric(step_raw),
                scope=_constraint_scope_label(
                    raw_scope=scope_raw,
                    read_opcodes=read_opcodes,
                ),
                read_opcodes=read_opcodes,
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


def lookup_static_constraint(
    catalog: StaticConstraintCatalog, *, identity: RegisterIdentity
) -> StaticConstraintEntry | None:
    """Resolve the current static catalog using canonical register identity.

    The bundled static catalog is opcode-0x02-scoped by default. Individual rows
    may opt into other namespaces via explicit read-opcode metadata.
    """

    opcode, group, _instance, register = identity
    entry = catalog.get(group, {}).get(register)
    if entry is None:
        return None
    if opcode not in entry.read_opcodes:
        return None
    return entry
