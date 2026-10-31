from __future__ import annotations

import csv
import io
import re
from dataclasses import dataclass
from pathlib import Path

from ..input_limits import MAX_EBUSD_CSV_BYTES, read_bounded_text
from ..protocol.b524 import B524RegisterSelector, parse_b524_id

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass(frozen=True, slots=True)
class EbusdRegisterSchemaEntry:
    name: str
    type_spec: str | None


# Preserve external packed-BCD tokens as unsupported raw evidence, never as aliases.
def _looks_like_type_spec(value: str) -> bool:
    normalized = value.strip().upper()
    if not normalized:
        return False
    if normalized in {
        "EXP",
        "UIN",
        "UCH",
        "TIME_HMS_U8X3",
        "DATE_DMY_U8X3",
        "HDA:3",
        "HTI",
        "I8",
        "I16",
        "U32",
        "I32",
        "BOOL",
    }:
        return True
    return normalized.startswith(("STR:", "HEX:"))


def _extract_b524_id_hex(fields: list[str]) -> str | None:
    for i, raw in enumerate(fields):
        field = raw.strip()
        if not field:
            continue
        lowered = field.lower()
        if lowered.startswith("b524,"):
            return field[5:].strip()
        if lowered == "b524" and i + 1 < len(fields):
            candidate = fields[i + 1].strip()
            if candidate and _HEX_RE.fullmatch(candidate) and len(candidate) % 2 == 0:
                return candidate
    return None


def _extract_b509_id_hex(fields: list[str]) -> str | None:
    for i, raw in enumerate(fields):
        field = raw.strip()
        if not field:
            continue
        lowered = field.lower()
        if lowered.startswith("b509,"):
            return field[5:].strip()
        if lowered == "b509":
            if i + 1 >= len(fields):
                continue
            first = fields[i + 1].strip()
            if not first or not _HEX_RE.fullmatch(first):
                continue
            # Common layout: b509,0d2701 (split in CSV as two fields).
            if len(first) % 2 == 0:
                return first
            if i + 2 >= len(fields):
                continue
            second = fields[i + 2].strip()
            if not second or not _HEX_RE.fullmatch(second):
                continue
            merged = first + second
            if len(merged) % 2 == 0:
                return merged
    return None


def _extract_b509_read_address(fields: list[str]) -> int | None:
    id_hex = _extract_b509_id_hex(fields)
    if id_hex is None:
        return None
    try:
        blob = bytes.fromhex(id_hex)
    except ValueError:
        return None
    if len(blob) < 3:
        return None
    # B509 register read selector: 0x0D + 16-bit address (hi, lo).
    if blob[0] != 0x0D:
        return None
    return (blob[1] << 8) | blob[2]


def _extract_value_type_spec(fields: list[str]) -> str | None:
    for raw in reversed(fields):
        if _looks_like_type_spec(raw):
            return raw.strip().upper()
    return None


class EbusdCsvSchema:
    """Lightweight loader for ebusd configuration CSV files (e.g. `15.720.csv`)."""

    def __init__(
        self,
        *,
        exact: dict[tuple[int, int, int, int], EbusdRegisterSchemaEntry],
        wildcard_instance: dict[tuple[int, int, int], EbusdRegisterSchemaEntry],
        b509_reads: dict[int, EbusdRegisterSchemaEntry],
    ) -> None:
        self._exact = exact
        self._wildcard_instance = wildcard_instance
        self._b509_reads = b509_reads

    @classmethod
    def from_path(cls, path: Path) -> EbusdCsvSchema:
        exact: dict[tuple[int, int, int, int], EbusdRegisterSchemaEntry] = {}
        wildcard_instance: dict[tuple[int, int, int], EbusdRegisterSchemaEntry] = {}
        b509_reads: dict[int, EbusdRegisterSchemaEntry] = {}

        text = read_bounded_text(path, limit=MAX_EBUSD_CSV_BYTES, label="ebusd CSV file")
        with io.StringIO(text, newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                # Skip comment lines.
                if row[0].lstrip().startswith("#"):
                    continue

                name = row[3].strip() if len(row) > 3 else ""
                if not name:
                    continue

                type_spec = _extract_value_type_spec(row)
                b509_address = _extract_b509_read_address(row)
                if b509_address is not None:
                    b509_reads.setdefault(
                        b509_address,
                        EbusdRegisterSchemaEntry(name=name, type_spec=type_spec),
                    )

                id_hex = _extract_b524_id_hex(row)
                if id_hex is None:
                    continue

                try:
                    selector = parse_b524_id(f"b524,{id_hex}")
                except Exception:
                    continue

                if not isinstance(selector, B524RegisterSelector):
                    continue
                if selector.optype != 0x00:
                    continue

                entry = EbusdRegisterSchemaEntry(name=name, type_spec=type_spec)

                if selector.instance == 0xFF:
                    wildcard_key = (selector.opcode, selector.group, selector.register)
                    wildcard_instance.setdefault(wildcard_key, entry)
                else:
                    exact_key = (
                        selector.opcode,
                        selector.group,
                        selector.instance,
                        selector.register,
                    )
                    exact.setdefault(exact_key, entry)

        return cls(exact=exact, wildcard_instance=wildcard_instance, b509_reads=b509_reads)

    def lookup(
        self,
        *,
        opcode: int,
        group: int,
        instance: int,
        register: int,
    ) -> EbusdRegisterSchemaEntry | None:
        entry = self._exact.get((opcode, group, instance, register))
        if entry is not None:
            return entry
        return self._wildcard_instance.get((opcode, group, register))

    def lookup_b509(self, *, register: int) -> EbusdRegisterSchemaEntry | None:
        return self._b509_reads.get(register)
