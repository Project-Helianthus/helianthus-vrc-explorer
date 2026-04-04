from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class MyvaillantRegisterName:
    leaf: str
    ebusd_name: str | None = None
    register_class: str | None = None
    type_hint: str | None = None
    opcode: int | None = None

    def resolved_ebusd_name(self, *, group: int, instance: int, register: int) -> str | None:
        template = (self.ebusd_name or "").strip()
        if not template:
            return None
        try:
            return template.format(
                gg=group,
                ii=instance,
                rr=register,
                gg_hex=f"0x{group:02X}",
                ii_hex=f"0x{instance:02X}",
                rr_hex=f"0x{register:04X}",
                hc=instance + 1,
                zone=instance + 1,
            )
        except Exception:
            # Keep mapping resilient even if a template placeholder is malformed.
            return template


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


class MyvaillantRegisterMap:
    """Optional register-to-myVaillant leaf-name mapping.

    File format (CSV with header):

        group,instance,register,leaf,ebusd_name,register_class,type_hint,opcode
        0x03,0x01,0x0016,name,Zone{zone}Name,state,,

    `instance` may be `*` to match all instances in the group.
    `ebusd_name` is optional and may use `{hc}`/`{zone}` placeholders.
    `register_class` is optional and may be `config`, `config_limits`, or `state`.
    `type_hint` is optional and overrides inferred parsing when consumed by callers.
    `opcode` is optional and disambiguates local (`0x02`) vs remote (`0x06`) namespace rows.
    """

    def __init__(
        self,
        *,
        exact: dict[tuple[int, int, int, int | None], MyvaillantRegisterName],
        wildcard_instance: dict[tuple[int, int, int | None], MyvaillantRegisterName],
        wildcard_group: dict[tuple[int, int | None], MyvaillantRegisterName],
    ) -> None:
        self._exact = exact
        self._wildcard_instance = wildcard_instance
        self._wildcard_group = wildcard_group

    @classmethod
    def from_path(cls, path: Path) -> MyvaillantRegisterMap:
        exact: dict[tuple[int, int, int, int | None], MyvaillantRegisterName] = {}
        wildcard_instance: dict[tuple[int, int, int | None], MyvaillantRegisterName] = {}
        wildcard_group: dict[tuple[int, int | None], MyvaillantRegisterName] = {}

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row:
                    continue
                gg_raw = (row.get("group") or "").strip()
                ii_raw = (row.get("instance") or "").strip()
                rr_raw = (row.get("register") or "").strip()
                leaf = (row.get("leaf") or "").strip()
                if not (gg_raw and ii_raw and rr_raw and leaf):
                    continue
                ebusd_name = (row.get("ebusd_name") or "").strip() or None
                register_class = (row.get("register_class") or "").strip().lower() or None
                if register_class not in {None, "config", "config_limits", "state"}:
                    register_class = None
                type_hint = (row.get("type_hint") or "").strip().upper() or None
                opcode_raw = (row.get("opcode") or "").strip()
                opcode = _parse_hex_u8(opcode_raw) if opcode_raw else None
                rr = _parse_hex_u16(rr_raw)
                entry = MyvaillantRegisterName(
                    leaf=leaf,
                    ebusd_name=ebusd_name,
                    register_class=register_class,
                    type_hint=type_hint,
                    opcode=opcode,
                )

                if gg_raw == "*":
                    if ii_raw != "*":
                        raise ValueError(
                            f"Group wildcard mappings require instance='*' for register=0x{rr:04X}"
                        )
                    if opcode is None:
                        raise ValueError(
                            "Group wildcard mappings require an explicit opcode "
                            f"for register=0x{rr:04X}"
                        )
                    wildcard_group_key = (rr, opcode)
                    if wildcard_group_key in wildcard_group:
                        raise ValueError(
                            f"Duplicate group wildcard mapping for register=0x{rr:04X} "
                            f"opcode={opcode_raw}"
                        )
                    wildcard_group[wildcard_group_key] = entry
                    continue

                gg = _parse_hex_u8(gg_raw)

                if ii_raw == "*":
                    wildcard_key = (gg, rr, opcode)
                    if wildcard_key in wildcard_instance:
                        raise ValueError(
                            f"Duplicate wildcard mapping for group=0x{gg:02X} "
                            f"register=0x{rr:04X} opcode={opcode_raw or '*'}"
                        )
                    wildcard_instance[wildcard_key] = entry
                    continue

                ii = _parse_hex_u8(ii_raw)
                exact_key = (gg, ii, rr, opcode)
                if exact_key in exact:
                    raise ValueError(
                        f"Duplicate exact mapping for group=0x{gg:02X} instance=0x{ii:02X} "
                        f"register=0x{rr:04X} opcode={opcode_raw or '*'}"
                    )
                exact[exact_key] = entry

        return cls(
            exact=exact,
            wildcard_instance=wildcard_instance,
            wildcard_group=wildcard_group,
        )

    def _allow_generic_fallback(self, *, opcode: int) -> bool:
        # Generic opcode-less rows in the bundled map are local-first defaults.
        # Remote namespaces must opt in with explicit opcode rows.
        return opcode == 0x02

    def lookup(
        self,
        *,
        group: int,
        instance: int,
        register: int,
        opcode: int | None = None,
    ) -> MyvaillantRegisterName | None:
        if opcode is not None:
            entry = self._exact.get((group, instance, register, opcode))
            if entry is not None:
                return entry

            entry = self._wildcard_instance.get((group, register, opcode))
            if entry is not None:
                return entry

            entry = self._wildcard_group.get((register, opcode))
            if entry is not None:
                return entry

            if not self._allow_generic_fallback(opcode=opcode):
                return None

        entry = self._exact.get((group, instance, register, None))
        if entry is not None:
            return entry

        entry = self._wildcard_instance.get((group, register, None))
        if entry is not None:
            return entry

        return self._wildcard_group.get((register, None))
