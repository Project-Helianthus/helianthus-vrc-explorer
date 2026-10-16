#!/usr/bin/env python3
"""Validate native B524 BASV0 description-profile evidence.

For selectors carried in both register-map namespaces, the retained fields alone
cannot distinguish the request opcode. The page-cited SHA-256 pins the published
fixture bytes, so a reassignment cannot be published silently. Codec qualification
is local-only in this profile: no retained evidence ties a remote description to
a codec, and a qualified remote claim is rejected.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import math
import re
import struct
import sys
from pathlib import Path
from typing import Any


class ValidationError(ValueError):
    """The fixture overstates or corrupts a B524 metadata observation."""


HEX = re.compile(r"^(?:[0-9A-F]{2})*$")
NUMERIC_CODECS = {"UCH", "UIN", "U32", "EXP"}
# Bytes per MIN/MAX/STEP span for each codec this fixture can name.
CODEC_WIDTH = {"UCH": 1, "UIN": 2, "U32": 4, "EXP": 4, "DATE_DMY_U8X3": 3, "TIME_HMS_U8X3": 3}
# Neutral plain-byte candidate layouts, distinct from the packed-BCD types in
# types/ebusd-csv.md. Records stay display_only on a Hypothesis codec basis.
PLAIN_BYTE_CLOCK_CODECS = {"DATE_DMY_U8X3", "TIME_HMS_U8X3"}
CLOCK_CODECS = PLAIN_BYTE_CLOCK_CODECS
ROOT = Path(__file__).resolve().parents[1]
REGISTER_MAP = ROOT / "protocols/vaillant/ebus-vaillant-B524-register-map.md"
SCOPE_OVERLAY = ROOT / "development/fixtures/b524-basv0-validation-scope-v1.json"
CALENDAR_CLOCK_CSV = ROOT / "protocols/vaillant/fixtures/b524-op02-calendar-clock-selectors.csv"
WIRE_CODEC = {"u8": "UCH", "u16": "UIN", "u32": "U32", "f32": "EXP", "date": "DATE_DMY_U8X3", "time": "TIME_HMS_U8X3"}
_WIRE_CACHE: dict[tuple[str, str, str], set[str]] | None = None
_CLOCK_CACHE: dict[tuple[str, str, str], str] | None = None
VENTILATION_INSTANCES = tuple(f"{index:02X}" for index in range(0x0B))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _description_operation(operation: str) -> int:
    return {"02": 0x01, "06": 0x07}[operation]


def _decode_limit(codec: str, raw: str) -> Any:
    value = bytes.fromhex(raw)
    try:
        if codec == "UCH": return value[0]
        if codec == "UIN": return int.from_bytes(value, "little")
        if codec == "U32": return int.from_bytes(value, "little")
        if codec == "EXP": return struct.unpack("<f", value)[0]
        if codec == "DATE_DMY_U8X3": return f"{2000 + value[2]:04d}-{value[1]:02d}-{value[0]:02d}"
        if codec == "TIME_HMS_U8X3": return f"{value[0]:02d}:{value[1]:02d}:{value[2]:02d}"
    except (struct.error, IndexError, ValueError) as exc:
        raise ValidationError(f"cannot decode {codec} limit {raw}: {exc}") from exc
    raise ValidationError(f"unsupported qualified codec {codec}")


def register_map_wire() -> dict[tuple[str, str, str], set[str]]:
    """(operation, group, register) -> Wire-column codecs from the register map tables."""
    global _WIRE_CACHE
    if _WIRE_CACHE is not None:
        return _WIRE_CACHE
    wire: dict[tuple[str, str, str], set[str]] = {}
    operation = group = None
    column = None
    for line in REGISTER_MAP.read_text(encoding="utf-8").splitlines():
        heading = re.match(r"^(#{2,4}) (.*)", line)
        if heading:
            column = None
            if heading.group(1) == "##":
                operation = "02" if "OP=0x02" in heading.group(2) else "06" if "OP=0x06" in heading.group(2) else None
                group = None
            found = re.match(r"GG=0x([0-9A-Fa-f]{2})\b", heading.group(2))
            if found and heading.group(1) == "###":
                group = found.group(1).upper()
            continue
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if cells and cells[0] == "RR":
            column = cells.index("Wire") if "Wire" in cells else None
            continue
        row = re.match(r"^0x([0-9A-Fa-f]{4})$", cells[0]) if cells else None
        if row and operation and group and column is not None and column < len(cells):
            codec = WIRE_CODEC.get(cells[column].strip("`").split()[0].lower()) if cells[column].strip("`") else None
            if codec:
                wire.setdefault((operation, group, row.group(1).upper()), set()).add(codec)
    _WIRE_CACHE = wire
    return wire


def calendar_clock_codecs() -> dict[tuple[str, str, str], str]:
    """(group, instance, register) -> codec implied by the calendar/clock candidate list."""
    global _CLOCK_CACHE
    if _CLOCK_CACHE is None:
        listed: dict[tuple[str, str, str], str] = {}
        with CALENDAR_CLOCK_CSV.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                if row["opcode"] == "0x02" and row["payload_bytes"] == "3":
                    key = (row["group"][2:].upper().zfill(2), row["instance"][2:].upper().zfill(2), row["register"][2:].upper().zfill(4))
                    listed[key] = "TIME_HMS_U8X3" if "time" in row["name"] else "DATE_DMY_U8X3"
        _CLOCK_CACHE = listed
    return _CLOCK_CACHE


# The 14 documented exact-selector-schema selectors (OP, GG, II, RR): the 13 date/time
# candidates and the U32 GG04 RR000B record, named in the "Basis of the codec labels"
# section of protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md. Eight of them
# (GG00 RR002C, RR00F2..RR00F5, GG01 RR0010/RR0011, GG04 RR000B) are absent from the
# calendar/clock candidate list and are pinned by the register map Wire column instead.
EXACT_SCHEMA_SELECTORS = frozenset(
    ("02", group, "00", register) for group, register in (
        ("00", "002C"), ("00", "0034"), ("00", "0035"), ("00", "00DA"), ("00", "00DB"),
        ("00", "00F2"), ("00", "00F3"), ("00", "00F4"), ("00", "00F5"),
        ("01", "0009"), ("01", "000A"), ("01", "0010"), ("01", "0011"),
        ("04", "000B"),
    )
)


def _validate_selector_codec(codec: str, basis: str, selector: dict[str, str], context: str) -> None:
    where = f"OP{selector['operation']}/GG{selector['group']}/II{selector['instance']}/RR{selector['register']}"
    if basis == "public_exact_selector_schema":
        _require(selector["operation"] == "02",
                 f"{context} request opcode corroboration failed "
                 "(exact-selector-schema basis requires OP02)")
    mapped = register_map_wire().get((selector["operation"], selector["group"], selector["register"]))
    if basis == "public_local_constraint_codec":
        _require(mapped is not None, f"{context}.decoded has no register-map Wire entry for {where}")
        _require(mapped == {codec}, f"{context}.decoded.codec {codec} disagrees with the register-map Wire codec {'/'.join(sorted(mapped))} for {where}")
        return
    listed = calendar_clock_codecs().get((selector["group"], selector["instance"], selector["register"])) if selector["operation"] == "02" else None
    if listed is not None:
        _require(codec == listed, f"{context}.decoded.codec {codec} disagrees with the calendar/clock selector list ({listed}) for {where}")
    else:
        _require(mapped is not None, f"{context}.decoded has neither a calendar/clock list entry nor a register-map Wire entry for {where}")
        _require(mapped == {codec}, f"{context}.decoded.codec {codec} disagrees with the register-map Wire codec {'/'.join(sorted(mapped))} for {where}")


def _validate_clock_value(codec: str, raw: str, field: str, context: str) -> None:
    value = bytes.fromhex(raw)
    if codec == "TIME_HMS_U8X3":
        valid = value[0] <= 23 and value[1] <= 59 and value[2] <= 59
        kind = "time (hour 0-23, minute 0-59, second 0-59)"
    else:
        try:
            datetime.date(2000 + value[2], value[1], value[0])
            valid = value[2] <= 99
        except ValueError:
            valid = False
        kind = "date (day, month, year offset 0-99 from 2000)"
    _require(valid, f"{context}.decoded.{field} is not a valid {kind}")


def _expected_validation_scope(record: dict[str, Any]) -> str:
    """The documented derivation of the source installation's validation_scope."""
    decoded = record.get("decoded")
    if not (record.get("selector", {}).get("operation") == "02"
            and isinstance(decoded, dict) and decoded.get("qualification") == "qualified"
            and decoded.get("codec_provenance") == "selector_qualified"):
        return "raw_evidence_only"
    if record.get("presence_state") == "observed_present" and decoded.get("codec_basis") == "public_local_constraint_codec":
        return "format_range_and_step"
    return "display_only"


def _validate_validation_scope(record: dict[str, Any], scope: Any, context: str) -> None:
    decoded = record.get("decoded")
    _require(not (scope == "format_range_and_step" and isinstance(decoded, dict)
                  and decoded.get("codec") in PLAIN_BYTE_CLOCK_CODECS),
             f"{context} grants range validation to a plain-byte DATE_DMY_U8X3/TIME_HMS_U8X3 candidate decoding, which must stay display_only")
    if scope == "format_range_and_step":
        _require(record.get("selector", {}).get("operation") == "02",
                 f"{context} grants range validation to a remote record")
        _require(isinstance(decoded, dict) and decoded.get("qualification") == "qualified"
                 and decoded.get("codec_provenance") == "selector_qualified",
                 f"{context} grants range validation without a qualified selector codec")
        _require(record.get("presence_state") == "observed_present",
                 f"{context} grants range validation without observed presence")
        _require(decoded.get("codec_basis") == "public_local_constraint_codec",
                 f"{context} grants range validation on a codec basis that is not a local constraint codec")
    expected = _expected_validation_scope(record)
    _require(scope == expected, f"{context}.validation_scope must be {expected} for this record")


def _validate_remote_presence(record: dict[str, Any], context: str) -> None:
    remote_identity = record.get("remote_identity")
    unqualified = isinstance(remote_identity, dict) and remote_identity.get("qualification") == "unqualified"
    _require(unqualified == (record.get("presence_state") == "remote_identity_unqualified"),
             f"{context} unqualified remote identity and remote_identity_unqualified presence must agree")
    if unqualified:
        decoded = record.get("decoded")
        _require(decoded is None or decoded.get("qualification") == "unqualified",
                 f"{context} unqualified remote identity must not carry a qualified codec")


def _validate_record(record: Any, index: int) -> None:
    context = f"records[{index}]"
    _require(isinstance(record, dict), f"{context} must be an object")
    selector = record.get("selector")
    _require(isinstance(selector, dict), f"{context}.selector must be an object")
    operation = selector.get("operation")
    group = selector.get("group")
    instance = selector.get("instance")
    register = selector.get("register")
    _require(operation in {"02", "06"}, f"{context}.selector.operation is unsupported")
    for name, value, length in (("group", group, 2), ("instance", instance, 2), ("register", register, 4)):
        _require(isinstance(value, str) and len(value) == length and HEX.fullmatch(value) is not None,
                 f"{context}.selector.{name} is not uppercase hexadecimal")
    _require(record.get("identity_scope") == ("local" if operation == "02" else "remote"),
             f"{context}.identity_scope does not match native operation; "
             "request opcode corroboration failed (identity scope)")
    remote_identity = record.get("remote_identity")
    if operation == "02":
        _require(remote_identity is None, f"{context} must not attach remote identity to a local selector; "
                 "request opcode corroboration failed (remote header requires OP06)")
    else:
        _require(isinstance(remote_identity, dict) and remote_identity.get("qualification") in {"observed_remote_header", "unqualified"},
                 f"{context} must retain remote identity qualification")
        if remote_identity.get("qualification") == "observed_remote_header":
            # Widths: group and address are one byte; firmware is major.minor.patch, three
            # byte-decimal bytes (register map RR0004 device_firmware_version).
            for name, length in (("group", 2), ("address_raw", 2), ("firmware_raw", 6)):
                value = remote_identity.get(name)
                _require(value is not None,
                         f"{context}.remote_identity.{name} is required for an observed remote header")
                _require(isinstance(value, str) and re.fullmatch(r"[0-9A-F]*", value) is not None,
                         f"{context}.remote_identity.{name} must be uppercase hexadecimal")
                _require(len(value) == length,
                         f"{context}.remote_identity.{name} must be {length // 2} bytes ({length} hex digits), not {len(value) // 2}")
        if "group" in remote_identity:
            _require(remote_identity["group"] == group, f"{context}.remote_identity.group disagrees with selector")
    raw = record.get("raw_description_hex")
    lengths = record.get("description_payload_length")
    limits = record.get("raw_limits")
    decoded = record.get("decoded")
    _require(decoded is None or isinstance(decoded, dict), f"{context}.decoded must be an object or null")
    _validate_remote_presence(record, context)
    if raw is None:
        _require(lengths is None and limits is None and decoded is None,
                 f"{context} cannot decode or bound a missing description")
        _require(record.get("response_state") == "describe_unavailable", f"{context} missing description has wrong response state")
        return
    _require(isinstance(raw, str) and HEX.fullmatch(raw) is not None, f"{context}.raw_description_hex is invalid")
    response = bytes.fromhex(raw)
    _require(record.get("response_state") == "describe_matched", f"{context} retained description has wrong response state")
    _require(len(response) >= 3 and response[0] == int(group, 16)
             and response[1:3] == int(register, 16).to_bytes(2, "little"),
             f"{context}.raw_description_hex does not echo GG/RR")
    body = response[3:]
    _require(len(body) > 0, f"{context}.raw_description_hex retains no MIN/MAX/STEP spans; an absent description must be describe_unavailable with null fields")
    _require(len(body) % 3 == 0, f"{context}.raw_description_hex has unequal limit spans")
    _require(lengths == len(body), f"{context}.description_payload_length does not match raw description")
    _require(isinstance(limits, dict), f"{context}.raw_limits is required with a description")
    width = len(body) // 3
    for offset, name in enumerate(("min_hex", "max_hex", "step_hex")):
        value = limits.get(name)
        _require(isinstance(value, str) and HEX.fullmatch(value) is not None and len(value) == width * 2,
                 f"{context}.raw_limits.{name} does not match description width")
        _require(value == body[offset * width:(offset + 1) * width].hex().upper(),
                 f"{context}.raw_limits.{name} does not match raw description")
    if decoded is not None:
        _require(isinstance(decoded, dict), f"{context}.decoded must be an object or null")
        provenance = decoded.get("codec_provenance")
        basis = decoded.get("codec_basis")
        qualification = decoded.get("qualification")
        _require(provenance in {"selector_qualified", "length_inferred"}, f"{context}.decoded.codec_provenance is invalid")
        _require(basis in {"public_exact_selector_schema", "public_local_constraint_codec", "payload_length_inferred"}, f"{context}.decoded.codec_basis is invalid")
        _require(qualification in {"qualified", "unqualified"}, f"{context}.decoded.qualification is invalid")
        codec = decoded.get("codec")
        _require(codec in CODEC_WIDTH, f"{context}.decoded.codec is unsupported")
        _require(CODEC_WIDTH[codec] == lengths // 3,
                 f"{context}.decoded.codec {codec} width disagrees with description span width")
        _require(not (provenance == "length_inferred" and qualification == "qualified"),
                 f"{context} promotes a length-inferred codec")
        _require((provenance == "length_inferred") == (basis == "payload_length_inferred"),
                 f"{context}.decoded codec basis disagrees with provenance")
        if provenance == "selector_qualified":
            # Claimed selector provenance is checked whatever the qualification: it asserts
            # that the named source maps this selector to this codec.
            _validate_selector_codec(codec, basis, selector, context)
        _require(qualification != "qualified" or operation == "02",
                 f"{context} codec qualification is local-only in this profile "
                 "(qualified requires OP02; no retained remote codec evidence)")
        for field in ("min", "max", "step"):
            if field == "step" and codec in CLOCK_CODECS and (decoded.get("step") is None or qualification == "qualified"):
                continue
            expected = _decode_limit(codec, limits[f"{field}_hex"])
            actual = decoded.get(field)
            if codec in NUMERIC_CODECS:
                # bool is an int subclass: True == 1 would otherwise pass the comparison below.
                _require(isinstance(actual, (int, float)) and not isinstance(actual, bool),
                         f"{context}.decoded.{field} must be a number for codec {codec}, not {type(actual).__name__}")
            else:
                _require(not isinstance(actual, bool), f"{context}.decoded.{field} must not be a boolean")
            same = actual == expected or (isinstance(actual, float) and isinstance(expected, float)
                                          and math.isnan(actual) and math.isnan(expected))
            _require(same, f"{context}.decoded.{field} disagrees with raw limits")
        if provenance == "selector_qualified":
            _require(codec not in CLOCK_CODECS or basis == "public_exact_selector_schema",
                     f"{context}.decoded DATE_DMY_U8X3/TIME_HMS_U8X3 must use the exact-selector-schema basis, a Hypothesis")
        if qualification == "qualified":
            if codec in CLOCK_CODECS:
                for field in ("min", "max"):
                    _validate_clock_value(codec, limits[f"{field}_hex"], field, context)
                low, high = (bytes.fromhex(limits[f"{field}_hex"]) for field in ("min", "max"))
                # Most significant component first: date = year, month, day; time = hour, minute, second.
                key = (lambda v: (v[0], v[1], v[2])) if codec == "TIME_HMS_U8X3" else (lambda v: (v[2], v[1], v[0]))
                _require(key(low) <= key(high),
                         f"{context}.decoded {codec} min {decoded.get('min')} is later than max {decoded.get('max')}")
                _require(decoded.get("step") is None, f"{context}.decoded.step must remain unknown")
            if codec in NUMERIC_CODECS:
                minimum, maximum, step = (decoded.get(field) for field in ("min", "max", "step"))
                _require(all(isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
                             for value in (minimum, maximum, step)),
                         f"{context}.decoded numeric range must be finite")
                _require(minimum <= maximum, f"{context}.decoded numeric range must be ordered")
                _require(step > 0, f"{context}.decoded numeric range step must be positive")


def _key(selector: Any) -> str:
    return json.dumps(selector, sort_keys=True)


def _find(records: list[Any], operation: str, group: str, instance: str, register: str) -> list[dict[str, Any]]:
    wanted = {"operation": operation, "group": group, "instance": instance, "register": register}
    return [record for record in records if record.get("selector") == wanted]


def _validate_family_invariance(records: list[dict[str, Any]]) -> None:
    """Reject a qualified decoded claim in an instance-divergent selector family.

    The description response echoes GG and RR but not the instance byte, and the
    fixture retains no request bytes, so the retained material cannot prove which
    instance a response answers. A qualified range is therefore accepted only where
    every retained described instance of (operation, group, register) carries
    byte-identical raw limits and description length, with matching qualified
    codecs; records without a description are absent evidence and take no part
    in the comparison.
    """
    # Keep the recorded operation: OP02 and OP06 are distinct native namespaces.
    # Consistent scope/observation edits cannot establish it; see module docstring.
    families: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for record in records:
        selector = record["selector"]
        families.setdefault((selector["operation"], selector["group"], selector["register"]), []).append(record)
    for (operation, group, register), members in families.items():
        described = [record for record in members if record.get("raw_description_hex") is not None]
        spans = {json.dumps([record.get("raw_limits"), record.get("description_payload_length")], sort_keys=True)
                 for record in described}
        qualified = any(isinstance(record.get("decoded"), dict) and record["decoded"].get("qualification") == "qualified"
                        for record in members)
        _require(not (len(spans) > 1 and qualified),
                 f"OP{operation}/GG{group}/RR{register} qualifies a decoded range although its described instances differ; "
                 "the instance byte is not echoed, so a qualified range must be identical across every retained instance")
        codecs = {record["decoded"]["codec"] for record in described
                  if isinstance(record.get("decoded"), dict) and record["decoded"].get("qualification") == "qualified"}
        _require(len(codecs) <= 1,
                 f"OP{operation}/GG{group}/RR{register} has conflicting qualified codecs across retained instances: "
                 f"{'/'.join(sorted(codecs))}; a qualified range must use the same codec")


def _validate_remote_slot_identity(records: list[dict[str, Any]]) -> None:
    """One remote (OP, GG, II) slot retains one identity qualification and one identity."""
    slots: dict[tuple[str, str, str], tuple[int, str, tuple[Any, Any]]] = {}
    for index, record in enumerate(records):
        identity = record.get("remote_identity")
        if not isinstance(identity, dict):
            continue
        selector = record["selector"]
        slot = (selector["operation"], selector["group"], selector["instance"])
        qualification = identity.get("qualification")
        value = (identity.get("address_raw"), identity.get("firmware_raw"))
        first = slots.setdefault(slot, (index, qualification, value))
        where = f"slot OP{slot[0]}/GG{slot[1]}/II{slot[2]}"
        _require(first[1] == qualification,
                 f"records[{index}] remote identity qualification {qualification} differs from "
                 f"records[{first[0]}] {first[1]} in {where}; one slot retains one qualification")
        if qualification != "observed_remote_header":
            continue
        _require(identity.get("group") == selector["group"],
                 f"records[{index}].remote_identity.group disagrees with selector")
        _require(first[2] == value,
                 f"records[{index}] remote identity (address {value[0]}, firmware {value[1]}) differs from "
                 f"records[{first[0]}] in {where}; one slot retains one identity")


def _validate_validation_scopes(records: list[dict[str, Any]], overlay: Any) -> None:
    """Check the application overlay against the CC0 description records it classifies."""
    _require(isinstance(overlay, dict), "validation-scope overlay must be an object")
    _require(overlay.get("schema_version") == "b524-basv0-validation-scope/v1", "unexpected validation-scope overlay schema version")
    _require(overlay.get("observation_id") == "basv0_sw0217_hw8803_api1", "validation-scope overlay observation identity mismatch")
    _require(overlay.get("description_catalog") == "b524-basv0-description-profile-v1.json", "validation-scope overlay catalog mismatch")
    entries = overlay.get("records")
    _require(isinstance(entries, list) and entries, "validation-scope overlay must contain records")
    scopes: dict[str, str] = {}
    for index, entry in enumerate(entries):
        _require(isinstance(entry, dict) and isinstance(entry.get("selector"), dict),
                 f"validation-scope overlay records[{index}] must be an object with a selector object")
        key = _key(entry["selector"])
        _require(key not in scopes, f"validation-scope overlay records[{index}] duplicates a selector")
        scopes[key] = entry.get("validation_scope")
    known = {_key(record["selector"]) for record in records}
    for index, entry in enumerate(entries):
        _require(_key(entry["selector"]) in known, f"validation-scope overlay records[{index}] matches no description record")
    for index, record in enumerate(records):
        key = _key(record["selector"])
        _require(key in scopes, f"records[{index}] has no validation-scope overlay entry")
        _validate_validation_scope(record, scopes[key], f"records[{index}]")


def _validate_exact_schema_pins(records: list[dict[str, Any]]) -> None:
    """The exact-schema basis belongs to exactly the documented selector set, in both directions."""
    for index, record in enumerate(records):
        decoded = record.get("decoded")
        if not isinstance(decoded, dict):
            continue
        selector = record["selector"]
        documented = (selector["operation"], selector["group"], selector["instance"], selector["register"]) in EXACT_SCHEMA_SELECTORS
        where = f"OP{selector['operation']}/GG{selector['group']}/II{selector['instance']}/RR{selector['register']}"
        if decoded.get("codec_basis") == "public_exact_selector_schema":
            _require(documented,
                     f"records[{index}].decoded.codec_basis public_exact_selector_schema is not documented for {where}")
        elif documented:
            _require(False,
                     f"records[{index}].decoded.codec_basis must be public_exact_selector_schema for the documented "
                     f"exact-schema selector {where}")


def _validate_codec_read_widths(records: list[dict[str, Any]], observed: Any = None) -> None:
    """A qualified codec width must agree with the observed read payload width."""
    for index, record in enumerate(records):
        decoded = record.get("decoded")
        width = record.get("observed_read_payload_width")
        if isinstance(decoded, dict) and decoded.get("qualification") == "qualified":
            if width is None:
                linked = ""
                if isinstance(observed, dict) and isinstance(observed.get("records"), list):
                    for row_index, row in enumerate(observed["records"]):
                        if (isinstance(row, dict) and isinstance(row.get("description"), dict)
                                and row["description"].get("record_index") == index):
                            linked = f" linked observation records[{row_index}]"
                            break
                raise ValidationError(
                    f"records[{index}]{linked} missing observed_read_payload_width for qualified codec {decoded['codec']}")
            _require(width == CODEC_WIDTH[decoded["codec"]],
                     f"records[{index}].decoded.codec {decoded['codec']} width {CODEC_WIDTH[decoded['codec']]} "
                     f"contradicts observed_read_payload_width {width}")


def validate_fixture(path: Path, observations: Path | None = None, scopes: Path | None = None) -> None:
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: cannot read JSON") from exc
    _require(isinstance(fixture, dict), f"{path}: description must be an object")
    observed = None
    if observations is not None:
        try:
            observed = json.loads(observations.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"{observations}: cannot read JSON") from exc
        _require(isinstance(observed, dict), f"{observations}: observations must be an object")
    overlay = None
    if scopes is None and SCOPE_OVERLAY.exists():
        scopes = SCOPE_OVERLAY
    if scopes is not None:
        try:
            overlay = json.loads(scopes.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError(f"{scopes}: cannot read JSON") from exc
        _require(isinstance(overlay, dict), "validation-scope overlay must be an object")
    validate_documents(fixture, observed, path.name, overlay)


def validate_documents(fixture: Any, observed: Any = None, catalog_name: str | None = None, scopes: Any = None) -> None:
    _require(isinstance(fixture, dict), "fixture must be an object")
    _require(fixture.get("schema_version") == "b524-basv0-description-profile/v1", "unexpected schema version")
    _require(fixture.get("observation_id") == "basv0_sw0217_hw8803_api1", "unexpected observation identity")
    _require(fixture.get("local_profile") == {
        "eid": "BASV0", "software_raw": "0217", "hardware_raw": "8803",
        "api_version_raw": "1", "api_revision_raw": "1",
    }, "local_profile must retain the separate raw identity fields")
    records = fixture.get("records")
    _require(isinstance(records, list) and records, "fixture must contain records")
    for index, record in enumerate(records):
        _validate_record(record, index)
    if scopes is not None:
        _validate_validation_scopes(records, scopes)
    seen: set[str] = set()
    for index, record in enumerate(records):
        key = _key(record["selector"])
        _require(key not in seen, f"records[{index}] duplicates a description selector")
        seen.add(key)
    _validate_family_invariance(records)
    _validate_remote_slot_identity(records)
    dhw = _find(records, "02", "00", "00", "0001")
    _require(len(dhw) == 1, "fixture must retain exactly one local DHW bivalence record")
    # Published pin source: protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md
    # "Observed local bound"; the EXP interpretation retains its stated codec basis.
    context = "OP02/GG00/II00/RR0001"
    for field, expected in (
        ("raw_description_hex", "0001000000A0C10000A0410000803F"),
        ("access_flags", "03"),
    ):
        _require(dhw[0].get(field) == expected,
                 f"{context}.{field} must retain published DHW value {expected}")
    decoded = dhw[0].get("decoded")
    _require(isinstance(decoded, dict), f"{context}.decoded must retain published DHW EXP decoding")
    for field, expected in (
        ("codec", "EXP"), ("codec_provenance", "selector_qualified"),
        ("codec_basis", "public_local_constraint_codec"), ("qualification", "qualified"),
        ("min", -20), ("max", 20), ("step", 1),
    ):
        _require(decoded.get(field) == expected,
                 f"{context}.decoded.{field} must retain published DHW value {expected}")
    solar = _find(records, "02", "04", "01", "000B")
    _require(len(solar) == 1 and (solar[0].get("decoded") is None or solar[0]["decoded"].get("qualification") == "unqualified"),
             "solar II01 must not gain a qualified codec")
    for register in ("006C", "006D", "006F", "0070"):
        matches = _find(records, "02", "00", "00", register)
        _require(len(matches) == 1 and matches[0].get("decoded") is None, f"installer selector {register} must remain raw")
    for instance in VENTILATION_INSTANCES:
        ventilation = _find(records, "02", "09", instance, "0001")
        _require(len(ventilation) == 1 and ventilation[0].get("observed_read_payload_width") == 2
                 and ventilation[0].get("presence_state") == "unknown",
                 f"ventilation II{instance} RR0001 must retain unknown two-byte evidence")
        decoded = ventilation[0].get("decoded")
        _require(isinstance(decoded, dict) and decoded.get("codec") == "UIN"
                 and ventilation[0].get("description_payload_length") == 6,
                 f"ventilation II{instance} RR0001 codec must remain UIN with width 2")
    _validate_exact_schema_pins(records)
    _validate_codec_read_widths(records, observed)
    if observed is None:
        return
    _require(isinstance(observed, dict), "observations must be an object")
    _require(observed.get("observation_id") == fixture.get("observation_id"), "cross-fixture identity mismatch")
    _require(observed.get("description_catalog") == catalog_name, "cross-fixture catalog mismatch")
    rows = observed.get("records")
    _require(isinstance(rows, list) and rows, "observations must contain records")
    seen = set()
    slot_presence: dict[tuple[Any, Any], tuple[int, Any]] = {}
    descriptions = {_key(record["selector"]): record for record in records}
    for index, row in enumerate(rows):
        _require(isinstance(row, dict) and isinstance(row.get("selector"), dict),
                 f"observation records[{index}] must be an object with a selector object")
        selector = row["selector"]
        key = _key(selector)
        _require(key not in seen, f"observation records[{index}] duplicates an observation selector")
        seen.add(key)
        _require(row.get("identity_scope") == ("local" if selector.get("operation") == "02" else "remote"), f"observation records[{index}] identity scope disagrees with selector; "
                 "request opcode corroboration failed (observation identity scope)")
        state = row.get("response_state")
        flags = row.get("access_flags")
        width = row.get("observed_payload_width")
        error = row.get("error_state")
        if state == "echo_payload":
            _require(isinstance(flags, str) and flags in {"00", "01", "02", "03"} and isinstance(width, int) and width > 0 and error in {None, "parse_error"},
                     f"observation records[{index}] echo_payload fields are inconsistent")
        elif state == "status_only":
            _require(flags == "00" and width is None and error is None,
                     f"observation records[{index}] status_only fields are inconsistent")
        elif state == "transport_error":
            _require(flags is None and width is None and error == "transport_error",
                     f"observation records[{index}] transport_error fields are inconsistent")
        else:
            raise ValidationError(f"observation records[{index}] response state is unsupported")
        if selector.get("operation") == "06":
            slot = (selector.get("group"), selector.get("instance"))
            first = slot_presence.setdefault(slot, (index, row.get("presence_state")))
            _require(first[1] == row.get("presence_state"),
                     f"observation records[{index}] presence state {row.get('presence_state')} differs from "
                     f"observation records[{first[0]}] {first[1]} in slot OP06/GG{slot[0]}/II{slot[1]}; "
                     "one remote slot retains one presence state")
        reference = row.get("description")
        if reference is None:
            _require(key not in descriptions, f"observation records[{index}] drops its description link")
            continue
        record_index = reference.get("record_index")
        _require(isinstance(record_index, int) and 0 <= record_index < len(records), f"observation records[{index}] description index out of bounds")
        _require(row.get("selector") == records[record_index].get("selector"), f"observation records[{index}] description selector mismatch; "
                 f"records[{record_index}] request opcode corroboration failed "
                 "(linked observation must match operation, group, instance and register)")
        described = records[record_index]
        _require(row.get("access_flags") == described.get("access_flags"), f"observation records[{index}] access flags disagree with description")
        decoded = described.get("decoded")
        if isinstance(decoded, dict) and decoded.get("qualification") == "qualified":
            _require(width is not None,
                     f"records[{record_index}] linked observation records[{index}] missing observed_payload_width "
                     f"for qualified codec {decoded['codec']}")
        _require(row.get("observed_payload_width") == described.get("observed_read_payload_width"),
                 f"observation records[{index}] payload width disagrees with description")
        if isinstance(decoded, dict) and decoded.get("qualification") == "qualified":
            _require(width == CODEC_WIDTH.get(decoded.get("codec")),
                     f"observation records[{index}] observed width contradicts the qualified codec width")
        _require(row.get("presence_state") == described.get("presence_state"),
                 f"observation records[{index}] presence state disagrees with description")
        _require(row.get("name") == described.get("name"), f"observation records[{index}] name disagrees with description")
        if reference.get("acquisition_state") == "unqualified":
            _require(described.get("decoded") is None,
                     f"observation records[{index}] unqualified description must not carry a decoded codec")
        if reference.get("acquisition_state") == "unavailable":
            _require(described.get("raw_description_hex") is None and described.get("response_state") == "describe_unavailable", f"observation records[{index}] unavailable description has raw metadata")
        else:
            _require(described.get("raw_description_hex") is not None and described.get("response_state") == "describe_matched", f"observation records[{index}] available description lacks raw metadata")


    for record in records:
        _require(_key(record["selector"]) in seen,
                 f"description selector {_key(record['selector'])} has no register-observation record")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--observations", type=Path)
    parser.add_argument("--scopes", type=Path, help="validation-scope overlay (default: the repository overlay when present)")
    args = parser.parse_args()
    try:
        validate_fixture(args.fixture, args.observations, args.scopes)
    except ValidationError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
