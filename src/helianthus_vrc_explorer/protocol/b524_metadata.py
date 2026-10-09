"""B524 system information and correlated parameter description metadata."""

from __future__ import annotations

import math
from datetime import date
from typing import Any

from .parser import ValueParseError, parse_typed_value

SYSTEM_INFORMATION_NAMES = (
    "circuit_count",
    "zone_count",
    "solar_circuit_count",
    "solar_loaded_tank_count",
    "device_count",
    "generator_count",
    "api_version",
    "api_revision",
    "vr70_count",
    "vr71_count",
    "remote_control_count",
    "delta_t_count",
    "boiler_count",
    "heat_pump_count",
    "vpm_w_count",
    "vpm_s_count",
    "recovair_count",
    "cooling_heat_pump_count",
)
COUNT_GROUP_IDS = {
    (0x02, 0x02): 0,
    (0x02, 0x03): 1,
    (0x02, 0x04): 2,
    (0x02, 0x05): 3,
    (0x02, 0x08): 11,
    (0x02, 0x09): 16,
    (0x06, 0x01): 12,
    (0x06, 0x02): 13,
    (0x06, 0x06): 15,
    (0x06, 0x07): 14,
    (0x06, 0x09): 10,
    (0x06, 0x0B): 8,
    (0x06, 0x0C): 9,
}
# OP00 keeps its wire-level ``*_count`` names.  For the two local topology
# fields, however, the value describes supported capacity rather than a
# configured-instance population.  The module tuple is only a cross-check: it
# must never replace the value reported on the wire.
CAPACITY_SYSTEM_INFORMATION_IDS = frozenset({0, 1})
MODULE_CAPACITY_MATRIX = {
    (0, 0): 1,
    (1, 0): 2,
    (0, 1): 3,
    (1, 1): 5,
    (2, 1): 7,
    (3, 1): 8,
}
_WIDTHS = {
    "UCH": 1,
    "BOOL": 1,
    "I8": 1,
    "UIN": 2,
    "I16": 2,
    "U32": 4,
    "I32": 4,
    "EXP": 4,
    "HDA:3": 3,
    "HTI": 3,
}


def expected_instance_count(value: float, *, capacity: int) -> int | None:
    if not math.isfinite(value) or value < 0 or not float(value).is_integer() or value > capacity:
        return None
    return int(value)


def supported_capacity(value: float) -> int | None:
    """Return a finite non-negative OP00 capacity without inferring presence."""
    if not math.isfinite(value) or value < 0 or not float(value).is_integer():
        return None
    return int(value)


def module_capacity_crosscheck(vr70_count: float, vr71_count: float) -> int | None:
    """Return the documented capacity for one known module-count tuple only."""
    vr70 = supported_capacity(vr70_count)
    vr71 = supported_capacity(vr71_count)
    if vr70 is None or vr71 is None:
        return None
    return MODULE_CAPACITY_MATRIX.get((vr70, vr71))


def decode_parameter_description(
    response: bytes,
    *,
    opcode: int,
    group: int,
    instance: int,
    register: int,
    type_spec: str,
) -> dict[str, Any]:
    """Decode a transport-normalized GG/RR16 + MIN/MAX/STEP response.

    The eBUS length is framing, not a datatype tag. The observed parameter codec
    determines how the three equal-width spans are interpreted.
    """
    if opcode not in {1, 7}:
        raise ValueError("Description opcode must be 0x01 or 0x07")
    normalized = type_spec.strip().upper()
    width = _WIDTHS.get(normalized)
    if width is None:
        raise ValueError(f"Unsupported description codec: {type_spec}")
    if len(response) != 3 + 3 * width:
        raise ValueError("Description length does not match the parameter codec")
    if response[0] != group or int.from_bytes(response[1:3], "little") != register:
        raise ValueError("Description GG/RR16 echo mismatch")
    spans = [response[3 + i * width : 3 + (i + 1) * width] for i in range(3)]
    try:
        lower = parse_typed_value(normalized, spans[0])
        upper = parse_typed_value(normalized, spans[1])
        if normalized in {"HDA:3", "HTI"}:
            # STEP is named by the operation; its calendar/time encoding is
            # not established by the scalar's three-byte current-value format.
            step: object = None
        else:
            step = parse_typed_value(normalized, spans[2])
    except ValueParseError as exc:
        raise ValueError(str(exc)) from exc
    if normalized not in {"HDA:3", "HTI"}:
        values = (lower, upper, step)
        if any(not isinstance(v, (int, float)) or not math.isfinite(v) for v in values):
            raise ValueError("Description has non-finite or non-numeric limits")
    if step is not None and (not isinstance(step, (int, float)) or step < 0):
        raise ValueError("Description has inconsistent step")
    if normalized in {"HDA:3", "HTI"}:
        if not isinstance(lower, str) or not isinstance(upper, str) or lower > upper:
            raise ValueError("Description has inconsistent calendar/time limits")
    elif (
        not isinstance(lower, (int, float)) or not isinstance(upper, (int, float)) or lower > upper
    ):
        raise ValueError("Description has inconsistent limits")
    return {
        "qualification": "matched",
        "description_opcode": f"0x{opcode:02x}",
        "read_opcode": "0x02" if opcode == 1 else "0x06",
        "group": f"0x{group:02x}",
        "instance": f"0x{instance:02x}",
        "register": f"0x{register:04x}",
        "type": normalized,
        "width": width,
        "min": lower,
        "max": upper,
        "step": step,
        "step_raw_hex": spans[2].hex(),
        "step_qualification": "unknown" if step is None else "decoded",
        "validation_scope": "format_and_range" if step is None else "format_range_and_step",
        "reply_hex": response.hex(),
        "source": "complete_description",
        "decoder_revision": "b524-description/v2",
    }


def validate_parameter_edit(
    description: dict[str, Any] | None,
    *,
    type_spec: str,
    value: object,
    encoded: bytes,
) -> str | None:
    """Return None for valid input, 'unvalidated' when absent, or a rejection reason."""
    if not description or description.get("qualification") not in {
        "matched",
        "profile_qualified",
    }:
        return "unvalidated"
    if description.get("type") != type_spec.strip().upper():
        return "Description format does not match the parameter codec"
    if len(encoded) != description.get("width"):
        return "Encoded width does not match the description format"
    try:
        candidate = parse_typed_value(type_spec, encoded)
        lower, upper, step = description["min"], description["max"], description["step"]
        if step is not None and (
            not isinstance(step, (int, float)) or not math.isfinite(step) or step < 0
        ):
            return "Description has an invalid step"
        if type_spec.strip().upper() == "HDA:3":
            candidate_date = date.fromisoformat(str(candidate))
            lower_date, upper_date = date.fromisoformat(lower), date.fromisoformat(upper)
            if not lower_date <= candidate_date <= upper_date:
                return "Value is outside the described range"
            delta = (candidate_date - lower_date).days
        elif type_spec.strip().upper() == "HTI":
            if not isinstance(candidate, str) or not lower <= candidate <= upper:
                return "Value is outside the described range"
            delta = 0
        else:
            if not isinstance(candidate, (int, float)) or not math.isfinite(candidate):
                return "Value is non-finite or has an invalid format"
            if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in (lower, upper)):
                return "Description has invalid limits"
            if not lower <= candidate <= upper:
                return "Value is outside the described range"
            delta = candidate - lower
        if step is None:
            return "unvalidated"
        if step > 0:
            quotient = delta / step
            if not math.isfinite(quotient) or not math.isclose(
                quotient, round(quotient), rel_tol=0.0, abs_tol=1e-4
            ):
                return "Value does not follow the described step"
    except (ValueError, TypeError, KeyError, OverflowError, ValueParseError):
        return "Description format cannot validate this value"
    return None
