"""Display-only formatting for B524 OP00 system information records."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence

_LABELS: dict[str, str] = {
    "circuit_count": "Circuits",
    "zone_count": "Zones",
    "solar_circuit_count": "Solar circuits",
    "solar_loaded_tank_count": "Solar loaded tanks",
    "device_count": "Devices",
    "generator_count": "Generators",
    "api_version": "API version",
    "api_revision": "API revision",
    "vr70_count": "VR 70",
    "vr71_count": "VR 71",
    "remote_control_count": "Remote controls",
    "delta_t_count": "Delta T",
    "boiler_count": "Boilers",
    "heat_pump_count": "Heat pumps",
    "vpm_w_count": "VPM W",
    "vpm_s_count": "VPM S",
    "recovair_count": "recoVAIR",
    "cooling_heat_pump_count": "Cooling heat pumps",
}


def _display_value(value: object) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return "unavailable"
        if value.is_integer():
            return str(int(value))
        return str(value)
    if value is None:
        return "unavailable"
    return str(value)


def format_system_information_rows(
    system_information: Sequence[Mapping[str, object]] | None,
) -> tuple[tuple[str, str], ...]:
    """Return label/value-only planner rows from artifact metadata."""

    if not system_information:
        return ()
    rows: list[tuple[str, str]] = []
    for record in system_information:
        name = record.get("name")
        if not isinstance(name, str) or not name:
            continue
        label = _LABELS.get(name, name.replace("_", " ").capitalize())
        rows.append((label, _display_value(record.get("value"))))
    return tuple(rows)


def format_system_information_text(
    system_information: Sequence[Mapping[str, object]] | None,
) -> str:
    """Return a compact one-line Textual planner summary."""

    rows = format_system_information_rows(system_information)
    return " · ".join(f"{label}: {value}" for label, value in rows)
