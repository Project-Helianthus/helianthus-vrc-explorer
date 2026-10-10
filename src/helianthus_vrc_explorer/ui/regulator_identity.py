"""Catalog identity labels shared by the scan, Browser and HTML headers."""

from __future__ import annotations

from collections.abc import Mapping

from ..schema.regulator_identity import lookup_regulator_identity, spn_from_hw


def regulator_profile_label(identity: Mapping[str, object]) -> str | None:
    """Use only an exact EID/SPN pair, preserving all raw identity fields."""
    eid = identity.get("eid", identity.get("device_id"))
    if not isinstance(eid, str):
        return None
    alternative = identity.get("device_id")
    if isinstance(alternative, str) and alternative.strip().upper() != eid.strip().upper():
        return None
    manufacturer = identity.get("manufacturer")
    if manufacturer is not None:
        try:
            parsed = int(manufacturer, 0) if isinstance(manufacturer, str) else manufacturer
        except ValueError:
            return None
        if isinstance(parsed, bool) or parsed != 0xB5:
            return None
    supplied_spn = identity.get("spn")
    if identity.get("spn_source") == "sw":
        # 0.6.0 stored an SPN decoded from the software-version field. That
        # derivation is known to be wrong, so the stored value is neither
        # trusted nor allowed to veto the raw hardware field.
        supplied_spn = None
    hw = identity.get("hw")
    spn: int | str | None
    if hw is not None:
        if not isinstance(hw, str):
            return None
        spn = spn_from_hw(hw)
        if spn is None:
            return None
    else:
        spn = supplied_spn if isinstance(supplied_spn, (int, str)) else None
    try:
        matched = lookup_regulator_identity(eid, spn)
        if supplied_spn is not None:
            if not isinstance(supplied_spn, (int, str)):
                return None
            if lookup_regulator_identity(eid, supplied_spn) != matched:
                return None
    except (TypeError, ValueError):
        return None
    if matched is None:
        return None
    return f"{matched.model_name} · {matched.protocol_family} · {matched.eid}/{matched.spn_hex}"
