"""Profile-scoped, publishable B524 description baselines.

Bundled metadata is a prior observation. It never substitutes for a description
verified on the current target or authorizes a device write.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from copy import deepcopy
from importlib import resources
from typing import Any

from ..protocol.b524_metadata import decode_parameter_description

_FIELDS = ("type", "width", "min", "max", "step")
_SELECTORS = ("read_opcode", "group", "instance", "register")


def _device_identity(artifact: dict[str, Any], group: str, instance: str) -> dict[str, Any]:
    registers = (
        artifact.get("operations", {})
        .get("0x06", {})
        .get("groups", {})
        .get(group, {})
        .get("instances", {})
        .get(instance, {})
        .get("registers", {})
    )

    def observed_bytes(register: str, codecs: tuple[str, ...], width: int) -> str | None:
        entry = registers.get(register, {})
        if entry.get("type") not in codecs or entry.get("value") is None:
            return None
        try:
            raw = bytes.fromhex(entry.get("raw_hex", ""))
        except (TypeError, ValueError):
            return None
        if len(raw) != width or raw == b"\xff" * width:
            return None
        return raw.hex()

    return {
        "class_raw": observed_bytes("0x0002", ("HEX:1",), 1),
        "firmware_raw": observed_bytes("0x0004", ("FW", "FWU"), 3),
    }


def description_profile(
    artifact: dict[str, Any], selector: dict[str, str] | None = None
) -> dict[str, Any]:
    meta = artifact.get("meta", {})
    identity = meta.get("identity", meta.get("resolved_identity", {}))
    context = meta.get("profile_context", {})
    if not isinstance(identity, dict) or not isinstance(context, dict):
        return {}
    controller = _device_identity(artifact, "0x09", "0x01")
    profile = {
        "profile": context.get("profile"),
        "model": identity.get("model"),
        "firmware": identity.get("firmware"),
        "api_version": context.get("api_version"),
        "api_revision": context.get("api_revision"),
        "controller_class_raw": controller["class_raw"],
        "controller_firmware_raw": controller["firmware_raw"],
    }
    if selector is not None and selector["read_opcode"] == "0x06":
        device = _device_identity(artifact, selector["group"], selector["instance"])
        profile.update(
            device_identity_required=True,
            device_class_raw=device["class_raw"],
            device_firmware_raw=device["firmware_raw"],
        )
    return profile


def _qualified_profile(profile: dict[str, Any]) -> bool:
    keys = ["profile", "model", "firmware"]
    if profile.get("device_identity_required"):
        keys.extend(("device_class_raw", "device_firmware_raw"))
    return all(
        isinstance(profile.get(key), str)
        and profile[key].strip().lower() not in {"", "n/a", "unknown", "not_available"}
        for key in keys
    )


def _known_profile_value(value: Any) -> bool:
    return value is not None and (
        not isinstance(value, str)
        or value.strip().lower() not in {"", "n/a", "unknown", "not_available"}
    )


def _profiles_conflict(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Only contradictory observations establish a profile mismatch."""
    return any(
        _known_profile_value(left.get(key))
        and _known_profile_value(right.get(key))
        and left[key] != right[key]
        for key in left.keys() | right.keys()
    )


def _compatible_profiles(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        _qualified_profile(left)
        and _qualified_profile(right)
        and bool(left.get("device_identity_required"))
        == bool(right.get("device_identity_required"))
        and not _profiles_conflict(left, right)
    )


def _entries(artifact: dict[str, Any]) -> Iterator[tuple[dict[str, str], dict[str, Any]]]:
    operations = artifact.get("operations", {})
    for op in ("0x02", "0x06"):
        for gg, group in operations.get(op, {}).get("groups", {}).items():
            for ii, instance in group.get("instances", {}).items():
                for rr, entry in instance.get("registers", {}).items():
                    if isinstance(entry, dict):
                        yield dict(zip(_SELECTORS, (op, gg, ii, rr), strict=True)), entry


def _same_selector(description: dict[str, Any], selector: dict[str, str]) -> bool:
    return all(description.get(key) == value for key, value in selector.items())


def export_description_baseline(artifact: dict[str, Any]) -> dict[str, Any]:
    """Export decoded metadata, excluding serials, endpoints and raw captures.

    Only complete, correlated replies that reproduce the stored interpretation
    are exported. An incomplete scan can supply qualified rows, but cannot claim
    complete coverage.
    """
    descriptions: list[dict[str, Any]] = []
    for selector, entry in _entries(artifact):
        profile = description_profile(artifact, selector)
        if _qualified_profile(profile):
            desc = entry.get("parameter_description")
            if not isinstance(desc, dict) or desc.get("qualification") != "matched":
                continue
            if not _same_selector(desc, selector):
                continue
            if desc.get("target_profile", profile) != profile:
                continue
            expected_opcode = "0x01" if selector["read_opcode"] == "0x02" else "0x07"
            if desc.get("description_opcode") != expected_opcode:
                continue
            try:
                decoded = decode_parameter_description(
                    bytes.fromhex(desc["reply_hex"]),
                    opcode=int(expected_opcode, 0),
                    group=int(selector["group"], 0),
                    instance=int(selector["instance"], 0),
                    register=int(selector["register"], 0),
                    type_spec=entry["type"],
                )
            except (KeyError, TypeError, ValueError):
                continue
            if any(decoded.get(key) != desc.get(key) for key in _FIELDS):
                continue
            descriptions.append(
                {
                    **selector,
                    "description_opcode": expected_opcode,
                    "profile": deepcopy(profile),
                    **{key: decoded[key] for key in _FIELDS},
                    "source": "read_only_observed_baseline",
                    "decoder_revision": decoded["decoder_revision"],
                    "step_qualification": decoded["step_qualification"],
                    "validation_scope": decoded["validation_scope"],
                }
            )
    coverage = artifact.get("meta", {}).get("parameter_description_coverage", {})
    return {
        "schema_version": 1,
        "descriptions": descriptions,
        "coverage": {
            "complete_scan": artifact.get("meta", {}).get("incomplete") is False,
            "exported": len(descriptions),
            **{key: coverage.get(key) for key in ("eligible", "attempted")},
            "interpreted": len(descriptions),
            "step_decoded": sum(row["step_qualification"] == "decoded" for row in descriptions),
        },
    }


def load_description_baseline() -> dict[str, Any]:
    path = resources.files("helianthus_vrc_explorer.data").joinpath(
        "b524_parameter_descriptions.json"
    )
    return json.loads(path.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def merge_description_baselines(
    previous: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Update qualified rows additively; a partial scan cannot erase other rows.

    Known optional identity fields from the previous baseline remain historical
    observations. They are never inserted into current-target evidence. Distinct
    firmware or device profiles remain distinct baseline variants.
    """
    if any(bundle.get("schema_version") != 1 for bundle in (previous, current)):
        raise ValueError("Unsupported B524 description baseline version")
    rows = deepcopy(previous.get("descriptions", []))
    for incoming in current.get("descriptions", []):
        profile = incoming.get("profile", {})
        if not _qualified_profile(profile):
            continue
        compatible = [
            index
            for index, existing in enumerate(rows)
            if all(existing.get(key) == incoming.get(key) for key in _SELECTORS)
            and _compatible_profiles(existing.get("profile", {}), profile)
        ]
        exact = [index for index in compatible if rows[index]["profile"] == profile]
        matches = exact or compatible
        replacement = deepcopy(incoming)
        if len(matches) == 1:
            index = matches[0]
            replacement["profile"] = {
                **rows[index]["profile"],
                **{key: value for key, value in profile.items() if _known_profile_value(value)},
            }
            rows[index] = replacement
        else:
            rows.append(replacement)
    rows.sort(
        key=lambda row: (
            *(row[key] for key in _SELECTORS),
            json.dumps(row["profile"], sort_keys=True),
        )
    )
    return {
        "schema_version": 1,
        "descriptions": rows,
        "coverage": {
            "complete_scan": False,
            "exported": len(rows),
            "interpreted": len(rows),
            "step_decoded": sum(row.get("step_qualification") == "decoded" for row in rows),
            "current_run_exported": len(current.get("descriptions", [])),
            "merged_observations": True,
        },
    }


def attach_bundled_descriptions(
    artifact: dict[str, Any], *, bundle: dict[str, Any] | None = None
) -> None:
    """Refresh baseline annotations without replacing current-target evidence."""
    if bundle is None:
        bundle = load_description_baseline()
    if bundle.get("schema_version") != 1:
        raise ValueError("Unsupported B524 description baseline version")
    for selector, entry in _entries(artifact):
        profile = description_profile(artifact, selector)
        live = entry.get("parameter_description")
        if isinstance(live, dict):
            live.setdefault("target_profile", deepcopy(profile))
            live["target_profile_match"] = (
                _qualified_profile(profile) and live["target_profile"] == profile
            )
        # Recompute after profile changes; stale annotations are never retained.
        entry.pop("bundled_parameter_description", None)
        candidates = [
            candidate
            for candidate in bundle.get("descriptions", [])
            if isinstance(candidate, dict) and _same_selector(candidate, selector)
        ]
        exact = [candidate for candidate in candidates if candidate.get("profile") == profile]
        compatible = [
            candidate
            for candidate in candidates
            if _compatible_profiles(candidate.get("profile", {}), profile)
        ]
        selected = exact or compatible or candidates
        if len(selected) != 1:
            continue
        cached = deepcopy(selected[0])
        cached["qualification"] = "bundled"
        cached["verification"] = "not_verified"
        cached_profile = cached.get("profile", {})
        cached["profile_qualification"] = "exact" if exact else "partial"
        if _profiles_conflict(cached_profile, profile):
            cached["verification"] = "profile_mismatch"
        elif not _compatible_profiles(cached_profile, profile):
            cached["verification"] = "profile_unqualified"
        else:
            if isinstance(live, dict):
                if not live.get("target_profile_match"):
                    cached["verification"] = (
                        "profile_mismatch"
                        if _profiles_conflict(live.get("target_profile", {}), profile)
                        else "profile_unqualified"
                    )
                elif live.get("qualification") == "matched" and _same_selector(live, selector):
                    cached["verification"] = (
                        "matches"
                        if all(live.get(key) == cached.get(key) for key in _FIELDS)
                        else "differs"
                    )
                else:
                    cached["verification"] = "unavailable"
        entry["bundled_parameter_description"] = cached
