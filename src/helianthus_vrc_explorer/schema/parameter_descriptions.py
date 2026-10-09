"""Profile-scoped, publishable B524 description baselines.

Bundled metadata remains a prior observation. An exact native controller profile,
plus separate remote class and firmware where applicable, can qualify it for value
validation without a fresh Describe request. Metadata alone never authorizes a
device write; the write path still requires fresh identity, access and baseline
evidence plus explicit UI confirmation.
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
_OBSERVED_CONTROLLER_PROFILE_KEYS = (
    "profile",
    "eid",
    "software_raw_hex",
    "hardware_raw_hex",
    "api_version",
    "api_revision",
)
_CONTROLLER_PROFILE_KEYS = (*_OBSERVED_CONTROLLER_PROFILE_KEYS, "profile_id")
_REMOTE_PROFILE_KEYS = ("device_class_raw", "device_firmware_raw")


def load_generic_description_catalog() -> dict[str, Any]:
    """Return class observations requested with II=FF, outside slot validation.

    These rows carry no verified device identity and are never a fallback for
    ``attach_bundled_descriptions`` or current-target edit validation.
    """
    return json.loads(
        resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_generic_parameter_descriptions.json")
        .read_text(encoding="utf-8")
    )


def load_description_profile_catalog() -> dict[str, Any]:
    """Load exact native identity constraints for bundled description profiles."""

    return json.loads(
        resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_description_profiles.json")
        .read_text(encoding="utf-8")
    )


def _canonical_raw(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    result = value.strip().replace(" ", "").upper()
    if not result or any(character not in "0123456789ABCDEF" for character in result):
        return None
    return result


def _controller_profile(artifact: dict[str, Any]) -> dict[str, Any]:
    meta = artifact.get("meta", {})
    identity = meta.get("identity", meta.get("resolved_identity", {}))
    context = meta.get("profile_context", {})
    if not isinstance(identity, dict) or not isinstance(context, dict):
        return {}
    eid = identity.get("eid", identity.get("device_id"))
    return {
        "profile": context.get("profile"),
        "eid": eid.strip().upper() if isinstance(eid, str) else None,
        "software_raw_hex": _canonical_raw(identity.get("sw")),
        "hardware_raw_hex": _canonical_raw(identity.get("hw")),
        "api_version": context.get("api_version"),
        "api_revision": context.get("api_revision"),
        # Human-readable fields remain useful evidence, but never qualify reuse.
        "model": identity.get("model"),
        "firmware": identity.get("firmware"),
    }


def _catalog_match(profile: dict[str, Any]) -> dict[str, Any] | None:
    catalog = load_description_profile_catalog()
    if catalog.get("schema_version") != 1:
        raise ValueError("Unsupported B524 description profile catalog version")
    matches: list[dict[str, Any]] = []
    for candidate in catalog.get("profiles", []):
        if not isinstance(candidate, dict) or not isinstance(candidate.get("controller"), dict):
            continue
        controller = candidate["controller"]
        if (
            profile.get("profile") == candidate.get("profile")
            and profile.get("eid") == controller.get("eid")
            and profile.get("software_raw_hex") == controller.get("software_raw_hex")
            and profile.get("hardware_raw_hex") == controller.get("hardware_raw_hex")
            and profile.get("api_version") == controller.get("api_version")
            and profile.get("api_revision") == controller.get("api_revision")
        ):
            matches.append(candidate)
    return matches[0] if len(matches) == 1 else None


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
    profile = _controller_profile(artifact)
    if not profile:
        return {}
    controller = _device_identity(artifact, "0x09", "0x01")
    profile.update(
        controller_class_raw=controller["class_raw"],
        controller_firmware_raw=controller["firmware_raw"],
    )
    catalog_profile = _catalog_match(profile)
    profile["profile_id"] = catalog_profile.get("id") if catalog_profile is not None else None
    if selector is not None and selector["read_opcode"] == "0x06":
        device = _device_identity(artifact, selector["group"], selector["instance"])
        profile.update(
            device_identity_required=True,
            device_class_raw=device["class_raw"],
            device_firmware_raw=device["firmware_raw"],
        )
    return profile


def _qualified_profile(profile: dict[str, Any]) -> bool:
    keys = list(_CONTROLLER_PROFILE_KEYS)
    if profile.get("device_identity_required"):
        keys.extend(_REMOTE_PROFILE_KEYS)
    return all(_known_profile_value(profile.get(key)) for key in keys)


def _observed_native_profile(profile: dict[str, Any]) -> bool:
    """Return whether fresh evidence identifies the native target exactly.

    A catalog profile id is deliberately not required here. Live Describe
    metadata remains usable for an unknown controller or remote device when its
    complete native identity was observed in the same artifact. Cached profile
    reuse continues to require ``_qualified_profile``.
    """

    keys = list(_OBSERVED_CONTROLLER_PROFILE_KEYS)
    if profile.get("device_identity_required"):
        keys.extend(_REMOTE_PROFILE_KEYS)
    return all(_known_profile_value(profile.get(key)) for key in keys)


def _known_profile_value(value: Any) -> bool:
    return value is not None and (
        not isinstance(value, str)
        or value.strip().lower() not in {"", "n/a", "unknown", "not_available"}
    )


def _profiles_conflict(left: dict[str, Any], right: dict[str, Any]) -> bool:
    """Only contradictory authoritative native observations establish mismatch."""
    keys = set(_CONTROLLER_PROFILE_KEYS)
    if left.get("device_identity_required") or right.get("device_identity_required"):
        keys.update(_REMOTE_PROFILE_KEYS)
    return any(
        _known_profile_value(left.get(key))
        and _known_profile_value(right.get(key))
        and left[key] != right[key]
        for key in keys
    )


def _compatible_profiles(left: dict[str, Any], right: dict[str, Any]) -> bool:
    if not _qualified_profile(left) or not _qualified_profile(right):
        return False
    if bool(left.get("device_identity_required")) != bool(right.get("device_identity_required")):
        return False
    keys = list(_CONTROLLER_PROFILE_KEYS)
    if left.get("device_identity_required"):
        keys.extend(_REMOTE_PROFILE_KEYS)
    return all(left.get(key) == right.get(key) for key in keys)


def description_catalog_status(
    artifact: dict[str, Any], selector: dict[str, str] | None = None
) -> dict[str, Any]:
    """Return exact catalog qualification for planner policy and UI labels."""

    profile = description_profile(artifact, selector)
    if _qualified_profile(profile) and (
        not profile.get("device_identity_required")
        or _remote_identity_in_catalog(profile, selector)
    ):
        return {
            "status": "exact",
            "profile_id": profile["profile_id"],
            "device_class": "remote" if profile.get("device_identity_required") else "local",
        }
    controller = _controller_profile(artifact)
    candidate = _catalog_match(controller) if controller else None
    return {
        "status": (
            "unqualified"
            if candidate is not None and not _observed_native_profile(profile)
            else "unknown"
        ),
        "profile_id": candidate.get("id") if candidate is not None else None,
        "device_class": (
            "remote" if selector is not None and selector.get("read_opcode") == "0x06" else "local"
        ),
    }


def _remote_identity_in_catalog(profile: dict[str, Any], selector: dict[str, str] | None) -> bool:
    """Match a remote class/firmware tuple within its observed group.

    Register presence is intentionally excluded. Once the remote identity is a
    known group/profile variant, an absent bundled register stays absent instead
    of causing an implicit live Describe request.
    """

    if selector is None or selector.get("read_opcode") != "0x06":
        return False
    return any(
        isinstance(row, dict)
        and row.get("read_opcode") == "0x06"
        and row.get("group") == selector.get("group")
        and _compatible_profiles(row.get("profile", {}), profile)
        for row in load_description_baseline().get("descriptions", [])
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
    bundle = json.loads(path.read_text(encoding="utf-8"))
    return _enrich_bundle_profiles(bundle)


def _enrich_bundle_profiles(bundle: dict[str, Any]) -> dict[str, Any]:
    """Bind legacy bundled rows to one exact native identity manifest entry."""

    result = deepcopy(bundle)
    catalog = load_description_profile_catalog()
    profiles = [row for row in catalog.get("profiles", []) if isinstance(row, dict)]
    for description in result.get("descriptions", []):
        if not isinstance(description, dict) or not isinstance(description.get("profile"), dict):
            continue
        profile = description["profile"]
        if all(_known_profile_value(profile.get(key)) for key in _CONTROLLER_PROFILE_KEYS):
            continue
        matches: list[dict[str, Any]] = []
        for candidate in profiles:
            signature = candidate.get("bundle_signature")
            controller = candidate.get("controller")
            if not isinstance(signature, dict) or not isinstance(controller, dict):
                continue
            if (
                profile.get("profile") == candidate.get("profile")
                and profile.get("model") == signature.get("model")
                and profile.get("firmware") == signature.get("firmware")
                and profile.get("api_version") == controller.get("api_version")
                and profile.get("api_revision") == controller.get("api_revision")
            ):
                matches.append(candidate)
        if len(matches) != 1:
            continue
        matched = matches[0]
        controller = matched["controller"]
        profile.update(
            profile_id=matched["id"],
            eid=controller["eid"],
            software_raw_hex=controller["software_raw_hex"],
            hardware_raw_hex=controller["hardware_raw_hex"],
            api_version=controller["api_version"],
            api_revision=controller["api_revision"],
        )
    return result


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
    bundle = load_description_baseline() if bundle is None else _enrich_bundle_profiles(bundle)
    if bundle.get("schema_version") != 1:
        raise ValueError("Unsupported B524 description baseline version")
    for selector, entry in _entries(artifact):
        profile = description_profile(artifact, selector)
        live = entry.get("parameter_description")
        if isinstance(live, dict):
            live.setdefault("target_profile", deepcopy(profile))
            live["target_profile_match"] = (
                _observed_native_profile(profile) and live["target_profile"] == profile
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
        cached["profile_qualification"] = "exact" if exact or compatible else "mismatch"
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


def _entry_for_selector(
    artifact: dict[str, Any], selector: dict[str, str]
) -> dict[str, Any] | None:
    if set(selector) != set(_SELECTORS) or any(
        not isinstance(selector.get(key), str) for key in _SELECTORS
    ):
        raise ValueError("selector must contain read_opcode, group, instance, and register strings")
    try:
        entry = artifact["operations"][selector["read_opcode"]]["groups"][selector["group"]][
            "instances"
        ][selector["instance"]]["registers"][selector["register"]]
    except (KeyError, TypeError):
        return None
    return entry if isinstance(entry, dict) else None


def effective_parameter_description(
    artifact: dict[str, Any], selector: dict[str, str]
) -> dict[str, Any] | None:
    """Resolve exact live metadata first, then an exact profile baseline.

    The returned copy is directly consumable by edit validation. Bundled rows
    retain their offline verification state and use ``profile_qualified`` rather
    than impersonating a freshly matched live Describe reply.
    """

    entry = _entry_for_selector(artifact, selector)
    if entry is None:
        return None
    profile = description_profile(artifact, selector)
    live = entry.get("parameter_description")
    if (
        isinstance(live, dict)
        and live.get("qualification") == "matched"
        and _observed_native_profile(profile)
        and _same_selector(live, selector)
        and live.get("target_profile") == profile
        and live.get("target_profile_match") is True
    ):
        result = deepcopy(live)
        result["source"] = "live"
        return result

    bundled = entry.get("bundled_parameter_description")
    if not _qualified_profile(profile):
        return None
    if not isinstance(bundled, dict) or not _same_selector(bundled, selector):
        return None
    if (
        not _compatible_profiles(bundled.get("profile", {}), profile)
        or bundled.get("profile_qualification") != "exact"
    ):
        return None
    if bundled.get("verification") in {"profile_mismatch", "profile_unqualified"}:
        return None
    result = deepcopy(bundled)
    result["source"] = "profile"
    result["qualification"] = "profile_qualified"
    return result
