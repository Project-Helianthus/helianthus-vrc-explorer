"""Profile-scoped, publishable B524 description baselines.

Bundled metadata remains a prior observation. An exact native controller profile,
plus separate remote class and firmware where applicable, can qualify it for value
validation without a fresh Describe request. Metadata alone never authorizes a
device write; the write path still requires fresh identity, access and baseline
evidence plus explicit UI confirmation.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from copy import deepcopy
from importlib import resources
from typing import Any

from ..evidence_compat import interpret_legacy_codecs, normalize_api_identity
from ..evidence_export import validate_scope_overlay, validation_scope_for_record
from ..protocol.b524_metadata import decode_parameter_description
from .description_profile_reminder import ABSENT, remote_slot_not_connected

_FIELDS = ("type", "width", "min", "max", "step")
_SELECTORS = ("read_opcode", "group", "instance", "register")
_OBSERVED_CONTROLLER_PROFILE_KEYS = (
    "profile",
    "eid",
    "software_raw_hex",
    "hardware_raw_hex",
    "api_version",
    "api_revision",
    "api_version_raw",
    "api_revision_raw",
)
_CONTROLLER_PROFILE_KEYS = (*_OBSERVED_CONTROLLER_PROFILE_KEYS, "profile_id")
_REMOTE_PROFILE_KEYS = ("device_class_raw", "device_firmware_raw")
# Catalogue blocks that record what a reference installation showed. They plan scans and
# recognise remote devices; they are never a profile limit.
INSTALLATION_OBSERVATION_QUALIFICATION = "installation_observation_not_profile_limit"
_INSTANCE_OBSERVATIONS = "instance_observations"
_REMOTE_DEVICE_OBSERVATIONS = "remote_device_observations"
_INSTANCE_SEMANTICS = frozenset({"capacity", "expected_population"})
_DEVICE_ROW_KEYS = ("group", "instance", "device_class_raw", "device_firmware_raw")


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


def _installation_block(profile_id: object, key: str) -> dict[str, Any] | None:
    """Return one installation-observation block of a catalogue profile, or ``None``.

    A block counts only when it carries the installation-observation qualification, so a
    malformed or unqualified block is ignored rather than trusted.
    """

    if not isinstance(profile_id, str):
        return None
    for candidate in load_description_profile_catalog().get("profiles", []):
        if isinstance(candidate, dict) and candidate.get("id") == profile_id:
            block = candidate.get(key)
            if (
                isinstance(block, dict)
                and block.get("observed_instance_qualification")
                == INSTALLATION_OBSERVATION_QUALIFICATION
            ):
                return block
    return None


def _count_field(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 0xFF else None


def bundled_instance_observation(
    profile_id: str | None, *, read_opcode: int, group: int
) -> dict[str, Any] | None:
    """Return the catalogue's installation observation for one OP/GG, or ``None``.

    The result has ``semantics`` (``capacity`` for the OP00 supported-capacity groups,
    ``expected_population`` for the count groups) plus ``capacity``, ``expected`` and
    ``observed`` as small integers or ``None``. It describes the installation that was
    scanned. Planners may use it as scan context, but it is not a profile limit: the RR
    bounds come from the profile tables and each slot still needs its own presence
    predicate.
    """

    block = _installation_block(profile_id, _INSTANCE_OBSERVATIONS)
    if block is None:
        return None
    for row in block.get("groups", []):
        if (
            isinstance(row, dict)
            and row.get("read_opcode") == f"0x{read_opcode:02x}"
            and row.get("group") == f"0x{group:02x}"
            and row.get("semantics") in _INSTANCE_SEMANTICS
        ):
            return {
                "semantics": row["semantics"],
                "capacity": _count_field(row.get("capacity")),
                "expected": _count_field(row.get("expected")),
                "observed": _count_field(row.get("observed")),
            }
    return None


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
    return normalize_api_identity(
        {
            "profile": context.get("profile"),
            "eid": eid.strip().upper() if isinstance(eid, str) else None,
            "software_raw_hex": _canonical_raw(identity.get("sw")),
            "hardware_raw_hex": _canonical_raw(identity.get("hw")),
            "api_version": context.get("api_version"),
            "api_revision": context.get("api_revision"),
            **{
                key: context[key]
                for key in ("api_version_raw", "api_revision_raw")
                if key in context
            },
            # Human-readable fields remain useful evidence, but never qualify reuse.
            "model": identity.get("model"),
            "firmware": identity.get("firmware"),
        }
    )


def _catalog_match(profile: dict[str, Any]) -> dict[str, Any] | None:
    profile = normalize_api_identity(profile)
    if profile.get("api_identity_conflicts"):
        return None
    catalog = load_description_profile_catalog()
    if catalog.get("schema_version") != 1:
        raise ValueError("Unsupported B524 description profile catalog version")
    matches: list[dict[str, Any]] = []
    for candidate in catalog.get("profiles", []):
        if not isinstance(candidate, dict) or not isinstance(candidate.get("controller"), dict):
            continue
        controller = normalize_api_identity(candidate["controller"])
        if (
            profile.get("profile") == candidate.get("profile")
            and profile.get("eid") == controller.get("eid")
            and profile.get("software_raw_hex") == controller.get("software_raw_hex")
            and profile.get("hardware_raw_hex") == controller.get("hardware_raw_hex")
            and profile.get("api_version") == controller.get("api_version")
            and profile.get("api_revision") == controller.get("api_revision")
            and profile.get("api_version_raw") == controller.get("api_version_raw")
            and profile.get("api_revision_raw") == controller.get("api_revision_raw")
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
    profile = normalize_api_identity(profile)
    if profile.get("api_identity_conflicts"):
        return False
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

    profile = normalize_api_identity(profile)
    if profile.get("api_identity_conflicts"):
        return False
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
    left, right = normalize_api_identity(left), normalize_api_identity(right)
    if left.get("api_identity_conflicts") or right.get("api_identity_conflicts"):
        return True
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
    left, right = normalize_api_identity(left), normalize_api_identity(right)
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

    if (
        selector is not None
        and selector.get("read_opcode") == "0x06"
        and remote_slot_not_connected(
            artifact, str(selector.get("group", "")), str(selector.get("instance", ""))
        )
    ):
        # No device answered the presence probe: there is no identity to qualify.
        controller = _controller_profile(artifact)
        candidate = _catalog_match(controller) if controller else None
        return {
            "status": ABSENT,
            "profile_id": candidate.get("id") if candidate is not None else None,
            "device_class": "remote",
        }
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
    if _remote_device_in_catalog(profile, selector):
        return True
    return any(
        isinstance(row, dict)
        and row.get("read_opcode") == "0x06"
        and row.get("group") == selector.get("group")
        and _compatible_profiles(row.get("profile", {}), profile)
        for row in load_description_baseline().get("descriptions", [])
    )


def _remote_device_in_catalog(profile: dict[str, Any], selector: dict[str, str]) -> bool:
    """Match a remote class/firmware tuple against the devices a reference scan observed.

    The catalogue records which remote devices were present, with their class and
    firmware, under the controller profile they were seen with. A tuple in the same group
    is recognised on any instance; a different class or firmware stays unknown.
    """

    block = _installation_block(profile.get("profile_id"), _REMOTE_DEVICE_OBSERVATIONS)
    device_class = _canonical_raw(profile.get("device_class_raw"))
    firmware = _canonical_raw(profile.get("device_firmware_raw"))
    group = str(selector.get("group", "")).lower()
    if block is None or device_class is None or firmware is None:
        return False
    return any(
        isinstance(row, dict)
        and str(row.get("group", "")).lower() == group
        and _canonical_raw(row.get("device_class_raw")) == device_class
        and _canonical_raw(row.get("device_firmware_raw")) == firmware
        for row in block.get("devices", [])
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


def _selector_codec_supported(
    selector: dict[str, str],
    type_spec: object,
    profile: dict[str, Any],
    *,
    bundle: dict[str, Any],
) -> bool:
    """Qualify a legacy omission only from the same exact native profile."""

    if not isinstance(type_spec, str) or not _qualified_profile(profile):
        return False
    return any(
        isinstance(candidate, dict)
        and _same_selector(candidate, selector)
        and candidate.get("type") == type_spec
        and candidate.get("codec_provenance") == "selector_qualified"
        and _compatible_profiles(candidate.get("profile", {}), profile)
        for candidate in bundle.get("descriptions", [])
    )


def export_description_baseline(
    artifact: dict[str, Any], *, allow_legacy_interpretation: bool = False
) -> dict[str, Any]:
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
            if not allow_legacy_interpretation and (
                "codec_migration" in entry or "codec_migration" in desc
            ):
                raise ValueError("Exporting a legacy interpretation requires explicit opt-in")
            provenance = desc.get("codec_provenance", entry.get("codec_provenance"))
            if provenance != "selector_qualified":
                continue
            if not _same_selector(desc, selector):
                continue
            if normalize_api_identity(desc.get("target_profile", profile)) != profile:
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
                    **(
                        {
                            "codec_migration": deepcopy(
                                desc.get("codec_migration", entry.get("codec_migration"))
                            )
                        }
                        if "codec_migration" in desc or "codec_migration" in entry
                        else {}
                    ),
                    "decoder_revision": decoded["decoder_revision"],
                    "step_qualification": decoded["step_qualification"],
                    "validation_scope": decoded["validation_scope"],
                    "codec_provenance": "selector_qualified",
                }
            )
    coverage = artifact.get("meta", {}).get("parameter_description_coverage", {})
    return {
        "schema_version": 2,
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
    return _enrich_bundle_profiles(bundle, trust_legacy_codec=True)


def _enrich_bundle_profiles(
    bundle: dict[str, Any], *, trust_legacy_codec: bool = False
) -> dict[str, Any]:
    """Bind legacy bundled rows to one exact native identity manifest entry."""

    result = deepcopy(bundle)
    if type(result.get("schema_version")) is not int or result["schema_version"] not in {1, 2}:
        raise ValueError("Unsupported B524 description baseline version")
    catalog = load_description_profile_catalog()
    profiles = [row for row in catalog.get("profiles", []) if isinstance(row, dict)]
    for description in result.get("descriptions", []):
        if not isinstance(description, dict) or not isinstance(description.get("profile"), dict):
            continue
        description["profile"] = normalize_api_identity(description["profile"])
        profile = description["profile"]
        if result.get("schema_version") == 1 and (
            trust_legacy_codec
            or (
                description.get("source") == "read_only_observed_baseline"
                and description.get("decoder_revision")
                in {"b524-description/v1", "b524-description/v2"}
            )
        ):
            interpret_legacy_codecs(description, source_version=1)
        if description.get("type") in {"DATE_DMY_U8X3", "TIME_HMS_U8X3"}:
            description["validation_scope"] = "display_only"
        if profile.get("api_identity_conflicts"):
            continue
        if trust_legacy_codec:
            description.setdefault("codec_provenance", "selector_qualified")
        if all(_known_profile_value(profile.get(key)) for key in _CONTROLLER_PROFILE_KEYS):
            continue
        matches: list[dict[str, Any]] = []
        for candidate in profiles:
            signature = candidate.get("bundle_signature")
            controller = candidate.get("controller")
            if not isinstance(signature, dict) or not isinstance(controller, dict):
                continue
            controller = normalize_api_identity(controller)
            if (
                profile.get("profile") == candidate.get("profile")
                and profile.get("model") == signature.get("model")
                and profile.get("firmware") == signature.get("firmware")
                and profile.get("api_version") == controller.get("api_version")
                and profile.get("api_revision") == controller.get("api_revision")
                and profile.get("api_version_raw") == controller.get("api_version_raw")
                and profile.get("api_revision_raw") == controller.get("api_revision_raw")
            ):
                matches.append(candidate)
        if len(matches) != 1:
            continue
        matched = matches[0]
        controller = normalize_api_identity(matched["controller"])
        profile.update(
            profile_id=matched["id"],
            eid=controller["eid"],
            software_raw_hex=controller["software_raw_hex"],
            hardware_raw_hex=controller["hardware_raw_hex"],
            api_version=controller["api_version"],
            api_revision=controller["api_revision"],
            api_version_raw=controller["api_version_raw"],
            api_revision_raw=controller["api_revision_raw"],
        )
    return result


def merge_description_baselines(
    previous: dict[str, Any], current: dict[str, Any], *, allow_legacy_interpretation: bool = False
) -> dict[str, Any]:
    """Update qualified rows additively; a partial scan cannot erase other rows.

    Known optional identity fields from the previous baseline remain historical
    observations. They are never inserted into current-target evidence. Distinct
    firmware or device profiles remain distinct baseline variants.
    """
    previous = _enrich_bundle_profiles(previous)
    current = _enrich_bundle_profiles(current)
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
    if not allow_legacy_interpretation and any("codec_migration" in row for row in rows):
        raise ValueError("Exporting a legacy interpretation requires explicit opt-in")
    return {
        "schema_version": 2,
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


def _hex_key(value: object, digits: int) -> str | None:
    if isinstance(value, str) and re.fullmatch(rf"0[xX][0-9a-fA-F]{{{digits}}}", value):
        return f"0x{int(value, 16):0{digits}x}"
    return None


def export_installation_observations(artifact: dict[str, Any]) -> dict[str, Any]:
    """Project the installation a scan observed into the two catalogue blocks.

    Only small integers, fixed enumerations, hex selectors and the remote class/firmware
    identity are retained: no serial, no free text, no clock and no raw reply bytes.
    The scan needs an exact catalogued controller profile, because the blocks are
    recorded under that profile. A remote device without a readable class or firmware
    keeps ``None`` for it and therefore never makes a row exact.
    """

    status = description_catalog_status(artifact)
    profile_id = status.get("profile_id")
    if status.get("status") != "exact" or not isinstance(profile_id, str):
        raise ValueError("Installation observations need an exact catalogued controller profile")
    meta = artifact.get("meta")
    counts = meta.get("instance_counts") if isinstance(meta, dict) else None
    groups: list[dict[str, Any]] = []
    for key, row in counts.items() if isinstance(counts, dict) else ():
        match = re.fullmatch(r"(0x[0-9a-f]{2}):(0x[0-9a-f]{2})", str(key).lower())
        if match is None or not isinstance(row, dict):
            continue
        read_opcode, group = match.groups()
        observed = _count_field(row.get("observed"))
        if read_opcode not in {"0x02", "0x06"} or observed is None:
            continue
        if row.get("semantics") not in _INSTANCE_SEMANTICS:
            continue
        groups.append(
            {
                "read_opcode": read_opcode,
                "group": group,
                "identifier": _hex_key(row.get("identifier"), 4),
                "semantics": row["semantics"],
                "capacity": _count_field(row.get("capacity")),
                "expected": _count_field(row.get("expected")),
                "observed": observed,
            }
        )
    devices: list[dict[str, Any]] = []
    remote_groups = artifact.get("operations", {}).get("0x06", {}).get("groups", {})
    for group_key, group_obj in remote_groups.items() if isinstance(remote_groups, dict) else ():
        probes = group_obj.get("availability_probes") if isinstance(group_obj, dict) else None
        for instance_key, probe in probes.items() if isinstance(probes, dict) else ():
            group, instance = _hex_key(group_key, 2), _hex_key(instance_key, 2)
            if (
                group is None
                or instance is None
                or not isinstance(probe, dict)
                or probe.get("present") is not True
                or probe.get("connection_state") != "connected"
            ):
                continue
            identity = _device_identity(artifact, group_key, instance_key)
            devices.append(
                {
                    "group": group,
                    "instance": instance,
                    "device_class_raw": identity["class_raw"],
                    "device_firmware_raw": identity["firmware_raw"],
                }
            )
    return {
        "profile_id": profile_id,
        _INSTANCE_OBSERVATIONS: {
            "observed_instance_qualification": INSTALLATION_OBSERVATION_QUALIFICATION,
            "groups": sorted(groups, key=lambda row: (row["read_opcode"], row["group"])),
        },
        _REMOTE_DEVICE_OBSERVATIONS: {
            "observed_instance_qualification": INSTALLATION_OBSERVATION_QUALIFICATION,
            "devices": sorted(devices, key=lambda row: (row["group"], row["instance"])),
        },
    }


def merge_installation_observations(
    catalog: dict[str, Any], observations: dict[str, Any]
) -> dict[str, Any]:
    """Add scan observations to one catalogue profile without removing other rows.

    A group row is replaced by the newer observation of the same OP/GG. A remote device
    row is keyed by group, instance, class and firmware, so a device seen again with
    other firmware adds a row instead of erasing the earlier one. Nothing else in the
    profile entry is touched, and an unknown profile id is refused.
    """

    result = deepcopy(catalog)
    profile = next(
        (
            row
            for row in result.get("profiles", [])
            if isinstance(row, dict) and row.get("id") == observations.get("profile_id")
        ),
        None,
    )
    if profile is None:
        raise ValueError("The scan's controller profile is not in the description profile catalog")
    for key, collection, identity in (
        (_INSTANCE_OBSERVATIONS, "groups", ("read_opcode", "group")),
        (_REMOTE_DEVICE_OBSERVATIONS, "devices", _DEVICE_ROW_KEYS),
    ):
        existing = profile.get(key, {})
        if existing and (
            not isinstance(existing, dict)
            or existing.get("observed_instance_qualification")
            != INSTALLATION_OBSERVATION_QUALIFICATION
        ):
            raise ValueError("Existing installation observations are not qualified as observations")
        rows = {
            tuple(row[field] for field in identity): row for row in existing.get(collection, [])
        }
        for row in observations[key][collection]:
            merged_row = deepcopy(row)
            previous = rows.get(tuple(row[field] for field in identity))
            if key == _INSTANCE_OBSERVATIONS and isinstance(previous, dict):
                # An unreadable OP00 count must not erase what an earlier scan recorded.
                for field in ("identifier", "capacity", "expected"):
                    if merged_row.get(field) is None and previous.get(field) is not None:
                        merged_row[field] = previous[field]
            rows[tuple(row[field] for field in identity)] = merged_row
        profile[key] = {
            "observed_instance_qualification": INSTALLATION_OBSERVATION_QUALIFICATION,
            collection: [
                rows[row_key]
                for row_key in sorted(rows, key=lambda row_key: tuple(map(str, row_key)))
            ],
        }
    return result


def attach_bundled_descriptions(
    artifact: dict[str, Any], *, bundle: dict[str, Any] | None = None
) -> None:
    """Refresh baseline annotations without replacing current-target evidence."""
    bundle = load_description_baseline() if bundle is None else _enrich_bundle_profiles(bundle)
    for selector, entry in _entries(artifact):
        profile = description_profile(artifact, selector)
        live = entry.get("parameter_description")
        candidates = [
            candidate
            for candidate in bundle.get("descriptions", [])
            if isinstance(candidate, dict) and _same_selector(candidate, selector)
        ]
        if isinstance(live, dict):
            provenance = live.get("codec_provenance", entry.get("codec_provenance"))
            if provenance not in {"selector_qualified", "length_inferred"}:
                provenance = (
                    "selector_qualified"
                    if _selector_codec_supported(selector, live.get("type"), profile, bundle=bundle)
                    else "legacy_unknown"
                )
            live["codec_provenance"] = provenance
            live["target_profile"] = normalize_api_identity(
                live.get("target_profile", deepcopy(profile))
            )
            live["target_profile_match"] = (
                _observed_native_profile(profile) and live["target_profile"] == profile
            )
        # Recompute after profile changes; stale annotations are never retained.
        entry.pop("bundled_parameter_description", None)
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


def _native_current_scope(
    artifact: dict[str, Any], selector: dict[str, str], record: dict[str, Any]
) -> str:
    """The overlay describes its source installation, never current presence."""
    group = (
        artifact.get("operations", {})
        .get(selector["read_opcode"], {})
        .get("groups", {})
        .get(selector["group"], {})
    )
    instance = group.get("instances", {}).get(selector["instance"], {})
    probe = group.get("availability_probes", {}).get(selector["instance"], {})
    # Instance presence may only schedule reads; require a current availability probe.
    present = probe.get("present")
    if (
        probe.get("availability_qualification") == "unknown"
        or probe.get("source", group.get("availability_contract", {}).get("source"))
        == "always_present"
    ):
        # A scheduling fallback is not a current observation of presence.
        present = None
    presence = (
        "observed_present"
        if present is True
        else "observed_inactive"
        if present is False
        else "unknown"
    )
    entry = instance.get("registers", {}).get(selector["register"], {})
    if entry.get("error") is not None or entry.get("response_state") in {
        "timeout",
        "nack",
        "nack_or_crc",
        "empty_reply",
    }:
        presence = "unknown"
    return validation_scope_for_record(record, presence=presence)


def attach_native_descriptions(
    artifact: dict[str, Any], native: dict[str, Any], overlay: dict[str, Any]
) -> None:
    """Adapt the CC0 description plus AGPL policy overlay to application metadata.

    Complete native local identity must match independently. Remote candidates
    stay outside reuse: this publication supplies no qualified remote codecs.
    Source scope is checked for consistency, then current applicability is derived
    from consumer presence. No native record's validation_scope is read.
    """
    validate_scope_overlay(native, overlay)
    if native.get("schema_version") != "b524-basv0-description-profile/v1":
        raise ValueError("Unsupported native description profile")
    identity = native["local_profile"]
    current = description_profile(artifact)
    matches = _qualified_profile(current) and all(
        isinstance(identity.get(native_key), str) and identity[native_key] == current.get(app_key)
        for native_key, app_key in (
            ("eid", "eid"),
            ("software_raw", "software_raw_hex"),
            ("hardware_raw", "hardware_raw_hex"),
            ("api_version_raw", "api_version_raw"),
            ("api_revision_raw", "api_revision_raw"),
        )
    )
    retained_descriptions: dict[tuple[str, ...], set[tuple[str, str | None]]] = {}
    for record in native["records"] if matches else []:
        if record.get("identity_scope") == "local" and record.get("raw_description_hex"):
            key = tuple(record["selector"][field] for field in ("operation", "group", "register"))
            decoded = record.get("decoded")
            codec = decoded.get("codec") if isinstance(decoded, dict) else None
            retained_descriptions.setdefault(key, set()).add(
                (record["raw_description_hex"].lower(), codec)
            )
    rows = []
    for record in native["records"] if matches else []:
        decoded = record.get("decoded")
        if (
            record.get("identity_scope") != "local"
            or not isinstance(decoded, dict)
            or decoded.get("qualification") != "qualified"
            or decoded.get("codec_provenance") != "selector_qualified"
        ):
            continue
        selector = {
            app_key: f"0x{record['selector'][native_key].lower()}"
            for native_key, app_key in zip(
                ("operation", "group", "instance", "register"), _SELECTORS, strict=True
            )
        }
        # Decode the retained bytes on a copy. This preserves the native observation
        # while keeping ordinary baseline identity and selector checks in force.
        desc = decode_parameter_description(
            bytes.fromhex(record["raw_description_hex"]),
            opcode=1,
            group=int(selector["group"], 0),
            instance=int(selector["instance"], 0),
            register=int(selector["register"], 0),
            type_spec=decoded["codec"],
        )
        if any(desc[key] != decoded[key] for key in ("min", "max", "step")):
            raise ValueError("Native decoded limits disagree with retained bytes")
        # Replies do not echo the instance and requests were not retained. Only
        # identical descriptions across all retained instances can supply limits.
        key = tuple(record["selector"][field] for field in ("operation", "group", "register"))
        instances_agree = len(retained_descriptions[key]) == 1
        scope = _native_current_scope(artifact, selector, record)
        if not instances_agree and scope == "format_range_and_step":
            scope = "display_only"
        rows.append(
            {
                **selector,
                **{key: desc[key] for key in _FIELDS},
                "profile": deepcopy(current),
                "codec_provenance": "selector_qualified",
                "validation_scope": scope,
                "native_instances_agree": instances_agree,
                "native_policy_record": deepcopy(record),
                "step_qualification": desc["step_qualification"],
                "source": "native_description_with_application_overlay",
            }
        )
    attach_bundled_descriptions(artifact, bundle={"schema_version": 2, "descriptions": rows})


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
        and live.get("codec_provenance") == "selector_qualified"
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
    if bundled.get("type") != entry.get("type"):
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
    # Native compatibility above qualifies this target. Preserve the original
    # observation's profile, while binding validation to the current identity.
    result["target_profile"] = deepcopy(profile)
    if isinstance(result.get("native_policy_record"), dict):
        result["validation_scope"] = _native_current_scope(
            artifact, selector, result["native_policy_record"]
        )
        if (
            result.get("native_instances_agree") is not True
            and result["validation_scope"] == "format_range_and_step"
        ):
            result["validation_scope"] = "display_only"
    return result
