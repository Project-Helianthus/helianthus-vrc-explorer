"""Application-only legacy interpretations; never modify source evidence files."""

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any

LEGACY_CALENDAR_CODECS = {"HDA:3": "DATE_DMY_U8X3", "HTI": "TIME_HMS_U8X3"}


def _interpret_overrides(overrides: dict[str, Any], path: tuple[str, ...] = ()) -> list:
    migrations = []
    for key, value in overrides.items():
        if isinstance(value, dict):
            migrations.extend(_interpret_overrides(value, (*path, key)))
        elif isinstance(value, str) and value in LEGACY_CALENDAR_CODECS:
            migrations.append({"path": [*path, key], "source_label": value})
            overrides[key] = LEGACY_CALENDAR_CODECS[value]
    return migrations


def has_explorer_provenance(artifact: dict[str, Any]) -> bool:
    """Recognize explicit provenance or the historical Explorer scan envelope.

    A schema number, controller family, or codec label alone is insufficient.
    Explicit external provenance takes precedence over a copied contract.
    """
    meta = artifact.get("meta", {})
    if not isinstance(meta, dict):
        return False
    if "producer" in meta:
        return meta["producer"] == "helianthus-vrc-explorer"
    # Before artifact_contract existed, the scanner emitted this complete
    # metadata envelope. Require all fields and the version-appropriate scan
    # container; a bare schema/type/device match is deliberately insufficient.
    # An explicit (even unrecognized) contract must not be overridden by this
    # historical fallback, nor may new-schema artifacts use it.
    version = artifact.get("schema_version")
    if "artifact_contract" not in meta and version in (None, "2.0", "2.1", "2.2", "2.3"):
        container = "operations" if version == "2.3" else "groups"
        if (
            isinstance(artifact.get(container), dict)
            and isinstance(meta.get("scan_timestamp"), str)
            and bool(meta["scan_timestamp"])
            and type(meta.get("scan_duration_seconds")) in {int, float}
            and isinstance(meta.get("destination_address"), str)
            and bool(meta["destination_address"])
            and isinstance(meta.get("schema_sources"), list)
            and isinstance(meta.get("incomplete"), bool)
        ):
            return True
    contract = meta.get("artifact_contract", {})
    if not isinstance(contract, dict):
        return False
    row_identity = contract.get("b524_row_identity", {})
    if (
        contract.get("operation_identity_keys") == "opcode_hex"
        and contract.get("operation_labels") == "presentation_only"
        and isinstance(row_identity, dict)
        and row_identity.get("dedupe_key_format") == "<group>:<operation>:<instance>:<register>"
    ):
        return True
    if "artifact_contract" in meta:
        return False
    replay = meta.get("replay_trace")
    sources = meta.get("schema_sources")
    return (
        isinstance(replay, dict)
        and replay.get("format") == "enhanced_v1"
        and isinstance(sources, list)
        and "replay_trace:enhanced_v1" in sources
    )


def interpret_legacy_codecs(value: Any, *, source_version: str | int) -> bool:
    """Adapt types on an already copied, provenance-qualified application object.

    Decoded values and bytes stay historical. Explicit replay or overrides may
    create a separate value interpretation; this adapter never decodes again.
    """
    changed = False
    if isinstance(value, dict):
        overrides = value.get("type_overrides")
        if isinstance(overrides, dict):
            migrations = _interpret_overrides(overrides)
            if migrations:
                value["type_override_migrations"] = [
                    {**row, "source_version": source_version, "source": "helianthus-vrc-explorer"}
                    for row in migrations
                ]
                changed = True
        for key in ("type", "codec"):
            original = value.get(key)
            if isinstance(original, str) and original in LEGACY_CALENDAR_CODECS:
                value["codec_migration"] = {
                    "source_label": original,
                    "source_version": source_version,
                    "source": "helianthus-vrc-explorer",
                }
                value[key] = LEGACY_CALENDAR_CODECS[original]
                changed = True
        for key, child in value.items():
            if key != "codec_migration":
                changed = interpret_legacy_codecs(child, source_version=source_version) or changed
    elif isinstance(value, list):
        for child in value:
            changed = interpret_legacy_codecs(child, source_version=source_version) or changed
    return changed


def api_identity_string(value: object) -> str | None:
    """Represent one independently observed numeric API dimension as a string."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        return None
    if not number.is_finite():
        return None
    return format(number.normalize(), "f")


def normalize_api_identity(profile: dict[str, Any]) -> dict[str, Any]:
    """Retain numeric write identities and normalize the two dimensions separately.

    Missing revisions remain missing. Contradictory or malformed dimensions are
    retained for inspection and explicitly prevent profile qualification.
    """
    result = dict(profile)
    conflicts = set(profile.get("api_identity_conflicts", []))
    for field in ("api_version", "api_revision"):
        raw_field = f"{field}_raw"
        numeric = api_identity_string(profile.get(field))
        if raw_field in profile and profile[raw_field] is not None:
            raw = api_identity_string(profile[raw_field])
            if (
                not isinstance(profile[raw_field], str)
                or raw is None
                or (field in profile and (numeric is None or raw != numeric))
            ):
                conflicts.add(field)
            else:
                result[raw_field] = raw
        else:
            result[raw_field] = numeric
    if conflicts:
        result["api_identity_conflicts"] = sorted(conflicts)
    return result
