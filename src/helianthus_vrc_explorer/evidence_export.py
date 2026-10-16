"""Deterministic native BASV0 evidence and separate application-policy overlay.

Inputs are Explorer's retained sanitized source pair, not a docs-ebus checkout.
The application baseline alone cannot reconstruct unqualified candidates, missing
replies or omitted request/response bytes. No such evidence is manufactured here.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from .evidence_compat import normalize_api_identity

DESCRIPTION = "b524-basv0-description-profile-v1.json"
OBSERVATIONS = "b524-basv0-register-observations-v1.json"
OVERLAY = "b524-basv0-validation-scope-v1.json"
_SELECTOR_FIELDS = ("operation", "group", "instance", "register")
_DESCRIPTION_FIELDS = (
    "selector",
    "identity_scope",
    "name",
    "access_flags",
    "presence_state",
    "response_state",
    "raw_description_hex",
    "description_payload_length",
    "raw_limits",
    "decoded",
    "observed_read_payload_width",
    "remote_identity",
)
_OBSERVATION_FIELDS = (
    "selector",
    "identity_scope",
    "name",
    "access_flags",
    "presence_state",
    "response_state",
    "observed_payload_width",
    "error_state",
    "description",
)
_INSTANCE_NONCLAIM = (
    "A description response does not echo the instance byte and no request is retained, "
    "so the retained material cannot prove which instance a description answers; "
    "a decoded range is qualified only where it is identical across every retained "
    "described instance of its selector."
)
_LEGACY_CODECS = {"HDA:3": "DATE_DMY_U8X3", "HTI": "TIME_HMS_U8X3"}


def selector_key(selector: dict[str, Any]) -> tuple[str, ...]:
    """Use the complete native selector; opcode namespaces must never collapse."""
    if not isinstance(selector, dict) or set(selector) != set(_SELECTOR_FIELDS):
        raise ValueError("Native selector requires operation/group/instance/register")
    values = tuple(selector[key] for key in _SELECTOR_FIELDS)
    if any(
        not isinstance(value, str) or re.fullmatch(pattern, value) is None
        for value, pattern in zip(
            values, ("02|06", "[0-9A-F]{2}", "[0-9A-F]{2}", "[0-9A-F]{4}"), strict=True
        )
    ):
        raise ValueError("Invalid native selector")
    return values


def validation_scope_for_record(record: dict[str, Any], *, presence: str) -> str:
    """Application classification; callers must supply their own presence evidence.

    Export uses the source observation. Reuse must pass current consumer presence.
    Selector qualification is acceptance vocabulary, not a Proven codec grade.
    """
    decoded = record.get("decoded")
    if (
        record.get("raw_description_hex") is None
        or not isinstance(decoded, dict)
        or decoded.get("qualification") != "qualified"
        or decoded.get("codec_provenance") != "selector_qualified"
    ):
        return "raw_evidence_only"
    if (
        decoded.get("codec") in {"DATE_DMY_U8X3", "TIME_HMS_U8X3"}
        or decoded.get("codec_basis") == "public_exact_selector_schema"
        or presence in {"observed_inactive", "unknown"}
    ):
        return "display_only"
    if (
        presence == "observed_present"
        and decoded.get("codec_basis") == "public_local_constraint_codec"
    ):
        return "format_range_and_step"
    return "raw_evidence_only"


def validate_scope_overlay(native: dict[str, Any], overlay: dict[str, Any]) -> None:
    """Require a bijection and the recorded source-installation classification."""
    if (
        overlay.get("schema_version") != "b524-basv0-validation-scope/v1"
        or overlay.get("evidence_class") != "application_classification_overlay"
        or overlay.get("description_catalog") != DESCRIPTION
        or overlay.get("observation_id") != native.get("observation_id")
    ):
        raise ValueError("Invalid validation-scope overlay identity")
    known = {}
    for record in native["records"]:
        if "validation_scope" in record:
            raise ValueError("Native description must not carry validation_scope")
        key = selector_key(record["selector"])
        if key in known:
            raise ValueError("Duplicate description selector")
        known[key] = record
    scopes = {}
    for row in overlay["records"]:
        key = selector_key(row["selector"])
        if key in scopes:
            raise ValueError("Duplicate overlay selector")
        if key not in known:
            raise ValueError("Orphan overlay selector")
        expected = validation_scope_for_record(known[key], presence=known[key]["presence_state"])
        if row.get("validation_scope") != expected:
            raise ValueError("Overlay scope disagrees with source classification")
        scopes[key] = row["validation_scope"]
    if known.keys() != scopes.keys():
        raise ValueError("Missing overlay selector")


def _pick(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Allowlist evidence fields so application provenance/private extras stay out."""
    return {key: deepcopy(source[key]) for key in fields}


def _native_identity(description: dict[str, Any], manifest: dict[str, Any]) -> dict[str, str]:
    identity = description["local_profile"]
    candidates = [
        row["controller"]
        for row in manifest["profiles"]
        if row.get("id") == description["observation_id"]
    ]
    if len(candidates) != 1:
        raise ValueError("Native identity needs one independent manifest entry")
    controller = normalize_api_identity(candidates[0])
    if controller.get("api_identity_conflicts"):
        raise ValueError("Contradictory API identity")
    result = {}
    for key, source in (
        ("eid", "eid"),
        ("software_raw", "software_raw_hex"),
        ("hardware_raw", "hardware_raw_hex"),
        ("api_version_raw", "api_version_raw"),
        ("api_revision_raw", "api_revision_raw"),
    ):
        value = controller.get(source)
        if not isinstance(value, str) or not value:
            raise ValueError(f"Missing independent native identity: {key}")
        if key in identity and identity[key] != value:
            raise ValueError(f"Native identity conflict: {key}")
        result[key] = value
    # This exporter targets the published BASV0 observation, not arbitrary profiles.
    if result != {
        "eid": "BASV0",
        "software_raw": "0217",
        "hardware_raw": "8803",
        "api_version_raw": "1",
        "api_revision_raw": "1",
    }:
        raise ValueError("Native identity differs from the BASV0 publication context")
    return result


def build_native_evidence(
    description: dict[str, Any],
    observations: dict[str, Any],
    identity_manifest: dict[str, Any],
    *,
    allow_legacy_interpretation: bool = False,
) -> dict[str, dict[str, Any]]:
    """Refresh the sanitized source pair, retaining all candidates and observations.

    Explicit opt-in is required to publish the legacy Explorer codec interpretation.
    The independent manifest corroborates both API dimensions, never the API1 label.
    The native schema suffix remains /v1; scan and application versions are separate.
    """
    if (
        description.get("schema_version") != "b524-basv0-description-profile/v1"
        or description.get("evidence_class") != "sanitized_read_only_metadata_observation"
        or description.get("observation_id") != "basv0_sw0217_hw8803_api1"
        or observations.get("schema_version") != "b524-basv0-register-observations/v1"
        or observations.get("evidence_class") != "sanitized_read_only_register_observation"
        or observations.get("observation_id") != description["observation_id"]
        or observations.get("description_catalog") != DESCRIPTION
    ):
        raise ValueError("Unsupported sanitized native source pair")
    legacy = (
        any(
            isinstance(row.get("decoded"), dict) and row["decoded"].get("codec") in _LEGACY_CODECS
            for row in description["records"]
        )
        or "api_revision" in description["local_profile"]
    )
    if legacy and not allow_legacy_interpretation:
        raise ValueError("Exporting a legacy interpretation requires explicit opt-in")
    native = _pick(description, ("schema_version", "evidence_class", "observation_id"))
    native["local_profile"] = _native_identity(description, identity_manifest)
    records = []
    for row in description["records"]:
        record = _pick(row, _DESCRIPTION_FIELDS)
        record["selector"] = _pick(row["selector"], _SELECTOR_FIELDS)
        if isinstance(record["decoded"], dict):
            decoded = _pick(
                record["decoded"],
                ("codec", "codec_provenance", "qualification", "min", "max", "step", "codec_basis"),
            )
            decoded["codec"] = _LEGACY_CODECS.get(decoded["codec"], decoded["codec"])
            record["decoded"] = decoded
        if record["raw_limits"] is not None:
            record["raw_limits"] = _pick(record["raw_limits"], ("min_hex", "max_hex", "step_hex"))
        if record["remote_identity"] is not None:
            remote = record["remote_identity"]
            record["remote_identity"] = _pick(
                remote,
                tuple(
                    key
                    for key in ("group", "address_raw", "firmware_raw", "qualification")
                    if key in remote
                ),
            )
        records.append(record)
    native["records"] = records
    native["nonclaims"] = list(description["nonclaims"])
    if _INSTANCE_NONCLAIM not in native["nonclaims"]:
        native["nonclaims"].append(_INSTANCE_NONCLAIM)
    overlay = {
        "schema_version": "b524-basv0-validation-scope/v1",
        "evidence_class": "application_classification_overlay",
        "observation_id": native["observation_id"],
        "description_catalog": DESCRIPTION,
        "records": [
            {
                "selector": deepcopy(row["selector"]),
                "validation_scope": validation_scope_for_record(
                    row, presence=row["presence_state"]
                ),
            }
            for row in records
        ],
    }
    validate_scope_overlay(native, overlay)
    scalar = _pick(observations, ("schema_version", "evidence_class", "observation_id"))
    scalar.update(
        current_values="omitted",
        native_headers="omitted",
        response_payloads="omitted",
        description_catalog=DESCRIPTION,
    )
    scalar["records"] = []
    seen = set()
    for row in observations["records"]:
        key = selector_key(row["selector"])
        if key in seen:
            raise ValueError("Duplicate observation selector")
        seen.add(key)
        record = _pick(row, _OBSERVATION_FIELDS)
        record["selector"] = _pick(row["selector"], _SELECTOR_FIELDS)
        link = record["description"]
        if link is not None:
            record["description"] = _pick(link, ("record_index", "acquisition_state"))
            index = link["record_index"]
            if (
                type(index) is not int
                or not 0 <= index < len(records)
                or records[index]["selector"] != record["selector"]
            ):
                raise ValueError("Observation description link/selector mismatch")
        scalar["records"].append(record)
    scalar["nonclaims"] = list(observations["nonclaims"])
    return {DESCRIPTION: native, OBSERVATIONS: scalar, OVERLAY: overlay}


def serialize_native_evidence(documents: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    """Match the published UTF-8 order, indentation and final newline exactly."""
    result = {}
    for name in (DESCRIPTION, OBSERVATIONS, OVERLAY):
        document = documents[name]
        if name == OVERLAY:
            header = json.dumps(
                {key: value for key, value in document.items() if key != "records"},
                indent=2,
                ensure_ascii=False,
            )
            lines = [json.dumps(row, ensure_ascii=False) for row in document["records"]]
            content = header[:-2] + ',\n  "records": [\n    ' + ",\n    ".join(lines) + "\n  ]\n}"
        else:
            content = json.dumps(document, indent=2, ensure_ascii=False)
        result[name] = (content + "\n").encode("utf-8")
    return result


def write_native_evidence(documents: dict[str, dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in serialize_native_evidence(documents).items():
        (output_dir / name).write_bytes(content)
