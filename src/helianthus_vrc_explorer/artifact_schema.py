from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

CURRENT_ARTIFACT_SCHEMA_VERSION = "2.2"
LEGACY_UNVERSIONED_SCHEMA = "legacy-unversioned"
LEGACY_VERSIONED_SCHEMAS = frozenset({"2.0", "2.1"})


class ArtifactSchemaError(ValueError):
    """Raised when an artifact schema version is unsupported or malformed."""


@dataclass(frozen=True, slots=True)
class ArtifactMigrationReport:
    source_schema_version: str
    target_schema_version: str
    changed: bool
    register_count_before: int
    register_count_after: int


def _normalize_schema_version(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if normalized else None


def detect_schema_version(artifact: dict[str, Any]) -> str:
    normalized = _normalize_schema_version(artifact.get("schema_version"))
    if normalized is None:
        return LEGACY_UNVERSIONED_SCHEMA
    return normalized


def iter_register_entries(
    artifact: dict[str, Any],
):
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return
    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue

        namespaces = group_obj.get("namespaces")
        if isinstance(namespaces, dict) and namespaces:
            for namespace_key, namespace_obj in namespaces.items():
                if not isinstance(namespace_key, str) or not isinstance(namespace_obj, dict):
                    continue
                instances = namespace_obj.get("instances")
                if not isinstance(instances, dict):
                    continue
                for instance_key, instance_obj in instances.items():
                    if not isinstance(instance_key, str) or not isinstance(instance_obj, dict):
                        continue
                    registers = instance_obj.get("registers")
                    if not isinstance(registers, dict):
                        continue
                    for register_key, entry in registers.items():
                        if not isinstance(register_key, str) or not isinstance(entry, dict):
                            continue
                        yield group_key, namespace_key, instance_key, register_key, entry
            continue

        instances = group_obj.get("instances")
        if not isinstance(instances, dict):
            continue
        for instance_key, instance_obj in instances.items():
            if not isinstance(instance_key, str) or not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers")
            if not isinstance(registers, dict):
                continue
            for register_key, entry in registers.items():
                if not isinstance(register_key, str) or not isinstance(entry, dict):
                    continue
                yield group_key, None, instance_key, register_key, entry


def count_register_entries(artifact: dict[str, Any]) -> int:
    return sum(1 for _ in iter_register_entries(artifact))


def _migrate_group(group_obj: dict[str, Any]) -> bool:
    changed = False

    namespaces = group_obj.get("namespaces")
    has_namespaces = isinstance(namespaces, dict)
    instances = group_obj.get("instances")
    has_instances = isinstance(instances, dict)

    # Legacy artifacts can contain an empty namespaces object plus populated flat instances.
    # Keep flat instances canonical in this shape so namespace-first readers do not drop data.
    if has_namespaces and not namespaces and has_instances and instances:
        group_obj.pop("namespaces", None)
        has_namespaces = False
        changed = True

    dual_namespace = group_obj.get("dual_namespace")
    if not isinstance(dual_namespace, bool):
        group_obj["dual_namespace"] = has_namespaces
        changed = True

    descriptor_observed = group_obj.get("descriptor_observed")
    if descriptor_observed is None:
        descriptor_type = group_obj.get("descriptor_type")
        if isinstance(descriptor_type, (int, float)) and not isinstance(descriptor_type, bool):
            group_obj["descriptor_observed"] = float(descriptor_type)
            changed = True

    return changed


def _derive_response_state(entry: dict[str, Any]) -> str | None:
    response_state = entry.get("response_state")
    if isinstance(response_state, str):
        normalized = response_state.strip().lower()
        if normalized in {"active", "empty_reply", "nack", "timeout"}:
            return normalized

    error = entry.get("error")
    if isinstance(error, str):
        lowered = error.strip().lower()
        if lowered == "timeout":
            return "timeout"
        if lowered == "transport_error: no_response":
            return "empty_reply"
        if lowered.startswith("transport_error:") and "nack" in lowered:
            return "nack"
        if lowered.startswith("transport_error:"):
            # Generic transport failures are not clean wire states and must not
            # be inferred as "active" during migration.
            return None

    flags_access = entry.get("flags_access")
    if isinstance(flags_access, str) and flags_access.strip().lower() == "dormant":
        return "empty_reply"

    if entry.get("reply_hex") == "":
        return "empty_reply"

    if (
        entry.get("flags") is not None
        or entry.get("reply_hex") is not None
        or entry.get("raw_hex") is not None
        or entry.get("type") is not None
        or "value" in entry
    ):
        return "active"

    return None


def _migrate_entry(entry: dict[str, Any]) -> bool:
    changed = False
    response_state = _derive_response_state(entry)
    if entry.get("response_state") != response_state:
        entry["response_state"] = response_state
        changed = True

    if response_state in {"timeout", "nack", "empty_reply"}:
        error = entry.get("error")
        if isinstance(error, str):
            lowered = error.strip().lower()
            if (
                lowered == "timeout"
                or lowered == "transport_error: no_response"
                or (lowered.startswith("transport_error:") and "nack" in lowered)
            ):
                entry["error"] = None
                changed = True

    if response_state == "empty_reply":
        if entry.get("reply_hex") != "":
            entry["reply_hex"] = ""
            changed = True
        if entry.get("flags_access") is not None:
            entry["flags_access"] = None
            changed = True
        if entry.get("flags") is not None:
            entry["flags"] = None
            changed = True
        if entry.get("reply_kind") is not None:
            entry["reply_kind"] = None
            changed = True

    return changed


def migrate_artifact_schema(
    artifact: dict[str, Any],
) -> tuple[dict[str, Any], ArtifactMigrationReport]:
    if not isinstance(artifact, dict):
        raise ArtifactSchemaError("Artifact root must be a JSON object.")

    source_schema_version = detect_schema_version(artifact)
    if source_schema_version not in {
        LEGACY_UNVERSIONED_SCHEMA,
        CURRENT_ARTIFACT_SCHEMA_VERSION,
        *LEGACY_VERSIONED_SCHEMAS,
    }:
        raise ArtifactSchemaError(
            "Unsupported schema_version "
            f"{source_schema_version!r}; supported: {CURRENT_ARTIFACT_SCHEMA_VERSION}, "
            f"{', '.join(sorted(LEGACY_VERSIONED_SCHEMAS))}, or omitted legacy version."
        )

    migrated = deepcopy(artifact)
    register_count_before = count_register_entries(migrated)
    changed = False

    if source_schema_version in {LEGACY_UNVERSIONED_SCHEMA, *LEGACY_VERSIONED_SCHEMAS}:
        migrated["schema_version"] = CURRENT_ARTIFACT_SCHEMA_VERSION
        changed = True
        groups = migrated.get("groups")
        if isinstance(groups, dict):
            for group_obj in groups.values():
                if isinstance(group_obj, dict):
                    changed = _migrate_group(group_obj) or changed

    for *_path, entry in iter_register_entries(migrated):
        if isinstance(entry, dict):
            changed = _migrate_entry(entry) or changed

    register_count_after = count_register_entries(migrated)
    if register_count_before != register_count_after:
        raise ArtifactSchemaError(
            "Artifact migration changed register count "
            f"({register_count_before} -> {register_count_after})."
        )

    report = ArtifactMigrationReport(
        source_schema_version=source_schema_version,
        target_schema_version=CURRENT_ARTIFACT_SCHEMA_VERSION,
        changed=changed,
        register_count_before=register_count_before,
        register_count_after=register_count_after,
    )
    return migrated, report
