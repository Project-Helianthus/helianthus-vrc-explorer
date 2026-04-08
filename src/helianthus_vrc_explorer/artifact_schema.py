from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any

CURRENT_ARTIFACT_SCHEMA_VERSION = "2.3"
LEGACY_UNVERSIONED_SCHEMA = "legacy-unversioned"
LEGACY_VERSIONED_SCHEMAS = frozenset({"2.0", "2.1", "2.2"})


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
    """Iterate register entries from a v2.3 (operations-first) artifact.

    Yields: (op_key, group_key, instance_key, register_key, entry)

    Also supports legacy v2.2 (groups-first) structure for backward
    compatibility during migration.
    """
    # v2.3 path: operations → groups → instances → registers
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        for op_key, op_obj in operations.items():
            if not isinstance(op_key, str) or not isinstance(op_obj, dict):
                continue
            op_groups = op_obj.get("groups")
            if not isinstance(op_groups, dict):
                continue
            for group_key, group_obj in op_groups.items():
                if not isinstance(group_key, str) or not isinstance(group_obj, dict):
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
                        yield op_key, group_key, instance_key, register_key, entry
        return

    # Legacy v2.2 path: groups → (namespaces →) instances → registers
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
                        yield namespace_key, group_key, instance_key, register_key, entry
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
                yield None, group_key, instance_key, register_key, entry


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


def _migrate_v22_to_v23(artifact: dict[str, Any]) -> bool:
    """Restructure groups-first (v2.2) to operations-first (v2.3).

    For each group in artifact["groups"]:
    - If dual_namespace=true: for each namespace, move group data to
      operations[opcode].groups[group_key]
    - If dual_namespace=false (or missing): move to
      operations["0x02"].groups[group_key] (flat groups default to OP=0x02)

    Also moves register_constraints to operations["0x01"].constraints.
    """
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return False

    operations: dict[str, Any] = {}

    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue

        # Collect fields to copy (excluding dual_namespace/namespaces/namespace_identity_keys)
        _skip_keys = {"dual_namespace", "namespaces", "namespace_identity_keys", "instances"}

        if bool(group_obj.get("dual_namespace")):
            namespaces = group_obj.get("namespaces")
            if not isinstance(namespaces, dict):
                continue
            for ns_key, ns_obj in namespaces.items():
                if not isinstance(ns_key, str) or not isinstance(ns_obj, dict):
                    continue
                op_obj = operations.setdefault(ns_key, {})
                op_groups = op_obj.setdefault("groups", {})
                new_group: dict[str, Any] = {}
                # Copy group-level fields (name, descriptor_observed, discovery_advisory, etc.)
                for k, v in group_obj.items():
                    if k not in _skip_keys:
                        new_group[k] = v
                # Copy namespace-level fields (instances, ii_max, availability_*, etc.)
                for k, v in ns_obj.items():
                    if k in {"label", "operation_label"}:
                        continue
                    if k == "group_name":
                        # Promote namespace-specific group_name to the group name.
                        ns_group_name = v.strip() if isinstance(v, str) else ""
                        if ns_group_name:
                            new_group["name"] = ns_group_name
                        continue
                    new_group[k] = v
                op_groups[group_key] = new_group
        else:
            # Flat group: split entries by read_opcode so that mixed-op
            # groups (entries with BOTH 0x02 and 0x06) are not collapsed
            # under a single operation key.
            instances = group_obj.get("instances")

            # Collect all distinct opcodes present in entries.
            _seen_opcodes: set[str] = set()
            if isinstance(instances, dict):
                for inst_obj in instances.values():
                    if not isinstance(inst_obj, dict):
                        continue
                    regs = inst_obj.get("registers")
                    if not isinstance(regs, dict):
                        continue
                    for entry in regs.values():
                        if isinstance(entry, dict):
                            read_opcode = entry.get("read_opcode")
                            if isinstance(read_opcode, str) and read_opcode.startswith("0x"):
                                _seen_opcodes.add(read_opcode)

            if not _seen_opcodes:
                # Fall back to discovery_advisory.proven_register_opcodes
                discovery = group_obj.get("discovery_advisory")
                if isinstance(discovery, dict):
                    proven = discovery.get("proven_register_opcodes")
                    if isinstance(proven, list) and proven:
                        for item in proven:
                            if isinstance(item, str) and item.startswith("0x"):
                                _seen_opcodes.add(item)
            if not _seen_opcodes:
                _seen_opcodes = {"0x02"}

            # Build shared group-level fields (everything except instances/namespace keys).
            _shared: dict[str, Any] = {}
            for k, v in group_obj.items():
                if k not in _skip_keys:
                    _shared[k] = v

            # Default OP for entries without read_opcode: first sorted OP.
            _default_op = sorted(_seen_opcodes)[0]

            for target_op in sorted(_seen_opcodes):
                op_obj = operations.setdefault(target_op, {})
                op_groups = op_obj.setdefault("groups", {})
                new_group = dict(_shared)
                new_instances: dict[str, Any] = {}
                if isinstance(instances, dict):
                    for inst_key, inst_obj in instances.items():
                        if not isinstance(inst_obj, dict):
                            continue
                        regs = inst_obj.get("registers")
                        if not isinstance(regs, dict):
                            continue
                        filtered_regs: dict[str, Any] = {}
                        for rr_key, entry in regs.items():
                            if not isinstance(entry, dict):
                                continue
                            entry_op = entry.get("read_opcode")
                            effective_op = (
                                entry_op
                                if isinstance(entry_op, str) and entry_op.startswith("0x")
                                else _default_op
                            )
                            if effective_op == target_op:
                                filtered_regs[rr_key] = entry
                        if filtered_regs:
                            new_inst = {k: v for k, v in inst_obj.items() if k != "registers"}
                            new_inst["registers"] = filtered_regs
                            new_instances[inst_key] = new_inst
                new_group["instances"] = new_instances
                op_groups[group_key] = new_group

    # Move register_constraints to operations["0x01"].constraints
    register_constraints = artifact.get("register_constraints")
    if isinstance(register_constraints, dict) and register_constraints:
        op_01 = operations.setdefault("0x01", {})
        op_01["constraints"] = register_constraints

    artifact["operations"] = operations
    artifact.pop("groups", None)
    artifact.pop("register_constraints", None)
    return True


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

    # Step 1: migrate legacy unversioned / 2.0 / 2.1 to 2.2 shape first
    if source_schema_version in {LEGACY_UNVERSIONED_SCHEMA, "2.0", "2.1"}:
        migrated["schema_version"] = "2.2"
        changed = True
        groups = migrated.get("groups")
        if isinstance(groups, dict):
            for group_obj in groups.values():
                if isinstance(group_obj, dict):
                    changed = _migrate_group(group_obj) or changed

    # Step 1b: normalize v2.2 groups that were not covered by step 1
    # (e.g. artifacts already at v2.2 need _migrate_group to repair legacy
    # shapes like dual_namespace=true with empty namespaces + populated instances)
    if source_schema_version == "2.2":
        groups = migrated.get("groups")
        if isinstance(groups, dict):
            for group_obj in groups.values():
                if isinstance(group_obj, dict):
                    changed = _migrate_group(group_obj) or changed

    # Step 2: migrate 2.2 to 2.3 (groups-first to operations-first)
    if detect_schema_version(migrated) == "2.2":
        changed = _migrate_v22_to_v23(migrated) or changed
        migrated["schema_version"] = CURRENT_ARTIFACT_SCHEMA_VERSION

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
