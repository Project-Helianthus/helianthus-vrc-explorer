#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import sys
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.artifact_schema import (
    LEGACY_UNVERSIONED_SCHEMA,
    LEGACY_VERSIONED_SCHEMAS,
    ArtifactSchemaError,
    count_register_entries,
    detect_schema_version,
    iter_register_entries,
    migrate_artifact_schema,
)
from helianthus_vrc_explorer.protocol.parser import ValueParseError, parse_typed_value


def _parse_hex_key(key: str) -> int | None:
    try:
        return int(key, 0)
    except ValueError:
        return None


def _normalize_opcode_hex(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        opcode = int(raw, 0)
    except ValueError:
        return None
    if not (0x00 <= opcode <= 0xFF):
        return None
    return f"0x{opcode:02x}"


def _validate_schema_shape(artifact: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    # v2.3 operations-first structure
    operations = artifact.get("operations")
    if isinstance(operations, dict):
        for op_key, op_obj in operations.items():
            if not isinstance(op_key, str) or not isinstance(op_obj, dict):
                errors.append(f"{op_key!r}: operation entry must be an object keyed by hex string")
                continue
            op_groups = op_obj.get("groups")
            if not isinstance(op_groups, dict):
                # Only opcode 0x01 may have "constraints" instead of "groups"
                if op_key == "0x01" and op_obj.get("constraints") is not None:
                    continue
                errors.append(f"{op_key}: operation missing groups object")
                continue
            for group_key, group_obj in op_groups.items():
                if not isinstance(group_key, str) or not isinstance(group_obj, dict):
                    errors.append(
                        f"{op_key}/{group_key!r}: group entry must be an object keyed by hex string"
                    )
                    continue
                has_instances = isinstance(group_obj.get("instances"), dict)
                if not has_instances:
                    errors.append(f"{op_key}/{group_key}: group missing instances object")
        return errors

    # Legacy v2.2 groups-first structure
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return ['missing required top-level "operations" or "groups" object']

    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            errors.append(f"{group_key!r}: group entry must be an object keyed by hex string")
            continue

        descriptor_observed = group_obj.get("descriptor_observed")
        descriptor_type = group_obj.get("descriptor_type")
        if not isinstance(descriptor_observed, (int, float)) and not isinstance(
            descriptor_type, (int, float)
        ):
            errors.append(
                f"{group_key}: expected numeric descriptor_observed (or descriptor_type for legacy)"
            )

        dual_namespace = group_obj.get("dual_namespace")
        if not isinstance(dual_namespace, bool):
            errors.append(f"{group_key}: missing required boolean dual_namespace")
            continue

        has_namespaces = isinstance(group_obj.get("namespaces"), dict)
        has_instances = isinstance(group_obj.get("instances"), dict)

        if dual_namespace:
            if not has_namespaces:
                errors.append(f"{group_key}: dual_namespace=true requires namespaces object")
            if has_instances:
                errors.append(f"{group_key}: dual_namespace=true must not include flat instances")
            continue

        if has_namespaces:
            errors.append(f"{group_key}: dual_namespace=false must not include namespaces")
        if not has_instances:
            errors.append(f"{group_key}: dual_namespace=false requires instances object")

    return errors


def validate_scan_artifact(
    artifact: dict[str, Any],
    *,
    allow_legacy: bool,
) -> tuple[list[str], dict[str, Any], str]:
    errors: list[str] = []
    source_schema_version = detect_schema_version(artifact)
    if not allow_legacy and source_schema_version == LEGACY_UNVERSIONED_SCHEMA:
        errors.append("schema_version: legacy unversioned artifact rejected (--reject-legacy)")
        return errors, artifact, source_schema_version
    if not allow_legacy and source_schema_version in LEGACY_VERSIONED_SCHEMAS:
        errors.append(
            "schema_version: legacy versioned artifact "
            f"{source_schema_version!r} rejected (--reject-legacy)"
        )
        return errors, artifact, source_schema_version

    try:
        migrated, _migration = migrate_artifact_schema(artifact)
    except ArtifactSchemaError as exc:
        errors.append(f"schema_version: {exc}")
        return errors, artifact, source_schema_version

    errors.extend(_validate_schema_shape(migrated))

    for op_key, group_key, instance_key, rr_key, entry in iter_register_entries(migrated):
        op_loc = op_key if op_key is not None else "flat"
        loc = f"{op_loc}/{group_key}/{instance_key}/{rr_key}"
        gg = _parse_hex_key(group_key)
        rr = _parse_hex_key(rr_key)
        if gg is None:
            errors.append(f"{loc}: invalid group key")
            continue
        if rr is None:
            errors.append(f"{loc}: invalid register key")
            continue

        if op_key is not None:
            op_opcode = _normalize_opcode_hex(op_key)
            if op_opcode is None:
                errors.append(f"{loc}: invalid operation key")
                continue
            read_opcode = _normalize_opcode_hex(entry.get("read_opcode"))
            if read_opcode is not None and read_opcode != op_opcode:
                errors.append(
                    f"{loc}: read_opcode {read_opcode} does not match namespace {op_opcode}"
                )

        reply_hex = entry.get("reply_hex")
        raw_hex = entry.get("raw_hex")
        type_spec = entry.get("type")
        value = entry.get("value")
        error = entry.get("error")

        if isinstance(reply_hex, str) and reply_hex:
            try:
                reply = bytes.fromhex(reply_hex)
            except ValueError:
                errors.append(f"{loc}: invalid reply_hex")
                reply = b""

            if len(reply) == 1:
                # Status-only reply: should not have a value tail.
                if raw_hex not in (None, ""):
                    errors.append(f"{loc}: status-only reply but raw_hex is present")
            elif len(reply) >= 4 and isinstance(raw_hex, str):
                try:
                    raw = bytes.fromhex(raw_hex)
                except ValueError:
                    errors.append(f"{loc}: invalid raw_hex")
                    raw = b""

                if raw and reply[4:] != raw:
                    errors.append(f"{loc}: reply_hex tail mismatch raw_hex")
                if reply and reply[1] != (gg & 0xFF):
                    errors.append(f"{loc}: reply_hex GG mismatch ({reply[1]:02x})")
                if reply and rr is not None:
                    rr_le = rr.to_bytes(2, byteorder="little", signed=False)
                    if reply[2:4] != rr_le:
                        errors.append(f"{loc}: reply_hex RR mismatch ({reply[2:4].hex()})")

        if error is not None:
            # Transport/decode/parse errors: no strict value validation.
            continue

        if isinstance(type_spec, str) and isinstance(raw_hex, str) and raw_hex:
            try:
                value_bytes = bytes.fromhex(raw_hex)
            except ValueError:
                errors.append(f"{loc}: invalid raw_hex for parsing")
                continue
            try:
                parsed = parse_typed_value(type_spec, value_bytes)
            except ValueParseError as exc:
                errors.append(f"{loc}: parse_typed_value failed: {exc}")
                continue

            # JSON round-tripping: floats are approximate, everything else should match exactly.
            if parsed is None:
                if value is not None:
                    errors.append(f"{loc}: expected null value, got {value!r}")
            elif isinstance(parsed, float):
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    errors.append(f"{loc}: expected numeric float, got {type(value).__name__}")
                elif not math.isclose(float(value), float(parsed), rel_tol=1e-6, abs_tol=1e-6):
                    errors.append(f"{loc}: float mismatch expected={parsed} got={value}")
            elif value != parsed:
                errors.append(
                    f"{loc}: value mismatch type={type_spec} expected={parsed!r} got={value!r}"
                )

    return errors, migrated, source_schema_version


def main(argv: list[str]) -> int:
    args = argv[1:]
    if not args or args[0] in {"-h", "--help"}:
        print("Usage: validate_artifact.py [--reject-legacy] <artifact.json>", file=sys.stderr)
        return 2

    reject_legacy = False
    if args and args[0] == "--reject-legacy":
        reject_legacy = True
        args = args[1:]

    if len(args) != 1:
        print("Usage: validate_artifact.py [--reject-legacy] <artifact.json>", file=sys.stderr)
        return 2

    path = Path(args[0])
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        print(f"Failed to read: {path} ({exc})", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON: {path} ({exc})", file=sys.stderr)
        return 2

    if not isinstance(artifact, dict):
        print("Invalid artifact root (expected JSON object).", file=sys.stderr)
        return 2

    errors, migrated, source_schema_version = validate_scan_artifact(
        artifact,
        allow_legacy=not reject_legacy,
    )
    if errors:
        for line in errors[:50]:
            print(line, file=sys.stderr)
        if len(errors) > 50:
            print(f"... ({len(errors) - 50} more)", file=sys.stderr)
        return 1

    suffix = ""
    if source_schema_version != str(migrated.get("schema_version")):
        suffix = (
            f"; migrated in-memory {source_schema_version} -> {migrated.get('schema_version')} "
            f"(registers={count_register_entries(migrated)})"
        )
    print(f"OK: validated artifact ({path.name}{suffix})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
