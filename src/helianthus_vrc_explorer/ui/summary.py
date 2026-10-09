from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..artifact_schema import migrate_artifact_schema
from ..scanner.director import operation_group_display_name


@dataclass(frozen=True, slots=True)
class _SummaryRow:
    group: str
    name: str
    namespace_key: str | None
    instances_total: int
    instances_present: int
    instances_display: str
    registers_scanned: int
    registers_errors: int


def _iter_register_entries(artifact: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for entry, _fallback_op_key in _iter_register_entries_with_op_hint(artifact):
        yield entry


def _iter_register_entries_with_op_hint(
    artifact: dict[str, Any],
) -> Iterable[tuple[dict[str, Any], str | None]]:
    """Yield (entry, op_key_hint) from the operations-first artifact."""
    operations = artifact.get("operations")
    if not isinstance(operations, dict) or not operations:
        return
    for op_key, op_obj in operations.items():
        if not isinstance(op_key, str) or not isinstance(op_obj, dict):
            continue
        op_hint = _normalize_namespace_key(op_key)
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        for group_obj in op_groups.values():
            if not isinstance(group_obj, dict):
                continue
            instances = group_obj.get("instances", {})
            if not isinstance(instances, dict):
                continue
            for instance_obj in instances.values():
                if not isinstance(instance_obj, dict):
                    continue
                registers = instance_obj.get("registers")
                if not isinstance(registers, dict):
                    continue
                for entry in registers.values():
                    if isinstance(entry, dict):
                        yield entry, op_hint


def _normalize_namespace_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = int(raw, 0)
    except ValueError:
        return None
    if 0 <= parsed <= 0xFF:
        return f"0x{parsed:02x}"
    return None


def _namespace_key_from_label(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip().lower()
    if raw == "local":
        return "0x02"
    if raw == "remote":
        return "0x06"
    if raw in {"readcontrollerregister", "writecontrollerregister"}:
        return "0x02"
    if raw in {"readdeviceslotregister", "writedeviceslotregister"}:
        return "0x06"
    return _normalize_namespace_key(value)


def _namespace_display_label(namespace_key: str, namespace_label: object = None) -> str:
    lowered_key = namespace_key.lower()
    if lowered_key == "0x02":
        return "local (0x02)"
    if lowered_key == "0x06":
        return "remote (0x06)"
    if isinstance(namespace_label, str):
        text = namespace_label.strip()
        if text and text.lower() != lowered_key:
            return f"{text} ({namespace_key})"
    return namespace_key


def _namespace_key_from_entry(
    entry: dict[str, Any], *, fallback_namespace_key: str | None = None
) -> str | None:
    namespace_key = _normalize_namespace_key(entry.get("read_opcode"))
    if namespace_key is None:
        namespace_key = _normalize_namespace_key(fallback_namespace_key)
    if namespace_key is None:
        namespace_key = _namespace_key_from_label(entry.get("read_opcode_label"))
    return namespace_key


def _namespace_label_from_entry(
    entry: dict[str, Any], *, fallback_namespace_key: str | None = None
) -> str | None:
    namespace_key = _namespace_key_from_entry(
        entry,
        fallback_namespace_key=fallback_namespace_key,
    )
    if namespace_key is None:
        return None
    return _namespace_display_label(namespace_key, entry.get("read_opcode_label"))


def _display_namespace_sort_key(label: str) -> tuple[int, int, str]:
    raw = label.strip()
    if raw.startswith("0x"):
        parsed = _normalize_namespace_key(raw)
        if parsed is not None:
            return (0, int(parsed, 0), raw)
    if raw.endswith(")") and "(" in raw:
        open_idx = raw.rfind("(")
        parsed = _normalize_namespace_key(raw[open_idx + 1 : -1])
        if parsed is not None:
            return (0, int(parsed, 0), raw)
    return (1, 0, raw.lower())


def _sorted_namespace_counts(counts: dict[str, int]) -> dict[str, int]:
    return dict(sorted(counts.items(), key=lambda item: _display_namespace_sort_key(item[0])))


def _parse_u8_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return value
        return None
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        parsed = int(raw, 0)
    except ValueError:
        return None
    if 0 <= parsed <= 0xFF:
        return parsed
    return None


def _topology_total_from_ii_max(value: object, minimum: object = 0) -> int | None:
    ii_max = _parse_u8_int(value)
    ii_min = _parse_u8_int(minimum)
    if ii_max is None or ii_min is None or ii_min > ii_max:
        return None
    return ii_max - ii_min + 1


def _counts_toward_topology_total(instance_key: object, *, total: int, minimum: int = 0) -> bool:
    instance_id = _parse_u8_int(instance_key)
    if instance_id is None:
        return False
    return minimum <= instance_id < minimum + total


def _format_instance_summary(
    *,
    present: int,
    total: int,
    topology_authoritative: bool,
) -> str:
    if total <= 0:
        return str(present)
    if topology_authoritative and total == 1:
        return "singleton"
    return f"{present}/{total}"


def _namespace_sort_key(namespace_key: str | None) -> tuple[int, int, str]:
    if namespace_key is None:
        return (3, 0, "")
    parsed = _normalize_namespace_key(namespace_key)
    if parsed == "0x02":
        return (0, 0x02, parsed)
    if parsed == "0x06":
        return (1, 0x06, parsed)
    if parsed is not None:
        return (2, int(parsed, 0), parsed)
    return (3, 0, str(namespace_key))


def _scan_plan_namespace_keys(artifact: dict[str, Any], group_key: str) -> list[str]:
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        return []
    scan_plan = meta.get("scan_plan")
    if not isinstance(scan_plan, dict):
        return []
    groups = scan_plan.get("groups")
    if not isinstance(groups, dict):
        return []
    group_plan = groups.get(group_key)
    if not isinstance(group_plan, dict):
        return []
    namespaces = group_plan.get("namespaces")
    if isinstance(namespaces, dict) and namespaces:
        return sorted(
            (namespace_key for namespace_key in namespaces if isinstance(namespace_key, str)),
            key=_namespace_sort_key,
        )
    namespace_key = _normalize_namespace_key(group_plan.get("namespace_key"))
    return [namespace_key] if namespace_key is not None else []


def _discovery_namespace_keys(group_obj: dict[str, Any]) -> list[str]:
    discovery_advisory = group_obj.get("discovery_advisory")
    if not isinstance(discovery_advisory, dict):
        return []
    proven_register_opcodes = discovery_advisory.get("proven_register_opcodes")
    if not isinstance(proven_register_opcodes, list):
        return []
    namespace_keys: set[str] = set()
    for opcode in proven_register_opcodes:
        namespace_key = _normalize_namespace_key(opcode)
        if namespace_key is not None:
            namespace_keys.add(namespace_key)
    return sorted(namespace_keys, key=_namespace_sort_key)


def _infer_single_namespace_key(
    artifact: dict[str, Any],
    *,
    group_key: str,
    group_obj: dict[str, Any],
) -> str | None:
    planned_namespace_keys = _scan_plan_namespace_keys(artifact, group_key)
    if len(planned_namespace_keys) == 1:
        return planned_namespace_keys[0]

    inferred_keys: set[str] = set()
    instances = group_obj.get("instances", {})
    if isinstance(instances, dict):
        for instance_obj in instances.values():
            if not isinstance(instance_obj, dict):
                continue
            registers = instance_obj.get("registers", {})
            if not isinstance(registers, dict):
                continue
            for entry in registers.values():
                if not isinstance(entry, dict):
                    continue
                namespace_key = _namespace_key_from_entry(entry)
                if namespace_key is not None:
                    inferred_keys.add(namespace_key)
    if len(inferred_keys) == 1:
        return next(iter(inferred_keys))
    if inferred_keys:
        # Conflicting observed opcode evidence should not be collapsed by
        # discovery fallback; keep the row in "Other Namespaces".
        return None

    discovery_namespace_keys = _discovery_namespace_keys(group_obj)
    if len(discovery_namespace_keys) == 1:
        return discovery_namespace_keys[0]
    return None


def _compute_summary_rows(artifact: dict[str, Any]) -> list[_SummaryRow]:
    rows: list[_SummaryRow] = []
    operations = artifact.get("operations")
    if not isinstance(operations, dict) or not operations:
        return rows

    for op_key, op_obj in operations.items():
        if not isinstance(op_key, str) or not isinstance(op_obj, dict):
            continue
        op_groups = op_obj.get("groups")
        if not isinstance(op_groups, dict):
            continue
        op_key_norm = _normalize_namespace_key(op_key) or op_key

        for group_key, group_obj in op_groups.items():
            if not isinstance(group_key, str) or not isinstance(group_obj, dict):
                continue
            name = str(group_obj.get("name") or "Unknown")
            name = operation_group_display_name(group_key, int(op_key_norm, 0)) or name
            instances = group_obj.get("instances", {})
            if not isinstance(instances, dict):
                instances = {}

            ii_min = _parse_u8_int(group_obj.get("ii_min", 0))
            group_total = _topology_total_from_ii_max(
                group_obj.get("ii_max"), group_obj.get("ii_min", 0)
            )
            topology_authoritative = group_total is not None
            if group_total is None:
                group_total = len(instances)

            instances_present = 0
            registers_scanned = 0
            registers_errors = 0
            for instance_key, instance_obj in instances.items():
                if not isinstance(instance_obj, dict):
                    continue
                if instance_obj.get("present") is True and (
                    not topology_authoritative
                    or _counts_toward_topology_total(
                        instance_key, total=group_total, minimum=ii_min or 0
                    )
                ):
                    instances_present += 1
                registers = instance_obj.get("registers", {})
                if not isinstance(registers, dict):
                    continue
                registers_scanned += len(registers)
                for entry in registers.values():
                    if not isinstance(entry, dict):
                        continue
                    if entry.get("error") is not None:
                        registers_errors += 1

            rows.append(
                _SummaryRow(
                    group=group_key,
                    name=name,
                    namespace_key=op_key_norm,
                    instances_total=group_total,
                    instances_present=instances_present,
                    instances_display=_format_instance_summary(
                        present=instances_present,
                        total=group_total,
                        topology_authoritative=topology_authoritative,
                    ),
                    registers_scanned=registers_scanned,
                    registers_errors=registers_errors,
                )
            )

    rows.sort(key=lambda row: (*_namespace_sort_key(row.namespace_key), int(row.group, 0)))
    return rows


def _render_summary_block(console: Console, *, title: str, rows: list[_SummaryRow]) -> None:
    if not rows:
        return
    console.print()
    console.print(Text(title, style="bold"))
    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Group", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Instances", style="white", justify="right", no_wrap=True)
    table.add_column("Registers", style="white", justify="right", no_wrap=True)
    table.add_column("Errors", style="white", justify="right", no_wrap=True)
    for row in rows:
        table.add_row(
            row.group,
            row.name,
            row.instances_display,
            str(row.registers_scanned),
            str(row.registers_errors),
        )
    console.print(table)


def _compute_namespace_totals(artifact: dict[str, Any]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for entry, fallback_op_key in _iter_register_entries_with_op_hint(artifact):
        label = _namespace_label_from_entry(
            entry,
            fallback_namespace_key=fallback_op_key,
        )
        if label is None:
            continue
        totals[label] = totals.get(label, 0) + 1
    return _sorted_namespace_counts(totals)


def _compute_flags_distribution(artifact: dict[str, Any]) -> dict[str, int]:
    counts = Counter(
        str(entry.get("flags_access")).strip()
        for entry in _iter_register_entries(artifact)
        if isinstance(entry.get("flags_access"), str) and str(entry.get("flags_access")).strip()
    )
    ordered = (
        "read_only_not_visible",
        "read_only_visible",
        "writable_not_visible",
        "writable_visible",
    )
    result = {key: counts.get(key, 0) for key in ordered}
    for key in sorted(counts):
        if key not in result:
            result[key] = counts[key]
    return result


def _format_counts(counts: dict[str, int]) -> str:
    if not counts:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in counts.items())


def render_summary(console: Console, artifact: dict[str, Any], *, output_path: Path) -> None:
    # Ensure operations-first structure for consistent iteration.
    artifact, _migration = migrate_artifact_schema(artifact)
    meta = artifact.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    dst = meta.get("destination_address", "0x??")
    duration = meta.get("scan_duration_seconds")
    incomplete = bool(meta.get("incomplete", False))
    incomplete_reason = meta.get("incomplete_reason")

    title = Text("Scan Summary", style="bold")
    console.print()
    console.print(title)

    header = f"dst={dst}"
    if isinstance(duration, (int, float)) and not isinstance(duration, bool):
        header += f" duration={duration:.3f}s"
    if incomplete:
        header += " incomplete=true"
        if isinstance(incomplete_reason, str) and incomplete_reason:
            header += f" reason={incomplete_reason}"
    console.print(header, style="dim")

    summary_rows = _compute_summary_rows(artifact)
    # Count unique group keys across all operations.
    _seen_groups: set[str] = set()
    _ops = artifact.get("operations")
    if isinstance(_ops, dict):
        for _op_obj in _ops.values():
            if not isinstance(_op_obj, dict):
                continue
            _op_groups = _op_obj.get("groups")
            if isinstance(_op_groups, dict):
                _seen_groups.update(k for k in _op_groups if isinstance(k, str))
    group_count = len(_seen_groups)
    total_regs = sum(row.registers_scanned for row in summary_rows)
    total_errs = sum(row.registers_errors for row in summary_rows)
    namespace_totals = _compute_namespace_totals(artifact)
    flags_distribution = _compute_flags_distribution(artifact)

    console.print(f"groups={group_count} registers={total_regs} errors={total_errs}", style="dim")
    console.print(f"namespaces {_format_counts(namespace_totals)}", style="dim")
    console.print(f"flags_access {_format_counts(flags_distribution)}", style="dim")

    b509_dump = artifact.get("b509_dump")
    if isinstance(b509_dump, dict):
        b509_meta = b509_dump.get("meta")
        if isinstance(b509_meta, dict):
            b509_reads = b509_meta.get("read_count")
            b509_errors = b509_meta.get("error_count")
            b509_incomplete = bool(b509_meta.get("incomplete", False))
            b509_txt = "b509"
            if isinstance(b509_reads, int):
                b509_txt += f" reads={b509_reads}"
            if isinstance(b509_errors, int):
                b509_txt += f" errors={b509_errors}"
            if b509_incomplete:
                b509_txt += " incomplete=true"
            console.print(b509_txt, style="dim")

    b555_dump = artifact.get("b555_dump")
    if isinstance(b555_dump, dict):
        b555_meta = b555_dump.get("meta")
        if isinstance(b555_meta, dict):
            b555_reads = b555_meta.get("read_count")
            b555_errors = b555_meta.get("error_count")
            b555_incomplete = bool(b555_meta.get("incomplete", False))
            programs = b555_dump.get("programs")
            b555_txt = "b555"
            if isinstance(b555_reads, int):
                b555_txt += f" reads={b555_reads}"
            if isinstance(b555_errors, int):
                b555_txt += f" errors={b555_errors}"
            if isinstance(programs, dict):
                b555_txt += f" programs={len(programs)}"
            if b555_incomplete:
                b555_txt += " incomplete=true"
            console.print(b555_txt, style="dim")

    b516_dump = artifact.get("b516_dump")
    if isinstance(b516_dump, dict):
        b516_meta = b516_dump.get("meta")
        if isinstance(b516_meta, dict):
            b516_reads = b516_meta.get("read_count")
            b516_errors = b516_meta.get("error_count")
            b516_incomplete = bool(b516_meta.get("incomplete", False))
            entries = b516_dump.get("entries")
            b516_txt = "b516"
            if isinstance(b516_reads, int):
                b516_txt += f" reads={b516_reads}"
            if isinstance(b516_errors, int):
                b516_txt += f" errors={b516_errors}"
            if isinstance(entries, dict):
                b516_txt += f" entries={len(entries)}"
            if b516_incomplete:
                b516_txt += " incomplete=true"
            console.print(b516_txt, style="dim")

    local_rows = [row for row in summary_rows if row.namespace_key == "0x02"]
    remote_rows = [row for row in summary_rows if row.namespace_key == "0x06"]
    other_rows = [row for row in summary_rows if row.namespace_key not in {"0x02", "0x06"}]
    _render_summary_block(console, title="Local Devices (0x02)", rows=local_rows)
    _render_summary_block(console, title="Remote Devices (0x06)", rows=remote_rows)
    _render_summary_block(console, title="Other Namespaces", rows=other_rows)
    suggestion_obj = meta.get("issue_suggestion")
    if isinstance(suggestion_obj, dict) and suggestion_obj.get("suggest_issue") is True:
        groups_obj = suggestion_obj.get("unknown_groups")
        unknown_groups = (
            ", ".join(str(value) for value in groups_obj)
            if isinstance(groups_obj, list) and groups_obj
            else "none"
        )
        descriptor_obj = suggestion_obj.get("unknown_descriptor_types")
        unknown_descriptors = (
            ", ".join(f"{float(value):g}" for value in descriptor_obj)
            if isinstance(descriptor_obj, list) and descriptor_obj
            else "none"
        )
        console.print(
            "Suggestion: open a GitHub issue for new protocol coverage "
            f"(groups: {unknown_groups}; descriptor classes: {unknown_descriptors}).",
            style="yellow",
        )
        console.print(
            f"Attach artifacts: {output_path} and {output_path.with_suffix('.html')}",
            style="yellow",
        )
    constraint_mismatches = meta.get("constraint_mismatches")
    if isinstance(constraint_mismatches, list) and constraint_mismatches:
        console.print(
            "Warning: observed values exceed the bundled static constraint catalog. "
            "Consider rerunning with --probe-constraints for live confirmation.",
            style="yellow",
        )
        for mismatch in constraint_mismatches[:5]:
            if not isinstance(mismatch, dict):
                continue
            selector = "/".join(
                str(mismatch.get(key))
                for key in ("group", "instance", "register")
                if mismatch.get(key) is not None
            )
            console.print(
                f"  {selector} value={mismatch.get('value')!r} "
                f"expected=[{mismatch.get('constraint_min')!r}, "
                f"{mismatch.get('constraint_max')!r}] "
                f"name={mismatch.get('name') or 'n/a'}",
                style="yellow",
            )
        if len(constraint_mismatches) > 5:
            console.print(
                f"  ... and {len(constraint_mismatches) - 5} more mismatches in "
                "meta.constraint_mismatches",
                style="yellow",
            )
    console.print(f"artifact={output_path}", style="dim")
