from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text


@dataclass(frozen=True, slots=True)
class _GroupStats:
    group: str
    name: str
    descriptor: float
    instances_total: int
    instances_present: int
    registers_scanned: int
    registers_errors: int
    namespace_registers: dict[str, int]


def _iter_register_entries(artifact: dict[str, Any]) -> Iterable[dict[str, Any]]:
    groups = artifact.get("groups", {})
    if not isinstance(groups, dict):
        return
    for group_obj in groups.values():
        if not isinstance(group_obj, dict):
            continue
        if bool(group_obj.get("dual_namespace")):
            namespaces = group_obj.get("namespaces", {})
            if not isinstance(namespaces, dict):
                continue
            for namespace_obj in namespaces.values():
                if not isinstance(namespace_obj, dict):
                    continue
                instances = namespace_obj.get("instances", {})
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
                            yield entry
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
                    yield entry


def _namespace_label_from_entry(entry: dict[str, Any]) -> str:
    label = entry.get("read_opcode_label")
    if isinstance(label, str) and label.strip():
        return label.strip()
    opcode = entry.get("read_opcode")
    if isinstance(opcode, str) and opcode.strip():
        return opcode.strip()
    return "single"


def _compute_group_stats(artifact: dict[str, Any]) -> list[_GroupStats]:
    stats: list[_GroupStats] = []
    groups = artifact.get("groups", {})
    if not isinstance(groups, dict):
        return stats

    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue
        name = str(group_obj.get("name") or "Unknown")
        descriptor = float(
            group_obj.get("descriptor_observed", group_obj.get("descriptor_type")) or 0.0
        )

        instances = group_obj.get("instances", {})
        if not isinstance(instances, dict):
            instances = {}

        instances_total = len(instances)
        instances_present = 0
        registers_scanned = 0
        registers_errors = 0
        namespace_registers: dict[str, int] = {}

        if bool(group_obj.get("dual_namespace")):
            namespaces = group_obj.get("namespaces", {})
            if not isinstance(namespaces, dict):
                namespaces = {}
            instances_total = 0
            instances_present = 0
            for namespace_key, namespace_obj in namespaces.items():
                if not isinstance(namespace_key, str) or not isinstance(namespace_obj, dict):
                    continue
                namespace_label_obj = namespace_obj.get("label")
                namespace_label = (
                    namespace_label_obj
                    if isinstance(namespace_label_obj, str) and namespace_label_obj.strip()
                    else namespace_key
                )
                namespace_count = 0
                namespace_instances = namespace_obj.get("instances", {})
                if not isinstance(namespace_instances, dict):
                    continue
                instances_total += len(namespace_instances)
                for instance_obj in namespace_instances.values():
                    if not isinstance(instance_obj, dict):
                        continue
                    if instance_obj.get("present") is True:
                        instances_present += 1
                    registers = instance_obj.get("registers", {})
                    if not isinstance(registers, dict):
                        continue
                    namespace_count += len(registers)
                    registers_scanned += len(registers)
                    for entry in registers.values():
                        if not isinstance(entry, dict):
                            continue
                        if entry.get("error") is not None:
                            registers_errors += 1
                namespace_registers[namespace_label] = namespace_count
        else:
            for instance_obj in instances.values():
                if not isinstance(instance_obj, dict):
                    continue
                if instance_obj.get("present") is True:
                    instances_present += 1
                registers = instance_obj.get("registers", {})
                if not isinstance(registers, dict):
                    continue
                registers_scanned += len(registers)
                for entry in registers.values():
                    if not isinstance(entry, dict):
                        continue
                    namespace_label = _namespace_label_from_entry(entry)
                    namespace_registers[namespace_label] = (
                        namespace_registers.get(namespace_label, 0) + 1
                    )
                    if entry.get("error") is not None:
                        registers_errors += 1

        stats.append(
            _GroupStats(
                group=group_key,
                name=name,
                descriptor=descriptor,
                instances_total=instances_total,
                instances_present=instances_present,
                registers_scanned=registers_scanned,
                registers_errors=registers_errors,
                namespace_registers=namespace_registers,
            )
        )

    stats.sort(key=lambda s: int(s.group, 0))
    return stats


def _compute_namespace_totals(artifact: dict[str, Any]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for entry in _iter_register_entries(artifact):
        label = _namespace_label_from_entry(entry)
        totals[label] = totals.get(label, 0) + 1
    return dict(sorted(totals.items()))


def _compute_flags_distribution(artifact: dict[str, Any]) -> dict[str, int]:
    counts = Counter(
        str(entry.get("flags_access")).strip()
        for entry in _iter_register_entries(artifact)
        if isinstance(entry.get("flags_access"), str) and str(entry.get("flags_access")).strip()
    )
    ordered = ("volatile_ro", "stable_ro", "technical_rw", "user_rw")
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

    group_stats = _compute_group_stats(artifact)
    total_regs = sum(s.registers_scanned for s in group_stats)
    total_errs = sum(s.registers_errors for s in group_stats)
    namespace_totals = _compute_namespace_totals(artifact)
    flags_distribution = _compute_flags_distribution(artifact)

    console.print(
        f"groups={len(group_stats)} registers={total_regs} errors={total_errs}", style="dim"
    )
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

    table = Table(show_header=True, header_style="bold", box=None)
    table.add_column("Group", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Type", style="white", justify="right", no_wrap=True)
    table.add_column("Instances", style="white", justify="right", no_wrap=True)
    table.add_column("Namespaces", style="white")
    table.add_column("Registers", style="white", justify="right", no_wrap=True)
    table.add_column("Errors", style="white", justify="right", no_wrap=True)

    for s in group_stats:
        if s.instances_total == 1 and s.instances_present == 1:
            instances = "singleton"
        elif s.instances_total > 0:
            instances = f"{s.instances_present}/{s.instances_total}"
        else:
            instances = str(s.instances_present)
        table.add_row(
            s.group,
            s.name,
            f"{s.descriptor:g}",
            instances,
            _format_counts(s.namespace_registers),
            str(s.registers_scanned),
            str(s.registers_errors),
        )

    console.print(table)
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
    console.print(f"artifact={output_path}", style="dim")
