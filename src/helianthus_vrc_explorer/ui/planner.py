from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..scanner.plan import (
    GroupScanPlan,
    estimate_eta_seconds,
    estimate_register_requests,
    format_int_set,
    parse_int_set,
    parse_int_token,
)
from ..scanner.register import opcode_for_group


@dataclass(frozen=True, slots=True)
class PlannerGroup:
    group: int
    name: str
    descriptor: float
    known: bool
    ii_max: int | None
    rr_max: int
    present_instances: tuple[int, ...]


PlannerPreset = Literal["conservative", "recommended", "aggressive", "custom"]


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _format_seconds(seconds: float) -> str:
    if seconds < 0:
        return "?"
    total = int(round(seconds))
    minutes, rem = divmod(total, 60)
    if minutes == 0:
        return f"{rem}s"
    if minutes < 60:
        if rem == 0:
            return f"{minutes}m"
        return f"{minutes}m {rem}s"
    hours = minutes // 60
    minutes = minutes % 60
    if minutes == 0:
        return f"{hours}h"
    return f"{hours}h {minutes}m"


def _print_estimate(
    console: Console,
    *,
    plan: dict[int, GroupScanPlan],
    request_rate_rps: float | None,
    prefix: str = "Estimated register requests",
) -> None:
    requests = estimate_register_requests(plan)
    eta_s = estimate_eta_seconds(
        requests=requests,
        request_rate_rps=request_rate_rps,
    )
    eta_txt = _format_seconds(eta_s) if eta_s is not None else "n/a"
    rps_txt = f"{request_rate_rps:.2f}" if request_rate_rps is not None else "n/a"
    console.print(
        f"[dim]{prefix}:[/dim] {requests}  "
        f"[dim]ETA:[/dim] {eta_txt}  "
        f"[dim]rate:[/dim] {rps_txt} req/s"
    )


def _ask_yes_no(console: Console, prompt: str, *, default: bool) -> bool:
    default_token = "y" if default else "n"
    default_label = "Y/n" if default else "y/N"
    while True:
        raw = Prompt.ask(
            f"{prompt} [{default_label}]",
            default=default_token,
            show_default=False,
            console=console,
        ).strip()
        lowered = raw.lower()
        if lowered in {"y", "yes"}:
            return True
        if lowered in {"n", "no"}:
            return False
        console.print("[red]Please enter Y or N.[/red]")


def _build_default_plan(
    eligible: dict[int, PlannerGroup],
    default_plan: dict[int, GroupScanPlan] | None,
) -> dict[int, GroupScanPlan]:
    if default_plan is not None:
        selected: dict[int, GroupScanPlan] = {}
        for gg, group_plan in default_plan.items():
            if gg in eligible:
                selected[gg] = group_plan
        if selected:
            return selected

    selected = {}
    for g in eligible.values():
        if not g.known:
            continue
        selected[g.group] = GroupScanPlan(
            group=g.group,
            opcode=opcode_for_group(g.group),
            rr_max=g.rr_max,
            instances=((0x00,) if g.ii_max is None else g.present_instances),
        )
    return selected


def _instances_for_preset(group: PlannerGroup, preset: PlannerPreset) -> tuple[int, ...]:
    if group.ii_max is None:
        return (0x00,)
    if preset == "conservative":
        return group.present_instances
    return tuple(range(0x00, group.ii_max + 1))


def build_plan_from_preset(
    groups: list[PlannerGroup],
    *,
    preset: PlannerPreset,
) -> dict[int, GroupScanPlan]:
    selected: dict[int, GroupScanPlan] = {}
    for group in sorted(groups, key=lambda g: g.group):
        if preset != "aggressive" and not group.known:
            continue
        selected[group.group] = GroupScanPlan(
            group=group.group,
            opcode=opcode_for_group(group.group),
            rr_max=group.rr_max,
            instances=_instances_for_preset(group, preset),
        )
    return selected


def _render_table(title: str, rows: list[PlannerGroup], *, unknown: bool, console: Console) -> None:
    if not rows:
        return
    console.print(Rule(title, style="dim"))
    table = Table(show_lines=False, header_style="bold dim")
    table.add_column("GG", style="cyan", no_wrap=True)
    table.add_column("Name", style="white")
    table.add_column("Type", style="dim", justify="right", no_wrap=True)
    table.add_column("Instances", style="dim", justify="right", no_wrap=True)
    table.add_column("RR_max", style="magenta", justify="right", no_wrap=True)
    for g in rows:
        if g.ii_max is None:
            instances = "singleton"
        elif unknown:
            instances = f"0/{g.ii_max + 1} (est.)"
        else:
            instances = f"{len(g.present_instances)}/{g.ii_max + 1}"
        name = g.name if not unknown else f"{g.name} (experimental)"
        table.add_row(
            _hex_u8(g.group),
            name,
            f"{g.descriptor:.1f}",
            instances,
            _hex_u16(g.rr_max),
        )
    console.print(table)


def _print_plan_breakdown(console: Console, plan: dict[int, GroupScanPlan]) -> None:
    if not plan:
        console.print("[yellow]No groups selected.[/yellow]")
        return
    console.print("[bold]Selected groups[/bold]")
    for gg in sorted(plan.keys()):
        group_plan = plan[gg]
        instance_spec = "singleton"
        if len(group_plan.instances) != 1 or group_plan.instances[0] != 0x00:
            instance_spec = format_int_set(list(group_plan.instances))
        console.print(
            f"  • {_hex_u8(gg)} instances={instance_spec} RR_max={_hex_u16(group_plan.rr_max)}",
            style="dim",
        )


def _ask_preset(console: Console, *, default_preset: PlannerPreset) -> PlannerPreset:
    preset_hint = "Preset: (1) conservative, (2) recommended, (3) aggressive, (4) custom"
    default_token = {
        "conservative": "1",
        "recommended": "2",
        "aggressive": "3",
        "custom": "4",
    }[default_preset]
    mapping: dict[str, PlannerPreset] = {
        "1": "conservative",
        "conservative": "conservative",
        "2": "recommended",
        "recommended": "recommended",
        "3": "aggressive",
        "aggressive": "aggressive",
        "4": "custom",
        "custom": "custom",
    }
    while True:
        raw = (
            Prompt.ask(
                preset_hint,
                default=default_token,
                show_default=True,
                console=console,
            )
            .strip()
            .lower()
        )
        preset = mapping.get(raw)
        if preset is not None:
            return preset
        console.print("[red]Invalid preset. Use 1,2,3,4 or name.[/red]")


def _ask_groups_to_scan(
    console: Console,
    *,
    eligible: dict[int, PlannerGroup],
    default_groups: list[int],
) -> list[int]:
    default_spec = (
        "all"
        if default_groups == sorted(eligible.keys())
        else (format_int_set(default_groups) or "none")
    )
    while True:
        raw = Prompt.ask(
            "Groups to scan ('all', 'none', or list like 0x02,0x03)",
            default=default_spec,
            show_default=True,
            console=console,
        ).strip()
        lowered = raw.lower()
        if lowered in {"all", "*"}:
            return sorted(eligible.keys())
        if lowered in {"none", "no"}:
            return []
        try:
            parsed = parse_int_set(raw, min_value=0x00, max_value=0xFF)
        except ValueError as exc:
            console.print(f"[red]Invalid group selection:[/red] {exc}")
            continue
        unknown = [gg for gg in parsed if gg not in eligible]
        if unknown:
            unknown_txt = ", ".join(_hex_u8(gg) for gg in unknown)
            console.print(f"[red]Unknown group(s):[/red] {unknown_txt}")
            continue
        return parsed


def _ask_instances(
    console: Console,
    *,
    group: PlannerGroup,
    current_instances: tuple[int, ...],
) -> tuple[int, ...]:
    assert group.ii_max is not None
    full_range = tuple(range(0x00, group.ii_max + 1))
    if current_instances == group.present_instances:
        default_mode = "present"
    elif current_instances == full_range:
        default_mode = "all"
    elif not current_instances:
        default_mode = "none"
    else:
        default_mode = format_int_set(list(current_instances))

    while True:
        raw_instances = Prompt.ask(
            f"{_hex_u8(group.group)} instances ('present', 'all', 'none', or '0-10')",
            default=default_mode,
            show_default=True,
            console=console,
        ).strip()
        lowered = raw_instances.lower()
        if lowered in {"present", "p"}:
            return group.present_instances
        if lowered in {"all", "*"}:
            return full_range
        if lowered in {"none", "no"}:
            return ()
        try:
            parsed_instances = parse_int_set(
                raw_instances,
                min_value=0x00,
                max_value=group.ii_max,
            )
        except ValueError as exc:
            console.print(f"[red]Invalid instance selection:[/red] {exc}")
            continue
        return tuple(parsed_instances)


def prompt_scan_plan(
    console: Console,
    groups: list[PlannerGroup],
    *,
    request_rate_rps: float | None,
    default_plan: dict[int, GroupScanPlan] | None = None,
    default_preset: PlannerPreset = "recommended",
) -> dict[int, GroupScanPlan]:
    """Prompt for a scan plan in interactive TTY mode.

    Returns a dict mapping GG -> GroupScanPlan.
    """

    eligible = {g.group: g for g in groups}
    if not eligible:
        return {}

    default_selected_plan = _build_default_plan(eligible, default_plan)

    console.print(Rule("Scan Planner", style="dim"))
    console.print(
        Text(
            "Review default scope, optionally apply a preset, then tune groups/instances/RR_max.",
            style="dim",
        )
    )

    known_groups = sorted([g for g in groups if g.known], key=lambda x: x.group)
    unknown_groups = sorted([g for g in groups if not g.known], key=lambda x: x.group)
    _render_table("Known Groups", known_groups, unknown=False, console=console)
    _render_table(
        "Unknown Groups (Disabled By Default)", unknown_groups, unknown=True, console=console
    )

    _print_estimate(
        console,
        plan=default_selected_plan,
        request_rate_rps=request_rate_rps,
        prefix="Default plan",
    )

    if not _ask_yes_no(console, "Customize scan plan?", default=False):
        if not _ask_yes_no(console, "Proceed with register scan?", default=True):
            raise KeyboardInterrupt
        return default_selected_plan

    preset = _ask_preset(console, default_preset=default_preset)
    if preset == "custom":
        selected_plan = dict(default_selected_plan)
    else:
        selected_plan = build_plan_from_preset(groups, preset=preset)

    if preset == "custom":
        selected_groups = _ask_groups_to_scan(
            console,
            eligible=eligible,
            default_groups=sorted(selected_plan.keys()),
        )
        selected_plan = {
            gg: selected_plan.get(
                gg,
                GroupScanPlan(
                    group=gg,
                    opcode=opcode_for_group(gg),
                    rr_max=eligible[gg].rr_max,
                    instances=(
                        (0x00,) if eligible[gg].ii_max is None else eligible[gg].present_instances
                    ),
                ),
            )
            for gg in selected_groups
        }

        if _ask_yes_no(console, "Override RR_max values?", default=False):
            for gg in sorted(selected_plan.keys()):
                current = selected_plan[gg]
                while True:
                    raw_rr_max = Prompt.ask(
                        f"{_hex_u8(gg)} RR_max",
                        default=_hex_u16(current.rr_max),
                        show_default=True,
                        console=console,
                    ).strip()
                    try:
                        rr_max = parse_int_token(raw_rr_max)
                    except ValueError as exc:
                        console.print(f"[red]Invalid RR_max:[/red] {exc}")
                        continue
                    if not (0x0000 <= rr_max <= 0xFFFF):
                        console.print("[red]RR_max out of range (0x0000..0xFFFF).[/red]")
                        continue
                    selected_plan[gg] = GroupScanPlan(
                        group=gg,
                        opcode=current.opcode,
                        rr_max=rr_max,
                        instances=current.instances,
                    )
                    break

        if _ask_yes_no(console, "Override instance selection?", default=False):
            for gg in sorted(selected_plan.keys()):
                group = eligible[gg]
                current = selected_plan[gg]
                if group.ii_max is None:
                    continue
                selected_plan[gg] = GroupScanPlan(
                    group=gg,
                    opcode=current.opcode,
                    rr_max=current.rr_max,
                    instances=_ask_instances(
                        console,
                        group=group,
                        current_instances=current.instances,
                    ),
                )

    _print_plan_breakdown(console, selected_plan)
    _print_estimate(console, plan=selected_plan, request_rate_rps=request_rate_rps)

    if not _ask_yes_no(console, "Proceed with register scan?", default=True):
        raise KeyboardInterrupt

    return selected_plan
