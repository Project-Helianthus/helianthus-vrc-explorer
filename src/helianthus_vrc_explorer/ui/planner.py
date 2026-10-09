from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.prompt import Prompt
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..protocol.b524 import RegisterOpcode
from ..scanner.plan import (
    GroupScanPlan,
    PlanKey,
    estimate_eta_seconds,
    estimate_register_requests,
    format_int_set,
    format_plan_key,
    make_plan_key,
    parse_int_set,
    parse_int_token,
)
from ..scanner.scan_policy import (
    profile_opcodes,
    research_rr_max,
    validate_scalar_request_limit,
)
from .system_information import format_system_information_rows


@dataclass(frozen=True, slots=True)
class PlannerGroup:
    group: int
    opcode: RegisterOpcode
    name: str
    descriptor: float
    known: bool
    ii_max: int | None
    rr_max: int | None
    rr_max_full: int | None
    present_instances: tuple[int, ...]
    namespace_label: str | None = None
    recommended: bool = True
    expected_count: int | None = None
    ii_min: int | None = None
    instances_probed: bool = True
    research_rr_max: int | None = None
    native_dhw_admitted: bool = False

    @property
    def key(self) -> PlanKey:
        return make_plan_key(self.group, self.opcode)

    @property
    def display_name(self) -> str:
        if self.namespace_label is None:
            return self.name
        if self.name.lower().endswith(f"({self.namespace_label.lower()})"):
            return self.name
        return f"{self.name} ({self.namespace_label})"

    @property
    def prompt_label(self) -> str:
        if self.namespace_label is None:
            return _hex_u8(self.group)
        return f"{_hex_u8(self.group)} ({self.namespace_label})"


PlannerPreset = Literal[
    "recommended",
    "full",
    "research",
    "custom",
]


# UI-only OP00 associations. These do not participate in planner discovery,
# instance bounds, or presence qualification.
OP00_GROUP_COUNT_NAMES: dict[tuple[int, int], str] = {
    (0x02, 0x02): "circuit_count",
    (0x02, 0x03): "zone_count",
    (0x02, 0x04): "solar_circuit_count",
    (0x02, 0x05): "solar_loaded_tank_count",
    (0x02, 0x08): "delta_t_count",
    (0x06, 0x01): "boiler_count",
    (0x06, 0x02): "heat_pump_count",
    (0x06, 0x03): "recovair_count",
    (0x06, 0x06): "vpm_s_count",
    (0x06, 0x07): "vpm_w_count",
    (0x06, 0x0B): "vr70_count",
    (0x06, 0x0C): "vr71_count",
}
_LEGACY_EXPECTED_COUNT_KEYS = frozenset({(0x02, 0x02), (0x02, 0x03)})


def _hex_u8(value: int) -> str:
    return f"0x{value:02x}"


def _hex_u16(value: int) -> str:
    return f"0x{value:04x}"


def _namespace_opcode_rank(opcode: int) -> tuple[int, int]:
    if opcode == 0x02:
        return (0, opcode)
    if opcode == 0x06:
        return (1, opcode)
    return (2, opcode)


def planner_group_sort_key(group: PlannerGroup) -> tuple[int, int, int]:
    return (*_namespace_opcode_rank(group.opcode), group.group)


def planner_namespace_title(opcode: int) -> str:
    if opcode == 0x02:
        return "Local Devices (0x02)"
    if opcode == 0x06:
        return "Remote Devices (0x06)"
    return f"Other Namespace ({_hex_u8(opcode)})"


def split_planner_groups_by_namespace(
    groups: list[PlannerGroup],
) -> list[tuple[str, list[PlannerGroup]]]:
    buckets: dict[int, list[PlannerGroup]] = {}
    for group in sorted(groups, key=planner_group_sort_key):
        buckets.setdefault(group.opcode, []).append(group)
    return [
        (planner_namespace_title(opcode), buckets[opcode])
        for opcode in sorted(buckets, key=_namespace_opcode_rank)
        if buckets[opcode]
    ]


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
    plan: dict[PlanKey, GroupScanPlan],
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
    eligible: dict[PlanKey, PlannerGroup],
    default_plan: dict[PlanKey, GroupScanPlan] | None,
    *,
    default_preset: PlannerPreset,
) -> dict[PlanKey, GroupScanPlan]:
    if default_plan is not None:
        selected: dict[PlanKey, GroupScanPlan] = {}
        for key, group_plan in default_plan.items():
            if key in eligible:
                selected[key] = group_plan
        if selected:
            return selected

    return build_plan_from_preset(
        sorted(eligible.values(), key=planner_group_sort_key),
        preset=default_preset,
    )


def planner_instance_bounds(group: PlannerGroup) -> tuple[int, int]:
    """Return the configured inclusive II bounds shown by planner surfaces."""
    if group.opcode == 0x06:
        ii_min = group.ii_min if group.ii_min is not None else 0x01
        ii_max = min(group.ii_max if group.ii_max is not None else 0x08, 0x08)
    elif group.opcode == 0x02 and group.group == 0x02:
        ii_min = group.ii_min if group.ii_min is not None else 0x01
        ii_max = min(group.ii_max if group.ii_max is not None else 0x09, 0x09)
    elif group.ii_max is None:
        return (0x00, 0x00)
    else:
        ii_min = group.ii_min if group.ii_min is not None else 0x00
        ii_max = group.ii_max
    if ii_min > ii_max:
        raise ValueError(
            f"Invalid II bounds for GG=0x{group.group:02X}/OP=0x{group.opcode:02X}: "
            f"0x{ii_min:02X}..0x{ii_max:02X}"
        )
    return (ii_min, ii_max)


def format_planner_instance_bounds(group: PlannerGroup) -> str:
    ii_min, ii_max = planner_instance_bounds(group)
    return f"0x{ii_min:02X}..0x{ii_max:02X}"


def format_planner_op00_count(
    group: PlannerGroup,
    system_information: Sequence[Mapping[str, object]] | None = None,
) -> str:
    """Return a UI-only qualified OP00 count/capacity for one native planner group.

    The snapshot association is intentionally separate from ``expected_count``:
    it neither guides instance probing nor asserts that an OP00 count proves
    presence.  ``expected_count`` remains a compatibility fallback for older
    planner records when the snapshot has no corresponding record.
    """

    key = (int(group.opcode), group.group)
    count_name = OP00_GROUP_COUNT_NAMES.get(key)
    if count_name is None:
        return "—"
    if system_information is not None:
        for record in system_information:
            if record.get("name") != count_name:
                continue
            state = record.get("state")
            value = record.get("value")
            if (
                (state is None or state == "available")
                and not isinstance(value, bool)
                and isinstance(value, (int, float))
                and math.isfinite(value)
                and value >= 0
                and float(value).is_integer()
            ):
                rendered = str(int(value))
                return f"capacity={rendered}" if key in _LEGACY_EXPECTED_COUNT_KEYS else rendered
            return "—"
        return "—"
    if key in _LEGACY_EXPECTED_COUNT_KEYS and group.expected_count is not None:
        return f"capacity={group.expected_count}"
    return "—"


def planner_unmapped_system_information(
    system_information: Sequence[Mapping[str, object]] | None,
) -> tuple[Mapping[str, object], ...]:
    """Keep planner-level OP00 details that have no dedicated group cell."""

    if not system_information:
        return ()
    mapped_names = frozenset(OP00_GROUP_COUNT_NAMES.values())
    return tuple(record for record in system_information if record.get("name") not in mapped_names)


def planner_instance_range(group: PlannerGroup) -> tuple[int, ...]:
    ii_min, ii_max = planner_instance_bounds(group)
    result = tuple(range(ii_min, ii_max + 1))
    if group.opcode == 0x06 or (group.opcode == 0x02 and group.group == 0x02):
        return result
    return result + ((0xFF,) if 0xFF in group.present_instances else ())


def planner_present_instances(group: PlannerGroup) -> tuple[int, ...]:
    allowed = set(planner_instance_range(group))
    return tuple(ii for ii in group.present_instances if ii in allowed)


def _instances_for_preset(group: PlannerGroup, preset: PlannerPreset) -> tuple[int, ...]:
    if group.ii_max is None and group.opcode != 6 and not (group.opcode == 2 and group.group == 2):
        return (0x00,)
    if preset == "recommended":
        return planner_present_instances(group)
    return planner_instance_range(group)


def _has_recommended_availability(group: PlannerGroup) -> bool:
    """Return whether an admitted group has affirmative default-scan evidence.

    The profile policy remains the static admission rule.  OP00 counts guide
    discovery only: a count cannot admit a family without a confirmed instance,
    and a confirmed instance remains usable when it contradicts a zero count.
    System is the mandatory OP=0x02/GG=0x00 singleton.  Native DHW has a
    dedicated, correlated gate; other singleton rows are not admitted by
    static inventory alone.  All other rows require a confirmed present
    instance, so unknown or unprobed results stay manually selectable only.
    """

    if group.opcode == 0x02 and group.group == 0x00:
        return True
    if group.opcode == 0x02 and group.group == 0x01:
        return group.native_dhw_admitted
    if group.ii_max is None:
        return False
    return bool(planner_present_instances(group))


def build_plan_from_preset(
    groups: list[PlannerGroup],
    *,
    preset: PlannerPreset,
) -> dict[PlanKey, GroupScanPlan]:
    selected: dict[PlanKey, GroupScanPlan] = {}
    for group in sorted(groups, key=planner_group_sort_key):
        if group.opcode not in profile_opcodes(group.group, preset):
            continue
        if preset == "recommended" and not _has_recommended_availability(group):
            continue
        if preset in {"recommended", "full"}:
            if group.rr_max is None:
                continue
            selected[group.key] = GroupScanPlan(
                group=group.group,
                opcode=group.opcode,
                rr_max=group.rr_max,
                instances=_instances_for_preset(group, preset),
            )
        elif preset == "research":
            normal_rr_max = group.research_rr_max
            if normal_rr_max is None and group.rr_max is not None:
                normal_rr_max = max(group.rr_max, group.rr_max_full or group.rr_max)
            if normal_rr_max is None:
                continue
            selected[group.key] = GroupScanPlan(
                group=group.group,
                opcode=group.opcode,
                rr_max=research_rr_max(
                    group=group.group,
                    opcode=group.opcode,
                    normal_rr_max=normal_rr_max,
                ),
                instances=_instances_for_preset(group, preset),
            )
    return selected


def _render_table(
    title: str,
    rows: list[PlannerGroup],
    *,
    unknown: bool,
    console: Console,
    system_information: Sequence[Mapping[str, object]] | None = None,
) -> None:
    if not rows:
        return
    for namespace_title, namespace_rows in split_planner_groups_by_namespace(rows):
        console.print(Rule(f"{title} - {namespace_title}", style="dim"))
        table = Table(show_lines=False, header_style="bold dim")
        table.add_column("GG", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("OP00 context", style="dim", justify="right", no_wrap=True)
        table.add_column("II range", style="dim", justify="right", no_wrap=True)
        table.add_column("Instances", style="dim", justify="right", no_wrap=True)
        table.add_column("RR_max", style="magenta", justify="right", no_wrap=True)
        for g in namespace_rows:
            if g.ii_max is None:
                instances = "singleton"
            elif not g.instances_probed:
                instances = f"unprobed/{len(planner_instance_range(g))}"
            elif unknown:
                instances = f"0/{len(planner_instance_range(g))} (est.)"
            else:
                instances = f"{len(planner_present_instances(g))}/{len(planner_instance_range(g))}"
            name = g.display_name if not unknown else f"{g.display_name} (experimental)"
            rr_max = (
                "— (explicit required)" if g.rr_max is None else _hex_u16(g.rr_max_full or g.rr_max)
            )
            if g.rr_max is not None and g.rr_max_full is not None and g.rr_max_full != g.rr_max:
                rr_max = f"{_hex_u16(g.rr_max)} / {rr_max}"
            table.add_row(
                _hex_u8(g.group),
                name,
                format_planner_op00_count(g, system_information),
                format_planner_instance_bounds(g),
                instances,
                rr_max,
            )
        console.print(table)


def _render_system_information(
    console: Console, system_information: Sequence[Mapping[str, object]] | None
) -> None:
    rows = format_system_information_rows(planner_unmapped_system_information(system_information))
    if not rows:
        return
    console.print(Rule("System Information", style="dim"))
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold dim")
    table.add_column()
    for label, value in rows:
        table.add_row(f"{label}:", value)
    console.print(table)


def _print_plan_breakdown(console: Console, plan: dict[PlanKey, GroupScanPlan]) -> None:
    if not plan:
        console.print("[yellow]No groups selected.[/yellow]")
        return
    console.print("[bold]Selected groups[/bold]")
    for key in sorted(plan.keys()):
        group_plan = plan[key]
        if not group_plan.instances:
            instance_spec = "none"
        else:
            instance_spec = format_int_set(list(group_plan.instances))
        console.print(
            "  • "
            f"{format_plan_key(key)} "
            f"instances={instance_spec} RR_max={_hex_u16(group_plan.rr_max)}",
            style="dim",
        )


def _ask_preset(console: Console, *, default_preset: PlannerPreset) -> PlannerPreset:
    preset_hint = "Preset: (1) recommended, (2) full, (3) research, (4) custom"
    default_token = {
        "recommended": "1",
        "full": "2",
        "research": "3",
        "custom": "4",
    }[default_preset]
    mapping: dict[str, PlannerPreset] = {
        "1": "recommended",
        "recommended": "recommended",
        "conservative": "recommended",
        "2": "full",
        "full": "full",
        "aggressive": "full",
        "3": "research",
        "research": "research",
        "exhaustive": "research",
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
    eligible_groups: dict[int, list[PlannerGroup]],
    default_groups: list[int],
) -> list[int]:
    default_spec = (
        "all"
        if default_groups == sorted(eligible_groups.keys())
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
            return sorted(eligible_groups.keys())
        if lowered in {"none", "no"}:
            return []
        try:
            parsed = parse_int_set(raw, min_value=0x00, max_value=0xFF)
        except ValueError as exc:
            console.print(f"[red]Invalid group selection:[/red] {exc}")
            continue
        unknown = [gg for gg in parsed if gg not in eligible_groups]
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
    full_range = planner_instance_range(group)
    allowed_instances = set(full_range)
    if current_instances == planner_present_instances(group):
        default_mode = "present"
    elif current_instances == full_range:
        default_mode = "all"
    elif not current_instances:
        default_mode = "none"
    else:
        default_mode = format_int_set(list(current_instances))

    while True:
        raw_instances = Prompt.ask(
            f"{group.prompt_label} instances ('present', 'all', 'none', or a selector range)",
            default=default_mode,
            show_default=True,
            console=console,
        ).strip()
        lowered = raw_instances.lower()
        if lowered in {"present", "p"}:
            return planner_present_instances(group)
        if lowered in {"all", "*"}:
            return full_range
        if lowered in {"none", "no"}:
            return ()
        try:
            parsed_instances = parse_int_set(
                raw_instances,
                min_value=0x00,
                max_value=(0xFF if 0xFF in group.present_instances else group.ii_max),
            )
        except ValueError as exc:
            console.print(f"[red]Invalid instance selection:[/red] {exc}")
            continue
        invalid_instances = [
            instance for instance in parsed_instances if instance not in allowed_instances
        ]
        if invalid_instances:
            invalid_text = ", ".join(_hex_u8(instance) for instance in invalid_instances)
            console.print(
                "[red]Invalid instance selection:[/red] "
                f"allowed values are {_hex_u8(full_range[0])}..{_hex_u8(full_range[-1])}"
                + (" plus 0xFF" if 0xFF in allowed_instances else "")
                + f"; got {invalid_text}"
            )
            continue
        return tuple(parsed_instances)


def _custom_plan_with_required_rr(console: Console, group: PlannerGroup) -> GroupScanPlan:
    """Create a custom row only after the operator supplies an RR scope."""

    from .planner_textual import _parse_register_scope

    while True:
        raw_rr_max = Prompt.ask(
            f"{group.prompt_label} RR scope is unqualified; enter ceiling, list, or range",
            console=console,
        ).strip()
        try:
            rr_max, registers = _parse_register_scope(raw_rr_max)
        except ValueError as exc:
            console.print(f"[red]Invalid RR_max:[/red] {exc}")
            continue
        return GroupScanPlan(
            group=group.group,
            opcode=group.opcode,
            rr_max=rr_max,
            instances=(0x00,) if group.ii_max is None else planner_present_instances(group),
            registers=registers,
        )


def _operation_request_label(request: object) -> str:
    operation = str(getattr(request, "operation", "operation"))
    opcode = getattr(request, "opcode", None)
    opcode_text = f"0x{opcode:02X}" if isinstance(opcode, int) else "?"
    selector = getattr(request, "selector", {})
    selector_text = (
        ", ".join(f"{key}={value}" for key, value in selector.items())
        if isinstance(selector, Mapping)
        else ""
    )
    return " ".join(part for part in (opcode_text, operation, selector_text) if part)


def _prompt_operation_selection(
    console: Console,
    operation_requests: Sequence[object],
    operation_selection: list[bool],
) -> None:
    """Select complete Event programs, preserving every underlying selector."""
    from .operation_planner import operation_planner_rows, replace_event_day_codes

    if not operation_requests:
        return
    if len(operation_selection) != len(operation_requests):
        raise ValueError("operation_selection must match operation_requests")
    rows = operation_planner_rows(operation_requests)
    table = Table(title="Events and Schedules (B524)")
    table.add_column("On")
    table.add_column("Request")
    for index, row in enumerate(rows, start=1):
        table.add_row(
            row.mark(operation_selection),
            f"{index}. {row.name} · {row.scope} · up to {len(row.indices)} reads",
        )
    console.print(table)
    while True:
        raw = (
            Prompt.ask(
                "Programs: all, none, indexes, or codes N <raw range>",
                default="keep",
                console=console,
            )
            .strip()
            .lower()
        )
        if raw in {"", "keep", "k"}:
            return
        if raw in {"all", "*"}:
            operation_selection[:] = [True] * len(operation_requests)
            return
        if raw in {"none", "off"}:
            operation_selection[:] = [False] * len(operation_requests)
            return
        if raw.startswith("codes "):
            try:
                _command, index_text, code_text = raw.split(maxsplit=2)
                index = parse_int_token(index_text)
                if not 1 <= index <= len(rows):
                    raise ValueError("Program index is outside the displayed list")
                codes = parse_int_set(code_text, min_value=0, max_value=0xFF)
                if not codes:
                    raise ValueError("Choose at least one raw Event code")
                if not isinstance(operation_requests, list):
                    raise ValueError(
                        "Explicit operation selectors are retained from their read plan"
                    )
                replace_event_day_codes(
                    operation_requests, operation_selection, rows[index - 1], codes
                )
            except ValueError as exc:
                console.print(f"[red]Invalid Event codes:[/red] {exc}")
            else:
                rows = operation_planner_rows(operation_requests)
                console.print(f"{rows[index - 1].name}: {rows[index - 1].scope}")
            continue
        try:
            selected = parse_int_set(raw, min_value=1, max_value=len(rows))
        except ValueError as exc:
            console.print(f"[red]Invalid operation selection:[/red] {exc}")
            continue
        operation_selection[:] = [False] * len(operation_requests)
        for index in selected:
            for request_index in rows[index - 1].indices:
                operation_selection[request_index] = True
        return


def prompt_scan_plan(
    console: Console,
    groups: list[PlannerGroup],
    *,
    request_rate_rps: float | None,
    default_plan: dict[PlanKey, GroupScanPlan] | None = None,
    default_preset: PlannerPreset = "recommended",
    system_information: Sequence[Mapping[str, object]] | None = None,
    operation_requests: Sequence[object] | None = None,
    operation_selection: list[bool] | None = None,
) -> dict[PlanKey, GroupScanPlan]:
    """Prompt for a scan plan in interactive TTY mode.

    Returns a dict mapping (GG, opcode) -> GroupScanPlan.
    """

    requests = operation_requests or ()
    if operation_selection is not None:
        _prompt_operation_selection(console, requests, operation_selection)
    eligible = {g.key: g for g in groups}
    if not eligible:
        return {}
    eligible_groups: dict[int, list[PlannerGroup]] = {}
    for group in groups:
        eligible_groups.setdefault(group.group, []).append(group)

    default_selected_plan = _build_default_plan(
        eligible,
        default_plan,
        default_preset=default_preset,
    )

    console.print(Rule("Scan Planner", style="dim"))
    console.print(
        Text(
            "Review default scope, optionally apply a preset, then tune groups/instances/RR_max.",
            style="dim",
        )
    )
    _render_system_information(console, system_information)

    known_groups = sorted([g for g in groups if g.known], key=lambda x: (x.group, x.opcode))
    unknown_groups = sorted(
        [g for g in groups if not g.known],
        key=lambda x: (x.group, x.opcode),
    )
    _render_table(
        "Known Groups",
        known_groups,
        unknown=False,
        console=console,
        system_information=system_information,
    )
    _render_table(
        "Unknown Groups (Disabled By Default)",
        unknown_groups,
        unknown=True,
        console=console,
        system_information=system_information,
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
        # An explicit incoming plan is already operator-selected, including
        # unqualified native routes. Ask for an RR scope only when a new route
        # is added below.
        selected_plan = dict(default_selected_plan)
    else:
        selected_plan = build_plan_from_preset(groups, preset=preset)

    if preset == "full":
        console.print(
            "[bold yellow]Warning:[/bold yellow] full preset scans all profile-supported "
            "pairs with full declared instance slots. Discovery pass — may take tens of minutes.",
        )
    if preset == "research":
        console.print(
            "[bold yellow]Warning:[/bold yellow] research preset scans broad read-namespace "
            "candidates with expanded RR ranges. Deep-dive — expect very long "
            "reverse-engineering runs.",
        )

    if preset == "custom":
        selected_groups = _ask_groups_to_scan(
            console,
            eligible_groups=eligible_groups,
            default_groups=sorted({group for (group, _opcode) in selected_plan}),
        )
        retained_plan: dict[PlanKey, GroupScanPlan] = {}
        for selected_group_id in selected_groups:
            for planner_group in sorted(
                eligible_groups[selected_group_id],
                key=lambda item: (item.group, item.opcode),
            ):
                existing = selected_plan.get(planner_group.key)
                if existing is not None:
                    retained_plan[planner_group.key] = existing
                elif planner_group.rr_max is not None:
                    retained_plan[planner_group.key] = GroupScanPlan(
                        group=planner_group.group,
                        opcode=planner_group.opcode,
                        rr_max=planner_group.rr_max,
                        instances=(
                            (0x00,)
                            if planner_group.ii_max is None
                            else planner_present_instances(planner_group)
                        ),
                    )
                else:
                    retained_plan[planner_group.key] = _custom_plan_with_required_rr(
                        console, planner_group
                    )
        selected_plan = retained_plan

        if _ask_yes_no(console, "Override register selections?", default=False):
            from .planner_textual import _parse_register_scope

            for key in sorted(selected_plan.keys()):
                current = selected_plan[key]
                planner_group = eligible[key]
                while True:
                    current_scope = (
                        format_int_set(current.registers)
                        if current.registers is not None
                        else _hex_u16(current.rr_max)
                    )
                    raw_rr_max = Prompt.ask(
                        f"{planner_group.prompt_label} RR scope (ceiling, list, or range)",
                        default=current_scope,
                        show_default=True,
                        console=console,
                    ).strip()
                    try:
                        rr_max, registers = _parse_register_scope(raw_rr_max)
                    except ValueError as exc:
                        console.print(f"[red]Invalid RR_max:[/red] {exc}")
                        continue
                    if not (0x0000 <= rr_max <= 0xFFFF):
                        console.print("[red]RR_max out of range (0x0000..0xFFFF).[/red]")
                        continue
                    selected_plan[key] = GroupScanPlan(
                        group=current.group,
                        opcode=current.opcode,
                        rr_max=rr_max,
                        instances=current.instances,
                        registers=registers,
                    )
                    break

        if _ask_yes_no(console, "Override instance selection?", default=False):
            for key in sorted(selected_plan.keys()):
                planner_group = eligible[key]
                current = selected_plan[key]
                if planner_group.ii_max is None:
                    continue
                selected_plan[key] = GroupScanPlan(
                    group=current.group,
                    opcode=current.opcode,
                    rr_max=current.rr_max,
                    instances=_ask_instances(
                        console,
                        group=planner_group,
                        current_instances=current.instances,
                    ),
                    registers=current.registers,
                )

    _print_plan_breakdown(console, selected_plan)
    _print_estimate(console, plan=selected_plan, request_rate_rps=request_rate_rps)

    try:
        validate_scalar_request_limit(selected_plan)
    except ValueError as exc:
        console.print(f"[red]Invalid scan plan:[/red] {exc}")
        raise

    if not _ask_yes_no(console, "Proceed with register scan?", default=True):
        raise KeyboardInterrupt

    return selected_plan
