from __future__ import annotations

from rich.console import Console

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan
from helianthus_vrc_explorer.ui.planner import (
    PlannerGroup,
    build_plan_from_preset,
    prompt_scan_plan,
)


def test_prompt_scan_plan_disables_unknown_groups_by_default(monkeypatch) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    answers = iter(
        [
            "n",  # Customize?
            "y",  # Proceed?
        ]
    )

    def fake_prompt(*_args, **_kwargs) -> str:
        return next(answers)

    monkeypatch.setattr(planner.Prompt, "ask", fake_prompt)

    console = Console(force_terminal=True)
    groups = [
        PlannerGroup(
            group=0x02,
            name="Heating Circuits",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x21,
            present_instances=(0x00,),
        ),
        PlannerGroup(
            group=0x69,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            present_instances=tuple(range(0x0A + 1)),
        ),
    ]

    plan = prompt_scan_plan(console, groups, request_rate_rps=None, default_plan=None)
    assert sorted(plan.keys()) == [0x02]


def test_prompt_scan_plan_accepts_lowercase_yes_and_aggressive_preset(monkeypatch) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    answers = iter(
        [
            "y",  # Customize?
            "3",  # Aggressive preset
            "y",  # Proceed?
        ]
    )

    def fake_prompt(*_args, **_kwargs) -> str:
        return next(answers)

    monkeypatch.setattr(planner.Prompt, "ask", fake_prompt)

    console = Console(force_terminal=True)
    groups = [
        PlannerGroup(
            group=0x69,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            present_instances=tuple(range(0x0A + 1)),
        )
    ]

    plan = prompt_scan_plan(console, groups, request_rate_rps=None, default_plan=None)
    assert plan == {
        0x69: GroupScanPlan(
            group=0x69,
            opcode=0x02,
            rr_max=0x30,
            instances=tuple(range(0x0A + 1)),
        )
    }


def test_build_plan_from_preset_recommended_skips_unknown_groups() -> None:
    groups = [
        PlannerGroup(
            group=0x02,
            name="Heating Circuits",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x21,
            present_instances=(0x00, 0x01),
        ),
        PlannerGroup(
            group=0x69,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            present_instances=tuple(range(0x0A + 1)),
        ),
    ]

    plan = build_plan_from_preset(groups, preset="recommended")
    assert sorted(plan.keys()) == [0x02]
    assert plan[0x02].instances == tuple(range(0x0A + 1))
