from __future__ import annotations

from rich.console import Console

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.ui.planner import (
    PlannerGroup,
    _print_plan_breakdown,
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
            opcode=0x02,
            name="Heating Circuits",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x21,
            rr_max_full=0x21,
            present_instances=(0x01,),
        ),
        PlannerGroup(
            group=0x69,
            opcode=0x02,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            rr_max_full=0x30,
            present_instances=tuple(range(0x0A + 1)),
            recommended=False,
        ),
    ]

    plan = prompt_scan_plan(console, groups, request_rate_rps=None, default_plan=None)
    assert sorted(plan.keys()) == [make_plan_key(0x02, 0x02)]


def test_prompt_scan_plan_preserves_exact_default_registers_without_changes(monkeypatch) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    answers = iter(["n", "y"])
    monkeypatch.setattr(planner.Prompt, "ask", lambda *_args, **_kwargs: next(answers))
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x0100,
        rr_max_full=0x0100,
        present_instances=(0x01, 0x03),
    )
    default = GroupScanPlan(
        group=0x02,
        opcode=0x02,
        rr_max=0x0100,
        instances=(0x01, 0x03),
        registers=(0x0002, 0x0010, 0x0100),
    )

    plan = prompt_scan_plan(
        Console(force_terminal=True),
        [group],
        request_rate_rps=None,
        default_plan={group.key: default},
    )

    assert plan == {group.key: default}


def test_classic_custom_preserves_explicit_unqualified_route(
    monkeypatch,
) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    group = PlannerGroup(
        group=0x0D,
        opcode=0x06,
        name="Unknown remote",
        descriptor=float("nan"),
        known=False,
        ii_max=0x08,
        rr_max=None,
        rr_max_full=None,
        present_instances=(0x01,),
    )
    default = GroupScanPlan(
        group=0x0D,
        opcode=0x06,
        rr_max=0x0003,
        instances=(0x01,),
        registers=(0x0001, 0x0003),
    )
    answers = iter([True, False, False, True])
    monkeypatch.setattr(planner, "_ask_yes_no", lambda *_args, **_kwargs: next(answers))
    monkeypatch.setattr(planner, "_ask_preset", lambda *_args, **_kwargs: "custom")
    monkeypatch.setattr(planner, "_ask_groups_to_scan", lambda *_args, **_kwargs: [0x0D])

    plan = prompt_scan_plan(
        Console(force_terminal=True),
        [group],
        request_rate_rps=None,
        default_plan={group.key: default},
    )

    assert plan == {group.key: default}


def test_prompt_scan_plan_full_alias_still_applies_profile_pair_policy(monkeypatch) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    answers = iter(
        [
            "y",  # Customize?
            "aggressive",  # Legacy alias for full preset
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
            opcode=0x02,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            rr_max_full=0x30,
            present_instances=tuple(range(0x0A + 1)),
        )
    ]

    plan = prompt_scan_plan(console, groups, request_rate_rps=None, default_plan=None)
    assert plan == {}


def test_build_plan_from_preset_recommended_skips_unknown_groups() -> None:
    groups = [
        PlannerGroup(
            group=0x02,
            opcode=0x02,
            name="Heating Circuits",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x21,
            rr_max_full=0x21,
            present_instances=(0x01, 0x02),
        ),
        PlannerGroup(
            group=0x69,
            opcode=0x02,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            rr_max_full=0x30,
            present_instances=tuple(range(0x0A + 1)),
            recommended=False,
        ),
    ]

    plan = build_plan_from_preset(groups, preset="recommended")
    key = make_plan_key(0x02, 0x02)
    assert sorted(plan.keys()) == [key]
    assert plan[key].instances == (0x01, 0x02, 0x09)


def test_build_plan_from_preset_research_caps_remote_slots() -> None:
    groups = [
        PlannerGroup(
            group=0x69,
            opcode=0x06,
            name="Unknown",
            descriptor=1.0,
            known=False,
            ii_max=0x0A,
            rr_max=0x30,
            rr_max_full=0x30,
            present_instances=(0x01, 0xFF),
        )
    ]

    plan = build_plan_from_preset(groups, preset="research")
    assert plan[make_plan_key(0x69, 0x06)].instances == tuple(range(1, 9))


def test_print_plan_breakdown_does_not_infer_singleton_from_selected_instance() -> None:
    console = Console(record=True, width=120)
    _print_plan_breakdown(
        console,
        {
            make_plan_key(0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0035,
                instances=(0x01,),
            )
        },
    )

    text = console.export_text()
    assert "instances=1" in text
    assert "instances=singleton" not in text
