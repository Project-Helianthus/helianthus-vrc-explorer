from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.ui.planner import PlannerGroup, prompt_scan_plan


def test_classic_custom_override_replaces_exact_register_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.ui.planner as planner

    confirmations = iter([True, True, False, True])
    prompts = iter(["custom", "all", "0x0010..0x0012"])
    monkeypatch.setattr(planner, "_ask_yes_no", lambda *args, **kwargs: next(confirmations))
    monkeypatch.setattr(planner.Prompt, "ask", lambda *args, **kwargs: next(prompts))
    key = make_plan_key(0, 2)
    default = {
        key: GroupScanPlan(
            group=0, opcode=2, rr_max=0x101, instances=(0,), registers=(1, 0x100, 0x101)
        )
    }
    group = PlannerGroup(
        group=0,
        opcode=2,
        name="System",
        descriptor=float("nan"),
        known=True,
        ii_max=None,
        rr_max=0x101,
        rr_max_full=0x1FF,
        present_instances=(0,),
    )
    selected = prompt_scan_plan(
        Console(file=StringIO()),
        [group],
        request_rate_rps=None,
        default_plan=default,
        default_preset="custom",
    )
    assert selected[key].registers == (0x10, 0x11, 0x12)
    assert selected[key].rr_max == 0x12
