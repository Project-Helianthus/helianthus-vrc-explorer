from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.plan import (
    GroupScanPlan,
    RegisterTask,
    build_work_queue,
    estimate_register_requests,
    format_int_set,
    parse_int_set,
    parse_int_token,
)
from helianthus_vrc_explorer.ui.planner import PlannerGroup, _format_seconds, build_plan_from_preset


def test_parse_int_token_accepts_decimal_and_hex() -> None:
    assert parse_int_token("10") == 10
    assert parse_int_token("0x0a") == 10
    assert parse_int_token("0A") == 10
    assert parse_int_token("ff") == 255


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("0-3", [0, 1, 2, 3]),
        ("1,3,5", [1, 3, 5]),
        ("0-3,7,9-10", [0, 1, 2, 3, 7, 9, 10]),
        ("3-1", [1, 2, 3]),
    ],
)
def test_parse_int_set(spec: str, expected: list[int]) -> None:
    assert parse_int_set(spec, min_value=0, max_value=255) == expected


def test_parse_int_set_rejects_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        parse_int_set("256", min_value=0, max_value=255)


def test_estimate_register_requests() -> None:
    plan = {
        (0x02, 0x02): GroupScanPlan(
            group=0x02,
            opcode=0x02,
            rr_max=0x0003,
            instances=(0x00, 0x01),
        ),
        (0x01, 0x02): GroupScanPlan(group=0x01, opcode=0x02, rr_max=0x0001, instances=(0x00,)),
    }
    # GG=0x02: 2 instances * (3+1) regs = 8
    # GG=0x01: 1 instance * (1+1) regs = 2
    assert estimate_register_requests(plan) == 10


def test_format_int_set_compacts_ranges() -> None:
    assert format_int_set([]) == ""
    assert format_int_set([0]) == "0"
    assert format_int_set([0, 1, 2, 4, 5]) == "0-2,4-5"


def test_build_work_queue_skips_done_tasks() -> None:
    plan = {
        (0x02, 0x02): GroupScanPlan(
            group=0x02,
            opcode=0x02,
            rr_max=0x0002,
            instances=(0x00,),
        ),
    }
    done = {RegisterTask(group=0x02, opcode=0x02, instance=0x00, register=0x0001)}
    tasks = build_work_queue(plan, done=done)
    assert tasks == [
        RegisterTask(group=0x02, opcode=0x02, instance=0x00, register=0x0000),
        RegisterTask(group=0x02, opcode=0x02, instance=0x00, register=0x0002),
    ]


def test_format_seconds_normalizes_boundaries() -> None:
    assert _format_seconds(480.0) == "8m"
    assert _format_seconds(481.0) == "8m 1s"


def test_plan_dual_namespace_creates_two_entries() -> None:
    groups = [
        PlannerGroup(
            group=0x09,
            opcode=0x02,
            name="Regulators",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x000F,
            rr_max_full=0x000F,
            present_instances=(0x00,),
            namespace_label="local",
            primary=True,
        ),
        PlannerGroup(
            group=0x09,
            opcode=0x06,
            name="Regulators",
            descriptor=1.0,
            known=True,
            ii_max=0x0A,
            rr_max=0x000F,
            rr_max_full=0x0035,
            present_instances=(0x00,),
            namespace_label="remote",
            primary=False,
        ),
    ]

    recommended = build_plan_from_preset(groups, preset="recommended")
    assert sorted(recommended) == [(0x09, 0x02), (0x09, 0x06)]
    assert recommended[(0x09, 0x02)].rr_max == 0x000F
    assert recommended[(0x09, 0x06)].rr_max == 0x000F
    assert recommended[(0x09, 0x02)].instances == (0x00,)
    assert recommended[(0x09, 0x06)].instances == (0x00,)

    full = build_plan_from_preset(groups, preset="full")
    assert full[(0x09, 0x02)].instances == tuple(range(0x0A + 1))
    assert full[(0x09, 0x06)].instances == tuple(range(0x0A + 1))
    assert full[(0x09, 0x06)].rr_max == 0x0035
