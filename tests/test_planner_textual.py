from __future__ import annotations

from helianthus_vrc_explorer.ui.planner import PlannerGroup, split_planner_groups_by_namespace
from helianthus_vrc_explorer.ui.planner_textual import (
    _EditableGroup,
    _estimate_footer,
    _parse_instances_spec,
    _table_row_values,
)


def test_parse_instances_spec_accepts_keywords_and_ranges() -> None:
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x21,
        rr_max_full=0x21,
        present_instances=(0x00, 0x02, 0x03),
    )
    assert _parse_instances_spec("present", group=group) == (0x00, 0x02, 0x03)
    assert _parse_instances_spec("all", group=group) == tuple(range(0x0A + 1))
    assert _parse_instances_spec("0-2", group=group) == (0x00, 0x01, 0x02)


def test_estimate_footer_reports_requests_and_eta() -> None:
    group = PlannerGroup(
        group=0x02,
        opcode=0x02,
        name="Heating Circuits",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x02,
        rr_max_full=0x02,
        present_instances=(0x00,),
    )
    states = {
        (0x02, 0x02): _EditableGroup(
            group=group,
            enabled=True,
            rr_max=0x02,
            instances=(0x00, 0x01),
        )
    }
    footer = _estimate_footer(states, request_rate_rps=2.0)
    assert "Plan: 6 requests" in footer
    assert "ETA:" in footer
    assert "1 plan entries selected" in footer


def test_table_row_values_show_explicit_namespace_column() -> None:
    remote_group = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Secondary Heating Sources",
        descriptor=3.0,
        known=True,
        ii_max=None,
        rr_max=0x0015,
        rr_max_full=0x0015,
        present_instances=(0x00,),
        namespace_label="remote",
        primary=False,
    )
    local_only_group = PlannerGroup(
        group=0x00,
        opcode=0x02,
        name="Regulator Parameters",
        descriptor=3.0,
        known=True,
        ii_max=None,
        rr_max=0x00FF,
        rr_max_full=0x00FF,
        present_instances=(0x00,),
    )

    remote_row = _table_row_values(
        _EditableGroup(
            group=remote_group,
            enabled=True,
            rr_max=0x0015,
            instances=(0x00,),
        )
    )
    local_row = _table_row_values(
        _EditableGroup(
            group=local_only_group,
            enabled=False,
            rr_max=0x00FF,
            instances=(0x00,),
        )
    )

    assert remote_row == (
        "✓",
        "0x01",
        "Secondary Heating Sources",
        "remote",
        "3.0",
        "singleton",
        "0x0015",
    )
    assert local_row == (
        " ",
        "0x00",
        "Regulator Parameters",
        "local",
        "3.0",
        "singleton",
        "0x00FF",
    )


def test_split_planner_groups_by_namespace_prefers_local_then_remote() -> None:
    local_group = PlannerGroup(
        group=0x09,
        opcode=0x02,
        name="Unknown 0x09 (local)",
        descriptor=1.0,
        known=True,
        ii_max=0x0A,
        rr_max=0x000F,
        rr_max_full=0x000F,
        present_instances=(0x00,),
        namespace_label="local",
    )
    remote_group = PlannerGroup(
        group=0x01,
        opcode=0x06,
        name="Secondary Heating Sources",
        descriptor=3.0,
        known=True,
        ii_max=None,
        rr_max=0x0015,
        rr_max_full=0x0015,
        present_instances=(0x00,),
        namespace_label="remote",
        primary=False,
    )

    sections = split_planner_groups_by_namespace([remote_group, local_group])

    assert [title for (title, _rows) in sections] == [
        "Local Devices (0x02)",
        "Remote Devices (0x06)",
    ]
    assert sections[0][1] == [local_group]
    assert sections[1][1] == [remote_group]
