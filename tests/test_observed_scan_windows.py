from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.b524_plan import planner_native_opcodes, planner_rr_max
from helianthus_vrc_explorer.scanner.director import group_namespace_profiles


@pytest.mark.parametrize("group", [0x01, 0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C])
def test_remote_observed_window_reaches_002f_without_changing_instance_interval(group: int) -> None:
    profile = group_namespace_profiles(group)[0x06]
    assert profile.rr_max == 0x002F
    assert planner_rr_max(group, 0x06) == 0x002F
    assert (profile.ii_min, profile.ii_max) == (0x01, 0x08)


@pytest.mark.parametrize("group", [0x0E, 0x0F])
def test_remote_read_only_tail_extends_window_beyond_description_metadata(group: int) -> None:
    assert planner_rr_max(group, 0x06) == 0x0033


def test_remote_windows_do_not_supply_unobserved_local_windows() -> None:
    assert planner_rr_max(0x00, 0x02) == 0x00FF
    assert planner_rr_max(0x01, 0x02) == 0x0013
    assert planner_rr_max(0x02, 0x02) == 0x0025
    assert planner_rr_max(0x08, 0x02) == 0x0007
    assert planner_rr_max(0x06, 0x02) is None
    assert planner_rr_max(0x07, 0x02) is None
    assert planner_rr_max(0x04, 0x06) is None
    assert planner_rr_max(0x0D, 0x06) is None
    assert planner_rr_max(0x0D, 0x02) is None
    assert planner_rr_max(0x0E, 0x02) is None


def test_observed_unknown_local_0a_remains_selectable_as_an_independent_namespace() -> None:
    assert planner_native_opcodes(0x0A) == (0x02, 0x06)
    profiles = group_namespace_profiles(0x0A)
    assert profiles[0x02].name == "Unknown"
    assert profiles[0x02].rr_max == 0x004D
    assert profiles[0x06].rr_max == 0x0035
