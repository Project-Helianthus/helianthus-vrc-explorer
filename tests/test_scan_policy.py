from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan_policy import parse_scan_plan, profile_opcodes


def test_profile_opcodes_are_deterministic_for_each_preset() -> None:
    assert profile_opcodes(0x00, "recommended") == (0x02,)
    assert profile_opcodes(0x0A, "full") == (0x06,)
    assert profile_opcodes(0x07, "recommended") == ()
    assert profile_opcodes(0x69, "research") == (0x02, 0x06)
    assert profile_opcodes(0x00, "research") == (0x02,)
    assert profile_opcodes(0x00, "custom") == (0x02, 0x06)


def test_parse_scan_plan_accepts_exact_instances_and_register_ranges() -> None:
    plan = parse_scan_plan(
        {
            "schema_version": 1,
            "groups": [
                {
                    "opcode": "0x02",
                    "group": "0x02",
                    "instances": ["0x00", 3],
                    "registers": ["0x0002", "0x0010..0x0012", 0x20],
                },
                {
                    "opcode": 0x06,
                    "group": 0x00,
                    "instances": [0xFF],
                    "registers": [0xFFFF],
                },
            ],
        }
    )

    assert plan == {
        make_plan_key(0x02, 0x02): GroupScanPlan(
            group=0x02,
            opcode=0x02,
            rr_max=0x0020,
            instances=(0x00, 0x03),
            registers=(0x0002, 0x0010, 0x0011, 0x0012, 0x0020),
        ),
        make_plan_key(0x00, 0x06): GroupScanPlan(
            group=0x00,
            opcode=0x06,
            rr_max=0xFFFF,
            instances=(0xFF,),
            registers=(0xFFFF,),
        ),
    }

    assert parse_scan_plan(
        {
            "schema_version": "1",
            "groups": [{"opcode": 2, "group": 2, "instances": [0], "registers": [0]}],
        }
    )


@pytest.mark.parametrize(
    ("data", "match"),
    [
        ({"schema_version": "1", "groups": []}, "at least one"),
        ({"schema_version": True, "groups": []}, "schema_version"),
        ({"schema_version": 1.0, "groups": []}, "schema_version"),
        ({"schema_version": "1", "groups": False}, "groups"),
        (
            {
                "schema_version": "1",
                "groups": [
                    {
                        "opcode": 0x03,
                        "group": 0,
                        "instances": [0],
                        "registers": [0],
                    }
                ],
            },
            "opcode",
        ),
        (
            {
                "schema_version": "1",
                "groups": [
                    {
                        "opcode": 2,
                        "group": True,
                        "instances": [0],
                        "registers": [0],
                    }
                ],
            },
            "group",
        ),
        (
            {
                "schema_version": "1",
                "groups": [
                    {
                        "opcode": 2,
                        "group": 2,
                        "instances": [],
                        "registers": [0],
                    }
                ],
            },
            "instances",
        ),
        (
            {
                "schema_version": "1",
                "groups": [
                    {
                        "opcode": 2,
                        "group": 2,
                        "instances": [0],
                        "registers": [1.5],
                    }
                ],
            },
            "registers",
        ),
        (
            {
                "schema_version": "1",
                "groups": [
                    {
                        "opcode": 2,
                        "group": 2,
                        "instances": [0],
                        "registers": [0],
                        "surprise": 1,
                    }
                ],
            },
            "unknown field",
        ),
    ],
)
def test_parse_scan_plan_rejects_invalid_or_ambiguous_input(data: object, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_scan_plan(data)


def test_parse_scan_plan_rejects_conflicting_duplicate_namespace_rows() -> None:
    data = {
        "schema_version": "1",
        "groups": [
            {"opcode": 2, "group": 2, "instances": [0], "registers": [1]},
            {"opcode": 2, "group": 2, "instances": [0], "registers": [2]},
        ],
    }

    with pytest.raises(ValueError, match="conflicting duplicate"):
        parse_scan_plan(data)


def test_parse_scan_plan_normalizes_mixed_equivalent_selectors_and_duplicate_rows() -> None:
    plan = parse_scan_plan(
        {
            "schema_version": 1,
            "groups": [
                {
                    "opcode": "02",
                    "group": "2",
                    "instances": [3, "0x00", "3"],
                    "registers": ["0x0012..0x0010", 2, "02"],
                },
                {
                    "opcode": 2,
                    "group": 2,
                    "instances": [0, "0x03"],
                    "registers": ["0x0002", "16-18"],
                },
            ],
        }
    )

    assert plan == {
        make_plan_key(0x02, 0x02): GroupScanPlan(
            group=0x02,
            opcode=0x02,
            rr_max=18,
            instances=(0, 3),
            registers=(2, 16, 17, 18),
        )
    }


def test_parse_scan_plan_accepts_exact_scalar_request_limit() -> None:
    data = {
        "schema_version": 1,
        "groups": [
            {
                "opcode": 2,
                "group": 3,
                "instances": ["0x00..0x01"],
                "registers": ["0x0000..0xc34f"],
            }
        ],
    }

    plan = parse_scan_plan(data)
    assert len(plan[make_plan_key(0x03, 0x02)].registers or ()) == 50_000


def test_parse_scan_plan_rejects_more_than_scalar_request_limit() -> None:
    data = {
        "schema_version": "1",
        "groups": [
            {
                "opcode": 2,
                "group": 2,
                "instances": ["0x00..0x01"],
                "registers": ["0x0000..0xc350"],
            }
        ],
    }

    with pytest.raises(ValueError, match="100000"):
        parse_scan_plan(data)


def test_parse_scan_plan_rejects_comma_separated_element() -> None:
    data = {
        "schema_version": 1,
        "groups": [
            {
                "opcode": 2,
                "group": 2,
                "instances": [0],
                "registers": ["0x0001,0x0002"],
            }
        ],
    }

    with pytest.raises(ValueError, match="one integer or range"):
        parse_scan_plan(data)


def test_system_profile_and_research_use_ff_register_ceiling() -> None:
    from helianthus_vrc_explorer.scanner.b524_plan import _rr_max_full_for_opcode
    from helianthus_vrc_explorer.scanner.director import group_namespace_profiles
    from helianthus_vrc_explorer.scanner.scan_policy import research_rr_max

    assert group_namespace_profiles(0)[2].rr_max == 0xFF
    assert _rr_max_full_for_opcode(group=0, opcode=2) == 0xFF
    assert research_rr_max(group=0, opcode=2, normal_rr_max=0xFF) == 0xFF
