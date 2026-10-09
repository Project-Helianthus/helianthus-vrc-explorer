from __future__ import annotations

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.scanner.plan import make_plan_key
from helianthus_vrc_explorer.scanner.scan_policy import parse_scan_plan
from helianthus_vrc_explorer.ui.scan_setup import ScanSetup
from tests.scan_ui_helpers import invoke_scan


def test_internal_custom_selector_parser_rejects_non_read_opcode() -> None:
    with pytest.raises(ValueError, match="opcode"):
        parse_scan_plan(
            {
                "schema_version": 1,
                "groups": [{"opcode": 8, "group": 0, "instances": [0], "registers": [1]}],
            }
        )


def test_internal_custom_selector_parser_normalizes_exact_registers() -> None:
    plan = parse_scan_plan(
        {
            "schema_version": 1,
            "groups": [
                {
                    "opcode": 2,
                    "group": 0,
                    "instances": [0],
                    "registers": ["0x0001", "0x0100..0x0101"],
                }
            ],
        }
    )

    group = plan[make_plan_key(0x00, 0x02)]
    assert group.instances == (0,)
    assert group.registers == (0x0001, 0x0100, 0x0101)
    assert group.rr_max == 0x0101


@pytest.mark.parametrize(
    "opcode,group,instance",
    [(6, 15, 0), (6, 15, 9), (2, 2, 10)],
)
def test_internal_custom_selector_parser_rejects_out_of_profile_instance(
    opcode: int, group: int, instance: int
) -> None:
    with pytest.raises(ValueError, match="instances"):
        parse_scan_plan(
            {
                "schema_version": 1,
                "groups": [
                    {
                        "opcode": opcode,
                        "group": group,
                        "instances": [instance],
                        "registers": [1],
                    }
                ],
            }
        )


def test_internal_custom_selector_parser_allows_basv2_circuit_ii00() -> None:
    plan = parse_scan_plan(
        {
            "schema_version": 1,
            "groups": [{"opcode": 2, "group": 2, "instances": [0], "registers": [2]}],
        }
    )
    assert 0 in plan[make_plan_key(0x02, 0x02)].instances


def test_headless_custom_scan_requires_visual_planner(monkeypatch) -> None:
    import helianthus_vrc_explorer.cli as cli

    monkeypatch.setattr(
        cli,
        "_build_transport",
        lambda *_args, **_kwargs: pytest.fail("headless custom must fail before transport"),
    )
    result = invoke_scan(
        CliRunner(),
        monkeypatch,
        ["--preset", "custom"],
        setup=ScanSetup(preset="custom", planner_ui="disabled"),
    )
    assert result.exit_code == 2
    assert "requires an interactive planner" in result.output
