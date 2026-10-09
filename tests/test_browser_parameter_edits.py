from __future__ import annotations

import re

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


@pytest.mark.parametrize(
    "flag",
    [
        "--scan-plan",
        "--b524-read-plan",
        "--preview-read-plan",
        "--description-budget",
        "--request-budget",
        "--probe-constraints",
        "--no-probe-constraints",
    ],
)
def test_scan_has_no_plan_or_description_budget_cli(flag: str) -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"], env={"COLUMNS": "240"})
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.output)
    assert flag not in text
    result = runner.invoke(app, ["scan", flag])
    assert result.exit_code == 2
    assert "No such option" in result.output


def test_offline_edit_keeps_observed_values_and_never_claims_device_write() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import record_offline_edit

    entry = {"value": 1, "raw_hex": "0100", "reply_hex": "03020e000100", "written": False}
    record_offline_edit(entry, value=0, raw_hex="0000", type_spec="UIN")
    assert entry["value"] == 1
    assert entry["raw_hex"] == "0100"
    assert entry["reply_hex"] == "03020e000100"
    assert entry["local_edit_preview"]["value"] == 0
    assert entry["local_edit_preview"]["device_write"] is False
    assert entry["written"] is False


def test_enum_choices_keep_code_labels_and_disable_range_exclusions() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import parameter_enum_choices

    choices = parameter_enum_choices(
        {},
        read_opcode=2,
        group=9,
        register=2,
        description={"min": 2, "max": 3, "step": 1},
    )
    assert [(c.value, c.label) for c in choices] == [
        (1, "TIME_CONTROLLED"),
        (2, "NORMAL"),
        (3, "REDUCED"),
    ]
    assert choices[0].enabled is False
    assert choices[1].enabled is True


def test_enum_gate_false_and_unknown_are_distinct() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import parameter_enum_choices

    choices = parameter_enum_choices(
        {
            "enum_options": [
                {"value": 0, "label": "OFF"},
                {
                    "value": 1,
                    "label": "ON",
                    "gate": {
                        "state": False,
                        "qualification": "qualified",
                        "reason": "Cooling disabled",
                    },
                },
                {
                    "value": 2,
                    "label": "AUTO",
                    "gate": {"state": None, "qualification": "qualified"},
                },
            ]
        },
        read_opcode=2,
        group=2,
        register=6,
        description=None,
    )
    assert choices[0].enabled
    assert not choices[1].enabled
    assert choices[1].reason == "Cooling disabled"
    assert choices[2].enabled and choices[2].gate_unknown


@pytest.mark.parametrize(
    "flag",
    [
        "--dst",
        "--dry-run",
        "--output-dir",
        "--ebusd-csv-path",
        "--myvaillant-map-path",
        "--trace-file",
        "--b509-range",
        "--b509-dump",
        "--b555-dump",
        "--b516-dump",
        "--planner-ui",
        "--no-tips",
        "--redact",
    ],
)
def test_scan_choices_are_visual_only(flag: str) -> None:
    result = CliRunner().invoke(app, ["scan", flag])
    assert result.exit_code == 2
    assert "No such option" in result.output


@pytest.mark.parametrize("flag", ["--file", "--live", "--device", "--allow-write"])
def test_browse_choices_are_visual_only(flag: str) -> None:
    result = CliRunner().invoke(app, ["browse", flag])
    assert result.exit_code == 2
    assert "No such option" in result.output


def test_unknown_enum_code_is_displayed_without_coercion() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import parameter_value_display

    assert parameter_value_display({"value": 99}, opcode=2, group=9, register=2) == "UNKNOWN (99)"


def test_nonfinite_limits_do_not_crash_enum_choices() -> None:
    from helianthus_vrc_explorer.ui.parameter_editor import parameter_enum_choices

    choices = parameter_enum_choices(
        {},
        read_opcode=2,
        group=9,
        register=2,
        description={"min": float("-inf"), "max": float("inf"), "step": 1},
    )
    assert len(choices) == 3
