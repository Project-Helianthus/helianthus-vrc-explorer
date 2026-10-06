from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


def test_invalid_custom_write_opcode_fails_before_transport(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli

    def forbidden_transport(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid plans must not open a transport")

    monkeypatch.setattr(cli.EbusdTcpTransport, "__init__", forbidden_transport)
    plan = tmp_path / "invalid.json"
    plan.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "groups": [{"opcode": 8, "group": 0, "instances": [0], "registers": [1]}],
            }
        )
    )
    result = CliRunner().invoke(app, ["scan", "--preset", "custom", "--scan-plan", str(plan)])
    assert result.exit_code == 2
    assert "opcode" in result.stderr


def test_custom_plan_dry_run_emits_exact_registers_and_budget(tmp_path: Path) -> None:
    plan = tmp_path / "plan.json"
    plan.write_text(
        json.dumps(
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
    )
    output = tmp_path / "output"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--dst",
            "0x15",
            "--preset",
            "custom",
            "--scan-plan",
            str(plan),
            "--description-budget",
            "0",
            "--request-budget",
            "100",
            "--output-dir",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    artifact = json.loads(next(output.glob("*.json")).read_text())
    scope = artifact["meta"]["scan_plan"]["groups"]["0x00"]["operations"]["0x02"]
    assert scope["registers"] == ["0x0001", "0x0100", "0x0101"]
    assert artifact["meta"]["scan_plan"]["estimated_register_requests"] == 3
    assert artifact["meta"]["scan_coverage"]["request_budget"] == 100
    assert next(output.glob("*.html")).is_file()
