import json

from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


def test_operation_plan_preview_validates_and_encodes_without_transport(tmp_path, monkeypatch):
    import helianthus_vrc_explorer.cli as cli

    def unexpected_transport(*args, **kwargs):
        raise AssertionError("offline preview opened transport")

    monkeypatch.setattr(cli, "_build_transport", unexpected_transport)
    path = tmp_path / "reads.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "requests": [
                    {
                        "operation": "GetEvent",
                        "profile": "zone",
                        "instance": 2,
                        "address": 1,
                        "weekday_code": 255,
                    },
                    {"operation": "ReadTimer", "channel": "dhw", "instance": 0, "weekday": 6},
                ],
            }
        )
    )
    result = CliRunner().invoke(app, ["scan", "--b524-read-plan", str(path), "--preview-read-plan"])
    assert result.exit_code == 0, result.output
    preview = json.loads(result.stdout)
    assert preview["live_send"] is False
    assert [row["payload_hex"] for row in preview["requests"]] == ["09030201ff", "0301000106"]


def test_operation_plan_rejects_writes_before_transport(tmp_path, monkeypatch):
    import helianthus_vrc_explorer.cli as cli

    monkeypatch.setattr(cli, "_build_transport", lambda *args, **kwargs: 1 / 0)
    path = tmp_path / "writes.json"
    path.write_text(json.dumps({"schema_version": 1, "requests": [{"operation": "SetEvent"}]}))
    result = CliRunner().invoke(app, ["scan", "--b524-read-plan", str(path)])
    assert result.exit_code == 2, result.output
    assert "Invalid B524 operation read plan" in result.output


def test_operation_preview_requires_explicit_plan_without_transport(monkeypatch):
    import helianthus_vrc_explorer.cli as cli

    monkeypatch.setattr(cli, "_build_transport", lambda *args, **kwargs: 1 / 0)
    result = CliRunner().invoke(app, ["scan", "--preview-read-plan"])
    assert result.exit_code == 2
    assert "requires --b524-read-plan" in result.output
