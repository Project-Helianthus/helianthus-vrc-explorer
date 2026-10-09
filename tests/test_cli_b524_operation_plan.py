import json
from contextlib import contextmanager
from pathlib import Path

from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


def test_normal_scan_passes_resolved_identity_for_automatic_event_policy(
    tmp_path, monkeypatch
) -> None:
    import helianthus_vrc_explorer.cli as cli

    class _Transport:
        @contextmanager
        def session(self):
            yield self

    @contextmanager
    def observer(*_args, **_kwargs):
        yield None

    identity = {
        "manufacturer": "0xB5",
        "device_id": "BASV2",
        "eid": "BASV2",
    }
    captured: dict[str, object] = {}

    def scan_vrc(*_args, **kwargs):
        captured.update(kwargs)
        return {
            "meta": {
                "scan_timestamp": "2026-10-09T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "operations": {},
        }

    monkeypatch.setattr(cli, "_build_transport", lambda *_args, **_kwargs: _Transport())
    monkeypatch.setattr(cli, "_probe_scan_identity", lambda *_args, **_kwargs: dict(identity))
    monkeypatch.setattr(cli, "make_scan_observer", observer)
    monkeypatch.setattr(cli, "scan_vrc", scan_vrc)

    result = CliRunner().invoke(
        app,
        ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)],
    )

    assert result.exit_code == 0, result.output
    assert captured["operation_identity"] == identity
    assert "operation_requests" not in captured


def test_read_plan_help_describes_optional_override() -> None:
    result = CliRunner().invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--b524-read-plan" in result.stdout
    assert "Optional" in result.stdout and "explicit JSON" in result.stdout
    assert "normal scans" in result.stdout and "bounded" in result.stdout


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


def test_bundled_dry_run_operation_plan_keeps_missing_responses_explicit(tmp_path, monkeypatch):
    import helianthus_vrc_explorer.cli as cli

    monkeypatch.setattr(cli, "_build_transport", lambda *args, **kwargs: 1 / 0)
    path = tmp_path / "reads.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "requests": [
                    {
                        "operation": "GetEvent",
                        "profile": "zone",
                        "instance": 1,
                        "address": 1,
                        "weekday_code": 0,
                    }
                ],
            }
        )
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--b524-read-plan",
            str(path),
            "--planner-ui",
            "disabled",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    artifact = json.loads(Path(result.stdout.strip()).read_text())
    assert artifact["meta"]["dry_run_mode"] == "deterministic_scan"
    record = artifact["b524_operation_reads"][0]
    assert record["response_state"] == "transport_error"
    assert record["error"] == "transport_error"
    assert record["response_raw_hex"] is None
    assert record["decoded"] is None
    assert record["decode_qualification"] == "schema_unqualified"
