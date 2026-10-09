import json
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


def timer_edit():
    return {
        "schema_version": 1,
        "operation": "WriteTimer",
        "selector": {"channel": "dhw", "instance": 0, "weekday": 0},
        "values": [[1, 36], None, None],
        "expected_before_raw_hex": ["00002490909090"],
    }


def test_timer_edit_preview_keeps_baseline_and_never_opens_transport(tmp_path, monkeypatch):
    import helianthus_vrc_explorer.commands.b524 as command

    monkeypatch.setattr(command, "_make_transport", lambda **kwargs: 1 / 0)
    path = tmp_path / "edit.json"
    path.write_text(json.dumps(timer_edit()))
    result = CliRunner().invoke(app, ["b524", "apply-operation", "--plan", str(path)])
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["live_send"] is False
    assert data["payload_hex"] == "0401000100012490909090"
    assert data["expected_before_raw_hex"] == ["00002490909090"]
    assert data["expected_after_raw_hex"] == ["00012490909090"]
    assert "CONFIRM WriteTimer" in data["required_confirmation"]


@pytest.mark.parametrize("extra", [["--execute"], ["--execute", "--confirm", "yes"]])
def test_timer_execute_requires_qualification_and_exact_confirmation_before_io(
    tmp_path, monkeypatch, extra
):
    import helianthus_vrc_explorer.commands.b524 as command

    monkeypatch.setattr(command, "_make_transport", lambda **kwargs: 1 / 0)
    path = tmp_path / "edit.json"
    path.write_text(json.dumps(timer_edit()))
    result = CliRunner().invoke(app, ["b524", "apply-operation", "--plan", str(path), *extra])
    assert result.exit_code == 2, result.output
    assert "qualification" in result.output.lower()


def test_events_preview_pairs_tables_and_execute_rejects_unqualified_schema(tmp_path, monkeypatch):
    import helianthus_vrc_explorer.commands.b524 as command

    monkeypatch.setattr(command, "_make_transport", lambda **kwargs: 1 / 0)
    path = tmp_path / "edit.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "operation": "SetEventSetPoint",
                "selector": {"profile": "zone", "instance": 2, "address": 1, "weekday_code": 255},
                "values": [40, 41, 42, 43, 44, 45, 46],
                "expected_before_raw_hex": ["03ff000648908fff", "0020202020202020"],
            }
        )
    )
    args = ["b524", "apply-operation", "--plan", str(path)]
    preview = CliRunner().invoke(app, args)
    assert preview.exit_code == 0, preview.output
    data = json.loads(preview.stdout)
    assert data["payload_hex"] == "0c030201ff28292a2b2c2d2e"
    assert data["expected_after_raw_hex"][0] == "03ff000648908fff"
    blocked = CliRunner().invoke(app, [*args, "--execute"])
    assert blocked.exit_code == 2, blocked.output
    assert "schema_unqualified" in blocked.output


def test_qualified_timer_cli_verifies_identity_baseline_single_send_and_readback(
    tmp_path, monkeypatch
):
    import helianthus_vrc_explorer.commands.b524 as command

    class FakeTimer:
        def __init__(self):
            self.sent = []
            self.changed = False
            self.identifications = 0

        @contextmanager
        def session(self):
            yield self

        def send_proto(self, dst, primary, secondary, payload):
            assert (primary, secondary, payload) == (7, 4, b"")
            self.identifications += 1
            return b"\xb570000\x01\x02\x00\x01"

        def send_with_attempt_hook(self, dst, payload, hook):
            hook()
            self.sent.append(payload)
            if payload[0] == 4:
                self.changed = True
                return b"\x00"
            return bytes.fromhex("00012490909090" if self.changed else "00002490909090")

    transport = FakeTimer()
    monkeypatch.setattr(command, "_make_transport", lambda **kwargs: transport)
    plan = tmp_path / "edit.json"
    document = timer_edit()
    plan.write_text(json.dumps(document))
    qualification = tmp_path / "qualification.json"
    qualification.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "scope": "timer_write_op04",
                "manufacturer": 181,
                "device_id": "70000",
                "profile": "synthetic_timer",
                "model": "synthetic",
                "software_raw_hex": "0102",
                "selector": document["selector"],
                "evidence_reference": "synthetic_test_fixture",
                "native_qualified": True,
            }
        )
    )
    args = ["b524", "apply-operation", "--plan", str(plan)]
    preview = CliRunner().invoke(app, args)
    confirmation = json.loads(preview.stdout)["required_confirmation"]
    result = CliRunner().invoke(
        app, [*args, "--execute", "--qualification", str(qualification), "--confirm", confirmation]
    )
    assert result.exit_code == 0, result.output
    evidence = json.loads(result.stdout)
    assert evidence["outcome"] == "verified"
    assert evidence["write_feedback_interpretation"] == "unknown"
    assert transport.identifications == 1
    assert [payload[0] for payload in transport.sent] == [3, 4, 3]
