from __future__ import annotations

import json
import re
from contextlib import contextmanager

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app


class _FakeTransport:
    def __init__(self, *, device_id: str = "70000", reply: bytes = b"") -> None:
        self.device_id = device_id
        self.reply = reply
        self.sent: list[tuple[int, bytes]] = []
        self.ident_requests = 0

    @contextmanager
    def session(self):
        yield self

    def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
        assert (dst, primary, secondary, payload) == (0x15, 0x07, 0x04, b"")
        self.ident_requests += 1
        return (
            bytes((0xB5,))
            + self.device_id.encode("ascii").ljust(5, b" ")
            + bytes.fromhex("01020304")
        )

    def send_with_attempt_hook(self, dst: int, payload: bytes, attempt_hook) -> bytes:  # noqa: ANN001
        attempt_hook()
        self.sent.append((dst, payload))
        return self.reply


def _install_transport(monkeypatch, transport: _FakeTransport) -> None:
    import helianthus_vrc_explorer.commands.b524 as command_mod

    monkeypatch.setattr(command_mod, "_make_transport", lambda **_kwargs: transport)


def test_b524_command_group_exposes_read_and_preview_operations() -> None:
    result = CliRunner().invoke(app, ["b524", "--help"])
    assert result.exit_code == 0
    for command in (
        "read-timer",
        "read-event",
        "read-event-setpoint",
        "read-vr91",
        "preview-write-timer",
        "preview-set-event",
        "preview-set-event-setpoint",
    ):
        assert command in result.stdout


def test_event_read_uses_profile_guard_without_vrc700_identity_gate(monkeypatch) -> None:
    transport = _FakeTransport(device_id="BASV2", reply=bytes.fromhex("03ff000648908fff"))
    _install_transport(monkeypatch, transport)

    result = CliRunner().invoke(
        app,
        [
            "b524",
            "read-event",
            "--profile",
            "zone",
            "--instance",
            "2",
            "--address",
            "1",
            "--weekday-code",
            "0xff",
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["operation"] == "GetEvent"
    assert output["request"]["payload_hex"] == "09030201ff"
    assert output["reply"]["raw_hex"] == "03ff000648908fff"
    assert output["reply"]["decoded"]["start1_raw"] == 255
    assert transport.ident_requests == 0
    assert transport.sent == [(0x15, bytes.fromhex("09030201ff"))]


def test_timer_read_requires_vrc700_identity_before_b524_request(monkeypatch) -> None:
    transport = _FakeTransport(device_id="BASV2", reply=bytes.fromhex("00002430909090"))
    _install_transport(monkeypatch, transport)

    result = CliRunner().invoke(
        app,
        ["b524", "read-timer", "--channel", "dhw", "--weekday", "0"],
    )

    assert result.exit_code == 2
    assert "requires device identity 70000 or B7S00" in result.stderr
    assert transport.ident_requests == 1
    assert transport.sent == []


def test_timer_read_returns_raw_and_decoded_schedule(monkeypatch) -> None:
    transport = _FakeTransport(device_id="70000", reply=bytes.fromhex("00002430909090"))
    _install_transport(monkeypatch, transport)

    result = CliRunner().invoke(
        app,
        ["b524", "read-timer", "--channel", "dhw", "--weekday", "0"],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["operation"] == "ReadTimer"
    assert output["device_id"] == "70000"
    assert output["request"]["payload_hex"] == "0301000100"
    assert output["reply"]["decoded"]["slots"][0]["stop_minutes"] == 360


def test_timer_read_returns_unknown_codes_without_losing_wire_evidence(monkeypatch) -> None:
    transport = _FakeTransport(device_id="70000", reply=bytes.fromhex("00919090909090"))
    _install_transport(monkeypatch, transport)
    result = CliRunner().invoke(app, ["b524", "read-timer", "--channel", "dhw"])
    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["reply"]["raw_hex"] == "00919090909090"
    assert output["reply"]["decoded"]["slots"][0]["start_raw"] == 0x91
    assert output["reply"]["decoded"]["slots"][0]["start_minutes"] is None


def test_event_setpoint_read_uses_profile_specific_decode(monkeypatch) -> None:
    transport = _FakeTransport(device_id="BASV2", reply=bytes.fromhex("00fdfeff00010203"))
    _install_transport(monkeypatch, transport)

    result = CliRunner().invoke(
        app,
        [
            "b524",
            "read-event-setpoint",
            "--profile",
            "dhw",
            "--address",
            "1",
            "--weekday-code",
            "0",
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    states = [value["state"] for value in output["reply"]["decoded"]["values"]]
    assert states[:3] == ["enable", "disable", "replacement"]
    assert states[3:] == [None, None, None, None]
    assert transport.ident_requests == 0


def test_read_vr91_accepts_b7s00_identity_and_keeps_temperatures_raw(monkeypatch) -> None:
    transport = _FakeTransport(device_id="B7S00", reply=bytes.fromhex("0102030405060708"))
    _install_transport(monkeypatch, transport)

    result = CliRunner().invoke(app, ["b524", "read-vr91"])

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["device_id"] == "B7S00"
    assert output["request"]["payload_hex"] == "08"
    assert output["reply"]["decoded"]["heating_temperature_raw"] == 7
    assert output["reply"]["decoded"]["cooling_temperature_raw"] == 8
    assert transport.ident_requests == 1


def test_preview_set_event_is_offline_only(monkeypatch) -> None:
    import helianthus_vrc_explorer.commands.b524 as command_mod

    monkeypatch.setattr(
        command_mod,
        "_make_transport",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("transport must remain unused")),
    )
    result = CliRunner().invoke(
        app,
        [
            "b524",
            "preview-set-event",
            "--profile",
            "system",
            "--instance",
            "0",
            "--address",
            "1",
            "--weekday-code",
            "0",
            "--value",
            "0xff",
            "--value",
            "1",
            "--value",
            "2",
            "--value",
            "3",
            "--value",
            "4",
            "--value",
            "5",
            "--value",
            "6",
        ],
    )

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output == {
        "live_send": False,
        "mutative": True,
        "opcode": "0x0A",
        "operation": "SetEvent",
        "payload_hex": "0a00000100ff010203040506",
    }


def test_event_profile_rejects_unknown_address_before_transport(monkeypatch) -> None:
    import helianthus_vrc_explorer.commands.b524 as command_mod

    monkeypatch.setattr(
        command_mod,
        "_make_transport",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("transport must remain unused")),
    )
    result = CliRunner().invoke(
        app,
        [
            "b524",
            "read-event-setpoint",
            "--profile",
            "zone",
            "--address",
            "3",
            "--weekday-code",
            "0",
        ],
    )
    assert result.exit_code == 2
    assert "is not documented for zone" in result.stderr


@pytest.mark.parametrize(
    "command",
    ["read-event", "read-event-setpoint", "preview-set-event", "preview-set-event-setpoint"],
)
def test_event_weekday_code_is_required_before_transport(command, monkeypatch) -> None:
    import helianthus_vrc_explorer.commands.b524 as command_mod

    monkeypatch.setattr(command_mod, "_make_transport", lambda **kwargs: 1 / 0)
    result = CliRunner().invoke(
        app,
        ["b524", command, "--profile", "zone", "--address", "1"],
        color=True,
        env={"FORCE_COLOR": "1"},
    )
    assert result.exit_code == 2
    plain_output = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", result.output)
    assert "--weekday-code" in plain_output
    assert "Missing option" in plain_output
