import json
import re
import struct
from contextlib import contextmanager
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from helianthus_vrc_explorer import __version__
from helianthus_vrc_explorer.cli import (
    _build_scan_session_preface,
    _format_fw,
    _load_default_dry_run_fixture_text,
    _load_ebus_model_name_map,
    _probe_group_descriptor,
    _probe_scan_identity,
    _resolve_scan_destination,
    app,
)

_ROLE_TARGET_TOKEN = bytes.fromhex("736c617665").decode("ascii")


def test_version_prints_version() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_scan_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", result.stdout)
    assert "planner-ui" in plain
    assert "preset" in plain
    assert "no-tips" in plain
    assert "disabled" in plain
    assert "auto" in plain


def test_scan_invalid_dst_fails_before_transport_setup(monkeypatch) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    def _fail_init(self, *_args, **_kwargs):  # noqa: ANN001
        raise AssertionError("transport should not be initialized for invalid --dst")

    monkeypatch.setattr(cli_mod.EbusdTcpTransport, "__init__", _fail_init)
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "bogus"])
    assert result.exit_code == 2
    assert "Invalid address: 'bogus'" in result.stderr


class _SessionOnlyTransport:
    def __init__(self, *, fail_open: bool) -> None:
        self._fail_open = fail_open

    @contextmanager
    def session(self):
        from helianthus_vrc_explorer.transport.base import TransportError

        if self._fail_open:
            raise TransportError("Failed talking to ebusd at 127.0.0.1:8888: refused")
        yield self


def test_scan_default_transport_failure_prompts_retry_and_succeeds(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    build_calls: list[tuple[str, str, int]] = []
    prompt_calls = {"count": 0}

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = trace_file
        build_calls.append((settings.protocol, settings.host, settings.port))
        fail = settings.host == "127.0.0.1" and settings.port == 8888
        return _SessionOnlyTransport(fail_open=fail)

    def _fake_prompt(_console, *, settings, error_message):  # noqa: ANN001
        prompt_calls["count"] += 1
        _ = settings
        _ = error_message
        return cli_mod._TransportSettings(protocol="tcp", host="127.0.0.2", port=9999)

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **_kwargs):
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: True)
    monkeypatch.setattr(cli_mod, "_prompt_transport_retry_settings", _fake_prompt)
    monkeypatch.setattr(cli_mod, "_resolve_scan_destination", lambda _transport, dst: 0x15)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert prompt_calls["count"] == 1
    assert build_calls == [("tcp", "127.0.0.1", 8888), ("tcp", "127.0.0.2", 9999)]


def test_scan_default_transport_failure_cancel_exits(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _SessionOnlyTransport(fail_open=True)

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: True)
    monkeypatch.setattr(
        cli_mod,
        "_prompt_transport_retry_settings",
        lambda _console, *, settings, error_message: None,
    )

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Transport setup aborted by user." in result.stderr


def test_scan_custom_transport_failure_does_not_prompt_retry(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    prompt_called = {"value": False}

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _SessionOnlyTransport(fail_open=True)

    def _fake_prompt(_console, *, settings, error_message):  # noqa: ANN001
        prompt_called["value"] = True
        _ = settings
        _ = error_message
        return None

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: True)
    monkeypatch.setattr(cli_mod, "_prompt_transport_retry_settings", _fake_prompt)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", "--host", "10.0.0.42", "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 1
    assert prompt_called["value"] is False


def test_scan_command_not_enabled_exits_with_enablehex_hint(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    from helianthus_vrc_explorer.transport.base import TransportCommandNotEnabled

    def _fake_scan_vrc(*_args, **_kwargs):
        raise TransportCommandNotEnabled("ERR: command not enabled")

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert "--enablehex" in result.stderr


def test_scan_cli_defaults_planner_ui_to_disabled(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    captured: dict[str, object] = {}

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **kwargs):
        captured["planner_ui"] = kwargs["planner_ui"]
        captured["b555_dump"] = kwargs["b555_dump"]
        captured["b516_dump"] = kwargs["b516_dump"]
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert captured["planner_ui"] == "disabled"
    assert captured["b555_dump"] is False
    assert captured["b516_dump"] is False


def test_scan_cli_passes_explicit_planner_ui(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    captured: dict[str, object] = {}

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **kwargs):
        captured["planner_ui"] = kwargs["planner_ui"]
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dst",
            "0x15",
            "--planner-ui",
            "auto",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert captured["planner_ui"] == "auto"


def test_scan_cli_passes_b555_dump_flag(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    captured: dict[str, object] = {}

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **kwargs):
        captured["b555_dump"] = kwargs["b555_dump"]
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dst",
            "0x15",
            "--b555-dump",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert captured["b555_dump"] is True


def test_scan_cli_passes_b516_dump_flag(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    captured: dict[str, object] = {}

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **kwargs):
        captured["b516_dump"] = kwargs["b516_dump"]
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dst",
            "0x15",
            "--b516-dump",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert captured["b516_dump"] is True


def test_scan_cli_missing_textual_browse_falls_back_to_html_and_summary(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **_kwargs):
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    def _fake_browse(*_args, **_kwargs):
        exc = ModuleNotFoundError("No module named 'textual'")
        exc.name = "textual"
        raise exc

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)
    monkeypatch.setattr(cli_mod, "_can_launch_interactive_browse", lambda _console: True)
    monkeypatch.setattr(cli_mod, "run_browse_from_artifact", _fake_browse)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    output_path = Path(result.stdout.strip())
    assert output_path.exists()
    assert output_path.with_suffix(".html").exists()
    assert "missing 'textual'" in result.stderr
    assert "Scan Summary" in result.stderr
    assert str(output_path) in result.stdout


def test_scan_persists_identity_metadata_in_artifact(monkeypatch, tmp_path: Path) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    class _OkTransport:
        @contextmanager
        def session(self):
            yield self

    def _fake_build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = settings
        _ = trace_file
        return _OkTransport()

    @contextmanager
    def _fake_observer(*_args, **_kwargs):
        yield None

    def _fake_scan_vrc(*_args, **_kwargs):
        return {
            "meta": {
                "scan_timestamp": "2026-02-13T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "groups": {},
        }

    identity = {
        "device": (
            "Wireless 720-series Regulator *BA*se *S*tation *V*aillant-branded Revision *2* (BASV2)"
        ),
        "model": "Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148",
        "serial": "21213400202621480000000001N7",
        "firmware": "SW 0507 / HW 1704",
    }

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: dict(identity))
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    output_path = Path(result.stdout.strip())
    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    meta = artifact.get("meta", {})
    assert meta.get("identity") == identity
    assert meta.get("resolved_identity") == identity


def test_discover_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["discover", "--help"])
    assert result.exit_code == 0


def test_browse_command_is_present() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["browse", "--help"])
    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", result.stdout)
    assert "--file" in plain
    assert "--live" in plain
    assert "--allow-write" in plain


def test_browse_requires_file_when_not_live() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["browse"])
    assert result.exit_code == 2
    assert "Missing required option: --file <artifact.json>." in result.stderr


def test_browse_non_tty_falls_back_to_summary(tmp_path: Path) -> None:
    artifact_path = tmp_path / "artifact.json"
    artifact_path.write_text(
        json.dumps(
            {
                "meta": {
                    "scan_timestamp": "2026-02-11T12:00:00Z",
                    "destination_address": "0x15",
                    "incomplete": False,
                },
                "groups": {},
            }
        ),
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(app, ["browse", "--file", str(artifact_path)])
    assert result.exit_code == 0
    assert "Browse UI requires a TTY terminal." in result.stderr


def test_scan_dry_run_writes_scan_artifact(tmp_path: Path) -> None:
    map_path = tmp_path / "myvaillant_register_map.csv"
    map_path.write_text(
        "group,instance,register,leaf\n0x03,0x00,0x000F,current_room_temperature\n",
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
            "--myvaillant-map-path",
            str(map_path),
        ],
    )
    assert result.exit_code == 0

    output_path = Path(result.stdout.strip())
    assert output_path.exists()
    assert output_path.with_suffix(".html").exists()

    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    assert isinstance(artifact, dict)
    assert "meta" in artifact
    assert "groups" in artifact
    assert isinstance(artifact["groups"], dict)

    # myVaillant mapping is loaded when a CSV path is provided (even in --dry-run mode).
    schema_sources = artifact.get("meta", {}).get("schema_sources")
    assert isinstance(schema_sources, list)
    assert "myvaillant_map:myvaillant_register_map.csv" in schema_sources

    raw_hex_values: list[str] = []
    for group in artifact["groups"].values():
        if not isinstance(group, dict):
            continue
        instances = group.get("instances", {})
        if not isinstance(instances, dict):
            continue
        for instance in instances.values():
            if not isinstance(instance, dict):
                continue
            registers = instance.get("registers", {})
            if not isinstance(registers, dict):
                continue
            for register in registers.values():
                if not isinstance(register, dict):
                    continue
                raw_hex = register.get("raw_hex")
                if isinstance(raw_hex, str):
                    raw_hex_values.append(raw_hex)

    assert raw_hex_values
    bytes.fromhex(raw_hex_values[0])


def test_scan_dry_run_loads_default_myvaillant_mapping(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0

    output_path = Path(result.stdout.strip())
    artifact = json.loads(output_path.read_text(encoding="utf-8"))
    schema_sources = artifact.get("meta", {}).get("schema_sources")
    assert isinstance(schema_sources, list)
    assert "myvaillant_map:myvaillant_register_map.csv" in schema_sources


def test_default_dry_run_fixture_is_bundled() -> None:
    fixture_text, fixture_source = _load_default_dry_run_fixture_text()
    assert fixture_text is not None
    assert fixture_source == "packaged:vrc720_full_scan.json"


def test_default_ebus_model_name_map_includes_basv2() -> None:
    names = _load_ebus_model_name_map()
    assert (
        names["BASV2"]
        == "Wireless 720-series Regulator *BA*se *S*tation *V*aillant-branded Revision *2*"
    )


def test_format_fw() -> None:
    assert _format_fw("0507", "1704") == "SW 0507 / HW 1704"
    assert _format_fw("", "") == "n/a"
    assert _format_fw("0507", "") == "SW 0507 / HW n/a"


def test_build_scan_session_preface() -> None:
    preface = _build_scan_session_preface(
        dst=0x15,
        endpoint="127.0.0.1:8888",
        identity={
            "device": "VRC 720f/2 (BASV2)",
            "model": "Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148",
            "serial": "21213400202621480000000001N7",
            "firmware": "SW 0507 / HW 1704",
        },
    )
    assert preface.app_line == f"helianthus-vrc-explorer v{__version__}"
    assert preface.scan_line == "Scanning VRC Regulator (B524) at address 0x15"
    assert ("Device", "VRC 720f/2 (BASV2)") in preface.rows
    assert ("ebusd", "127.0.0.1:8888") in preface.rows


class _FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, bytes]] = []

    def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
        self.calls.append((primary, secondary, payload))
        if (primary, secondary) == (0x07, 0x04):
            return bytes.fromhex("b556524320373230662f3205071704")
        qq = payload[0] if payload else 0
        chunks = {
            0x24: b"\x0021213400",
            0x25: b"\x0020262148",
            0x26: b"\x0000000000",
            0x27: b"\x0001N7    ",
        }
        return chunks[qq]


class _FakeTransportBasv:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, bytes]] = []

    def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
        self.calls.append((primary, secondary, payload))
        if (primary, secondary) == (0x07, 0x04):
            return bytes.fromhex("b5424153563205071704")
        qq = payload[0] if payload else 0
        chunks = {
            0x24: b"\x0021213400",
            0x25: b"\x0020262148",
            0x26: b"\x0000000000",
            0x27: b"\x0001N7    ",
        }
        return chunks[qq]


class _AutoResolveTransport:
    def __init__(
        self,
        *,
        info_lines: list[str],
        ident_payloads: dict[int, bytes | list[bytes | Exception]],
        descriptors: dict[int, bytes],
    ) -> None:
        self._info_lines = info_lines
        self._ident_payloads = ident_payloads
        self._descriptors = descriptors
        self.info_calls = 0
        self.send_proto_calls = 0
        self.send_calls = 0

    def command_lines(self, command: str, *, read_all: bool = False) -> list[str]:
        assert command == "info"
        assert read_all is True
        self.info_calls += 1
        return list(self._info_lines)

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        self.send_proto_calls += 1
        if (dst, primary, secondary) == (0xFE, 0x07, 0xFE):
            assert expect_response is False
            return b""
        assert (primary, secondary) == (0x07, 0x04)
        response = self._ident_payloads[dst]
        if isinstance(response, list):
            assert response, "test setup error: empty ident payload sequence"
            next_response = response.pop(0)
            if isinstance(next_response, Exception):
                raise next_response
            return next_response
        if isinstance(response, Exception):
            raise response
        return response

    def send(self, dst: int, payload: bytes) -> bytes:
        self.send_calls += 1
        return self._descriptors[dst]


def test_probe_scan_identity() -> None:
    identity = _probe_scan_identity(_FakeTransport(), dst=0x15)  # type: ignore[arg-type]
    assert identity["device"] == "VRC 720f/2"
    assert identity["model"] == "Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148"
    assert identity["serial"] == "21213400202621480000000001N7"
    assert identity["firmware"] == "SW 0507 / HW 1704"


def test_probe_scan_identity_formats_basv2_friendly_name() -> None:
    identity = _probe_scan_identity(_FakeTransportBasv(), dst=0x15)  # type: ignore[arg-type]
    assert (
        identity["device"]
        == "Wireless 720-series Regulator *BA*se *S*tation *V*aillant-branded Revision *2* (BASV2)"
    )
    assert identity["model"] == "Vaillant sensoCOMFORT RF (VRC 720f/2) 0020262148"
    assert identity["serial"] == "21213400202621480000000001N7"


def test_resolve_scan_destination_explicit_skips_autodiscovery() -> None:
    transport = _AutoResolveTransport(
        info_lines=[],
        ident_payloads={},
        descriptors={},
    )
    assert _resolve_scan_destination(transport, dst="0x15") == 0x15
    assert transport.info_calls == 0
    assert transport.send_proto_calls == 0
    assert transport.send_calls == 0


def test_resolve_scan_destination_auto_prefers_0x15() -> None:
    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    descriptor = struct.pack("<f", 3.0)
    transport = _AutoResolveTransport(
        info_lines=[
            f"address 30: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ",
            f"address 15: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ",
        ],
        ident_payloads={
            0x30: vaillant_ident,
            0x15: vaillant_ident,
        },
        descriptors={
            0x30: descriptor,
            0x15: descriptor,
        },
    )
    assert _resolve_scan_destination(transport, dst="auto") == 0x15


def test_resolve_scan_destination_auto_picks_lowest_compatible_non_0x15() -> None:
    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    descriptor = struct.pack("<f", 3.0)
    transport = _AutoResolveTransport(
        info_lines=[
            f"address 30: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ",
            f"address 08: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ",
        ],
        ident_payloads={
            0x30: vaillant_ident,
            0x08: vaillant_ident,
        },
        descriptors={
            0x30: descriptor,
            0x08: descriptor,
        },
    )
    assert _resolve_scan_destination(transport, dst="auto") == 0x08


def test_resolve_scan_destination_auto_errors_when_no_compatible_target() -> None:
    # Non-Vaillant 0704 payload (manufacturer byte != 0xB5).
    non_vaillant_ident = bytes.fromhex("105652432d4e4f5001020304")
    transport = _AutoResolveTransport(
        info_lines=[f"address 08: {_ROLE_TARGET_TOKEN}, scanned device"],
        ident_payloads={0x08: non_vaillant_ident},
        descriptors={0x08: struct.pack("<f", 3.0)},
    )
    with pytest.raises(typer.Exit) as exc:
        _resolve_scan_destination(transport, dst="auto")
    assert exc.value.exit_code == 2


def test_resolve_scan_destination_auto_retries_0704_probe_once() -> None:
    from helianthus_vrc_explorer.transport.base import TransportTimeout

    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    descriptor = struct.pack("<f", 3.0)
    transport = _AutoResolveTransport(
        info_lines=[f"address 15: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ"],
        ident_payloads={
            0x15: [
                TransportTimeout("transient timeout"),
                vaillant_ident,
            ]
        },
        descriptors={0x15: descriptor},
    )
    assert _resolve_scan_destination(transport, dst="auto") == 0x15
    # 1 wake-up + 2 probe attempts.
    assert transport.send_proto_calls == 3


def test_probe_group_descriptor_returns_zero() -> None:
    transport = _AutoResolveTransport(
        info_lines=[],
        ident_payloads={},
        descriptors={0x15: struct.pack("<f", 0.0)},
    )

    assert _probe_group_descriptor(transport, dst=0x15, group=0x00) == 0.0


def test_resolve_scan_destination_accepts_zero_descriptor() -> None:
    vaillant_ident = bytes.fromhex("b556524320373230662f3205071704")
    transport = _AutoResolveTransport(
        info_lines=[f"address 15: {_ROLE_TARGET_TOKEN}, scanned Vaillant;XYZ"],
        ident_payloads={0x15: vaillant_ident},
        descriptors={0x15: struct.pack("<f", 0.0)},
    )

    assert _resolve_scan_destination(transport, dst="auto") == 0x15
