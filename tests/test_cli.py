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
from helianthus_vrc_explorer.transport.base import TransportNack, TransportTimeout
from helianthus_vrc_explorer.ui.scan_setup import ScanSetup

_ROLE_TARGET_TOKEN = bytes.fromhex("736c617665").decode("ascii")


@pytest.fixture(autouse=True)
def _ui_owned_scan_and_browse_setup(monkeypatch: pytest.MonkeyPatch):
    """Translate legacy test inputs into the visual setup seam.

    Tests retain their scenario values while public command invocation exercises
    only its adapter arguments and optional preset.
    """
    import helianthus_vrc_explorer.cli as cli

    original_invoke = CliRunner.invoke

    def wrapped(runner, cli_app, args=None, *extra, **kwargs):  # noqa: ANN001
        argv = list(args or [])
        if cli_app is not app or not argv or argv[0] not in {"scan", "browse"}:
            return original_invoke(runner, cli_app, argv, *extra, **kwargs)
        if "--help" in argv or "-h" in argv:
            return original_invoke(runner, cli_app, argv, *extra, **kwargs)
        if argv[0] == "browse":
            selected = None
            if "--file" in argv:
                selected = Path(argv[argv.index("--file") + 1])
            monkeypatch.setattr(cli, "run_artifact_open_modal", lambda: selected)
            return original_invoke(runner, cli_app, ["browse"], *extra, **kwargs)

        setup_values: dict[str, object] = {"preset": "recommended", "planner_ui": "disabled"}
        public = ["scan"]
        index = 1
        value_options = {
            "--dst": "dst",
            "--output-dir": "output_dir",
            "--ebusd-csv-path": "ebusd_csv_path",
            "--myvaillant-map-path": "myvaillant_map_path",
            "--trace-file": "trace_file",
            "--planner-ui": "planner_ui",
            "--b509-range": "b509_range",
        }
        adapter_options = {"--transport", "--host", "--port", "--source-address", "--preset"}
        while index < len(argv):
            option = argv[index]
            if option in adapter_options:
                public.extend((option, argv[index + 1]))
                if option == "--preset":
                    setup_values["preset"] = argv[index + 1]
                index += 2
            elif option in value_options:
                field = value_options[option]
                value = argv[index + 1]
                if field in {"output_dir", "ebusd_csv_path", "myvaillant_map_path", "trace_file"}:
                    value = Path(value)
                if field == "b509_range":
                    value = [value]
                setup_values[field] = value
                index += 2
            elif option in {
                "--dry-run",
                "--b509-dump",
                "--b555-dump",
                "--b516-dump",
                "--no-tips",
                "--redact",
            }:
                setup_values[option[2:].replace("-", "_")] = True
                index += 1
            elif option.startswith("--no-"):
                setup_values[option[5:].replace("-", "_")] = False
                index += 1
            else:
                index += 1
        selected = ScanSetup(**setup_values)
        monkeypatch.setattr(cli, "_collect_scan_setup", lambda _preset, _transport: selected)
        return original_invoke(runner, cli_app, public, *extra, **kwargs)

    monkeypatch.setattr(CliRunner, "invoke", wrapped)


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
    for option in ("--transport", "--host", "--port", "--source-address", "--preset"):
        assert option in plain
    for removed in ("planner-ui", "no-tips", "--dst", "--dry-run", "--output-dir"):
        assert removed not in plain


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


def test_scan_custom_transport_failure_can_prompt_retry_and_cancel(
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
    assert prompt_called["value"] is True
    assert "Transport setup aborted by user." in result.stderr


@pytest.mark.parametrize(
    "error",
    [
        pytest.param(TimeoutError("ENS socket connect timed out"), id="timeout"),
        pytest.param(ConnectionRefusedError("ENS connection refused"), id="refused"),
        pytest.param(ConnectionAbortedError("ENS connection rejected"), id="rejected"),
    ],
)
def test_scan_ens_startup_failure_non_tty_exits_concisely(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    error: OSError,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    class _FailingEnsTransport:
        @contextmanager
        def session(self):
            from helianthus_vrc_explorer.transport.base import TransportError, TransportTimeout

            if isinstance(error, TimeoutError):
                raise TransportTimeout(str(error))
            raise TransportError(str(error))
            yield self  # pragma: no cover - explicit startup failure

    def _build_transport(settings, *, trace_file):  # noqa: ANN001
        _ = trace_file
        assert settings.protocol == "enhanced"
        return _FailingEnsTransport()

    monkeypatch.setattr(cli_mod, "_build_transport", _build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: False)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--transport",
            "ens",
            "--host",
            "192.0.2.2",
            "--dst",
            "0x15",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert f"Transport setup failed: {error}" in result.stderr
    assert "Traceback" not in result.output


def test_scan_ens_startup_failure_tty_cancel_exits_without_retry_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod

    def _build_transport(_settings, *, trace_file):  # noqa: ANN001
        _ = trace_file
        return _SessionOnlyTransport(fail_open=True)

    prompt_calls = 0

    def _cancel(_console, *, settings, error_message):  # noqa: ANN001
        nonlocal prompt_calls
        prompt_calls += 1
        assert settings.protocol == "enhanced"
        assert "refused" in error_message
        return None

    monkeypatch.setattr(cli_mod, "_build_transport", _build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: True)
    monkeypatch.setattr(cli_mod, "_prompt_transport_retry_settings", _cancel)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--transport",
            "ens",
            "--host",
            "192.0.2.2",
            "--dst",
            "0x15",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 1
    assert prompt_calls == 1
    assert "Transport setup aborted by user." in result.stderr


def test_scan_runtime_transport_failure_does_not_restart_scan(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import helianthus_vrc_explorer.cli as cli_mod
    from helianthus_vrc_explorer.transport.base import TransportTimeout

    class _ReadyTransport:
        @contextmanager
        def session(self):
            yield self

    builds = 0
    prompt_calls = 0

    def _build_transport(_settings, *, trace_file):  # noqa: ANN001
        nonlocal builds
        _ = trace_file
        builds += 1
        return _ReadyTransport()

    def _prompt(*_args, **_kwargs):  # noqa: ANN002, ANN003
        nonlocal prompt_calls
        prompt_calls += 1
        return None

    def _runtime_timeout(*_args, **_kwargs):  # noqa: ANN002, ANN003
        raise TransportTimeout("runtime timeout")

    monkeypatch.setattr(cli_mod, "_build_transport", _build_transport)
    monkeypatch.setattr(cli_mod, "_can_prompt_transport_retry", lambda _console: True)
    monkeypatch.setattr(cli_mod, "_prompt_transport_retry_settings", _prompt)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "scan_vrc", _runtime_timeout)

    result = CliRunner().invoke(app, ["scan", "--dst", "0x15", "--output-dir", str(tmp_path)])

    assert result.exit_code == 1
    assert builds == 1
    assert prompt_calls == 0


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


def test_scan_emits_pre_identification_status_during_auto_detection(
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

    monkeypatch.setattr(cli_mod, "_build_transport", _fake_build_transport)
    monkeypatch.setattr(cli_mod, "_resolve_scan_destination", lambda _transport, dst: 0x15)
    monkeypatch.setattr(cli_mod, "_probe_scan_identity", lambda _transport, *, dst: {})
    monkeypatch.setattr(cli_mod, "make_scan_observer", _fake_observer)
    monkeypatch.setattr(cli_mod, "scan_vrc", _fake_scan_vrc)

    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--output-dir", str(tmp_path)])

    assert result.exit_code == 0
    plain = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", result.stderr)
    assert "[scan] Opening TCP transport to 127.0.0.1:8888" in plain
    assert "[scan] Resolving destination address from ebusd" in plain
    assert "[scan] Resolved destination to 0x15" in plain
    assert "[scan] Probing regulator identity at 0x15" in plain


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


def test_scan_cli_b509_is_disabled_by_default(monkeypatch, tmp_path: Path) -> None:
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
        captured["b509_dump"] = kwargs["b509_dump"]
        captured["b509_ranges"] = kwargs["b509_ranges"]
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
    assert captured["b509_dump"] is False
    assert captured["b509_ranges"] == []


def test_scan_cli_b509_range_requires_b509_dump(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dst",
            "0x15",
            "--b509-range",
            "0x0000..0x0001",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 2
    assert "B509 ranges require enabling the B509 dump in scan setup." in result.stderr


def test_scan_cli_b509_range_requires_b509_dump_in_dry_run(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            "--dry-run",
            "--b509-range",
            "0x0000..0x0001",
            "--output-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 2
    assert "B509 ranges require enabling the B509 dump in scan setup." in result.stderr


def test_scan_cli_passes_b509_dump_and_ranges(monkeypatch, tmp_path: Path) -> None:
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
        captured["b509_dump"] = kwargs["b509_dump"]
        captured["b509_ranges"] = kwargs["b509_ranges"]
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
            "--b509-dump",
            "--b509-range",
            "0x0000..0x0001",
            "--output-dir",
            str(tmp_path),
        ],
    )
    assert result.exit_code == 0
    assert captured["b509_dump"] is True
    assert captured["b509_ranges"] == [(0x0000, 0x0001)]


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
    assert "--file" not in plain
    assert "--live" not in plain
    assert "--allow-write" not in plain


def test_browse_requires_file_when_not_live() -> None:
    runner = CliRunner()
    result = runner.invoke(app, ["browse"])
    assert result.exit_code == 2
    assert "Browse requires a TTY for the visual file-open dialog." in result.stderr


def test_browse_non_tty_requires_visual_file_open_dialog(tmp_path: Path) -> None:
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
    result = runner.invoke(app, ["browse"])
    assert result.exit_code == 2
    assert "Browse requires a TTY for the visual file-open dialog." in result.stderr


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
    assert "operations" in artifact
    assert isinstance(artifact["operations"], dict)

    # myVaillant mapping is loaded when a CSV path is provided (even in --dry-run mode).
    schema_sources = artifact.get("meta", {}).get("schema_sources")
    assert isinstance(schema_sources, list)
    assert "myvaillant_map:myvaillant_register_map.csv" in schema_sources

    raw_hex_values: list[str] = []
    for op_obj in artifact["operations"].values():
        if not isinstance(op_obj, dict):
            continue
        for group in op_obj.get("groups", {}).values():
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


class _IdentityProbeTransport:
    def __init__(self, *, failure: Exception | None = None, stage: str = "") -> None:
        self._failure = failure
        self._stage = stage

    def send_proto(self, _dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
        if (primary, secondary) == (0x07, 0x04):
            if self._stage == "0704" and self._failure is not None:
                raise self._failure
            return bytes.fromhex("b556524320373230662f3205071704")
        if self._stage == "b509" and self._failure is not None:
            raise self._failure
        return _FakeTransport().send_proto(0x15, primary, secondary, payload)


@pytest.mark.parametrize(
    ("stage", "error"),
    [
        pytest.param("0704", TransportTimeout("socket timeout"), id="0704-timeout"),
        pytest.param("b509", TransportTimeout("socket timeout"), id="b509-timeout"),
    ],
)
def test_probe_scan_identity_propagates_transport_startup_failures(
    stage: str,
    error: Exception,
) -> None:
    transport = _IdentityProbeTransport(failure=error, stage=stage)

    with pytest.raises(TransportTimeout, match="socket timeout"):
        _probe_scan_identity(transport, dst=0x15)  # type: ignore[arg-type]


@pytest.mark.parametrize("stage", ("0704", "b509"))
def test_probe_scan_identity_does_not_mask_unexpected_failures(stage: str) -> None:
    transport = _IdentityProbeTransport(failure=RuntimeError("unexpected preflight"), stage=stage)

    with pytest.raises(RuntimeError, match="unexpected preflight"):
        _probe_scan_identity(transport, dst=0x15)  # type: ignore[arg-type]


def test_probe_scan_identity_keeps_0704_fields_when_b509_chunks_fail_to_parse() -> None:
    class _MalformedScanIdTransport(_IdentityProbeTransport):
        def send_proto(self, dst: int, primary: int, secondary: int, payload: bytes) -> bytes:
            if (primary, secondary) == (0xB5, 0x09):
                return b"\x00"
            return super().send_proto(dst, primary, secondary, payload)

    identity = _probe_scan_identity(_MalformedScanIdTransport(), dst=0x15)  # type: ignore[arg-type]

    assert identity["device"] == "VRC 720f/2"
    assert identity["firmware"] == "SW 0507 / HW 1704"
    assert identity["model"] == "n/a"
    assert identity["serial"] == "n/a"


def test_probe_scan_identity_keeps_0704_fields_when_optional_b509_nacks() -> None:
    identity = _probe_scan_identity(
        _IdentityProbeTransport(failure=TransportNack("nack"), stage="b509"), dst=0x15
    )

    assert identity["device"] == "VRC 720f/2"
    assert identity["firmware"] == "SW 0507 / HW 1704"
    assert identity["model"] == "n/a"
    assert identity["serial"] == "n/a"


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
