from __future__ import annotations

import socketserver
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from queue import Queue

import pytest

from helianthus_vrc_explorer.transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportTimeout,
    emit_trace_label,
)
from helianthus_vrc_explorer.transport.ebusd_tcp import (
    EbusdTcpConfig,
    EbusdTcpTransport,
    _parse_ebusd_info_lines,
    _parse_ebusd_response_lines,
)
from helianthus_vrc_explorer.transport.instrumented import CountingTransport


@dataclass(frozen=True)
class _EbusdTestServerResponse:
    lines: list[str]
    send_terminator: bool = True
    keep_open: bool = False


@contextmanager
def _run_ebusd_test_server(
    responses: list[list[str] | None | _EbusdTestServerResponse],
) -> Iterator[tuple[str, int, list[str]]]:
    """Run a local TCP server that mimics ebusd's command port framing.

    Each connection consumes one entry from `responses`:
    - `list[str]`: response lines (without terminators). A blank line terminator is added.
    - `_EbusdTestServerResponse`: response lines with configurable framing/connection behavior.
    - `None`: accept the command but keep the socket open without responding
      (useful for socket-timeout tests).
    """

    commands: list[str] = []
    queue: Queue[list[str] | None | _EbusdTestServerResponse] = Queue()
    for response in responses:
        queue.put(response)

    stop_event = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver signature
            cmd = self.rfile.readline().decode("ascii", errors="replace").rstrip("\r\n")
            commands.append(cmd)

            response = queue.get_nowait()
            if response is None:
                # Keep connection open without responding so the client hits its socket timeout.
                stop_event.wait(timeout=5)
                return

            keep_open = False
            send_terminator = True
            lines = response
            if isinstance(response, _EbusdTestServerResponse):
                keep_open = response.keep_open
                send_terminator = response.send_terminator
                lines = response.lines

            for line in lines:
                self.wfile.write(line.encode("ascii") + b"\n")
            if send_terminator:
                self.wfile.write(b"\n")
            self.wfile.flush()
            if keep_open:
                stop_event.wait(timeout=5)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port, commands
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


@contextmanager
def _run_ebusd_test_server_multi_command(
    responses: list[list[str] | None | _EbusdTestServerResponse],
) -> Iterator[tuple[str, int, list[str], list[int]]]:
    """Run a local TCP server that supports multiple commands per connection."""

    commands: list[str] = []
    connections: list[int] = []
    queue: Queue[list[str] | None | _EbusdTestServerResponse] = Queue()
    for response in responses:
        queue.put(response)

    stop_event = threading.Event()

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver signature
            connections.append(1)
            while True:
                raw_cmd = self.rfile.readline()
                if not raw_cmd:
                    return
                cmd = raw_cmd.decode("ascii", errors="replace").rstrip("\r\n")
                if cmd == "":
                    continue
                commands.append(cmd)

                response = queue.get_nowait()
                if response is None:
                    # Keep connection open without responding so the client hits its socket timeout.
                    stop_event.wait(timeout=5)
                    return

                send_terminator = True
                lines = response
                if isinstance(response, _EbusdTestServerResponse):
                    send_terminator = response.send_terminator
                    lines = response.lines

                for line in lines:
                    self.wfile.write(line.encode("ascii") + b"\n")
                if send_terminator:
                    self.wfile.write(b"\n")
                self.wfile.flush()

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port, commands, connections
    finally:
        stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_parse_ebusd_response_lines_returns_first_hex_payload_line() -> None:
    lines = [
        "010203",
        "ERR: some trailing noise",
    ]
    assert _parse_ebusd_response_lines(lines) == bytes.fromhex("010203")


@pytest.mark.parametrize("line", ["ERR: timeout", "ERR: timed out", "ERR: no answer"])
def test_parse_ebusd_response_lines_timeout_errors_raise_transport_timeout(line: str) -> None:
    with pytest.raises(TransportTimeout, match=r"ERR:"):
        _parse_ebusd_response_lines([line])


def test_parse_ebusd_response_lines_command_not_enabled_raises() -> None:
    with pytest.raises(TransportCommandNotEnabled, match=r"command not enabled"):
        _parse_ebusd_response_lines(["ERR: command not enabled"])


def test_transport_send_parses_multiline_response_and_ignores_trailing_err() -> None:
    with _run_ebusd_test_server([["010203", "ERR: timeout"]]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00"]


def test_trace_labels_are_emitted_before_send_lines(tmp_path: Path) -> None:
    trace_path = tmp_path / "ebusd-trace.log"
    with _run_ebusd_test_server([["010203"]]) as (host, port, _commands):
        transport = EbusdTcpTransport(
            EbusdTcpConfig(host=host, port=port, timeout_s=0.5, trace_path=trace_path)
        )
        wrapped = CountingTransport(transport)
        emit_trace_label(wrapped, "Discovering Groups")
        wrapped.send(0x15, bytes.fromhex("020002000F00"))

    text = trace_path.read_text(encoding="utf-8")
    op_index = text.find("OP Discovering Groups")
    send_index = text.find("SEND attempt_payload=")
    assert op_index != -1
    assert send_index != -1
    assert op_index < send_index


def test_transport_send_retries_timeout_once_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    with _run_ebusd_test_server([["ERR: timeout"], ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00", "hex 15B52406020002000F00"]
    assert sleep_calls == [5.0]


def test_transport_send_timeout_retries_exhaust_after_five_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([["ERR: timeout"] for _ in range(6)]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        with pytest.raises(TransportTimeout, match=r"timeout retries exhausted"):
            transport.send(0x15, payload)

    assert commands == ["hex 15B52406020002000F00"] * 6
    assert sleep_calls == [5.0] * 5


@pytest.mark.parametrize(
    "err_line",
    ["ERR: arbitration lost", "ERR: SYN received", "ERR: wrong symbol received"],
)
def test_transport_send_retries_retryable_transport_errors_once_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    err_line: str,
) -> None:
    with _run_ebusd_test_server([[err_line], ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00", "hex 15B52406020002000F00"]
    assert sleep_calls == [5.0]


def test_transport_send_retries_socket_timeout_once_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([None, ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.05))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00", "hex 15B52406020002000F00"]
    assert sleep_calls == []


def test_transport_send_polls_no_signal_then_recovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([["ERR: no signal"], ["010203"]]) as (
        host,
        port,
        commands,
    ):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00", "hex 15B52406020002000F00"]
    assert sleep_calls == [15.0]


def test_transport_send_no_signal_backoff_exhausts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([["ERR: no signal"]] * 2) as (host, port, commands):
        sleep_calls: list[float] = []
        now = {"t": 0.0}

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)
            now["t"] += seconds

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        monkeypatch.setattr(ebusd_tcp.time, "monotonic", lambda: now["t"])
        transport = EbusdTcpTransport(
            EbusdTcpConfig(
                host=host,
                port=port,
                timeout_s=0.5,
                no_signal_max_s=15.0,
                no_signal_poll_ms=200,
            )
        )
        payload = bytes.fromhex("020002000F00")
        with pytest.raises(TransportError, match=r"no-signal polling exceeded 15.0s"):
            transport.send(0x15, payload)

    assert commands == ["hex 15B52406020002000F00"] * 2
    assert sleep_calls == [15.0]


def test_parse_ebusd_info_lines_scans_all_lines_for_errors() -> None:
    with pytest.raises(TransportError, match=r"ERR: no signal"):
        _parse_ebusd_info_lines(["signal: acquired", "ERR: no signal"])


def test_transport_session_depth_is_restored_when_open_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = EbusdTcpTransport(EbusdTcpConfig(host="127.0.0.1", port=9, timeout_s=0.01))

    def _fail_open() -> None:
        raise TransportError("forced open failure")

    monkeypatch.setattr(transport, "_open_session", _fail_open)

    with pytest.raises(TransportError, match="forced open failure"), transport.session():
        pass

    assert transport._session_depth == 0


def test_transport_send_does_not_timeout_if_ebusd_keeps_socket_open_after_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

    monkeypatch.setattr(ebusd_tcp.time, "sleep", lambda _seconds: None)
    response = _EbusdTestServerResponse(
        lines=["010203"],
        send_terminator=False,
        keep_open=True,
    )
    with _run_ebusd_test_server([response, response]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.05))
        payload = bytes.fromhex("020002000F00")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00"]


def test_transport_send_strips_length_prefix_from_hex_response() -> None:
    with _run_ebusd_test_server([["040000803F"]]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("000000")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("0000803F")
    assert commands == ["hex 15B52403000000"]


def test_transport_send_strips_length_prefix_from_short_hex_response() -> None:
    # Some ebusd replies are status-only (1 byte). When returned via the `hex` command they may
    # still carry the leading length byte (0x01). Ensure we strip it.
    with _run_ebusd_test_server([["0100"]]) as (host, port, commands):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("000000")
        result = transport.send(0x15, payload)

    assert result == bytes.fromhex("00")
    assert commands == ["hex 15B52403000000"]


def test_transport_session_reuses_single_connection_for_multiple_sends() -> None:
    with _run_ebusd_test_server_multi_command([["010203"], ["040506"]]) as (
        host,
        port,
        commands,
        connections,
    ):
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload_1 = bytes.fromhex("020002000F00")
        payload_2 = bytes.fromhex("020002001000")
        with transport.session():
            result_1 = transport.send(0x15, payload_1)
            result_2 = transport.send(0x15, payload_2)

    assert result_1 == bytes.fromhex("010203")
    assert result_2 == bytes.fromhex("040506")
    assert len(connections) == 1
    assert commands == [
        "hex 15B52406020002000F00",
        "hex 15B52406020002001000",
    ]


def test_transport_session_reconnects_on_socket_timeout_once_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _run_ebusd_test_server([None, ["010203"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.05))
        payload = bytes.fromhex("020002000F00")
        with transport.session():
            result = transport.send(0x15, payload)

    assert result == bytes.fromhex("010203")
    assert commands == ["hex 15B52406020002000F00", "hex 15B52406020002000F00"]
    assert sleep_calls == []


def test_transport_send_collision_retries_exhaust(monkeypatch: pytest.MonkeyPatch) -> None:
    err = "ERR: SYN received"
    with _run_ebusd_test_server([[err] for _ in range(6)]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        payload = bytes.fromhex("020002000F00")
        with pytest.raises(TransportError, match=r"collision retries exhausted"):
            transport.send(0x15, payload)

    assert commands == ["hex 15B52406020002000F00"] * 6
    assert sleep_calls == [5.0] * 5


def test_transport_send_respects_max_command_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    with _run_ebusd_test_server([["ERR: no signal"]] * 10) as (host, port, _commands):
        now = {"t": 0.0}

        def _sleep(seconds: float) -> None:
            now["t"] += seconds

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        monkeypatch.setattr(ebusd_tcp.time, "monotonic", lambda: now["t"])
        transport = EbusdTcpTransport(
            EbusdTcpConfig(
                host=host,
                port=port,
                timeout_s=0.5,
                no_signal_max_s=15.0,
                no_signal_poll_ms=200,
                max_command_s=0.5,
            )
        )
        payload = bytes.fromhex("020002000F00")
        with pytest.raises(TransportTimeout, match=r"Command exceeded 0.5s retry budget"):
            transport.send(0x15, payload)


def test_transport_send_proto_uses_retry_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    with _run_ebusd_test_server([["ERR: timeout"], ["0100"]]) as (host, port, commands):
        sleep_calls: list[float] = []

        def _sleep(seconds: float) -> None:
            sleep_calls.append(seconds)

        import helianthus_vrc_explorer.transport.ebusd_tcp as ebusd_tcp

        monkeypatch.setattr(ebusd_tcp.time, "sleep", _sleep)
        transport = EbusdTcpTransport(EbusdTcpConfig(host=host, port=port, timeout_s=0.5))
        result = transport.send_proto(0x15, 0x07, 0x04, b"")

    assert result == bytes.fromhex("00")
    assert commands == ["hex 15070400", "hex 15070400"]
    assert sleep_calls == [5.0]
