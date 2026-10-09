from __future__ import annotations

import contextlib
import socketserver
import threading
from collections.abc import Iterator

import pytest

from helianthus_vrc_explorer.transport.base import TransportTimeout
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport


@contextlib.contextmanager
def _timeout_server(commands: list[str]) -> Iterator[tuple[str, int]]:
    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            line = self.rfile.readline().decode("ascii").strip()
            commands.append(line)
            self.wfile.write(b"ERR: timeout\n\n")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield str(host), int(port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_ebusd_tcp_write_timeout_is_never_resubmitted(monkeypatch) -> None:
    transport = EbusdTcpTransport(
        EbusdTcpConfig(timeout_max_retries=5, collision_max_retries=5, max_command_s=30)
    )
    attempts = 0
    hooks = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise TransportTimeout("uncertain write")

    def hook():
        nonlocal hooks
        hooks += 1

    monkeypatch.setattr(transport, "_send_once", fail_once)
    with pytest.raises(TransportTimeout, match="uncertain write"):
        transport.send_with_attempt_hook(0x15, bytes.fromhex("02010200140005"), hook)
    assert attempts == 1
    assert hooks == 1


def test_ebusd_tcp_socket_observes_exactly_one_write_command_after_uncertain_timeout() -> None:
    commands: list[str] = []
    with _timeout_server(commands) as (host, port):
        transport = EbusdTcpTransport(
            EbusdTcpConfig(
                host=host,
                port=port,
                timeout_s=0.5,
                timeout_max_retries=5,
                collision_max_retries=5,
            )
        )
        with pytest.raises(TransportTimeout):
            transport.send(0x15, bytes.fromhex("02010200140005"))

    assert commands == ["hex 15B5240702010200140005"]
