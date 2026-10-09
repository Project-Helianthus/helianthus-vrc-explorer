from __future__ import annotations

import threading
from pathlib import Path

import pytest

from helianthus_vrc_explorer.scanner.browser_session import (
    BrowserSession,
    BrowserTransportConfig,
    create_browser_transport,
)
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpTransport
from helianthus_vrc_explorer.transport.enhanced_tcp import EnhancedTcpTransport


class RecordingTransport(TransportInterface):
    def __init__(self) -> None:
        self.events: list[tuple[str, int]] = []
        self.release = threading.Event()
        self.first_started = threading.Event()
        self.closed = False

    def send(self, dst: int, payload: bytes) -> bytes:
        return b""

    def close(self) -> None:
        self.closed = True


def test_browser_session_serializes_work_on_one_worker_without_blocking_submitter() -> None:
    transport = RecordingTransport()
    session = BrowserSession(transport)

    def first(inner: RecordingTransport) -> str:
        inner.events.append(("first-start", threading.get_ident()))
        inner.first_started.set()
        inner.release.wait(timeout=2)
        inner.events.append(("first-end", threading.get_ident()))
        return "one"

    def second(inner: RecordingTransport) -> str:
        inner.events.append(("second", threading.get_ident()))
        return "two"

    first_future = session.submit(first)
    assert transport.first_started.wait(timeout=1)
    second_future = session.submit(second)
    assert not second_future.done()
    transport.release.set()
    assert first_future.result(timeout=2) == "one"
    assert second_future.result(timeout=2) == "two"
    session.close()

    assert [name for name, _ in transport.events] == ["first-start", "first-end", "second"]
    assert len({thread_id for _, thread_id in transport.events}) == 1
    assert transport.closed is True


def test_transport_factory_maps_browser_fields_to_existing_transports(tmp_path: Path) -> None:
    tcp = create_browser_transport(
        BrowserTransportConfig(
            kind="tcp",
            host="127.0.0.1",
            port=8888,
            source=0x31,
            destination=0x15,
            timeout_s=1.5,
            trace_path=tmp_path / "tcp.log",
        )
    )
    ens = create_browser_transport(
        BrowserTransportConfig(
            kind="ens",
            host="127.0.0.1",
            port=9999,
            source=0xF7,
            destination=0x15,
            timeout_s=2.0,
            trace_path=tmp_path / "ens.log",
        )
    )
    assert isinstance(tcp, EbusdTcpTransport)
    assert isinstance(ens, EnhancedTcpTransport)
    assert tcp._config.src == 0x31
    assert ens._config.src == 0xF7


def test_tcp_keeps_daemon_source_and_ens_requires_explicit_source() -> None:
    config = BrowserTransportConfig(
        kind="tcp", host="127.0.0.1", port=8888, source=None, destination=0x15
    )
    transport = create_browser_transport(config)
    assert isinstance(transport, EbusdTcpTransport)
    assert transport._config.src is None
    with pytest.raises(ValueError, match="source"):
        BrowserTransportConfig(
            kind="ens", host="127.0.0.1", port=9999, source=None, destination=0x15
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (("port", 0), ("source", 0x100), ("destination", 0xA9), ("timeout_s", 0.0)),
)
def test_transport_config_rejects_ambiguous_or_invalid_coordinates(field, value) -> None:
    values = {
        "kind": "tcp",
        "host": "127.0.0.1",
        "port": 8888,
        "source": 0x31,
        "destination": 0x15,
        "timeout_s": 1.0,
    }
    values[field] = value
    with pytest.raises((TypeError, ValueError)):
        BrowserTransportConfig(**values)
