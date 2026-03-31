from __future__ import annotations

import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Queue

from helianthus_vrc_explorer.transport.ens_tcp import (
    _ENH_REQ_INIT,
    _ENH_REQ_SEND,
    _ENH_REQ_START,
    _ENH_RES_RECEIVED,
    _ENH_RES_RESETTED,
    _ENH_RES_STARTED,
    EnsTcpConfig,
    EnsTcpTransport,
    _crc,
    _encode_enh,
)


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = conn.recv(size - len(chunks))
        if not chunk:
            raise AssertionError("unexpected EOF while waiting for ENH frame")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_enh_frame(conn: socket.socket) -> tuple[int, int]:
    data = _read_exact(conn, 2)
    byte1, byte2 = data
    if byte1 & 0xC0 != 0xC0:
        raise AssertionError(f"invalid ENH frame start 0x{byte1:02X}")
    if byte2 & 0xC0 != 0x80:
        raise AssertionError(f"invalid ENH frame end 0x{byte2:02X}")
    command = (byte1 >> 2) & 0x0F
    payload = ((byte1 & 0x03) << 6) | (byte2 & 0x3F)
    return command, payload


def _write_enh_frame(conn: socket.socket, command: int, data: int) -> None:
    conn.sendall(_encode_enh(command, data))


def _write_bus_symbol(conn: socket.socket, symbol: int) -> None:
    _write_enh_frame(conn, _ENH_RES_RECEIVED, symbol)


@contextmanager
def _run_ens_test_server(
    handler_fn: Callable[[socket.socket], None],
) -> Iterator[tuple[str, int]]:
    errors: Queue[BaseException] = Queue()

    class _Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:  # noqa: D401 - socketserver signature
            try:
                handler_fn(self.request)
            except BaseException as exc:  # pragma: no cover - surfaced after shutdown
                errors.put(exc)
                raise

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
        if not errors.empty():
            raise errors.get()


def test_ens_transport_send_proto_round_trips_identification_request() -> None:
    src = 0xF1
    dst = 0x15
    request = bytes((src, dst, 0x07, 0x04, 0x00, _crc(bytes((src, dst, 0x07, 0x04, 0x00)))))
    response = bytes.fromhex("b556524320373230662f3205071704")
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x00)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x00)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnsTcpTransport(EnsTcpConfig(host=host, port=port, timeout_s=0.5, src=src))
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ens_transport_send_wraps_b524_request() -> None:
    src = 0xF1
    dst = 0x15
    payload = bytes.fromhex("020002000F00")
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01, 0x02, 0x03))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x00)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x00)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnsTcpTransport(EnsTcpConfig(host=host, port=port, timeout_s=0.5, src=src))
        result = transport.send(dst, payload)

    assert result == response


def test_ens_transport_broadcast_does_not_expect_response() -> None:
    src = 0xF1
    dst = 0xFE
    request_without_crc = bytes((src, dst, 0x07, 0xFE, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x00)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x00)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnsTcpTransport(EnsTcpConfig(host=host, port=port, timeout_s=0.5, src=src))
        result = transport.send_proto(dst, 0x07, 0xFE, b"", expect_response=False)

    assert result == b""
