from __future__ import annotations

import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Queue

from helianthus_vrc_explorer.transport.base import TransportNack
from helianthus_vrc_explorer.transport.enhanced_tcp import (
    _ENH_REQ_INIT,
    _ENH_REQ_SEND,
    _ENH_REQ_START,
    _ENH_RES_RECEIVED,
    _ENH_RES_RESETTED,
    _ENH_RES_STARTED,
    EnhancedTcpConfig,
    EnhancedTcpTransport,
    _crc,
    _crc_update,
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
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

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
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
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
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

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
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)

    assert result == response


def test_ens_transport_broadcast_does_not_expect_response() -> None:
    src = 0xF1
    dst = 0xFE
    request_without_crc = bytes((src, dst, 0x07, 0xFE, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0xFE, b"", expect_response=False)

    assert result == b""


def test_internal_enhanced_nack_maps_to_transport_nack() -> None:
    from helianthus_vrc_explorer.transport.enhanced_tcp import _EnhancedNack

    assert issubclass(_EnhancedNack, TransportNack)


def test_ve1_send_payload_containing_escape_byte() -> None:
    """VE1/VE20: Verify that 0xA9 (ESCAPE) in payload sends correctly via ENH.

    The enhanced adapter firmware handles wire escape encoding.  The ENH
    SEND command carries logical bytes -- the client must NOT pre-escape.
    """
    src = 0xF1
    dst = 0x15
    # Payload deliberately contains 0xA9 (eBUS escape) and 0xAA (eBUS SYN).
    payload = bytes((0xA9, 0x42, 0xAA))
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        # Adapter receives logical bytes via ENH -- no wire escaping at this layer.
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN (end)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send(dst, payload)

    assert result == response


def test_ve21_response_crc_with_escape_bytes() -> None:
    """VE21/VE25: Verify CRC verification works when response contains 0xA9.

    The _crc() function correctly applies escape expansion to logical bytes
    before CRC computation, matching what the bus slave does.

    Note: 0xAA (SYN) cannot appear as a logical data byte in eBUS responses
    because SYN is the bus frame delimiter.  The escape byte 0xA9 CAN appear
    as logical data (wire-escaped to [0xA9, 0x00] and un-escaped by the
    adapter firmware).
    """
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    # Response deliberately contains 0xA9 (eBUS escape) bytes.
    # 0xA9 triggers CRC escape expansion: logical 0xA9 -> wire [0xA9, 0x00].
    response = bytes((0x01, 0xA9, 0x42, 0xA9, 0x03))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)  # ACK
        # Adapter sends logical (un-escaped) response bytes via ENH RECEIVED.
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN (end)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=0.5, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ve25_crc_escape_expansion_is_correct() -> None:
    """VE25: Verify _crc() correctly handles escape expansion for CRC computation.

    Per eBUS spec, CRC is computed on the wire-expanded form.  Logical 0xA9
    expands to [0xA9, 0x00] and logical 0xAA expands to [0xA9, 0x01].
    """
    # CRC of a single 0xA9 byte = CRC of wire sequence [0xA9, 0x00]
    expected = _crc_update(_crc_update(0, 0xA9), 0x00)
    assert _crc(bytes((0xA9,))) == expected

    # CRC of a single 0xAA byte = CRC of wire sequence [0xA9, 0x01]
    expected_aa = _crc_update(_crc_update(0, 0xA9), 0x01)
    assert _crc(bytes((0xAA,))) == expected_aa

    # Normal bytes pass through unchanged
    expected_42 = _crc_update(0, 0x42)
    assert _crc(bytes((0x42,))) == expected_42

    # Mixed: [0x42, 0xA9, 0x01] -> CRC([0x42, 0xA9, 0x00, 0x01])
    crc = 0
    crc = _crc_update(crc, 0x42)
    crc = _crc_update(crc, 0xA9)
    crc = _crc_update(crc, 0x00)  # escape expansion of 0xA9
    crc = _crc_update(crc, 0x01)
    assert _crc(bytes((0x42, 0xA9, 0x01))) == crc
