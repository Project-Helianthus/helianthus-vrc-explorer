from __future__ import annotations

import contextlib
import socket
import socketserver
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Queue

from helianthus_vrc_explorer.transport.base import TransportError, TransportNack, TransportTimeout
from helianthus_vrc_explorer.transport.enhanced_tcp import (
    _ENH_REQ_INFO,
    _ENH_REQ_INIT,
    _ENH_REQ_SEND,
    _ENH_REQ_START,
    _ENH_RES_ERROR_EBUS,
    _ENH_RES_ERROR_HOST,
    _ENH_RES_INFO,
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
    # VE9: Non-daemon threads so handler exceptions are visible.
    server.daemon_threads = False

    thread = threading.Thread(target=server.serve_forever, daemon=False)
    thread.start()
    try:
        host, port = server.server_address
        assert isinstance(host, str)
        assert isinstance(port, int)
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
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
    before CRC computation, matching what the bus target does.

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


def test_ve22_concurrent_session_entry() -> None:
    """VE22: _session_depth must be thread-safe under concurrent session() calls."""
    import time as _time

    results: list[bool] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        # Keep connection alive for all threads
        _time.sleep(1.0)

    def _session_user(transport: EnhancedTcpTransport) -> None:
        try:
            with transport.session():
                _time.sleep(0.1)
            results.append(True)
        except Exception:
            results.append(False)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        threads = [threading.Thread(target=_session_user, args=(transport,)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

    # At least some threads should succeed
    assert any(results), f"All threads failed: {results}"


def test_ve17_session_depth_never_negative() -> None:
    """VE17: session depth must never go negative even with spurious close calls."""
    transport = EnhancedTcpTransport(EnhancedTcpConfig(host="127.0.0.1", port=1, timeout_s=0.1))
    # Depth starts at 0, multiple closes must not drive it negative
    transport._session_depth = 0
    transport.close()
    assert transport._session_depth >= 0
    transport.close()
    assert transport._session_depth >= 0


def test_ve15_malformed_enh_byte_no_immediate_close() -> None:
    """VE15: A single malformed ENH byte should not close the transport."""

    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01, 0x02))
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

        # Inject a single malformed byte (0x85 has bit pattern 10xxxxxx — invalid start)
        conn.sendall(bytes((0x85,)))

        # Then send valid response
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)

        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_ve2_host_error_not_retried() -> None:
    """VE2: TransportHostError should propagate without retry."""
    import pytest

    from helianthus_vrc_explorer.transport.base import TransportHostError

    call_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal call_count
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, 0xF7)
        # Respond with host error
        _write_enh_frame(conn, _ENH_RES_ERROR_HOST, 0x01)
        call_count += 1

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=1.0, collision_max_retries=3)
        )
        with pytest.raises(TransportHostError):
            transport.send_proto(0x15, 0x07, 0x04, b"")

    # Should have been called exactly once — no retry
    assert call_count == 1


def test_ve6_src_escape_rejected() -> None:
    """VE6: src=0xA9 (ESCAPE) must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xA9))


def test_ve6_src_syn_rejected() -> None:
    """VE6: src=0xAA (SYN) must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xAA))


def test_ve6_src_zero_rejected() -> None:
    """VE6: src=0x00 must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0x00))


def test_ve6_src_0xff_rejected() -> None:
    """VE6: src=0xFF must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="reserved address"):
        EnhancedTcpTransport(EnhancedTcpConfig(src=0xFF))


def test_ve7_dst_escape_rejected() -> None:
    """VE7: dst=0xA9 (ESCAPE) must be rejected."""
    import pytest

    transport = EnhancedTcpTransport(EnhancedTcpConfig())
    with pytest.raises(ValueError, match="reserved address"):
        transport.send_proto(0xA9, 0x07, 0x04, b"")


def test_ve7_dst_syn_rejected() -> None:
    """VE7: dst=0xAA (SYN) must be rejected."""
    import pytest

    transport = EnhancedTcpTransport(EnhancedTcpConfig())
    with pytest.raises(ValueError, match="reserved address"):
        transport.send_proto(0xAA, 0x07, 0x04, b"")


def test_ve19r2_negative_timeout_rejected() -> None:
    """VE19-R2: timeout_s <= 0 must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=-1.0))


def test_ve19r2_zero_timeout_rejected() -> None:
    """VE19-R2: timeout_s=0 must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=0.0))


def test_ve19r2_nan_timeout_rejected() -> None:
    """VE19-R2: timeout_s=NaN must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="timeout_s"):
        EnhancedTcpTransport(EnhancedTcpConfig(timeout_s=float("nan")))


def test_ve19r2_port_zero_rejected() -> None:
    """VE19-R2: port=0 must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="port"):
        EnhancedTcpTransport(EnhancedTcpConfig(port=0))


def test_ve19r2_port_too_large_rejected() -> None:
    """VE19-R2: port=99999 must be rejected."""
    import pytest

    with pytest.raises(ValueError, match="port"):
        EnhancedTcpTransport(EnhancedTcpConfig(port=99999))


def test_ve4_nack_retry_without_rearbitration() -> None:
    """VE4: After NACK, retry telegram without re-arbitrating."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    start_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal start_count
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        # First (and only) arbitration
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        start_count += 1

        # First telegram send — will be NACKed
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0xFF)  # NACK

        # Local retry — same telegram, NO re-arbitration
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK this time

        # Response
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src, nack_max_retries=1)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response
    assert start_count == 1  # Only ONE arbitration


def test_ve23_timeout_retries_accumulate_across_reconnect() -> None:
    """VE23: timeout_retries must not reset after reconnect."""
    import time as _time

    import pytest

    connect_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal connect_count
        connect_count += 1
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        # Never respond to START — causes timeout
        _time.sleep(5.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=0.3,
                src=0xF1,
                timeout_max_retries=1,
                reconnect_max_retries=1,
                reconnect_delay_s=0.1,
            )
        )
        with pytest.raises((TransportTimeout, TransportError)):
            transport.send_proto(0x15, 0x07, 0x04, b"")

    # With timeout_max_retries=1, reconnect_max_retries=1:
    # Without VE23 fix (timeout reset): would loop indefinitely
    # With VE23 fix: bounded number of connections
    assert connect_count <= 3  # Bounded, not infinite


def test_ve8_cli_default_src() -> None:
    """VE8: CLI default src must match EnhancedTcpConfig default (0xF7)."""
    config = EnhancedTcpConfig()
    assert config.src == 0xF7


# ---------------------------------------------------------------------------
# Adversarial tests added by angry-tester audit
# ---------------------------------------------------------------------------


def test_adv_all_escape_syn_payload() -> None:
    """ADV: Payload where every byte is 0xA9 (ESCAPE) or 0xAA (SYN)."""
    src = 0xF1
    dst = 0x15
    payload = bytes((0xA9, 0xAA, 0xA9, 0xAA))
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


def test_adv_crc_value_is_escape_byte() -> None:
    """ADV: Response CRC value itself is 0xA9 (ESCAPE)."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x32,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    assert response_crc == 0xA9

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


def test_adv_crc_value_is_syn_byte_succeeds() -> None:
    """ADV: Response CRC value 0xAA must succeed (not false-timeout).

    In the ENH protocol, 0xAA from _recv_bus_symbol() is a legitimate
    data byte — the adapter decoded wire-escaped [0xA9, 0x01] back to
    logical 0xAA.  Bus SYN loss is reported via _ENH_RES_FAILED, not
    as a RECEIVED frame with data=0xAA.
    """
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x31,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    assert response_crc == 0xAA  # This CRC is the SYN byte value

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)  # 0xAA — valid CRC byte

        # Transport should send ACK + SYN (success, not timeout)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_adv_response_data_containing_0xaa() -> None:
    """ADV: Response data byte 0xAA must not trigger false SYN timeout."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    # Response contains 0xAA as a data byte
    response = bytes((0xAA, 0x42, 0xA9))
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
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_adv_four_threads_hammering_send_proto() -> None:
    """ADV: 4 threads call send_proto() simultaneously."""
    import time as _time

    src = 0xF1
    completed: list[bool] = []
    errors: list[str] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        for _ in range(4):
            try:
                cmd, data = _read_enh_frame(conn)
                if cmd != _ENH_REQ_START:
                    break
                _write_enh_frame(conn, _ENH_RES_STARTED, data)
                while True:
                    cmd2, data2 = _read_enh_frame(conn)
                    if cmd2 != _ENH_REQ_SEND:
                        break
                    _write_bus_symbol(conn, data2)
                    if data2 == 0xAA:
                        break
            except Exception:
                break
        _time.sleep(0.5)

    def _send_one(transport: EnhancedTcpTransport, idx: int) -> None:
        try:
            transport.send_proto(0xFE, 0x07, 0xFE, b"", expect_response=False)
            completed.append(True)
        except Exception as exc:
            errors.append(f"thread-{idx}: {type(exc).__name__}: {exc}")
            completed.append(False)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        threads = [threading.Thread(target=_send_one, args=(transport, i)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
    assert len(completed) == 4
    assert any(completed), f"No thread succeeded: {errors}"


def test_adv_reconnect_storm_disconnect_every_2nd() -> None:
    """ADV: Server disconnects after every 2nd message."""
    import pytest

    connect_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal connect_count
        connect_count += 1
        try:
            _read_enh_frame(conn)
            _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
            _read_enh_frame(conn)
        except Exception:
            pass
        conn.close()

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=0.3,
                src=0xF1,
                timeout_max_retries=0,
                reconnect_max_retries=2,
                reconnect_delay_s=0.05,
            )
        )
        with pytest.raises((TransportError, TransportTimeout)):
            transport.send_proto(0x15, 0x07, 0x04, b"")
    assert connect_count <= 4


def test_adv_stream_of_0xff_to_enh_parser() -> None:
    """ADV: Stream of 0xFF bytes fed to the ENH parser."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        with contextlib.suppress(Exception):
            conn.sendall(bytes([0xFF] * 200))
        import time as _time

        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=0.5,
                src=0xF1,
                timeout_max_retries=0,
                reconnect_max_retries=0,
            )
        )
        with pytest.raises((TransportError, TransportTimeout)):
            transport.send_proto(0x15, 0x07, 0x04, b"")


def test_adv_send_symbol_escape_byte_explicit() -> None:
    """ADV: _send_symbol_with_echo with symbol=0xA9 (ESCAPE) explicitly."""
    src = 0xF1
    dst = 0x15
    payload = bytes((0xA9,))
    request_without_crc = bytes((src, dst, 0xB5, 0x24, len(payload))) + payload
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x42,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)
    symbols_sent: list[int] = []

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            cmd, data = _read_enh_frame(conn)
            assert cmd == _ENH_REQ_SEND
            assert data == expected
            symbols_sent.append(data)
            _write_bus_symbol(conn, data)
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
    assert 0xA9 in symbols_sent


def test_ve_new_07_started_mismatch_aborts_early() -> None:
    """VE-NEW-07 / EG14/EG39: Abort after 3 STARTED with wrong address."""
    import pytest

    src = 0xF7
    wrong_addr = 0x10

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        # Reply with wrong address 3 times
        for _ in range(3):
            _write_enh_frame(conn, _ENH_RES_STARTED, wrong_addr)

        import time as _time

        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=5.0,
                src=src,
                collision_max_retries=0,
            )
        )
        with pytest.raises(TransportError, match="mismatch"):
            transport.send_proto(0x15, 0x07, 0x04, b"")


def test_send_symbol_with_echo_suppresses_post_grant_syn() -> None:
    """XR-SYN-GUARD: Idle SYN bytes between STARTED and first echo are suppressed.

    Same bug family as adaptermux AM-NEW-42, ebusgo postGrantPreEcho,
    proxy requestBytesSeen==0 guard.

    Race: adapter emits RECEIVED(0xAA) idle SYN between STARTED and
    our first SEND. Without suppression, _recv_bus_symbol returns
    0xAA as the echo, which mismatches the real DST byte and raises
    _EnhancedCollision. With suppression, the SYN is silently
    consumed and the real echo is returned.
    """
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        # Emit 2 idle SYN RECEIVED frames before the client sends its first byte.
        _write_bus_symbol(conn, 0xAA)
        _write_bus_symbol(conn, 0xAA)

        # Client sends first telegram byte (dst). Should get real echo,
        # not the suppressed SYN.
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)

        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=2.0,
                src=src,
                collision_max_retries=0,
            )
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_post_grant_syn_guard_clears_on_first_non_syn() -> None:
    """XR-SYN-GUARD: Flag clears on first non-SYN byte, so SYN after echo
    is treated as a real bus symbol, not suppressed."""
    src = 0xF1
    dst = 0x15
    response = bytes((0xAA, 0x42))
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
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
        # Response contains 0xAA as data; it must not be suppressed after
        # the flag was cleared by the first echo.
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_xr_enh_parser_reset_after_read_timeout() -> None:
    """XR_ENH_ParserReset_AfterReadTimeout: Partial frame timeout no contamination."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    call_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal call_count
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        # First attempt: respond to START, send telegram echoes, ACK,
        # but only send partial response length byte with no data.
        # The client will timeout waiting for the remaining data bytes.
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        _write_bus_symbol(conn, 0x05)  # length=5 but we send 0 data bytes -> timeout
        call_count += 1
        # Don't send more data.  The client times out (0.3s), resets the
        # parser, and retries with a new START on the same TCP session.
        # We just fall through to read the retry START immediately.

        # Second attempt (after timeout retry on the same session): full success.
        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)
        call_count += 1

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=0.3,
                src=src,
                timeout_max_retries=1,
            )
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response
    assert call_count == 2


def test_xr_disconnect_reconnect_resets_retry_budget() -> None:
    """Item 5: Retry budgets must reset after successful reconnect on disconnect."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    connect_count = 0

    def _handler(conn: socket.socket) -> None:
        nonlocal connect_count
        connect_count += 1
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        if connect_count == 1:
            # First connection: respond to START then disconnect (EOF).
            assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
            _write_enh_frame(conn, _ENH_RES_STARTED, src)
            conn.close()
            return

        if connect_count == 2:
            # Second connection (after reconnect): timeout once so
            # timeout_retries goes to 1. If budget was NOT reset, the
            # next timeout would exhaust it (timeout_max_retries=1).
            assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
            _write_enh_frame(conn, _ENH_RES_STARTED, src)
            for expected in request[1:]:
                assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
                _write_bus_symbol(conn, expected)
            _write_bus_symbol(conn, 0x00)  # ACK
            # Send partial response to trigger timeout (length=5, no data)
            _write_bus_symbol(conn, 0x05)
            # Don't send more data -- client times out, resets parser,
            # retries with START on the same connection.

            # After timeout retry (timeout_retries should be 1 now),
            # succeed on the retry.
            assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
            _write_enh_frame(conn, _ENH_RES_STARTED, src)
            for expected in request[1:]:
                assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
                _write_bus_symbol(conn, expected)
            _write_bus_symbol(conn, 0x00)  # ACK
            for value in response_segment:
                _write_bus_symbol(conn, value)
            _write_bus_symbol(conn, response_crc)
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
            _write_bus_symbol(conn, 0x00)
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
            _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=0.3,
                src=src,
                timeout_max_retries=1,
                reconnect_max_retries=1,
                reconnect_delay_s=0.05,
            )
        )
        # Without the budget reset fix, the timeout on connection 2 would
        # be the 2nd timeout overall, exhausting timeout_max_retries=1
        # and then exhausting reconnect_max_retries=1 -> failure.
        # With the fix, disconnect-reconnect resets timeout_retries to 0,
        # so the single timeout on connection 2 is fine.
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response
    assert connect_count == 2


# ---------------------------------------------------------------------------
# XR1-XR4: ENS/ENH alignment tests
# ---------------------------------------------------------------------------


def test_xr1_info_serialized_with_send_proto() -> None:
    """XR1: request_info must be serialized under lock with send_proto.

    Both threads must complete with deterministic results — no parser
    corruption, no response theft, no silent partial success.
    """
    import time as _time

    src = 0xF1
    info_result: list[bytes | None] = [None]
    send_result: list[bytes | None] = [None]
    info_error: list[Exception | None] = [None]
    send_error: list[Exception | None] = [None]

    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        # Serve two requests sequentially (lock ensures ordering).
        for _ in range(2):
            try:
                cmd, data = _read_enh_frame(conn)
            except Exception:
                return

            if cmd == _ENH_REQ_INFO:
                # INFO: length=1, payload=0x42
                _write_enh_frame(conn, _ENH_RES_INFO, 0x01)  # len=1
                _write_enh_frame(conn, _ENH_RES_INFO, 0x42)  # data
            elif cmd == _ENH_REQ_START:
                _write_enh_frame(conn, _ENH_RES_STARTED, data)
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

    def _do_info(transport: EnhancedTcpTransport) -> None:
        try:
            info_result[0] = transport.request_info(0x00)
        except Exception as exc:
            info_error[0] = exc

    def _do_send(transport: EnhancedTcpTransport) -> None:
        try:
            send_result[0] = transport.send_proto(dst, 0x07, 0x04, b"")
        except Exception as exc:
            send_error[0] = exc

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=3.0, src=src)
        )
        t1 = threading.Thread(target=_do_info, args=(transport,))
        t2 = threading.Thread(target=_do_send, args=(transport,))
        t1.start()
        _time.sleep(0.05)
        t2.start()
        t1.join(timeout=5.0)
        t2.join(timeout=5.0)

    # Both must succeed — lock serializes access.
    assert info_error[0] is None, f"INFO failed: {info_error[0]}"
    assert send_error[0] is None, f"send failed: {send_error[0]}"
    assert info_result[0] == b"\x42", f"INFO result: {info_result[0]}"
    assert send_result[0] == response, f"send result: {send_result[0]}"


def test_xr2_info_stale_response_drained() -> None:
    """XR2: Stale INFO in kernel TCP buffer must be drained, not accepted.

    The server sends a stale INFO frame immediately after RESETTED (same
    TCP stream, before the client sends its INFO request).  request_info()
    calls _reset_parser() which drains the kernel TCP buffer non-blockingly,
    discarding the stale frame.  Only the fresh response is returned.
    """

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        # Send RESETTED + stale INFO in one burst — both land in kernel
        # buffer before the client calls request_info().
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        _write_enh_frame(conn, _ENH_RES_INFO, 0xBB)  # stale

        # Wait for the actual INFO request
        cmd, data = _read_enh_frame(conn)
        assert cmd == _ENH_REQ_INFO
        assert data == 0x00
        # Send fresh response: length=1, payload=0x42
        _write_enh_frame(conn, _ENH_RES_INFO, 0x01)  # len
        _write_enh_frame(conn, _ENH_RES_INFO, 0x42)  # data

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session():
            # _reset_parser() in request_info drains stale 0xBB from
            # kernel buffer before sending the new INFO request.
            result = transport.request_info(0x00)

    # Must get fresh payload b"\x42", not stale 0xBB.
    assert result == b"\x42"


def test_xr2_info_error_host() -> None:
    """XR2 negative: ERROR_HOST during INFO raises TransportHostError."""
    import pytest

    from helianthus_vrc_explorer.transport.base import TransportHostError

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_INFO, 0x00)
        _write_enh_frame(conn, _ENH_RES_ERROR_HOST, 0x01)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session(), pytest.raises(TransportHostError, match="host error"):
            transport.request_info(0x00)


def test_xr2_info_error_ebus() -> None:
    """XR2 negative: ERROR_EBUS during INFO raises TransportError."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_INFO, 0x00)
        _write_enh_frame(conn, _ENH_RES_ERROR_EBUS, 0x02)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session(), pytest.raises(TransportError, match="eBUS error"):
            transport.request_info(0x00)


def test_xr2_info_resetted_during_exchange() -> None:
    """XR2 negative: RESETTED during INFO exchange raises TransportTimeout."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        try:
            cmd, data = _read_enh_frame(conn)
        except (AssertionError, OSError):
            return
        if cmd == _ENH_REQ_INIT:
            _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
            try:
                cmd2, _ = _read_enh_frame(conn)
            except (AssertionError, OSError):
                return
            if cmd2 == _ENH_REQ_INFO:
                # RESETTED instead of INFO response
                _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        # Client closes this connection and reconnects (new handler).

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session(), pytest.raises(TransportTimeout, match="reset"):
            transport.request_info(0x00)


def test_xr2_info_unknown_command_explicit_error() -> None:
    """XR2 negative: Unknown ENH command during INFO raises TransportError."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_INFO, 0x00)
        _write_enh_frame(conn, 0x0D, 0x00)
        import time as _time

        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session(), pytest.raises(TransportError, match="unexpected ENH"):
            transport.request_info(0x00)


def test_xr2_info_ignores_unsolicited_received() -> None:
    """XR2: unsolicited RECEIVED during INFO wait is busy-bus background traffic.

    The adapter may surface _ENH_RES_RECEIVED while other masters are active.
    request_info() must ignore that frame and continue waiting for the INFO
    payload instead of failing the request.
    """

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_INFO, 0x00)
        _write_enh_frame(conn, _ENH_RES_RECEIVED, 0xAA)
        _write_enh_frame(conn, _ENH_RES_INFO, 0x01)
        _write_enh_frame(conn, _ENH_RES_INFO, 0x42)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=2.0))
        with transport.session():
            result = transport.request_info(0x00)

    assert result == b"\x42"


def test_xr2_info_truncated_payload_timeout() -> None:
    """XR2 negative: INFO with length=3 but only 1 data frame times out."""
    import pytest

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)
        assert _read_enh_frame(conn) == (_ENH_REQ_INFO, 0x00)
        _write_enh_frame(conn, _ENH_RES_INFO, 0x03)  # length=3
        _write_enh_frame(conn, _ENH_RES_INFO, 0x42)  # only 1 of 3
        import time as _time

        _time.sleep(2.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=0.5))
        with transport.session(), pytest.raises(TransportTimeout):
            transport.request_info(0x00)


def test_xr3_enh_unknown_command_explicit_error() -> None:
    """XR3: Unknown ENH command in _recv_bus_symbol must produce TransportError.

    After arbitration succeeds, the server sends an unknown ENH command
    (0x0D) instead of a valid bus symbol.  This must raise TransportError,
    not silently continue.
    """
    import pytest

    src = 0xF1
    dst = 0x15

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        assert _read_enh_frame(conn) == (_ENH_REQ_START, src)
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        # Echo first telegram byte normally
        cmd, data = _read_enh_frame(conn)
        assert cmd == _ENH_REQ_SEND
        _write_bus_symbol(conn, data)

        # Now send an unknown ENH command 0x0D (not in valid set)
        _write_enh_frame(conn, 0x0D, 0x00)

        import time as _time

        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(
                host=host,
                port=port,
                timeout_s=2.0,
                src=src,
                # Disable retries to observe the raw error
                timeout_max_retries=0,
                collision_max_retries=0,
                reconnect_max_retries=0,
            )
        )
        with pytest.raises(TransportError, match="Unknown ENH response command"):
            transport.send_proto(dst, 0x07, 0x04, b"")


def test_xr4_init_resetted_plus_malformed_tail() -> None:
    """XR4: RESETTED + malformed tail in same TCP chunk must not fail INIT.

    The server sends RESETTED followed by a single malformed byte (0x85)
    in the same sendall().  VE15 tolerates 1-2 malformed bytes (below the
    3-consecutive threshold), and _reset_parser() after RESETTED clears
    the malformed counter and drains the TCP buffer.
    """
    src = 0xF1

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        # Send RESETTED + 1 malformed byte in one chunk.
        resetted_frame = _encode_enh(_ENH_RES_RESETTED, 0x01)
        malformed_tail = bytes((0x85,))
        conn.sendall(resetted_frame + malformed_tail)

        # The transport should have survived INIT.  Verify it can
        # process a subsequent INFO request normally.
        cmd, data = _read_enh_frame(conn)
        assert cmd == _ENH_REQ_INFO
        # INFO: length=1, payload=0x42
        _write_enh_frame(conn, _ENH_RES_INFO, 0x01)
        _write_enh_frame(conn, _ENH_RES_INFO, 0x42)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        with transport.session():
            result = transport.request_info(0x00)

    assert result == b"\x42"


def test_xr4_init_resetted_plus_heavy_malformed_tail() -> None:
    """XR4 defense-in-depth: 3 malformed bytes after RESETTED in same chunk.

    When 3 consecutive malformed bytes appear in the same recv chunk as
    RESETTED, _parse_enh_byte raises TransportError (with close()) before
    _read_message returns the RESETTED frame.  This is expected behavior:
    the malformed threshold fires cleanly, and _open_session's except
    block handles the re-raise.
    """
    import pytest

    src = 0xF1

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        resetted_frame = _encode_enh(_ENH_RES_RESETTED, 0x01)
        malformed_tail = bytes((0x85, 0x85, 0x85))
        conn.sendall(resetted_frame + malformed_tail)

        import time as _time

        _time.sleep(1.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        # 3 consecutive malformed bytes after RESETTED in the same recv
        # chunk causes _parse_enh_byte to raise TransportError before
        # RESETTED is returned.  Clean error, not a hang or crash.
        with pytest.raises(TransportError, match="Malformed ENH start"), transport.session():
            pass


# ---------------------------------------------------------------------------
# XR_ Shared ENS/ENH Conformance Tests (alignment with proxy, adaptermux, ebusgo)
# ---------------------------------------------------------------------------
#
# XR Coverage Manifest — VRC Explorer
#
# VRC Explorer only implements the ENH transport (enhanced_tcp.py).
# It does NOT implement ENS or ebusd-tcp transports.  Therefore:
#
#   IMPLEMENTED (ENH-only, no ENS counterpart needed):
#     XR_INIT_TimeoutFailOpen_Bounded  → test_xr_init_timeout_fail_closed_bounded
#       (VRC DEVIATION: fail-closed, not fail-open — documented)
#     XR_ENH_UnknownCommand_ExplicitError → test_xr3_enh_unknown_command_explicit_error
#     XR_ENH_0xAA_DataNotSYN             → test_xr_enh_0xaa_data_not_syn
#     XR_START_WriteAll_NoDoubleSend
#       → test_xr_start_request_start_write_all_no_double_send
#     XR_ENH_ParserReset_AfterReadTimeout → test_xr_enh_parser_reset_after_read_timeout
#     XR_INFO_FrameLength_AndSerialAccess → test_xr1_info_serialized_with_send_proto
#       + test_xr2_info_stale_response_drained
#       + test_xr2_info_error_host/ebus/resetted/unknown/truncated
#     XR_INFO_RESETTED_CachePolicy_Explicit → covered by XR2 stale drain + RESETTED preservation
#
#   NOT APPLICABLE (VRC has no ENS transport):
#     XR_START_Cancel_ReleasesOwnership — VRC is synchronous, no cancel path
#     Any ENS-specific tests — no ENS codec in VRC Explorer
#


def test_xr_init_timeout_fail_closed_bounded() -> None:
    """XR_INIT_TimeoutFailOpen_Bounded — VRC DEVIATION: fail-closed.

    The canonical XR invariant is fail-open (degraded state with
    init_confirmed=false).  VRC Explorer deviates: it cannot operate
    without confirmed INIT because the scanner requires accurate
    adapter feature flags for escape/protocol selection.  INIT timeout
    raises TransportTimeout, which _open_session propagates to the
    caller.  The session is bounded (timeout_s) and deterministic.
    """
    import pytest

    def _handler(conn: socket.socket) -> None:
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        # Never respond — let client timeout
        import time as _time

        _time.sleep(2.0)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(EnhancedTcpConfig(host=host, port=port, timeout_s=0.3))
        with pytest.raises(TransportTimeout), transport.session():
            pass  # session() calls _open_session → _init_transport


def test_xr_enh_0xaa_data_not_syn() -> None:
    """XR_ENH_0xAA_DataNotSYN: 0xAA in response data/CRC must not trigger false timeout."""
    src = 0xF1
    dst = 0x15
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    # Response with 0xAA as a data byte
    response = bytes((0xAA, 0x42))
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
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)  # ACK
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)  # SYN
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response


def test_xr_start_request_start_write_all_no_double_send() -> None:
    """XR_START_RequestStart_WriteAll_NoDoubleSend: Exactly one START, full write, no duplicate.

    Drive the transaction to a deterministic terminal state (complete
    send+response) and verify exactly one START frame was sent.
    """
    src = 0xF1
    dst = 0x15
    start_frames_seen = 0
    request_without_crc = bytes((src, dst, 0x07, 0x04, 0x00))
    request = request_without_crc + bytes((_crc(request_without_crc),))
    response = bytes((0x01,))
    response_segment = bytes((len(response),)) + response
    response_crc = _crc(response_segment)

    def _handler(conn: socket.socket) -> None:
        nonlocal start_frames_seen
        assert _read_enh_frame(conn) == (_ENH_REQ_INIT, 0x01)
        _write_enh_frame(conn, _ENH_RES_RESETTED, 0x01)

        cmd, data = _read_enh_frame(conn)
        assert cmd == _ENH_REQ_START
        assert data == src
        start_frames_seen += 1
        _write_enh_frame(conn, _ENH_RES_STARTED, src)

        # Complete full exchange to terminal state
        for expected in request[1:]:
            assert _read_enh_frame(conn) == (_ENH_REQ_SEND, expected)
            _write_bus_symbol(conn, expected)
        _write_bus_symbol(conn, 0x00)  # ACK
        for value in response_segment:
            _write_bus_symbol(conn, value)
        _write_bus_symbol(conn, response_crc)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0x00)
        _write_bus_symbol(conn, 0x00)
        assert _read_enh_frame(conn) == (_ENH_REQ_SEND, 0xAA)
        _write_bus_symbol(conn, 0xAA)

    with _run_ens_test_server(_handler) as (host, port):
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host=host, port=port, timeout_s=2.0, src=src)
        )
        result = transport.send_proto(dst, 0x07, 0x04, b"")

    assert result == response
    assert start_frames_seen == 1  # Exactly one START, no duplicate
