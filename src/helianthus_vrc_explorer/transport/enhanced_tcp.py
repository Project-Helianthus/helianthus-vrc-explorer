from __future__ import annotations

import contextlib
import random
import socket
import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .base import TransportError, TransportInterface, TransportTimeout

_EBUS_ESCAPE = 0xA9
_EBUS_SYN = 0xAA
_EBUS_ACK = 0x00
_EBUS_NACK = 0xFF
_ADDRESS_BROADCAST = 0xFE

_ENH_REQ_INIT = 0x0
_ENH_REQ_SEND = 0x1
_ENH_REQ_START = 0x2

_ENH_RES_RESETTED = 0x0
_ENH_RES_RECEIVED = 0x1
_ENH_RES_STARTED = 0x2
_ENH_RES_INFO = 0x3
_ENH_RES_FAILED = 0xA
_ENH_RES_ERROR_EBUS = 0xB
_ENH_RES_ERROR_HOST = 0xC

_CRC_TABLE: tuple[int, ...] = (
    0x00,
    0x9B,
    0xAD,
    0x36,
    0xC1,
    0x5A,
    0x6C,
    0xF7,
    0x19,
    0x82,
    0xB4,
    0x2F,
    0xD8,
    0x43,
    0x75,
    0xEE,
    0x32,
    0xA9,
    0x9F,
    0x04,
    0xF3,
    0x68,
    0x5E,
    0xC5,
    0x2B,
    0xB0,
    0x86,
    0x1D,
    0xEA,
    0x71,
    0x47,
    0xDC,
    0x64,
    0xFF,
    0xC9,
    0x52,
    0xA5,
    0x3E,
    0x08,
    0x93,
    0x7D,
    0xE6,
    0xD0,
    0x4B,
    0xBC,
    0x27,
    0x11,
    0x8A,
    0x56,
    0xCD,
    0xFB,
    0x60,
    0x97,
    0x0C,
    0x3A,
    0xA1,
    0x4F,
    0xD4,
    0xE2,
    0x79,
    0x8E,
    0x15,
    0x23,
    0xB8,
    0xC8,
    0x53,
    0x65,
    0xFE,
    0x09,
    0x92,
    0xA4,
    0x3F,
    0xD1,
    0x4A,
    0x7C,
    0xE7,
    0x10,
    0x8B,
    0xBD,
    0x26,
    0xFA,
    0x61,
    0x57,
    0xCC,
    0x3B,
    0xA0,
    0x96,
    0x0D,
    0xE3,
    0x78,
    0x4E,
    0xD5,
    0x22,
    0xB9,
    0x8F,
    0x14,
    0xAC,
    0x37,
    0x01,
    0x9A,
    0x6D,
    0xF6,
    0xC0,
    0x5B,
    0xB5,
    0x2E,
    0x18,
    0x83,
    0x74,
    0xEF,
    0xD9,
    0x42,
    0x9E,
    0x05,
    0x33,
    0xA8,
    0x5F,
    0xC4,
    0xF2,
    0x69,
    0x87,
    0x1C,
    0x2A,
    0xB1,
    0x46,
    0xDD,
    0xEB,
    0x70,
    0x0B,
    0x90,
    0xA6,
    0x3D,
    0xCA,
    0x51,
    0x67,
    0xFC,
    0x12,
    0x89,
    0xBF,
    0x24,
    0xD3,
    0x48,
    0x7E,
    0xE5,
    0x39,
    0xA2,
    0x94,
    0x0F,
    0xF8,
    0x63,
    0x55,
    0xCE,
    0x20,
    0xBB,
    0x8D,
    0x16,
    0xE1,
    0x7A,
    0x4C,
    0xD7,
    0x6F,
    0xF4,
    0xC2,
    0x59,
    0xAE,
    0x35,
    0x03,
    0x98,
    0x76,
    0xED,
    0xDB,
    0x40,
    0xB7,
    0x2C,
    0x1A,
    0x81,
    0x5D,
    0xC6,
    0xF0,
    0x6B,
    0x9C,
    0x07,
    0x31,
    0xAA,
    0x44,
    0xDF,
    0xE9,
    0x72,
    0x85,
    0x1E,
    0x28,
    0xB3,
    0xC3,
    0x58,
    0x6E,
    0xF5,
    0x02,
    0x99,
    0xAF,
    0x34,
    0xDA,
    0x41,
    0x77,
    0xEC,
    0x1B,
    0x80,
    0xB6,
    0x2D,
    0xF1,
    0x6A,
    0x5C,
    0xC7,
    0x30,
    0xAB,
    0x9D,
    0x06,
    0xE8,
    0x73,
    0x45,
    0xDE,
    0x29,
    0xB2,
    0x84,
    0x1F,
    0xA7,
    0x3C,
    0x0A,
    0x91,
    0x66,
    0xFD,
    0xCB,
    0x50,
    0xBE,
    0x25,
    0x13,
    0x88,
    0x7F,
    0xE4,
    0xD2,
    0x49,
    0x95,
    0x0E,
    0x38,
    0xA3,
    0x54,
    0xCF,
    0xF9,
    0x62,
    0x8C,
    0x17,
    0x21,
    0xBA,
    0x4D,
    0xD6,
    0xE0,
    0x7B,
)


@dataclass(frozen=True)
class EnhancedTcpConfig:
    host: str = "127.0.0.1"
    port: int = 9999
    timeout_s: float = 5.0
    # Default initiator: priority class 3, sub-address 0xF.
    # Lowest useful priority while avoiding the 0xFF target-address
    # conflict with NETX3 (0x04).  Per eBUS spec section 6.4,
    # address 0xF7 yields to all priority-0/1/2 masters.
    src: int = 0xF7
    trace_path: Path | None = None
    timeout_max_retries: int = 2
    # Collisions are expected at low priority — be persistent.
    collision_max_retries: int = 10
    nack_max_retries: int = 1  # Per spec section 7.4: exactly 1 retry
    # Collision backoff: the PIC16F firmware enforces a 0x3C (60) tick
    # minimum scan deadline after FAILED, but a rapid START bypasses it
    # (race in protocol_state_dispatch line 9938).  A 50ms floor lets
    # the PIC flush its FAILED response, apply the deadline, and reset
    # the UART state before we re-arbitrate.  Without this, rapid
    # START floods cause transient eBUS signal loss (ebus_error=0x00).
    collision_backoff_min_ms: int = 50
    collision_backoff_max_ms: int = 50


@dataclass(slots=True)
class _EnhancedTcpSession:
    sock: socket.socket


class _EnhancedCollision(TransportError):
    """Retryable collision or unexpected bus-ownership event."""


class _EnhancedNack(TransportError):
    """Retryable NACK from the bus peer."""


class _EnhancedCrcMismatch(TransportError):
    """Retryable CRC mismatch while reading a target response."""


def _utc_ts() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _short_hex(blob: bytes, max_bytes: int = 48) -> str:
    hx = blob.hex()
    if len(blob) > max_bytes:
        return hx[: max_bytes * 2] + "..."
    return hx


def _validate_u8(field_name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field_name} must be an int, got {type(value).__name__}")
    if not (0x00 <= value <= 0xFF):
        raise ValueError(f"{field_name} must be in range 0..255, got {value}")


def _encode_enh(command: int, data: int) -> bytes:
    _validate_u8("command", command)
    _validate_u8("data", data)
    byte1 = 0xC0 | ((command & 0x0F) << 2) | ((data & 0xC0) >> 6)
    byte2 = 0x80 | (data & 0x3F)
    return bytes((byte1, byte2))


def _crc_update(crc: int, value: int) -> int:
    return _CRC_TABLE[crc & 0xFF] ^ (value & 0xFF)


def _crc(data: bytes) -> int:
    value = 0
    for item in data:
        if item == _EBUS_ESCAPE:
            value = _crc_update(value, _EBUS_ESCAPE)
            value = _crc_update(value, 0x00)
        elif item == _EBUS_SYN:
            value = _crc_update(value, _EBUS_ESCAPE)
            value = _crc_update(value, 0x01)
        else:
            value = _crc_update(value, item)
    return value


def _is_initiator_capable_address(addr: int) -> bool:
    def _part_index(bits: int) -> int:
        return {
            0x0: 1,
            0x1: 2,
            0x3: 3,
            0x7: 4,
            0xF: 5,
        }.get(bits, 0)

    return _part_index(addr & 0x0F) > 0 and _part_index((addr & 0xF0) >> 4) > 0


class EnhancedTcpTransport(TransportInterface):
    """Enhanced-protocol TCP client for direct eBUS adapter connections."""

    def __init__(self, config: EnhancedTcpConfig) -> None:
        _validate_u8("src", config.src)
        if config.timeout_max_retries < 0:
            raise ValueError("timeout_max_retries must be >= 0")
        if config.collision_max_retries < 0:
            raise ValueError("collision_max_retries must be >= 0")
        if config.nack_max_retries < 0:
            raise ValueError("nack_max_retries must be >= 0")
        if config.collision_backoff_min_ms < 0 or config.collision_backoff_max_ms < 0:
            raise ValueError("collision backoff must be >= 0 ms")
        if config.collision_backoff_max_ms < config.collision_backoff_min_ms:
            raise ValueError("collision_backoff_max_ms must be >= collision_backoff_min_ms")

        self._config = config
        self._trace_seq = 0
        self._session_depth = 0
        self._session: _EnhancedTcpSession | None = None
        self._messages = deque[tuple[str, int, int]]()
        self._enh_pending_first: int | None = None

    def _trace(self, message: str) -> None:
        trace_path = self._config.trace_path
        if trace_path is None:
            return
        with contextlib.suppress(OSError):
            trace_path.parent.mkdir(parents=True, exist_ok=True)
            with trace_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{_utc_ts()} {message}\n")

    def trace_label(self, label: str) -> None:
        if not isinstance(label, str):
            raise TypeError(f"label must be a str, got {type(label).__name__}")
        text = label.strip()
        if text:
            self._trace(f"OP {text}")

    def _reset_parser(self) -> None:
        self._messages.clear()
        self._enh_pending_first = None

    def close(self) -> None:
        session = self._session
        self._session = None
        self._reset_parser()
        if session is None:
            return
        with contextlib.suppress(OSError):
            session.sock.close()

    @contextlib.contextmanager
    def session(self) -> Iterator[EnhancedTcpTransport]:
        self._session_depth += 1
        if self._session_depth == 1:
            try:
                self._open_session()
            except Exception:
                self._session_depth -= 1
                if self._session_depth < 0:
                    self._session_depth = 0
                raise
        try:
            yield self
        finally:
            self._session_depth -= 1
            if self._session_depth <= 0:
                self._session_depth = 0
                self.close()

    def _open_session(self) -> None:
        try:
            sock = socket.create_connection(
                (self._config.host, self._config.port),
                self._config.timeout_s,
            )
            sock.settimeout(self._config.timeout_s)
        except TimeoutError as exc:
            raise TransportTimeout(
                f"Enhanced adapter timeout {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"Enhanced adapter {self._config.host}:{self._config.port}: {exc}"
            ) from exc

        self._session = _EnhancedTcpSession(sock=sock)
        self._reset_parser()
        try:
            self._init_transport(features=0x01)
        except Exception:
            self.close()
            raise

    def _ensure_session(self) -> _EnhancedTcpSession:
        session = self._session
        if session is not None:
            return session
        self._open_session()
        session = self._session
        assert session is not None
        return session

    def _send_enh_frame(self, command: int, data: int) -> None:
        session = self._ensure_session()
        try:
            session.sock.sendall(_encode_enh(command, data))
        except TimeoutError as exc:
            self.close()
            raise TransportTimeout(
                f"Enhanced adapter timeout {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            self.close()
            raise TransportError(
                f"Enhanced adapter {self._config.host}:{self._config.port}: {exc}"
            ) from exc

    def _read_message(self) -> tuple[str, int, int]:
        while True:
            if self._messages:
                return self._messages.popleft()

            session = self._ensure_session()
            try:
                chunk = session.sock.recv(4096)
            except TimeoutError as exc:
                self._reset_parser()
                raise TransportTimeout(
                    f"Enhanced adapter timeout {self._config.host}:{self._config.port}"
                ) from exc
            except OSError as exc:
                self.close()
                raise TransportError(
                    f"Enhanced adapter {self._config.host}:{self._config.port}: {exc}"
                ) from exc

            if not chunk:
                self.close()
                raise TransportError(
                    f"Enhanced adapter disconnected {self._config.host}:{self._config.port}"
                )

            for value in chunk:
                message = self._parse_enh_byte(value)
                if message is not None:
                    self._messages.append(message)

    def _parse_enh_byte(self, value: int) -> tuple[str, int, int] | None:
        if self._enh_pending_first is None:
            if value & 0x80 == 0:
                return ("data", value, 0)
            if value & 0xC0 == 0x80:
                self.close()
                raise TransportError(f"Malformed ENH byte pair start 0x{value:02X}")
            self._enh_pending_first = value
            return None

        if value & 0xC0 != 0x80:
            self._enh_pending_first = None
            self.close()
            raise TransportError(f"Malformed ENH byte pair end 0x{value:02X}")

        first = self._enh_pending_first
        self._enh_pending_first = None
        assert first is not None
        command = (first >> 2) & 0x0F
        data = ((first & 0x03) << 6) | (value & 0x3F)
        return ("frame", command, data)

    def _init_transport(self, *, features: int) -> None:
        self._trace(f"INIT features=0x{features:02X}")
        self._send_enh_frame(_ENH_REQ_INIT, features)
        while True:
            try:
                kind, command, data = self._read_message()
            except TransportTimeout:
                self._trace("INIT_RESP timeout")
                return
            if kind != "frame":
                continue
            if command == _ENH_RES_RESETTED:
                self._trace(f"INIT_RESP reset features=0x{data:02X}")
                self._reset_parser()
                return
            if command == _ENH_RES_ERROR_EBUS:
                self._trace(f"INIT_RESP ebus_error=0x{data:02X}")
                raise TransportError(f"ENH init eBUS error 0x{data:02X}")
            if command == _ENH_RES_ERROR_HOST:
                self._trace(f"INIT_RESP host_error=0x{data:02X}")
                raise TransportError(f"ENH init host error 0x{data:02X}")

    def _start_arbitration(self, initiator: int) -> None:
        self._trace(f"START initiator=0x{initiator:02X}")
        self._send_enh_frame(_ENH_REQ_START, initiator)
        while True:
            kind, command, data = self._read_message()
            if kind != "frame":
                continue
            if command == _ENH_RES_STARTED and data == initiator:
                self._trace(f"START_RESP started initiator=0x{data:02X}")
                self._reset_parser()
                return
            if command == _ENH_RES_FAILED:
                self._trace(f"START_RESP failed winner=0x{data:02X}")
                self._reset_parser()
                raise _EnhancedCollision(
                    f"Arbitration failed src=0x{initiator:02X} winner=0x{data:02X}"
                )
            if command == _ENH_RES_ERROR_EBUS:
                self._trace(f"START_RESP ebus_error=0x{data:02X}")
                self._reset_parser()
                raise _EnhancedCollision(f"enhanced arbitration eBUS error 0x{data:02X}")
            if command == _ENH_RES_ERROR_HOST:
                self._trace(f"START_RESP host_error=0x{data:02X}")
                self._reset_parser()
                raise _EnhancedCollision(f"enhanced arbitration host error 0x{data:02X}")
            if command == _ENH_RES_RESETTED:
                self._trace(f"START_RESP reset features=0x{data:02X}")
                self._reset_parser()

    def _recv_bus_symbol(self) -> int:
        while True:
            kind, command, data = self._read_message()
            if kind == "data":
                return command
            if command == _ENH_RES_RECEIVED:
                return data
            if command == _ENH_RES_RESETTED:
                self._reset_parser()
                continue
            if command == _ENH_RES_INFO:
                continue
            if command == _ENH_RES_ERROR_EBUS:
                raise TransportError(f"enhanced bus read eBUS error 0x{data:02X}")
            if command == _ENH_RES_ERROR_HOST:
                raise TransportError(f"enhanced bus read host error 0x{data:02X}")

    def _send_symbol_with_echo(self, symbol: int) -> None:
        self._send_enh_frame(_ENH_REQ_SEND, symbol)
        echo = self._recv_bus_symbol()
        if echo == _EBUS_SYN and symbol != _EBUS_SYN:
            raise _EnhancedCollision("unexpected SYN while waiting for echo")
        if echo != symbol:
            raise _EnhancedCollision(
                f"echo mismatch while waiting for 0x{symbol:02X}: got 0x{echo:02X}"
            )

    def _send_end_of_message(self) -> None:
        self._send_symbol_with_echo(_EBUS_SYN)

    def send(self, dst: int, payload: bytes) -> bytes:
        return self.send_proto(dst, 0xB5, 0x24, payload)

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        _validate_u8("dst", dst)
        _validate_u8("primary", primary)
        _validate_u8("secondary", secondary)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")
        if len(payload) > 0xFF:
            raise ValueError(f"payload too large for eBUS telegram: {len(payload)} bytes")

        self._trace_seq += 1
        seq = self._trace_seq
        payload_bytes = bytes(payload)
        return self._send_with_policy(
            seq,
            lambda: self._send_proto_once(
                seq,
                dst=dst,
                primary=primary,
                secondary=secondary,
                payload=payload_bytes,
                expect_response=expect_response,
            ),
        )

    def _send_with_policy(self, seq: int, send_once: Callable[[], bytes]) -> bytes:
        timeout_retries = 0
        collision_retries = 0
        nack_retries = 0

        while True:
            try:
                return send_once()
            except TransportTimeout as exc:
                timeout_retries += 1
                if timeout_retries > self._config.timeout_max_retries:
                    self.close()
                    raise TransportTimeout(
                        f"{exc} (timeout retries exhausted ({self._config.timeout_max_retries}))"
                    ) from exc
                # First timeout: reset parser and retry on the same session.
                # Subsequent timeouts after exhaustion: close above.
                self._reset_parser()
                self._trace(
                    f"#{seq} RETRY type=timeout "
                    f"n={timeout_retries}/{self._config.timeout_max_retries}"
                )
            except _EnhancedCollision as exc:
                # Collision is normal on a shared bus.  Per eBUS spec
                # section 6.2.2.2 the adapter waits for the winner's
                # telegram and the subsequent SYN release automatically.
                # We just re-issue START — no software backoff needed.
                collision_retries += 1
                if collision_retries > self._config.collision_max_retries:
                    self.close()
                    raise TransportError(
                        f"{exc} (collision retries exhausted "
                        f"({self._config.collision_max_retries}))"
                    ) from exc
                self._reset_parser()
                backoff_max = self._config.collision_backoff_max_ms
                if backoff_max > 0:
                    sleep_s = random.uniform(
                        self._config.collision_backoff_min_ms / 1000.0,
                        backoff_max / 1000.0,
                    )
                    time.sleep(sleep_s)
                else:
                    sleep_s = 0.0
                self._trace(
                    f"#{seq} RETRY type=collision n={collision_retries}/"
                    f"{self._config.collision_max_retries} "
                    f"sleep_ms={int(round(sleep_s * 1000))}"
                )
            except (_EnhancedNack, _EnhancedCrcMismatch) as exc:
                # NACK/CRC are retryable on the same session — the bus
                # protocol already handled ACK/NACK exchange.
                nack_retries += 1
                if nack_retries > self._config.nack_max_retries:
                    self.close()
                    raise TransportError(
                        f"{exc} (nack/crc retries exhausted ({self._config.nack_max_retries}))"
                    ) from exc
                self._reset_parser()
                self._trace(
                    f"#{seq} RETRY type=nack_or_crc "
                    f"n={nack_retries}/{self._config.nack_max_retries}"
                )

    def _send_proto_once(
        self,
        seq: int,
        *,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        expect_response: bool,
    ) -> bytes:
        self._start_arbitration(self._config.src)

        telegram = bytearray((self._config.src, dst, primary, secondary, len(payload)))
        telegram.extend(payload)
        telegram.append(_crc(bytes(telegram)))
        self._trace(
            f"#{seq} SEND_PROTO src=0x{self._config.src:02X} dst=0x{dst:02X} "
            f"primary=0x{primary:02X} secondary=0x{secondary:02X} payload={_short_hex(payload)}"
        )

        for symbol in telegram[1:]:
            self._send_symbol_with_echo(symbol)

        if dst == _ADDRESS_BROADCAST or not expect_response:
            self._send_end_of_message()
            self._trace(f"#{seq} RECV_PROTO broadcast_or_no_response")
            return b""

        ack = self._recv_bus_symbol()
        if ack == _EBUS_NACK:
            raise _EnhancedNack("nack received while waiting for command ack")
        if ack == _EBUS_SYN:
            raise TransportTimeout("syn received while waiting for command ack")
        if ack != _EBUS_ACK:
            raise TransportError(f"unexpected symbol 0x{ack:02X} while waiting for command ack")

        if _is_initiator_capable_address(dst):
            self._send_end_of_message()
            self._trace(f"#{seq} RECV_PROTO initiator_initiator=no_response")
            return b""

        for response_attempt in range(2):
            length = self._recv_bus_symbol()
            if length == _EBUS_SYN:
                raise TransportTimeout("syn received while waiting for response length")

            response = bytearray()
            for _ in range(length):
                value = self._recv_bus_symbol()
                if value == _EBUS_SYN:
                    raise TransportTimeout("syn received while waiting for response data")
                response.append(value)

            crc_value = self._recv_bus_symbol()
            if crc_value == _EBUS_SYN:
                raise TransportTimeout("syn received while waiting for response crc")

            segment = bytes((length,)) + bytes(response)
            if _crc(segment) != crc_value:
                self._send_symbol_with_echo(_EBUS_NACK)
                if response_attempt == 0:
                    continue
                self._send_end_of_message()
                raise _EnhancedCrcMismatch("response crc mismatch")

            self._send_symbol_with_echo(_EBUS_ACK)
            self._send_end_of_message()
            parsed = bytes(response)
            self._trace(f"#{seq} PARSED_PROTO len={len(parsed)} hex={_short_hex(parsed)}")
            return parsed

        raise TransportTimeout("unreachable enhanced response loop")

    def command_lines(self, command: str, *, read_all: bool = False) -> list[str]:
        _ = read_all
        raise TransportError(
            f"enhanced adapter transport does not support ebusd command passthrough: {command!r}"
        )
