from __future__ import annotations

import contextlib
import math
import random
import socket
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO

from .base import (
    TransportDisconnected,
    TransportError,
    TransportHostError,
    TransportInterface,
    TransportNack,
    TransportTimeout,
)

_EBUS_ESCAPE = 0xA9
_EBUS_SYN = 0xAA
_EBUS_ACK = 0x00
_EBUS_NACK = 0xFF
_ADDRESS_BROADCAST = 0xFE

_ENH_REQ_INIT = 0x0
_ENH_REQ_SEND = 0x1
_ENH_REQ_START = 0x2
_ENH_REQ_INFO = 0x3  # D4: Query adapter metadata (INFO ID in data byte)

_ENH_RES_RESETTED = 0x0
_ENH_RES_RECEIVED = 0x1
_ENH_RES_STARTED = 0x2
_ENH_RES_INFO = 0x3
_ENH_RES_FAILED = 0xA
_ENH_RES_ERROR_EBUS = 0xB
_ENH_RES_ERROR_HOST = 0xC

# D3: Valid ENH response command set — reject undefined at parse level.
_ENH_VALID_RESPONSE_COMMANDS: frozenset[int] = frozenset(
    {
        _ENH_RES_RESETTED,
        _ENH_RES_RECEIVED,
        _ENH_RES_STARTED,
        _ENH_RES_INFO,
        _ENH_RES_FAILED,
        _ENH_RES_ERROR_EBUS,
        _ENH_RES_ERROR_HOST,
    }
)

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
    # TCP reconnect: when timeout retries are exhausted, reconnect instead
    # of giving up.  This handles stale TCP sessions (adapter reboot,
    # network blip) without aborting the scan.
    reconnect_max_retries: int = 3
    reconnect_delay_s: float = 2.0


@dataclass(slots=True)
class _EnhancedTcpSession:
    sock: socket.socket
    trace_handle: IO[str] | None = None


class _EnhancedCollision(TransportError):
    """Retryable collision or unexpected bus-ownership event."""


class _EnhancedNack(TransportNack):
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


# Pre-encoded ENH frames for hot-path symbols (avoids per-call encoding).
_ENH_SEND_SYN = _encode_enh(_ENH_REQ_SEND, _EBUS_SYN)
_ENH_SEND_ACK = _encode_enh(_ENH_REQ_SEND, _EBUS_ACK)
_ENH_SEND_NACK = _encode_enh(_ENH_REQ_SEND, _EBUS_NACK)


def _crc_update(crc: int, value: int) -> int:
    return _CRC_TABLE[crc & 0xFF] ^ (value & 0xFF)


def _crc(data: bytes) -> int:
    """Compute eBUS CRC-8 over logical frame bytes.

    Per eBUS specification, the CRC is computed over the wire-expanded form
    of the frame.  Logical bytes 0xA9 (ESCAPE) and 0xAA (SYN) are expanded
    to their two-byte wire sequences [0xA9, 0x00] and [0xA9, 0x01] before
    feeding into the CRC polynomial.  This function accepts logical bytes
    and performs the expansion internally -- callers should NOT pre-expand.

    The enhanced adapter firmware handles wire escape encoding/decoding
    transparently: ENH SEND carries logical bytes; ENH RECEIVED returns
    logical bytes.  CRC computation is the only place where escape expansion
    matters to the client.
    """
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
        if config.src in (0x00, _EBUS_ESCAPE, _EBUS_SYN, 0xFF):
            raise ValueError(
                f"src 0x{config.src:02X} is a reserved address "
                f"(0x00, 0xA9/ESCAPE, 0xAA/SYN, 0xFF are not valid initiator addresses)"
            )
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
        if config.timeout_s <= 0 or not math.isfinite(config.timeout_s):
            raise ValueError(f"timeout_s must be positive and finite, got {config.timeout_s}")
        if not (1 <= config.port <= 65535):
            raise ValueError(f"port must be in range 1..65535, got {config.port}")

        self._config = config
        self._trace_seq = 0
        self._session_depth = 0
        self._session: _EnhancedTcpSession | None = None
        self._messages = deque[tuple[str, int, int]]()
        self._enh_pending_first: int | None = None
        self._malformed_count: int = 0
        self._lock = threading.RLock()

    def _trace(self, message: str) -> None:
        session = self._session
        if session is None or session.trace_handle is None:
            return
        with contextlib.suppress(OSError):
            session.trace_handle.write(f"{_utc_ts()} {message}\n")
            session.trace_handle.flush()

    def trace_label(self, label: str) -> None:
        if not isinstance(label, str):
            raise TypeError(f"label must be a str, got {type(label).__name__}")
        text = label.strip()
        if text:
            self._trace(f"OP {text}")

    def _reset_parser(self) -> None:
        self._messages.clear()
        self._enh_pending_first = None
        self._malformed_count = 0
        # VE12/VE19: Drain stale bytes from kernel TCP buffer.
        session = self._session
        if session is not None:
            with contextlib.suppress(OSError):
                session.sock.setblocking(False)
                try:
                    # Cap at 64 KB to avoid spinning on a flooded bus.
                    for _ in range(16):
                        if not session.sock.recv(4096):
                            break
                except BlockingIOError:
                    pass
                finally:
                    session.sock.settimeout(self._config.timeout_s)

    def close(self) -> None:
        with self._lock:
            session = self._session
            self._session = None
            self._reset_parser()
        if session is None:
            return
        if session.trace_handle is not None:
            with contextlib.suppress(OSError):
                session.trace_handle.close()
        with contextlib.suppress(OSError):
            session.sock.close()

    @contextlib.contextmanager
    def session(self) -> Iterator[EnhancedTcpTransport]:
        with self._lock:
            self._session_depth += 1
            if self._session_depth == 1:
                try:
                    self._open_session()
                except Exception:
                    self._session_depth = max(0, self._session_depth - 1)
                    raise
        try:
            yield self
        finally:
            with self._lock:
                self._session_depth = max(0, self._session_depth - 1)
                if self._session_depth == 0:
                    self.close()

    def _open_session(self) -> None:
        try:
            sock = socket.create_connection(
                (self._config.host, self._config.port),
                self._config.timeout_s,
            )
            sock.settimeout(self._config.timeout_s)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except TimeoutError as exc:
            raise TransportTimeout(
                f"Enhanced adapter timeout {self._config.host}:{self._config.port}"
            ) from exc
        except OSError as exc:
            raise TransportError(
                f"Enhanced adapter {self._config.host}:{self._config.port}: {exc}"
            ) from exc

        trace_handle = None
        trace_path = self._config.trace_path
        if trace_path is not None:
            with contextlib.suppress(OSError):
                trace_path.parent.mkdir(parents=True, exist_ok=True)
                trace_handle = trace_path.open("a", encoding="utf-8")
        self._session = _EnhancedTcpSession(sock=sock, trace_handle=trace_handle)
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
            # Use pre-encoded frames for common hot-path symbols.
            if command == _ENH_REQ_SEND and data == _EBUS_SYN:
                frame = _ENH_SEND_SYN
            elif command == _ENH_REQ_SEND and data == _EBUS_ACK:
                frame = _ENH_SEND_ACK
            elif command == _ENH_REQ_SEND and data == _EBUS_NACK:
                frame = _ENH_SEND_NACK
            else:
                frame = _encode_enh(command, data)
            session.sock.sendall(frame)
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
                raise TransportDisconnected(
                    f"Enhanced adapter disconnected {self._config.host}:{self._config.port}"
                )

            for value in chunk:
                message = self._parse_enh_byte(value)
                if message is not None:
                    self._messages.append(message)

    def _parse_enh_byte(self, value: int) -> tuple[str, int, int] | None:
        if self._enh_pending_first is None:
            if value & 0x80 == 0:
                self._malformed_count = 0  # Valid data byte resets counter
                return ("data", value, 0)
            if value & 0xC0 == 0x80:
                self._malformed_count += 1
                cnt = self._malformed_count
                self._trace(f"Malformed ENH start 0x{value:02X} (n={cnt})")
                if cnt >= 3:
                    self._malformed_count = 0
                    self.close()
                    raise TransportError(f"Malformed ENH start 0x{value:02X} (3 consecutive)")
                return None
            self._enh_pending_first = value
            return None

        if value & 0xC0 != 0x80:
            self._enh_pending_first = None
            self._malformed_count += 1
            cnt = self._malformed_count
            self._trace(f"Malformed ENH end 0x{value:02X} (n={cnt})")
            if cnt >= 3:
                self._malformed_count = 0
                self.close()
                raise TransportError(f"Malformed ENH end 0x{value:02X} (3 consecutive)")
            # Resync: re-interpret the current byte instead of discarding.
            if value & 0x80 == 0:
                self._malformed_count = 0
                return ("data", value, 0)
            # Could be a new ENH frame start (0xC0..0xFF range).
            self._enh_pending_first = value
            return None

        first = self._enh_pending_first
        self._enh_pending_first = None
        assert first is not None
        self._malformed_count = 0
        command = (first >> 2) & 0x0F
        data = ((first & 0x03) << 6) | (value & 0x3F)
        # D3: Log undefined ENH command nibbles at parse level.
        # Still returned as ("frame", ...) so _read_message yields it to
        # callers — prevents spin if adapter streams unknown frames, and
        # lets deadline checks in _recv_bus_symbol/_start_arbitration fire.
        if command not in _ENH_VALID_RESPONSE_COMMANDS:
            self._trace(f"Unknown ENH command 0x{command:02X} data=0x{data:02X}")
        return ("frame", command, data)

    def _init_transport(self, *, features: int) -> None:
        self._trace(f"INIT features=0x{features:02X}")
        self._send_enh_frame(_ENH_REQ_INIT, features)
        deadline = time.monotonic() + self._config.timeout_s
        while time.monotonic() < deadline:
            try:
                kind, command, data = self._read_message()
            except TransportTimeout:
                self._trace("INIT_RESP timeout")
                raise
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
                raise TransportHostError(f"ENH init host error 0x{data:02X}")
        self._trace("INIT_RESP deadline expired (bus data flooding)")
        raise TransportTimeout("ENH init deadline expired (bus data flooding)")

    def _start_arbitration(self, initiator: int) -> None:
        self._trace(f"START initiator=0x{initiator:02X}")
        self._send_enh_frame(_ENH_REQ_START, initiator)
        now = time.monotonic()
        deadline = now + self._config.timeout_s
        # VE11: Absolute cap prevents infinite wait on a flooded bus.
        # Activity deadline resets on each RECEIVED frame, but the
        # absolute cap (10× timeout) is never extended.
        absolute_cap = now + self._config.timeout_s * 10
        mismatch_count = 0
        while time.monotonic() < min(deadline, absolute_cap):
            kind, command, data = self._read_message()
            if kind != "frame":
                continue
            if command == _ENH_RES_RECEIVED:
                # VE11: Bus traffic extends activity deadline — received
                # frames should not consume arbitration budget.
                deadline = time.monotonic() + self._config.timeout_s
                # R6-VE-NEW-01: Do NOT reset mismatch_count on RECEIVED.
                # Aligns with Go StartArbitration behavior — prevents
                # adversarial STARTED(wrong)+RECEIVED alternation from
                # bypassing the 3-mismatch abort guard.
                continue
            if command == _ENH_RES_STARTED and data == initiator:
                self._trace(f"START_RESP started initiator=0x{data:02X}")
                self._reset_parser()
                return
            if command == _ENH_RES_STARTED and data != initiator:
                # VE-NEW-07 / EG14/EG39: Abort early on repeated
                # STARTED with wrong address instead of waiting for
                # the full absolute cap timeout.
                mismatch_count += 1
                self._trace(
                    f"START_RESP mismatch want=0x{initiator:02X} "
                    f"got=0x{data:02X} (n={mismatch_count})"
                )
                if mismatch_count >= 3:
                    self._reset_parser()
                    raise _EnhancedCollision(
                        f"Arbitration mismatch: expected 0x{initiator:02X}, "
                        f"got 0x{data:02X} ({mismatch_count}× consecutive)"
                    )
                continue
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
                raise TransportHostError(f"enhanced arbitration host error 0x{data:02X}")
            if command == _ENH_RES_RESETTED:
                self._trace(f"START_RESP reset features=0x{data:02X}")
                self.close()
                self._open_session()
                raise _EnhancedCollision(
                    f"Adapter reset during arbitration (features=0x{data:02X})"
                )
        self._trace("START_RESP deadline expired")
        raise _EnhancedCollision("Arbitration deadline expired (bus data flooding)")

    def _recv_bus_symbol(self, *, deadline: float | None = None) -> int:
        if deadline is None:
            deadline = time.monotonic() + self._config.timeout_s
        while time.monotonic() < deadline:
            kind, command, data = self._read_message()
            if kind == "data":
                return command
            if command == _ENH_RES_RECEIVED:
                return data
            if command == _ENH_RES_RESETTED:
                self.close()
                self._open_session()
                raise TransportTimeout(f"Adapter reset during bus read (features=0x{data:02X})")
            if command == _ENH_RES_INFO:
                continue
            if command == _ENH_RES_FAILED:
                # D2: Explicitly trace FAILED during response read (Go silently
                # drops these — Python raises, which is stricter and correct).
                self._trace(f"BUS_READ_FAILED data=0x{data:02X}")
                raise _EnhancedCollision(f"Bus FAILED during read (data=0x{data:02X})")
            if command == _ENH_RES_ERROR_EBUS:
                raise TransportError(f"enhanced bus read eBUS error 0x{data:02X}")
            if command == _ENH_RES_ERROR_HOST:
                raise TransportHostError(f"enhanced bus read host error 0x{data:02X}")
            # D3: Unreachable after parse-level rejection in _parse_enh_byte.
            # Kept as defense-in-depth safety net.
            self._trace(f"Unexpected ENH command 0x{command:02X} data=0x{data:02X}")
            continue
        raise TransportTimeout("Bus symbol read deadline expired")

    def _send_symbol_with_echo(self, symbol: int) -> None:
        """Send a logical eBUS byte via ENH SEND and verify the echo.

        The enhanced adapter firmware handles wire escape encoding
        (0xA9->[0xA9,0x00], 0xAA->[0xA9,0x01]) transparently.  The ENH
        protocol operates at the logical byte level -- no client-side
        escape encoding is needed or desired.

        Audit VE1/VE20: Verified correct -- adapter firmware handles wire
        escape encoding.  Client-side escaping would cause double-encoding
        corruption on the physical bus.
        """
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

    def request_info(self, info_id: int) -> int:
        """Query adapter metadata via ENH INFO request (D4).

        Sends _ENH_REQ_INFO with the given info_id and waits for the
        corresponding _ENH_RES_INFO response.  Returns the data byte
        from the response.

        Known INFO IDs:
          0x00 — firmware version
          0x01 — jumper/hardware config
          0x06 — device identification (gated on 0x00)
          0x07 — build timestamp (gated on 0x00)
        """
        _validate_u8("info_id", info_id)
        self._trace(f"INFO_REQ id=0x{info_id:02X}")
        self._send_enh_frame(_ENH_REQ_INFO, info_id)
        deadline = time.monotonic() + self._config.timeout_s
        while time.monotonic() < deadline:
            kind, command, data = self._read_message()
            if kind != "frame":
                continue
            if command == _ENH_RES_INFO:
                self._trace(f"INFO_RESP id=0x{info_id:02X} data=0x{data:02X}")
                return data
            if command == _ENH_RES_ERROR_HOST:
                raise TransportHostError(f"INFO request 0x{info_id:02X} host error 0x{data:02X}")
            if command == _ENH_RES_ERROR_EBUS:
                raise TransportError(f"INFO request 0x{info_id:02X} eBUS error 0x{data:02X}")
            if command == _ENH_RES_RESETTED:
                self.close()
                self._open_session()
                raise TransportTimeout(f"Adapter reset during INFO (features=0x{data:02X})")
        raise TransportTimeout(f"INFO request 0x{info_id:02X} deadline expired")

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
        if dst in (0x00, _EBUS_ESCAPE, _EBUS_SYN):
            raise ValueError(
                f"dst 0x{dst:02X} is a reserved address "
                f"(0x00, 0xA9/ESCAPE, 0xAA/SYN are not valid destination addresses)"
            )
        _validate_u8("primary", primary)
        _validate_u8("secondary", secondary)
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(f"payload must be bytes-like, got {type(payload).__name__}")
        if len(payload) > 0xFF:
            raise ValueError(f"payload too large for eBUS telegram: {len(payload)} bytes")

        with self._lock:
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

    def _reconnect(self, seq: int, attempt: int) -> None:
        """Close the current session and re-establish a fresh TCP + INIT handshake."""
        self._trace(
            f"#{seq} RECONNECT attempt={attempt}/{self._config.reconnect_max_retries} "
            f"delay={self._config.reconnect_delay_s}s"
        )
        self.close()
        time.sleep(self._config.reconnect_delay_s)
        self._open_session()

    def _send_with_policy(self, seq: int, send_once: Callable[[], bytes]) -> bytes:
        timeout_retries = 0
        reconnect_retries = 0
        collision_retries = 0
        nack_retries = 0

        while True:
            try:
                return send_once()
            except TransportTimeout as exc:
                timeout_retries += 1
                if timeout_retries > self._config.timeout_max_retries:
                    # Timeout retries exhausted — try TCP reconnect before giving up.
                    reconnect_retries += 1
                    if reconnect_retries > self._config.reconnect_max_retries:
                        self.close()
                        raise TransportTimeout(
                            f"{exc} (reconnect retries exhausted "
                            f"({self._config.reconnect_max_retries}))"
                        ) from exc
                    try:
                        self._reconnect(seq, reconnect_retries)
                    except (TransportError, TransportTimeout, OSError) as reconn_exc:
                        self._trace(f"#{seq} RECONNECT failed: {reconn_exc}")
                        if reconnect_retries >= self._config.reconnect_max_retries:
                            raise TransportTimeout(
                                f"{exc} (reconnect failed: {reconn_exc})"
                            ) from exc
                        time.sleep(self._config.reconnect_delay_s)
                        continue
                    # R6-VE-NEW-02: Reset ALL retry counters on successful
                    # reconnect — fresh TCP session deserves fresh budget.
                    # VE23 originally kept timeout cumulative, but R6 feedback
                    # showed this starves fresh sessions of timeout retries.
                    # Unbounded loops are prevented by reconnect_max_retries.
                    timeout_retries = 0
                    collision_retries = 0
                    nack_retries = 0
                    continue
                # First timeout: reset parser and retry on the same session.
                self._reset_parser()
                self._trace(
                    f"#{seq} RETRY type=timeout "
                    f"n={timeout_retries}/{self._config.timeout_max_retries}"
                )
            except TransportHostError:
                # Host errors are non-retryable — the request is malformed.
                raise
            except TransportDisconnected as exc:
                # Clean EOF — attempt TCP reconnect.
                reconnect_retries += 1
                if reconnect_retries > self._config.reconnect_max_retries:
                    self.close()
                    raise TransportError(
                        f"{exc} (reconnect retries exhausted "
                        f"({self._config.reconnect_max_retries}))"
                    ) from exc
                try:
                    self._reconnect(seq, reconnect_retries)
                except (TransportError, TransportTimeout, OSError) as reconn_exc:
                    self._trace(f"#{seq} RECONNECT failed: {reconn_exc}")
                    if reconnect_retries >= self._config.reconnect_max_retries:
                        raise TransportError(f"{exc} (reconnect failed: {reconn_exc})") from exc
                    time.sleep(self._config.reconnect_delay_s)
                    continue
                continue
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
                    message = (
                        f"{exc} (nack/crc retries exhausted ({self._config.nack_max_retries}))"
                    )
                    if isinstance(exc, _EnhancedNack):
                        raise TransportNack(message) from exc
                    raise TransportError(message) from exc
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

        # VE4: Local NACK retry without re-arbitration (per eBUS spec 7.4).
        # After NACK the bus is still owned — retry the telegram directly.
        # Honors nack_max_retries config (attempts = 1 + nack_max_retries).
        max_nack_attempts = 1 + self._config.nack_max_retries
        for nack_attempt in range(max_nack_attempts):
            if nack_attempt > 0:
                self._trace(f"#{seq} LOCAL_NACK_RETRY attempt={nack_attempt}")

            for symbol in telegram[1:]:
                self._send_symbol_with_echo(symbol)

            if dst == _ADDRESS_BROADCAST or not expect_response:
                self._send_end_of_message()
                self._trace(f"#{seq} RECV_PROTO broadcast_or_no_response")
                return b""

            ack = self._recv_bus_symbol()
            if ack == _EBUS_NACK:
                if nack_attempt < max_nack_attempts - 1:
                    continue  # retry without re-arbitration
                # Local retry exhausted — raise non-retryable TransportNack
                # so _send_with_policy does NOT re-arbitrate again.
                raise TransportNack("nack received (local retry exhausted)")
            if ack != _EBUS_ACK:
                # In ENH protocol, 0xAA (SYN) from _recv_bus_symbol is a data
                # byte, not a bus-idle signal.  Treat any non-ACK/non-NACK as
                # an unexpected symbol error (not a timeout).
                raise TransportError(f"unexpected symbol 0x{ack:02X} while waiting for command ack")

            if _is_initiator_capable_address(dst):
                self._send_end_of_message()
                self._trace(f"#{seq} RECV_PROTO initiator_initiator=no_response")
                return b""

            # VE26-R2: Cumulative deadline for the entire response read.
            response_deadline = time.monotonic() + self._config.timeout_s

            for response_attempt in range(2):
                # In the ENH protocol, response bytes arrive via _ENH_RES_RECEIVED
                # frames.  The adapter firmware handles wire-level SYN detection and
                # reports bus loss via _ENH_RES_FAILED / _ENH_RES_ERROR_*, NOT by
                # sending a RECEIVED frame with data=0xAA.  Therefore 0xAA from
                # _recv_bus_symbol() is a legitimate data byte (the adapter decoded
                # wire-escaped [0xA9, 0x01] back to logical 0xAA).  SYN guards are
                # not needed here — _recv_bus_symbol() already raises appropriate
                # exceptions for real bus errors and timeouts.
                length = self._recv_bus_symbol(deadline=response_deadline)

                response = bytearray()
                for _ in range(length):
                    value = self._recv_bus_symbol(deadline=response_deadline)
                    response.append(value)

                crc_value = self._recv_bus_symbol(deadline=response_deadline)

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

        raise TransportTimeout("unreachable enhanced nack retry loop")

    def command_lines(self, command: str, *, read_all: bool = False) -> list[str]:
        _ = read_all
        raise TransportError(
            f"enhanced adapter transport does not support ebusd command passthrough: {command!r}"
        )
