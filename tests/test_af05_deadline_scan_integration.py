"""Real request deadlines through ``scan_b524`` keep scan evidence and accounting.

Both production transports run their own deadline, retry, reconnect, backoff,
framing and response code underneath the real ``CountingTransport`` and
``scan_b524``.  Only the boundaries are replaced: the transport modules'
``socket.create_connection`` returns an in-memory socket, and their ``time``
reference is a virtual clock whose ``sleep`` only advances that clock.  No real
socket, loopback listener, sleep, thread or adapter is used.

Every scripted phase consumes a binary-exact amount of virtual time, so reaching
the deadline is an equality, never a rounding accident.  All bytes are synthetic
and only a scripted target answers: an omitted reply (``None`` in a script) is
silence, distinct from an empty ``b""`` reply.  This is a software budget for
transport-controlled waits; nothing here measures native or physical timing,
proves target absence, or qualifies a selector.
"""

from __future__ import annotations

import json
import math
import socket
import struct
import threading
from collections import deque
from collections.abc import Iterator
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any

import pytest

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport import ebusd_tcp, enhanced_tcp
from helianthus_vrc_explorer.transport.base import (
    TransportRecoveryExhausted,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.ebusd_tcp import EbusdTcpConfig, EbusdTcpTransport
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
    _encode_enh,
)
from helianthus_vrc_explorer.transport.instrumented import (
    CountingTransport,
    ScanRequestBudgetExceeded,
)
from helianthus_vrc_explorer.transport.request_deadline import RequestDeadlineExpired

_SRC = 0xF7  # Enhanced default initiator.
_RECV_LIMIT = 20000  # A regressed loop fails here instead of spinning.

# ebusd command port: connection setup and every scripted reply cost 0.25 s and
# 0.5 s; a mandatory read waits at most 4 s; three attempts fit in 7 s.
_EBUSD_CONNECT_S = 0.25
_EBUSD_REPLY_S = 0.5
_EBUSD_TIMEOUT_S = 4.0
_EBUSD_BUDGET_S = 7.0
# Enhanced adapter: every ENH frame costs 1/64 s; one symbol wait is 1 s.
_ENH_SYMBOL_S = 0.015625
_ENH_TIMEOUT_S = 1.0

TRANSPORTS = ("ebusd", "enhanced")
MODES = ("session", "standalone")


class VirtualClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        assert seconds >= 0.0
        assert len(self.slept) < _RECV_LIMIT, "regressed backoff loop"
        self.slept.append(seconds)
        self.now += seconds

    def advance(self, seconds: float) -> None:
        assert seconds >= 0.0
        self.now += seconds


# --- synthetic target -----------------------------------------------------------


@dataclass(frozen=True)
class Selector:
    """One explicit plan: three registers, the middle one is the pending one."""

    dst: int = 0x15
    opcode: int = 0x02
    group: int = 0x00
    instance: int = 0x00
    registers: tuple[int, int, int] = (0x0000, 0x0001, 0x0002)

    @property
    def description_opcode(self) -> int:
        return 0x01 if self.opcode == 0x02 else 0x07

    def read(self, register: int) -> bytes:
        return bytes((self.opcode, 0x00, self.group, self.instance)) + register.to_bytes(
            2, "little"
        )

    def describe(self, register: int) -> bytes:
        return bytes((self.description_opcode, self.group, self.instance)) + register.to_bytes(
            2, "little"
        )

    def plan(self) -> dict[Any, GroupScanPlan]:
        return {
            make_plan_key(self.group, self.opcode): GroupScanPlan(
                group=self.group,
                opcode=self.opcode,
                instances=(self.instance,),
                rr_max=max(self.registers),
                registers=self.registers,
            )
        }


BASE = Selector()
# Each variant changes exactly one key of the baseline selector.
SELECTOR_VARIANTS = {
    "baseline": BASE,
    "destination": replace(BASE, dst=0x26),
    "opcode": replace(BASE, opcode=0x06),
    "group": replace(BASE, group=0x03),
    "instance": replace(BASE, instance=0x01),
    "register": replace(BASE, registers=(0x0000, 0x0005, 0x0006)),
}
# OP00 has its own identifier key; destination is varied independently.
OP00_VARIANTS = {
    "baseline": (0x15, 0x0003),
    "identifier": (0x15, 0x000B),
    "destination": (0x26, 0x0003),
}


_OP00_SENTINEL = 0x0002  # Observed invalid value: bytes retained, value null.
_NAN = bytes.fromhex("0000c07f")


def _op00(identifier: int) -> bytes:
    return b"\x00" + identifier.to_bytes(2, "little")


def _answer(payload: bytes) -> bytes:
    """Synthetic replies whose bytes depend on every selector key echoed."""

    opcode = payload[0]
    if opcode == 0x00 and len(payload) == 3:
        identifier = int.from_bytes(payload[1:3], "little")
        if identifier == _OP00_SENTINEL:
            return _NAN
        return struct.pack("<f", float(identifier + 1))
    if opcode in {0x02, 0x06} and len(payload) == 6 and payload[1] == 0x00:
        register = int.from_bytes(payload[4:6], "little")
        value = (0x0110 + register + (payload[3] << 4)).to_bytes(2, "little")
        return bytes((0x03, payload[2])) + payload[4:6] + value
    if opcode in {0x01, 0x07} and len(payload) == 5:
        return payload[1:2] + payload[3:5] + bytes.fromhex("000064000100")
    raise AssertionError(f"unscripted synthetic request {payload.hex()}")


class Target:
    """The addressed device: one pending request may misbehave, others answer.

    ``behavior`` for the pending request: ``silent`` omits every reply,
    ``err_timeout`` makes ebusd report a bus timeout, and ``late`` delivers a
    valid reply whose final byte arrives exactly at the operation deadline.
    """

    def __init__(self, dst: int, *, pending: bytes | None = None, behavior: str = "silent") -> None:
        self.dst = dst
        self.pending = pending
        self.behavior = behavior
        # Set by the rig: the operation budget and the time an operation spends
        # before its first wire byte (the per-command connect of ebusd only).
        self.budget_s: float | None = None
        self.pre_wire_s = 0.0
        self.requests: list[tuple[float, int, bytes]] = []  # (op wire start, dst, payload)

    def payloads_sent(self, payload: bytes) -> int:
        return sum(1 for _start, _dst, item in self.requests if item == payload)

    def deadline_for(self, start: float) -> float:
        assert self.budget_s is not None
        return start - self.pre_wire_s + self.budget_s

    def decide(self, start: float, dst: int, payload: bytes) -> tuple[str, bytes | None]:
        self.requests.append((start, dst, payload))
        if dst != self.dst:
            return ("silent", None)  # Nobody answers a wrong destination.
        if payload == self.pending:
            if self.behavior == "silent":
                return ("silent", None)
            return (self.behavior, _answer(payload))
        return ("reply", _answer(payload))


# --- in-memory socket boundary ------------------------------------------------------


class FakeSocket:
    """Every blocking wait is bounded by the applied timeout, in virtual time."""

    def __init__(self, peer: EbusdPeer | EnhancedPeer) -> None:
        self.peer = peer
        self.timeout: float | None = None
        self.blocking = True
        self.closed = False
        self.rx: deque[tuple[float, bytes]] = deque()

    def settimeout(self, timeout: float | None) -> None:
        assert timeout is not None and timeout > 0.0
        self.timeout = timeout
        self.blocking = True

    def setblocking(self, blocking: bool) -> None:
        self.blocking = blocking

    def setsockopt(self, *_args: object) -> None:
        pass

    def sendall(self, data: bytes) -> None:
        assert not self.closed
        self.peer.send_times.append(self.peer.clock.now)
        self.peer.on_wire(self, bytes(data))

    def recv(self, size: int) -> bytes:
        assert not self.closed
        if not self.blocking:
            # Stale-buffer drain: only bytes that have already arrived.
            if self.rx and self.rx[0][0] == 0.0:
                return self.rx.popleft()[1]
            raise BlockingIOError
        peer = self.peer
        peer.recv_calls += 1
        assert peer.recv_calls < _RECV_LIMIT, "regressed receive loop"
        timeout = self.timeout
        assert timeout is not None
        cost, chunk = self.rx[0] if self.rx else (math.inf, b"")
        if cost > timeout:
            # The OS waits exactly the applied timeout; the bytes stay pending.
            peer.clock.advance(timeout)
            if self.rx:
                self.rx[0] = (cost - timeout, chunk)
            raise TimeoutError("scripted receive timeout")
        self.rx.popleft()
        peer.clock.advance(cost)
        if len(chunk) > size:
            self.rx.appendleft((0.0, chunk[size:]))
            chunk = chunk[:size]
        return chunk

    def close(self) -> None:
        self.closed = True


class EbusdPeer:
    """Scripted ebusd command port in front of one synthetic target."""

    def __init__(self, clock: VirtualClock, target: Target) -> None:
        self.clock = clock
        self.target = target
        self.sockets: list[FakeSocket] = []
        self.send_times: list[float] = []
        self.recv_calls = 0

    def connect(self, _address: object, timeout: float) -> FakeSocket:
        assert 0.0 < timeout <= _EBUSD_TIMEOUT_S
        self.clock.advance(_EBUSD_CONNECT_S)
        sock = FakeSocket(self)
        self.sockets.append(sock)
        return sock

    def on_wire(self, sock: FakeSocket, data: bytes) -> None:
        text = data.decode("ascii")
        assert text.startswith("hex ") and text.endswith("\n"), text
        telegram = bytes.fromhex(text[4:-1])
        dst, primary, secondary, length = telegram[:4]
        payload = telegram[4:]
        assert (primary, secondary, length) == (0xB5, 0x24, len(payload))
        start = self.clock.now
        kind, reply = self.target.decide(start, dst, payload)
        if kind == "silent":
            return
        if kind == "err_timeout":
            sock.rx.append((_EBUSD_REPLY_S, b"ERR: timeout\n\n"))
            return
        assert reply is not None
        line = f"{len(reply):02x}{reply.hex()}\n\n".encode("ascii")
        if kind == "reply":
            sock.rx.append((_EBUSD_REPLY_S, line))
            return
        assert kind == "late"
        # Six one-second fragments, then the terminating fragment exactly at
        # the deadline: a slow trickle that must not renew any wait.
        pieces = [line[index * 3 : index * 3 + 3] for index in range(6)] + [line[18:]]
        final_s = self.target.deadline_for(start) - start - 6.0
        assert 0.0 < final_s <= _EBUSD_TIMEOUT_S
        sock.rx.extend([(1.0, piece) for piece in pieces[:-1]] + [(final_s, pieces[-1])])


def _wire(logical: bytes) -> list[int]:
    symbols: list[int] = []
    for value in logical:
        if value == 0xA9:
            symbols.extend((0xA9, 0x00))
        elif value == 0xAA:
            symbols.extend((0xA9, 0x01))
        else:
            symbols.append(value)
    return symbols


def _received(symbol: int) -> bytes:
    return _encode_enh(_ENH_RES_RECEIVED, symbol)


class EnhancedPeer:
    """Scripted ENH adapter: echoes, arbitration and one synthetic bus target."""

    def __init__(self, clock: VirtualClock, target: Target) -> None:
        self.clock = clock
        self.target = target
        self.sockets: list[FakeSocket] = []
        self.send_times: list[float] = []
        self.recv_calls = 0
        self.connect_timeouts: list[float] = []
        self._start: float | None = None
        self._logical: bytearray | None = None
        self._escape = False

    def connect(self, _address: object, timeout: float) -> FakeSocket:
        assert 0.0 < timeout <= _ENH_TIMEOUT_S
        self.connect_timeouts.append(timeout)
        self.clock.advance(_ENH_SYMBOL_S)
        sock = FakeSocket(self)
        self.sockets.append(sock)
        return sock

    def _queue(self, sock: FakeSocket, frame: bytes, cost: float = _ENH_SYMBOL_S) -> None:
        sock.rx.append((cost, frame))

    def on_wire(self, sock: FakeSocket, frame: bytes) -> None:
        assert len(frame) == 2
        command = (frame[0] >> 2) & 0x0F
        data = ((frame[0] & 0x03) << 6) | (frame[1] & 0x3F)
        if command == _ENH_REQ_INIT:
            self._queue(sock, _encode_enh(_ENH_RES_RESETTED, data))
            return
        if command == _ENH_REQ_START:
            assert data == _SRC
            self._start = self.clock.now
            self._logical = bytearray()
            self._escape = False
            self._queue(sock, _encode_enh(_ENH_RES_STARTED, data))
            return
        assert command == _ENH_REQ_SEND
        self._queue(sock, _received(data))  # Every sent wire symbol echoes.
        logical = self._logical
        if logical is None:
            return  # ACK/NACK/SYN after the target's reply.
        if self._escape:
            self._escape = False
            logical.append({0x00: 0xA9, 0x01: 0xAA}[data])
        elif data == 0xA9:
            self._escape = True
            return
        else:
            logical.append(data)
        if len(logical) < 4 or len(logical) < 5 + logical[3]:
            return
        self._logical = None
        assert _crc(bytes((_SRC,)) + bytes(logical[:-1])) == logical[-1]
        dst, primary, secondary, _length = logical[:4]
        assert (primary, secondary) == (0xB5, 0x24)
        assert self._start is not None
        kind, reply = self.target.decide(self._start, dst, bytes(logical[4:-1]))
        if kind == "silent":
            return
        assert reply is not None and kind in {"reply", "late"}
        segment = bytes((len(reply),)) + reply
        symbols = _wire(segment + bytes((_crc(segment),)))
        costs = [_ENH_SYMBOL_S] * (1 + len(symbols))
        if kind == "late":
            # The final response symbol arrives exactly at the deadline.
            echo_end = self.clock.now + _ENH_SYMBOL_S  # This symbol's echo.
            final_s = self.target.deadline_for(self._start) - echo_end - sum(costs[:-1])
            assert 0.0 < final_s <= _ENH_TIMEOUT_S
            costs[-1] = final_s
        self._queue(sock, _received(0x00), costs[0])  # Target ACK.
        for symbol, cost in zip(symbols, costs[1:], strict=True):
            self._queue(sock, _received(symbol), cost)


# --- harness ----------------------------------------------------------------------


@dataclass
class Rig:
    kind: str
    mode: str
    clock: VirtualClock
    target: Target
    peer: EbusdPeer | EnhancedPeer
    transport: EbusdTcpTransport | EnhancedTcpTransport
    # Snapshot taken when the scan returned, before any later operation.
    scan_end: float = math.nan
    scan_requests: tuple[tuple[float, int, bytes], ...] = ()
    scan_send_times: tuple[float, ...] = ()
    scan_unread: int = -1

    def scan_payloads(self) -> list[bytes]:
        return [payload for _start, _dst, payload in self.scan_requests]

    def scan_count(self, payload: bytes) -> int:
        return self.scan_payloads().count(payload)

    def first_start(self, payload: bytes) -> float:
        return next(start for start, _dst, item in self.scan_requests if item == payload)

    @property
    def budget_s(self) -> float:
        return self.transport._config.max_command_s

    def session(self) -> AbstractContextManager[object]:
        return self.transport.session() if self.mode == "session" else nullcontext()


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Any escape past the scripted boundary fails instead of opening a socket."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("real network access attempted")

    monkeypatch.setattr(socket, "create_connection", refuse)
    threads = threading.active_count()
    yield
    assert threading.active_count() == threads  # No abandoned worker.


def _rig(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    mode: str,
    target: Target,
    *,
    max_command_s: float | None,
) -> Rig:
    clock = VirtualClock()
    peer: EbusdPeer | EnhancedPeer
    budget = {} if max_command_s is None else {"max_command_s": max_command_s}
    transport: EbusdTcpTransport | EnhancedTcpTransport
    if kind == "ebusd":
        module: Any = ebusd_tcp
        peer = EbusdPeer(clock, target)
        transport = EbusdTcpTransport(
            EbusdTcpConfig(host="ebusd.invalid", timeout_s=_EBUSD_TIMEOUT_S, **budget)
        )
        target.pre_wire_s = _EBUSD_CONNECT_S if mode == "standalone" else 0.0
    else:
        module = enhanced_tcp
        peer = EnhancedPeer(clock, target)
        transport = EnhancedTcpTransport(
            EnhancedTcpConfig(host="adapter.invalid", timeout_s=_ENH_TIMEOUT_S, **budget)
        )
        target.pre_wire_s = 0.0  # The session stays open between operations.
    target.budget_s = transport._config.max_command_s
    # Replace only the module references: process-wide time and socket stay intact.
    monkeypatch.setattr(
        module, "time", SimpleNamespace(monotonic=clock.monotonic, sleep=clock.sleep)
    )
    monkeypatch.setattr(
        module,
        "socket",
        SimpleNamespace(
            create_connection=peer.connect,
            IPPROTO_TCP=socket.IPPROTO_TCP,
            TCP_NODELAY=socket.TCP_NODELAY,
        ),
    )
    return Rig(kind, mode, clock, target, peer, transport)


def _scan(
    rig: Rig,
    selector: Selector,
    *,
    request_budget: int | None = None,
    fresh: bytes | None = None,
    closed: bool = True,
) -> dict[str, Any]:
    with rig.session():
        artifact = scan_b524(
            rig.transport,
            dst=selector.dst,
            planner_preset="custom",
            explicit_plan=selector.plan(),
            request_budget=request_budget,
        )
        rig.scan_end = rig.clock.now
        rig.scan_requests = tuple(rig.target.requests)
        rig.scan_send_times = tuple(rig.peer.send_times)
        rig.scan_unread = sum(len(sock.rx) for sock in rig.peer.sockets)
        if fresh is not None:
            _assert_fresh_operation(rig, selector, fresh, closed=closed)
    return artifact


def _registers(artifact: dict[str, Any], selector: Selector) -> dict[str, Any]:
    operation = artifact["operations"][f"0x{selector.opcode:02x}"]
    group = operation["groups"][f"0x{selector.group:02x}"]
    return group["instances"][f"0x{selector.instance:02x}"]["registers"]


def _instance(artifact: dict[str, Any], selector: Selector) -> dict[str, Any]:
    operation = artifact["operations"][f"0x{selector.opcode:02x}"]
    return operation["groups"][f"0x{selector.group:02x}"]["instances"][f"0x{selector.instance:02x}"]


def _control(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str, selector: Selector
) -> dict[str, Any]:
    """The same scan with nothing pending: the evidence a prefix must keep."""

    with monkeypatch.context() as patch:
        rig = _rig(patch, kind, mode, Target(selector.dst), max_command_s=None)
        artifact = _scan(rig, selector)
    assert artifact["meta"]["incomplete"] is False
    return artifact


_RAW_FIELDS = ("reply_hex", "raw_hex", "value", "type", "flags", "response_state", "error")


def _raw(entry: dict[str, Any]) -> dict[str, Any]:
    return {name: entry.get(name) for name in _RAW_FIELDS}


def _expected_recovery(
    attempts: int, reconnects: int, pending_selector: dict[str, str]
) -> dict[str, Any]:
    return {
        "cause": "timeout",
        "phase": "transaction",
        "request_attempts": attempts,
        "retry_count": attempts - 1,
        "reconnect_attempts": reconnects,
        "pending_selector": pending_selector,
    }


def _assert_boundary(
    artifact: dict[str, Any],
    rig: Rig,
    pending: bytes,
    attempts: int,
    *,
    prior: int,
    prior_exceeds_budget: bool = True,
) -> None:
    """Admitted attempts are counted exactly once and nothing after expiry."""

    meta = artifact["meta"]
    # Each admitted attempt reached the wire once; nothing was sent at expiry.
    assert rig.scan_count(pending) == attempts
    assert max(rig.scan_send_times) < rig.scan_end
    assert meta["scan_coverage"]["actual_requests"] == prior + attempts
    evidence = [
        item for item in meta["transport_boundary_evidence"] if item["request_hex"] == pending.hex()
    ]
    assert len(evidence) == attempts
    assert all(item["reply_hex"] is None for item in evidence)
    assert all(item["destination_address"] == f"0x{rig.target.dst:02x}" for item in evidence)
    assert evidence[-1]["error_type"] == "TransportRecoveryExhausted"
    # The helper's internal expiry is translated, never leaked into output.
    text = json.dumps(artifact)
    assert "RequestDeadlineExpired" not in text and "request deadline expired" not in text
    # The pending operation used one whole, unrenewed budget from its own start.
    start = rig.first_start(pending) - rig.target.pre_wire_s
    assert rig.scan_end == start + rig.budget_s
    if prior_exceeds_budget:
        # Earlier successes took longer than one budget in total: no shared root.
        assert start > rig.budget_s


def _assert_fresh_operation(
    rig: Rig, selector: Selector, payload: bytes, *, closed: bool = True
) -> None:
    """After cleanup a new independent operation gets a new root and succeeds.

    Runs inside the scan's own session context, right after the scan returned.
    """

    if closed:
        # The ambiguous session was closed, so a new one must be opened.
        assert all(sock.closed for sock in rig.peer.sockets)
    assert rig.transport._active_root() is None
    sockets = len(rig.peer.sockets)
    fresh = CountingTransport(rig.transport)
    start = rig.clock.now
    assert fresh.send(selector.dst, payload) == _answer(payload)
    assert 0.0 < rig.clock.now - start < rig.budget_s
    assert fresh.counters.send_calls == 1
    reconnects = closed or (rig.kind == "ebusd" and rig.mode == "standalone")
    assert len(rig.peer.sockets) == sockets + (1 if reconnects else 0)
    assert rig.transport._active_root() is None


# Per transport: the pending register's retry path and its exact accounting.
# ebusd: ``ERR: timeout`` gets the fixed 5 s quiet backoff; the second backoff
# is clamped to the remaining budget (1.0 s with a session, 0.5 s after the
# per-command connect).  Enhanced: three silent attempts (1 + 2 timeout
# retries) then one reconnect whose 2 s delay is clamped to 0.9375 s.
REGISTER_PATHS = {
    "ebusd": {"behavior": "err_timeout", "budget": _EBUSD_BUDGET_S, "attempts": 2, "reconnects": 0},
    "enhanced": {"behavior": "silent", "budget": 4.5, "attempts": 3, "reconnects": 1},
}


@pytest.mark.parametrize("variant", sorted(SELECTOR_VARIANTS))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_register_deadline_keeps_prior_evidence_and_exact_pending_selector(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str, variant: str
) -> None:
    selector = SELECTOR_VARIANTS[variant]
    first, pending_register, later = selector.registers
    pending = selector.read(pending_register)
    path = REGISTER_PATHS[kind]
    control = _control(monkeypatch, kind, mode, selector)
    target = Target(selector.dst, pending=pending, behavior=path["behavior"])
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=path["budget"])

    artifact = _scan(rig, selector, fresh=selector.read(later))

    meta = artifact["meta"]
    assert meta["destination_address"] == f"0x{selector.dst:02x}"
    assert meta["incomplete"] is True
    assert meta["incomplete_reason"] == "transport_recovery_exhausted"
    assert meta["scan_coverage"]["completed"] is False
    pending_selector = {
        "read_opcode": f"0x{selector.opcode:02x}",
        "group": f"0x{selector.group:02x}",
        "instance": f"0x{selector.instance:02x}",
        "register": f"0x{pending_register:04x}",
        "request_hex": pending.hex(),
    }
    assert meta["transport_recovery"] == _expected_recovery(
        path["attempts"], path["reconnects"], pending_selector
    )
    if kind == "ebusd":
        remainder = 1.0 if mode == "session" else 0.5
        assert rig.clock.slept == [5.0, remainder]
    else:
        assert rig.clock.slept == [0.9375]

    registers = _registers(artifact, selector)
    # The prior register keeps its raw bytes and value exactly as observed.
    prior_key = f"0x{first:04x}"
    assert _raw(registers[prior_key]) == _raw(_registers(control, selector)[prior_key])
    assert registers[f"0x{first:04x}"]["reply_hex"] == _answer(selector.read(first)).hex()
    # The pending register stays unknown: no bytes, state, absence or qualification.
    entry = registers[f"0x{pending_register:04x}"]
    assert entry["reply_hex"] is None and entry["raw_hex"] is None and entry["value"] is None
    assert entry["response_state"] is None
    assert entry["error"].startswith("transport_error: transport recovery exhausted: cause=timeout")
    assert entry["transport_diagnostic"] == {
        key: meta["transport_recovery"][key]
        for key in ("cause", "phase", "request_attempts", "retry_count", "reconnect_attempts")
    }
    assert "availability_qualification" not in entry
    assert "parameter_description" not in entry
    # The unattempted later register was never sent and claims nothing.
    assert f"0x{later:04x}" not in registers
    assert selector.read(later) not in rig.scan_payloads()
    assert not any(payload[0] in {0x01, 0x07} for payload in rig.scan_payloads())
    assert _instance(artifact, selector)["present"] is _instance(control, selector)["present"]
    assert meta["system_information"] == control["meta"]["system_information"]

    _assert_boundary(artifact, rig, pending, path["attempts"], prior=18 + 1)


# ebusd: a silent target forces one connection-level reconnect; its second wait
# is clamped to the remaining budget.  Enhanced: two silent attempts, the second
# wait clamped (0.71875 s).  Neither path sleeps.
OP00_PATHS = {
    "ebusd": {"budget": _EBUSD_BUDGET_S, "attempts": 2, "reconnects": 1},
    "enhanced": {"budget": 2.0, "attempts": 2, "reconnects": 0},
}


@pytest.mark.parametrize("variant", sorted(OP00_VARIANTS))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_system_information_deadline_keeps_prior_identifiers(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str, variant: str
) -> None:
    dst, identifier = OP00_VARIANTS[variant]
    selector = replace(BASE, dst=dst)
    pending = _op00(identifier)
    path = OP00_PATHS[kind]
    control = _control(monkeypatch, kind, mode, selector)
    target = Target(dst, pending=pending, behavior="silent")
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=path["budget"])

    artifact = _scan(rig, selector, fresh=_op00(identifier + 1))

    meta = artifact["meta"]
    assert meta["destination_address"] == f"0x{dst:02x}"
    assert meta["incomplete_reason"] == "transport_recovery_exhausted"
    assert meta["transport_recovery"] == _expected_recovery(
        path["attempts"],
        path["reconnects"],
        {"read_opcode": "0x00", "identifier": f"0x{identifier:04x}", "request_hex": pending.hex()},
    )
    assert rig.clock.slept == []
    # Prior identifiers keep their raw bytes and values, the observed sentinel
    # included.  The pending and later identifiers carry no bytes, value or
    # qualification: omitted (raw_hex null) is distinct from an observed reply.
    records = meta["system_information"]
    assert records[:identifier] == control["meta"]["system_information"][:identifier]
    assert [record["raw_hex"] for record in records[:identifier]] == [
        _answer(_op00(index)).hex() for index in range(identifier)
    ]
    assert [record["value"] for record in records[:identifier]] == [
        None if index == _OP00_SENTINEL else float(index + 1) for index in range(identifier)
    ]
    assert records[_OP00_SENTINEL]["raw_hex"] == _NAN.hex()
    for record in records[identifier:]:
        assert (record["raw_hex"], record["value"]) == (None, None)
        assert "qualification" not in record and "transport_diagnostic" not in record
    assert [record["identifier"] for record in records] == [f"0x{index:04x}" for index in range(18)]
    assert (
        rig.scan_payloads()
        == [_op00(index) for index in range(identifier)] + [pending] * path["attempts"]
    )
    assert artifact["operations"] == {}
    _assert_boundary(
        artifact, rig, pending, path["attempts"], prior=identifier, prior_exceeds_budget=False
    )


# The pending description's valid reply is delivered as a slow trickle whose
# last byte arrives exactly at the deadline: it is refused, never retried.
DESCRIPTION_BUDGETS = {"ebusd": _EBUSD_BUDGET_S, "enhanced": 1.0}


@pytest.mark.parametrize("variant", sorted(SELECTOR_VARIANTS))
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_description_deadline_refuses_late_reply_and_keeps_prior_description(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str, variant: str
) -> None:
    selector = SELECTOR_VARIANTS[variant]
    first, pending_register, later = selector.registers
    pending = selector.describe(pending_register)
    control = _control(monkeypatch, kind, mode, selector)
    target = Target(selector.dst, pending=pending, behavior="late")
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=DESCRIPTION_BUDGETS[kind])

    artifact = _scan(rig, selector, fresh=selector.describe(later))

    meta = artifact["meta"]
    assert meta["incomplete_reason"] == "transport_recovery_exhausted"
    assert meta["transport_recovery"] == _expected_recovery(
        1,
        0,
        {
            "description_opcode": f"0x{selector.description_opcode:02x}",
            "read_opcode": f"0x{selector.opcode:02x}",
            "group": f"0x{selector.group:02x}",
            "instance": f"0x{selector.instance:02x}",
            "register": f"0x{pending_register:04x}",
            "request_hex": pending.hex(),
        },
    )
    assert rig.scan_unread == 0  # The complete reply was delivered, at the deadline.
    assert rig.clock.slept == []
    registers = _registers(artifact, selector)
    control_registers = _registers(control, selector)
    for register in selector.registers:
        key = f"0x{register:04x}"
        assert _raw(registers[key]) == _raw(control_registers[key])
    # The prior description is retained unchanged, raw reply included.
    prior = registers[f"0x{first:04x}"]["parameter_description"]
    assert prior == control_registers[f"0x{first:04x}"]["parameter_description"]
    assert prior["reply_hex"] == _answer(selector.describe(first)).hex()
    # The late reply is not evidence: omitted, not empty, and not qualified.
    late = registers[f"0x{pending_register:04x}"]["parameter_description"]
    assert "reply_hex" not in late
    assert late["qualification"] == "unavailable"
    assert late["reason"].startswith(
        "transport recovery exhausted: cause=timeout phase=transaction"
    )
    assert (late["request_attempted"], late["request_attempts"]) == (True, 1)
    assert late["request_hex"] == pending.hex()
    # The later candidate was never sent.
    unattempted = registers[f"0x{later:04x}"]["parameter_description"]
    assert unattempted["request_attempted"] is False
    assert selector.describe(later) not in rig.scan_payloads()
    coverage = meta["parameter_description_coverage"]
    assert (coverage["attempted"], coverage["not_attempted"], coverage["matched"]) == (2, 1, 0)
    assert coverage["request_attempts"] == 2
    assert _instance(artifact, selector)["present"] is _instance(control, selector)["present"]
    _assert_boundary(artifact, rig, pending, 1, prior=18 + 3 + 1)


def test_both_transports_default_to_a_finite_thirty_second_budget() -> None:
    assert EbusdTcpConfig().max_command_s == 30.0
    assert EnhancedTcpConfig().max_command_s == 30.0


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_attempt_limit_wins_when_it_is_reached_before_the_default_deadline(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str
) -> None:
    """The same scripts as the register test, under the default 30 s budget."""

    selector = BASE
    first, pending_register, later = selector.registers
    pending = selector.read(pending_register)
    target = Target(selector.dst, pending=pending, behavior=REGISTER_PATHS[kind]["behavior"])
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=None)
    assert rig.budget_s == 30.0

    artifact = _scan(rig, selector)

    start = rig.first_start(pending) - target.pre_wire_s
    registers = _registers(artifact, selector)
    if kind == "ebusd":
        # 1 + 5 timeout retries, five full 5 s backoffs: 28 s (29.5 s with
        # per-command connects).  The count limit ends one read; scanning goes on.
        assert rig.scan_count(pending) == 6
        assert rig.clock.slept[:5] == [5.0] * 5
        assert artifact["meta"]["incomplete"] is False
        assert "transport_recovery" not in artifact["meta"]
        assert registers[f"0x{pending_register:04x}"]["response_state"] == "timeout"
        assert registers[f"0x{later:04x}"]["value"] is not None
    else:
        # Four sessions of three attempts and three full reconnect delays.
        assert rig.scan_count(pending) == 12
        assert rig.clock.slept == [2.0] * 3
        assert artifact["meta"]["transport_recovery"]["request_attempts"] == 12
        assert artifact["meta"]["transport_recovery"]["reconnect_attempts"] == 3
        assert rig.scan_end - start < 30.0
    assert registers[f"0x{first:04x}"]["reply_hex"] == _answer(selector.read(first)).hex()


@pytest.mark.parametrize("extra", ["before_pending", "at_retry", "exactly_enough"])
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_request_budget_is_a_count_cap_independent_of_the_deadline(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str, extra: str
) -> None:
    selector = BASE
    _first, pending_register, _later = selector.registers
    pending = selector.read(pending_register)
    path = REGISTER_PATHS[kind]
    prior = 18 + 1
    admitted = {"before_pending": 0, "at_retry": 1, "exactly_enough": path["attempts"]}[extra]
    target = Target(selector.dst, pending=pending, behavior=path["behavior"])
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=path["budget"])

    artifact = _scan(
        rig,
        selector,
        request_budget=prior + admitted,
        fresh=selector.read(selector.registers[0]),
        closed=extra == "exactly_enough",
    )

    meta = artifact["meta"]
    assert rig.scan_count(pending) == admitted
    assert meta["scan_coverage"]["actual_requests"] == prior + admitted
    if extra == "exactly_enough":
        # The deadline arrives first; no hook runs after it to hit the cap.
        assert meta["incomplete_reason"] == "transport_recovery_exhausted"
        assert meta["transport_recovery"]["request_attempts"] == admitted
        assert "budget_boundary_evidence" not in meta
        return
    # The count cap stops the scan while the operation still has time left.
    assert meta["incomplete_reason"] == "request_budget_exhausted"
    assert "transport_recovery" not in meta
    if admitted:
        start = rig.first_start(pending) - target.pre_wire_s
        assert rig.scan_end < start + rig.budget_s


# --- wrapper boundary -------------------------------------------------------------


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_counting_wrapper_admits_each_real_attempt_once_and_none_after_expiry(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str
) -> None:
    selector = BASE
    pending = selector.read(0x0040)
    path = REGISTER_PATHS[kind]
    target = Target(selector.dst, pending=pending, behavior=path["behavior"])
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=path["budget"])
    counting = CountingTransport(rig.transport, request_budget=1000)
    hook_times: list[float] = []

    def outer_hook() -> None:
        hook_times.append(rig.clock.now)

    with rig.session():
        # Successful operations whose cumulative time exceeds several budgets.
        for register in range(0x20):
            payload = selector.read(register)
            assert counting.send_with_attempt_hook(selector.dst, payload, outer_hook) == _answer(
                payload
            )
        assert rig.clock.now > 2 * rig.budget_s
        start = rig.clock.now
        with pytest.raises(TransportRecoveryExhausted) as raised:
            counting.send_with_attempt_hook(selector.dst, pending, outer_hook)
        deadline = start + rig.budget_s
        assert rig.clock.now == deadline

    failure = raised.value
    assert type(failure) is TransportRecoveryExhausted  # Internal expiry never leaks.
    assert isinstance(failure.__cause__, RequestDeadlineExpired)
    assert (failure.cause, failure.phase) == ("timeout", "transaction")
    assert (failure.request_attempts, failure.reconnect_attempts) == (
        path["attempts"],
        path["reconnects"],
    )
    assert counting.counters.send_calls == 0x20 + path["attempts"]
    assert len(hook_times) == counting.counters.send_calls
    assert max(hook_times) < deadline
    assert max(rig.peer.send_times) < deadline
    pending_evidence = [
        item for item in counting.recent_requests if item["request_hex"] == pending.hex()
    ]
    assert [item["attempt"] for item in pending_evidence] == list(
        range(0x21, 0x21 + path["attempts"])
    )
    starts = [when for when, _dst, payload in target.requests if payload == pending]
    assert len(starts) == path["attempts"]
    assert starts[0] == start + target.pre_wire_s
    assert all(when < deadline for when in starts)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_counting_wrapper_cap_stops_a_retry_before_the_deadline(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str
) -> None:
    """A spent count cap ends the operation early; a fresh root does not reset it."""

    selector = BASE
    pending = selector.read(0x0040)
    path = REGISTER_PATHS[kind]
    target = Target(selector.dst, pending=pending, behavior=path["behavior"])
    rig = _rig(monkeypatch, kind, mode, target, max_command_s=path["budget"])
    capped = CountingTransport(rig.transport, request_budget=1)

    with rig.session():
        start = rig.clock.now
        with pytest.raises(ScanRequestBudgetExceeded):
            capped.send(selector.dst, pending)
        # The first attempt was admitted; its retry hit the cap with time left.
        assert start < rig.clock.now < start + rig.budget_s
        assert target.payloads_sent(pending) == 1
        assert rig.transport._active_root() is None
        wire = len(target.requests)
        # A new operation gets a new root, but the spent count cap still applies.
        with pytest.raises(ScanRequestBudgetExceeded):
            capped.send(selector.dst, selector.read(0x0000))
        assert len(target.requests) == wire
        assert capped.counters.send_calls == 1
        payload = selector.read(0x0000)
        assert CountingTransport(rig.transport).send(selector.dst, payload) == _answer(payload)


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("kind", TRANSPORTS)
def test_deadline_never_resubmits_an_uncertain_write(
    monkeypatch: pytest.MonkeyPatch, kind: str, mode: str
) -> None:
    """A recognized write is sent once whether the deadline or a timeout ends it."""

    selector = BASE
    write = bytes.fromhex("0201000001001100")  # OP02 write to GG00/II00/RR0001.
    for budget in (1.0, None):
        with monkeypatch.context() as patch:
            target = Target(selector.dst, pending=write, behavior="silent")
            rig = _rig(patch, kind, mode, target, max_command_s=budget)
            counting = CountingTransport(rig.transport)
            with rig.session():
                start = rig.clock.now
                with pytest.raises((TransportRecoveryExhausted, TransportTimeout)) as raised:
                    counting.send(selector.dst, write)
                # Snapshot before the follow-up operation, as ``_scan`` does.
                rig.scan_end = rig.clock.now
                rig.scan_requests = tuple(target.requests)
                rig.scan_send_times = tuple(rig.peer.send_times)
                # ebusd closes a persistent session on any read timeout.
                closed = budget is not None or kind == "ebusd"
                _assert_fresh_operation(rig, selector, selector.read(0x0001), closed=closed)
        assert rig.scan_count(write) == 1
        assert counting.counters.send_calls == 1
        if budget is None:
            # Ample time left: the local timeout still ends the write unretried.
            assert type(raised.value) is TransportTimeout
            continue
        failure = raised.value
        assert type(failure) is TransportRecoveryExhausted
        assert (failure.cause, failure.phase) == ("timeout", "transaction")
        assert (failure.request_attempts, failure.reconnect_attempts) == (1, 0)
        assert rig.scan_end == start + 1.0
        assert max(rig.scan_send_times) < rig.scan_end
