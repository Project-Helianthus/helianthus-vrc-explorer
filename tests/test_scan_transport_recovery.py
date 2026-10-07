from __future__ import annotations

import struct
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import (
    TransportInterface,
    TransportProtocolFailure,
    TransportRecoveryExhausted,
)
from helianthus_vrc_explorer.transport.enhanced_tcp import (
    EnhancedTcpConfig,
    EnhancedTcpTransport,
    _EnhancedSessionError,
)


class InterruptedScan(TransportInterface):
    def __init__(self, *, fail_description: bool = False) -> None:
        self.requests: list[bytes] = []
        self.fail_description = fail_description

    def send(self, dst: int, payload: bytes) -> bytes:
        self.requests.append(payload)
        if payload[0] == 0:
            return struct.pack("<f", float("nan"))
        register = int.from_bytes(payload[-2:], "little")
        if (payload[0] == 2 and register == 1 and not self.fail_description) or (
            payload[0] == 1 and register == 1
        ):
            raise TransportRecoveryExhausted(
                cause="socket_error", phase="reconnect", request_attempts=4, reconnect_attempts=3
            )
        if payload[0] == 1:
            return payload[1:2] + payload[-2:] + bytes.fromhex("000064000100")
        return b"\x03" + payload[2:3] + payload[-2:] + b"\x01\x00"


def _scan(transport: InterruptedScan) -> dict:
    return scan_b524(
        transport,
        dst=0x15,
        planner_preset="custom",
        explicit_plan={
            make_plan_key(0, 2): GroupScanPlan(
                group=0, opcode=2, instances=(0,), rr_max=2, registers=(0, 1, 2)
            )
        },
    )


def test_terminal_outage_stops_at_pending_register_and_retains_success() -> None:
    transport = InterruptedScan()
    artifact = _scan(transport)
    meta = artifact["meta"]
    assert meta["incomplete"] is True
    assert meta["incomplete_reason"] == "transport_recovery_exhausted"
    assert meta["scan_coverage"]["completed"] is False
    recovery = meta["transport_recovery"]
    assert recovery["pending_selector"]["register"] == "0x0001"
    assert recovery["cause"] == "socket_error"
    assert recovery["reconnect_attempts"] == 3
    registers = artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]
    assert registers["0x0000"]["value"] == 1
    assert registers["0x0001"]["error"].startswith("transport_error:")
    assert "0x0002" not in registers
    assert len([request for request in transport.requests if request[0] == 2]) == 2


def test_description_outage_retains_previous_description_and_remaining_candidates() -> None:
    transport = InterruptedScan(fail_description=True)
    artifact = _scan(transport)
    assert artifact["meta"]["incomplete_reason"] == "transport_recovery_exhausted"
    coverage = artifact["meta"]["parameter_description_coverage"]
    assert coverage["eligible"] == 3
    assert coverage["matched"] == 1
    assert coverage["attempted"] == 2
    assert coverage["not_attempted"] == 1
    registers = artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]
    assert registers["0x0000"]["parameter_description"]["qualification"] == "matched"
    assert "socket_error" in registers["0x0001"]["parameter_description"]["reason"]
    assert registers["0x0002"]["parameter_description"]["request_attempted"] is False


def test_system_information_outage_preserves_exact_pending_identifier() -> None:
    class InterruptedInformation(TransportInterface):
        def __init__(self) -> None:
            self.requests: list[bytes] = []

        def send(self, dst: int, payload: bytes) -> bytes:
            self.requests.append(payload)
            identifier = int.from_bytes(payload[1:3], "little")
            if identifier == 3:
                raise TransportRecoveryExhausted(
                    cause="socket_error",
                    phase="reconnect",
                    request_attempts=2,
                    reconnect_attempts=1,
                )
            return struct.pack("<f", float(identifier))

    transport = InterruptedInformation()
    artifact = scan_b524(transport, dst=0x15)
    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["transport_recovery"]["pending_selector"] == {
        "read_opcode": "0x00",
        "identifier": "0x0003",
        "request_hex": "000300",
    }
    assert [record["value"] for record in artifact["meta"]["system_information"][:3]] == [0, 1, 2]
    assert len(transport.requests) == 4


def test_failed_discovery_selector_remains_unknown_and_planner_is_reached(monkeypatch) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan

    inner = EnhancedTcpTransport(EnhancedTcpConfig(reconnect_max_retries=1, reconnect_delay_s=0))
    payloads = []

    def send_once(_seq, **kwargs):
        if kwargs["attempt_hook"] is not None:
            kwargs["attempt_hook"]()
        kwargs["attempt_admitted_hook"]()
        payload = kwargs["payload"]
        payloads.append(payload)
        if payload[0] == 0:
            return struct.pack("<f", float("nan"))
        if payload == bytes.fromhex("020008070000"):
            raise _EnhancedSessionError(
                "unexpected command ACK",
                cause="protocol_sync_error",
                phase="command_ack",
                unexpected_symbol=0xAA,
            )
        if payload[0] == 6:
            return b"\x01" + payload[2:3] + payload[-2:] + b"\x00"
        return b""

    planner_calls = []
    monkeypatch.setattr(inner, "_send_proto_once", send_once)
    monkeypatch.setattr(inner, "_reconnect", lambda *_args: None)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        scan,
        "_PlannerHotkeyReader",
        lambda **kwargs: nullcontext(SimpleNamespace(poll=lambda: False)),
    )

    def planner(groups, **kwargs):
        planner_calls.append(groups)
        return kwargs["default_plan"]

    monkeypatch.setattr("helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan", planner)
    artifact = scan_b524(
        inner,
        dst=0x15,
        planner_ui="textual",
        observer=MagicMock(spec=ScanObserver),
        console=Console(force_terminal=True),
        probe_constraints=False,
    )
    assert len(planner_calls) == 1
    assert artifact["meta"]["incomplete"] is False
    assert artifact["meta"]["scan_coverage"]["completed"] is True
    assert artifact["meta"]["scan_coverage"]["qualification_incomplete"] is True
    assert artifact["meta"]["scan_coverage"]["instance_discovery_complete"] is False
    group = artifact["operations"]["0x02"]["groups"]["0x08"]
    assert group["availability_probes"]["0x07"]["present"] is None
    assert (
        group["availability_probes"]["0x07"]["transport_diagnostic"]["unexpected_symbol"] == "0xaa"
    )
    assert "0x07" not in group["instances"]
    assert bytes.fromhex("020008080000") in payloads
    assert artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]


@pytest.mark.parametrize("later_outage", [False, True])
def test_system_information_protocol_failure_preserves_diagnostics(later_outage):
    class InformationFailure(InterruptedScan):
        def send(self, dst, payload):
            if payload[0] == 0:
                identifier = int.from_bytes(payload[1:3], "little")
                if identifier == 3:
                    raise TransportProtocolFailure(
                        request_attempts=4, reconnect_attempts=3, unexpected_symbol=0xAA
                    )
                if identifier == 4 and later_outage:
                    raise TransportRecoveryExhausted(
                        cause="socket_error",
                        phase="reconnect",
                        request_attempts=1,
                        reconnect_attempts=1,
                    )
                return struct.pack("<f", float("nan"))
            return b""

    plan = {make_plan_key(0, 0x02): GroupScanPlan(group=0, opcode=0x02, instances=(0,), rr_max=0)}
    artifact = scan_b524(
        InformationFailure(),
        dst=0x15,
        explicit_plan=plan,
        probe_constraints=False,
        planner_preset="custom",
    )
    record = artifact["meta"]["system_information"][3]
    assert record["qualification"] == "unknown"
    assert record["value"] is None
    assert record["transport_diagnostic"] == {
        "cause": "protocol_sync_error",
        "phase": "command_ack",
        "request_attempts": 4,
        "retry_count": 3,
        "reconnect_attempts": 3,
        "unexpected_symbol": "0xaa",
    }
    if later_outage:
        assert artifact["meta"]["incomplete"] is True
    else:
        assert artifact["meta"]["incomplete"] is False
        assert artifact["meta"]["scan_coverage"]["qualification_incomplete"] is True
        assert artifact["meta"]["scan_coverage"]["system_information_complete"] is False
        assert artifact["meta"]["scan_coverage"]["unknown_system_information"] == ["0x0003"]
