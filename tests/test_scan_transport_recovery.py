from __future__ import annotations

import struct

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportRecoveryExhausted


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
