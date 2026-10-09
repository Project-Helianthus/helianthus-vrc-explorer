from __future__ import annotations

import struct

import pytest

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface


class AttributeTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:
        if payload[0] in (2, 6):
            register = int.from_bytes(payload[4:6], "little")
            return bytes((register % 4, payload[2])) + payload[4:6] + struct.pack("<f", 1)
        return b""


def test_describe_selects_only_writable_in_both_read_namespaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    described: list[tuple[int, int]] = []

    def probe(_transport: object, **kwargs: object) -> dict[str, object]:
        described.append((int(kwargs["opcode"]), int(kwargs["register"])))  # type: ignore[call-overload]
        return {"qualification": "unqualified", "reply_hex": "00"}

    monkeypatch.setattr(
        "helianthus_vrc_explorer.scanner.description_acquisition.probe_parameter_description", probe
    )
    plan = {
        make_plan_key(0, 2): GroupScanPlan(group=0, opcode=2, rr_max=3, instances=(0,)),
        make_plan_key(1, 6): GroupScanPlan(
            group=1, opcode=6, rr_max=7, instances=(1,), registers=(4, 5, 6, 7)
        ),
    }
    scan_b524(AttributeTransport(), dst=0x15, planner_preset="custom", explicit_plan=plan)
    assert set(described) == {(2, 2), (2, 3), (6, 6), (6, 7)}
