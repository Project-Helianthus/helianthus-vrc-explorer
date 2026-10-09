import struct
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.b524_operation_reads import parse_operation_read_plan
from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface


class OperationTransport(TransportInterface):
    def __init__(self):
        self.payloads = []

    def send(self, dst, payload):
        self.payloads.append(payload)
        if payload[0] == 0:
            return struct.pack("<f", float("nan"))
        if payload[0] == 9:
            return bytes.fromhex("03ff000648908fff")
        if payload[0] == 11:
            return bytes.fromhex("0020202020202020")
        return b""


def operation_plan():
    return parse_operation_read_plan(
        {
            "schema_version": 1,
            "requests": [
                {
                    "operation": op,
                    "profile": "zone",
                    "instance": 2,
                    "address": 1,
                    "weekday_code": 255,
                }
                for op in ("GetEvent", "GetEventSetPoint")
            ],
        }
    )


def scan(transport, **kwargs):
    return scan_b524(
        transport,
        dst=0x15,
        planner_preset="custom",
        probe_constraints=False,
        explicit_plan={
            make_plan_key(0x69, 2): GroupScanPlan(
                group=0x69, opcode=2, instances=(0,), rr_max=1, registers=(1,)
            )
        },
        operation_requests=operation_plan(),
        operation_identity={"device_id": "BASV2", "manufacturer": "0xB5"},
        **kwargs,
    )


def test_operation_reads_share_scan_accounting_and_keep_decoded_pair():
    transport = OperationTransport()
    artifact = scan(transport)
    assert [payload[0] for payload in transport.payloads[-3:]] == [2, 9, 11]
    assert artifact["meta"]["scan_coverage"]["actual_requests"] == len(transport.payloads)
    records = artifact["b524_operation_reads"]
    assert [row["response_state"] for row in records] == ["value", "value"]
    assert records[0]["decoded"]["start1_raw"] == 255
    assert records[1]["decoded"]["values"][0]["raw"] == 32
    assert records[0]["decode_qualification"] == "schema_unqualified"


def test_global_budget_keeps_operation_result_and_unsent_selector():
    transport = OperationTransport()
    artifact = scan(transport, request_budget=20)
    assert len(transport.payloads) == 20
    assert artifact["meta"]["incomplete_reason"] == "request_budget_exhausted"
    assert [row["response_state"] for row in artifact["b524_operation_reads"]] == [
        "value",
        "unattempted",
    ]
    assert [row["request_attempts"] for row in artifact["b524_operation_reads"]] == [1, 0]


def test_unsupported_timer_target_is_rejected_before_scalar_io():
    transport = OperationTransport()
    requests = parse_operation_read_plan(
        {"schema_version": 1, "requests": [{"operation": "ReadVR91"}]}
    )
    with pytest.raises(ValueError, match="VRC700"):
        scan_b524(
            transport,
            dst=0x15,
            operation_requests=requests,
            operation_identity={"eid": "BASV2", "manufacturer": 181},
        )
    assert transport.payloads == []


def test_planner_can_deselect_every_explicit_operation(monkeypatch):
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_module

    def planner(groups, **kwargs):
        kwargs["operation_selection"][:] = [False] * len(kwargs["operation_requests"])
        return kwargs["default_plan"]

    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan", planner)
    monkeypatch.setattr(
        scan_module,
        "_PlannerHotkeyReader",
        lambda **kwargs: nullcontext(SimpleNamespace(poll=lambda: False)),
    )
    observer = MagicMock(spec=ScanObserver)
    observer.suspend.return_value = nullcontext()
    transport = OperationTransport()
    artifact = scan(
        transport, planner_ui="textual", console=Console(force_terminal=True), observer=observer
    )
    assert not any(payload[0] in {9, 11} for payload in transport.payloads)
    assert artifact["b524_operation_reads"] == []
    assert all(not row["selected"] for row in artifact["meta"]["b524_operation_read_plan"])
