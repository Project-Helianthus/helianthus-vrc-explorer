from __future__ import annotations

import struct

from helianthus_vrc_explorer.scanner.b524_default_events import (
    build_default_event_requests,
    event_program_requests,
)
from helianthus_vrc_explorer.scanner.b524_operation_reads import (
    acquire_operation_reads,
    parse_operation_read_plan,
)
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface


class _Transport(TransportInterface):
    def __init__(self, replies: dict[bytes, bytes]) -> None:
        self.replies = replies
        self.calls: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        assert dst == 0x15
        self.calls.append(payload)
        return self.replies[payload]


def test_event_program_requests_are_raw_alternating_automatic_pairs() -> None:
    requests = event_program_requests(
        "zone",
        instance=2,
        address=1,
        weekday_codes=(0, 7, 255),
    )

    assert [request.operation for request in requests] == [
        "GetEvent",
        "GetEventSetPoint",
        "GetEvent",
        "GetEventSetPoint",
        "GetEvent",
        "GetEventSetPoint",
    ]
    assert [request.payload.hex() for request in requests] == [
        "0903020100",
        "0b03020100",
        "0903020107",
        "0b03020107",
        "09030201ff",
        "0b030201ff",
    ]
    assert all(request.automatic_event for request in requests)


def test_default_requests_use_only_supplied_scalar_instances_and_documented_addresses() -> None:
    requests = build_default_event_requests(
        instances={"system": (0,), "dhw": (), "zone": (1, 3)},
        weekday_codes=(0,),
    )

    assert [
        (
            request.operation,
            request.selector["profile"],
            request.selector["instance"],
            request.selector["address"],
        )
        for request in requests
    ] == [
        (operation, profile, instance, address)
        for profile, instance, addresses in (
            ("system", 0, (1, 2, 3)),
            ("zone", 1, (1, 2)),
            ("zone", 3, (1, 2)),
        )
        for address in addresses
        for operation in ("GetEvent", "GetEventSetPoint")
    ]


def test_automatic_empty_event_skips_only_its_pair_and_later_code_still_runs() -> None:
    requests = event_program_requests("zone", instance=1, address=1, weekday_codes=(0, 1))
    transport = _Transport(
        {
            bytes.fromhex("0903010100"): b"",
            bytes.fromhex("0903010101"): bytes.fromhex("0001020304050607"),
            bytes.fromhex("0b03010101"): bytes.fromhex("0020202020202020"),
        }
    )

    records = acquire_operation_reads(
        transport,
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="BASV2",
        manufacturer=0xB5,
    )

    assert [payload.hex() for payload in transport.calls] == [
        "0903010100",
        "0903010101",
        "0b03010101",
    ]
    assert [record["response_state"] for record in records] == [
        "empty",
        "unattempted",
        "value",
        "value",
    ]
    assert records[1]["error"] == "not_scheduled_op09_precondition"
    assert records[1]["op09_response_state"] == "empty"
    assert records[1]["request_attempts"] == 0


def test_automatic_all_ff_event_remains_schema_unqualified_and_allows_setpoint() -> None:
    requests = event_program_requests("system", instance=0, address=1, weekday_codes=(0,))
    transport = _Transport(
        {
            bytes.fromhex("0900000100"): b"\xff" * 8,
            bytes.fromhex("0b00000100"): b"\xff" * 8,
        }
    )

    records = acquire_operation_reads(
        transport,
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="BASV2",
        manufacturer=0xB5,
    )

    assert transport.calls == [bytes.fromhex("0900000100"), bytes.fromhex("0b00000100")]
    assert records[0]["response_state"] == "value"
    assert records[0]["decode_qualification"] == "schema_unqualified"
    assert records[1]["response_state"] == "value"
    assert records[1]["request_attempts"] == 1


def test_explicit_setpoint_is_not_conditioned_on_an_event_request() -> None:
    requests = parse_operation_read_plan(
        {
            "schema_version": 1,
            "requests": [
                {
                    "operation": "GetEventSetPoint",
                    "profile": "dhw",
                    "instance": 0,
                    "address": 1,
                    "weekday_code": 0,
                }
            ],
        }
    )
    payload = bytes.fromhex("0b01000100")
    transport = _Transport({payload: b""})

    records = acquire_operation_reads(
        transport,
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="BASV2",
        manufacturer=0xB5,
    )

    assert transport.calls == [payload]
    assert records[0]["response_state"] == "empty"


class _AutomaticScanTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        assert dst == 0x15
        self.calls.append(payload)
        if payload[0] == 0:
            return struct.pack("<f", float("nan"))
        return b""


def _custom_system_scan(transport: TransportInterface, *, identity: dict[str, object]):
    return scan_b524(
        transport,
        dst=0x15,
        planner_preset="custom",
        probe_constraints=False,
        explicit_plan={
            make_plan_key(0x00, 0x02): GroupScanPlan(
                group=0x00,
                opcode=0x02,
                instances=(0,),
                rr_max=0,
                registers=(0,),
            )
        },
        operation_identity=identity,
    )


def test_scan_builds_default_window_for_scoped_system_and_skips_empty_pairs() -> None:
    transport = _AutomaticScanTransport()
    artifact = _custom_system_scan(
        transport,
        identity={"manufacturer": "0xB5", "eid": "BASV2"},
    )

    op09_calls = [payload for payload in transport.calls if payload[0] == 0x09]
    assert len(op09_calls) == 3 * 8
    assert not any(payload[0] == 0x0B for payload in transport.calls)
    assert {payload[-1] for payload in op09_calls} == set(range(8))
    metadata = artifact["meta"]["b524_event_acquisition"]
    assert metadata["candidate_window"] == {
        "codes": [f"0x{code:02X}" for code in range(8)],
        "range": "0x00..0x07",
        "exhaustive_wire_space": False,
    }
    assert metadata["editable_in_planner"] is True
    assert metadata["worst_case_requests"] == 48
    assert artifact["meta"]["b524_operation_read_attempts"] == {
        "OP09": 24,
        "OP0B": 0,
        "total": 24,
    }
    assert artifact["meta"]["scan_plan"]["estimated_operation_requests_worst_case"] == 48


def test_unknown_identity_does_not_schedule_automatic_event_work() -> None:
    transport = _AutomaticScanTransport()
    artifact = _custom_system_scan(
        transport,
        identity={"manufacturer": "0xB5", "eid": "unknown"},
    )

    assert not any(payload[0] in {0x09, 0x0B} for payload in transport.calls)
    assert artifact["meta"]["b524_event_acquisition"]["status"] == (
        "not_scheduled_unknown_identity"
    )
    assert "b524_operation_reads" not in artifact
