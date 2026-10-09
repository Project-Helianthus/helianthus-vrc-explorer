from __future__ import annotations

from contextlib import nullcontext

import pytest

from helianthus_vrc_explorer.scanner.b524_operation_reads import (
    acquire_operation_reads,
    parse_operation_read_plan,
    validate_operation_read_identity,
)
from helianthus_vrc_explorer.transport.base import (
    TransportError,
    TransportInterface,
    TransportNack,
    TransportRecoveryExhausted,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.instrumented import (
    CountingTransport,
    ScanRequestBudgetExceeded,
)


class _Transport(TransportInterface):
    def __init__(self, replies: dict[bytes, bytes | Exception]) -> None:
        self.replies = replies
        self.calls: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        assert dst == 0x15
        self.calls.append(payload)
        reply = self.replies[payload]
        if isinstance(reply, Exception):
            raise reply
        return reply


class _RetryTransport(TransportInterface):
    def __init__(self, reply: bytes) -> None:
        self.reply = reply

    def send(self, dst: int, payload: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("send_with_attempt_hook must be used")

    def send_with_attempt_hook(self, dst, payload, attempt_hook):
        assert dst == 0x15
        attempt_hook()
        attempt_hook()
        return self.reply


class _InterruptTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("send_with_attempt_hook must be used")

    def send_with_attempt_hook(self, dst, payload, attempt_hook):
        assert dst == 0x15
        attempt_hook()
        raise KeyboardInterrupt


class _Observer:
    def __init__(self) -> None:
        self.finishes: list[str] = []
        self.advances: list[int] = []
        self.statuses: list[str] = []

    def phase_start(self, phase: str, *, total: int) -> None:
        pass

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        self.advances.append(advance)

    def phase_set_total(self, phase: str, *, total: int) -> None:
        pass

    def phase_finish(self, phase: str) -> None:
        self.finishes.append(phase)

    def status(self, message: str) -> None:
        self.statuses.append(message)

    def log(self, message: str, *, level: str = "info") -> None:
        pass

    def suspend(self):
        return nullcontext()


def _plan(*requests: dict[str, object]):
    return parse_operation_read_plan({"schema_version": 1, "requests": list(requests)})


def test_plan_is_strict_deduplicated_and_operation_determines_opcode() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "zone",
            "instance": 2,
            "address": 1,
            "weekday_code": 0,
        },
        {"operation": "ReadVR91"},
        {
            "operation": "GetEvent",
            "profile": "zone",
            "instance": 2,
            "address": 1,
            "weekday_code": 0,
        },
    )

    assert [request.operation for request in requests] == ["GetEvent", "ReadVR91"]
    assert [request.payload.hex() for request in requests] == ["0903020100", "08"]


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": True, "requests": [{"operation": "ReadVR91"}]},
        {"schema_version": 1.0, "requests": [{"operation": "ReadVR91"}]},
        {"schema_version": "1", "requests": [{"operation": "ReadVR91"}]},
        {"schema_version": 1, "requests": []},
        {
            "schema_version": 1,
            "requests": [{"operation": "ReadVR91", "opcode": "0x08"}],
        },
        {
            "schema_version": 1,
            "requests": [
                {"operation": "ReadTimer", "channel": "dhw", "instance": True, "weekday": 0}
            ],
        },
        {
            "schema_version": 1,
            "requests": [
                {
                    "operation": "GetEvent",
                    "profile": "zone",
                    "instance": 0,
                    "address": 3,
                    "weekday_code": 0,
                }
            ],
        },
    ],
)
def test_plan_rejects_bool_empty_unknown_and_invalid_selectors(document) -> None:
    with pytest.raises(ValueError):
        parse_operation_read_plan(document)


def test_identity_guard_requires_known_vaillant_and_keeps_legacy_vrc700_ids() -> None:
    events = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        }
    )
    validate_operation_read_identity(events, device_id="BASV2", manufacturer=0xB5)
    with pytest.raises(ValueError, match="known Vaillant"):
        validate_operation_read_identity(events, device_id=None, manufacturer=0xB5)
    with pytest.raises(ValueError, match="known Vaillant"):
        validate_operation_read_identity(events, device_id="unknown", manufacturer=0xB5)
    with pytest.raises(ValueError, match="known Vaillant"):
        validate_operation_read_identity(events, device_id="BASV2", manufacturer=0x50)

    timer = _plan({"operation": "ReadTimer", "channel": "dhw", "instance": 0, "weekday": 0})
    with pytest.raises(ValueError, match="70000 or B7S00"):
        validate_operation_read_identity(timer, device_id="B7V00", manufacturer=0xB5)


def test_acquisition_keeps_states_pair_context_raw_and_candidate_decode() -> None:
    requests = _plan(
        {"operation": "ReadTimer", "channel": "dhw", "instance": 0, "weekday": 0},
        {
            "operation": "GetEvent",
            "profile": "zone",
            "instance": 2,
            "address": 1,
            "weekday_code": 129,
        },
        {
            "operation": "GetEventSetPoint",
            "profile": "dhw",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
        {"operation": "ReadVR91"},
    )
    transport = _Transport(
        {
            bytes.fromhex("0301000100"): bytes.fromhex("00002430909090"),
            bytes.fromhex("0903020181"): TransportNack("nack"),
            bytes.fromhex("0b01000100"): b"",
            bytes.fromhex("08"): bytes.fromhex("01020304050607"),
        }
    )
    artifact: dict[str, object] = {}

    records = acquire_operation_reads(
        transport,
        dst=0x15,
        artifact=artifact,
        requests=requests,
        device_id="70000",
        manufacturer=0xB5,
    )

    assert [record["response_state"] for record in records] == [
        "value",
        "nack",
        "empty",
        "malformed",
    ]
    assert records[0]["decode_qualification"] == "profile_vrc700"
    assert records[0]["decoded"]["slots"][0]["stop_minutes"] == 360
    assert records[1]["pair_context"] == records[1]["selector"]
    assert records[1]["selector_correlation"] == "request_context"
    assert records[2]["response_raw_hex"] == ""
    assert records[3]["response_raw_hex"] == "01020304050607"
    assert all(record["request_attempts"] == 1 for record in records)


def test_actual_attempt_hook_counts_transport_internal_retries() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        }
    )
    records = acquire_operation_reads(
        _RetryTransport(bytes.fromhex("0000000000000000")),
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="BASV2",
        manufacturer=0xB5,
    )
    assert records[0]["request_attempts"] == 2


def test_shared_counting_transport_budget_retains_unattempted_selectors() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 2,
            "weekday_code": 0,
        },
    )
    inner = _Transport(
        {
            bytes.fromhex("0900000100"): bytes.fromhex("0000000000000000"),
            bytes.fromhex("0900000200"): bytes.fromhex("0000000000000000"),
        }
    )
    artifact: dict[str, object] = {}

    with pytest.raises(ScanRequestBudgetExceeded):
        acquire_operation_reads(
            CountingTransport(inner, request_budget=1),
            dst=0x15,
            artifact=artifact,
            requests=requests,
            device_id="BASV2",
            manufacturer=0xB5,
        )

    assert [item["response_state"] for item in artifact["b524_operation_reads"]] == [
        "value",
        "unattempted",
    ]
    assert artifact["b524_operation_reads"][1]["request_attempts"] == 0


def test_budget_during_retry_preserves_attempted_current_and_does_not_finish_phase() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        }
    )
    artifact: dict[str, object] = {}
    observer = _Observer()

    with pytest.raises(ScanRequestBudgetExceeded):
        acquire_operation_reads(
            CountingTransport(
                _RetryTransport(bytes.fromhex("0000000000000000")),
                request_budget=1,
            ),
            dst=0x15,
            artifact=artifact,
            requests=requests,
            device_id="BASV2",
            manufacturer=0xB5,
            observer=observer,
        )

    record = artifact["b524_operation_reads"][0]
    assert record["response_state"] == "transport_error"
    assert record["error"] == "request_budget_exhausted"
    assert record["request_attempts"] == 1
    assert observer.advances == [1]
    assert observer.finishes == []


def test_interrupt_preserves_current_and_remaining_without_false_phase_finish() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
        {
            "operation": "GetEventSetPoint",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
    )
    artifact: dict[str, object] = {}
    observer = _Observer()

    with pytest.raises(KeyboardInterrupt):
        acquire_operation_reads(
            _InterruptTransport(),
            dst=0x15,
            artifact=artifact,
            requests=requests,
            device_id="BASV2",
            manufacturer=0xB5,
            observer=observer,
        )

    current, remaining = artifact["b524_operation_reads"]
    assert (current["response_state"], current["error"], current["request_attempts"]) == (
        "transport_error",
        "user_interrupt",
        1,
    )
    assert (
        remaining["response_state"],
        remaining["error"],
        remaining["request_attempts"],
    ) == ("unattempted", "user_interrupt", 0)
    assert observer.advances == [1]
    assert observer.finishes == []


def test_terminal_recovery_preserves_partial_progress_without_finishing_phase() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 2,
            "weekday_code": 0,
        },
    )
    artifact: dict[str, object] = {}
    observer = _Observer()
    failure = TransportRecoveryExhausted(
        cause="timeout",
        phase="receive",
        request_attempts=1,
        reconnect_attempts=1,
    )
    transport = _Transport({bytes.fromhex("0900000100"): failure})

    with pytest.raises(TransportRecoveryExhausted):
        acquire_operation_reads(
            transport,
            dst=0x15,
            artifact=artifact,
            requests=requests,
            device_id="BASV2",
            manufacturer=0xB5,
            observer=observer,
        )

    current, remaining = artifact["b524_operation_reads"]
    assert (current["response_state"], current["request_attempts"]) == (
        "transport_error",
        1,
    )
    assert (remaining["response_state"], remaining["request_attempts"]) == (
        "unattempted",
        0,
    )
    assert observer.advances == [1]
    assert observer.finishes == []
    assert failure.selector["request_payload_hex"] == "0900000100"
    assert failure.selector["operation"] == "GetEvent"


def test_transport_error_is_distinct_and_does_not_erase_following_read() -> None:
    requests = _plan(
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 1,
            "weekday_code": 0,
        },
        {
            "operation": "GetEvent",
            "profile": "system",
            "instance": 0,
            "address": 2,
            "weekday_code": 0,
        },
    )
    records = acquire_operation_reads(
        _Transport(
            {
                bytes.fromhex("0900000100"): TransportError("broken"),
                bytes.fromhex("0900000200"): TransportTimeout("timeout"),
            }
        ),
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="BASV2",
        manufacturer=0xB5,
    )
    assert [record["response_state"] for record in records] == [
        "transport_error",
        "timeout",
    ]


def test_protocol_failure_keeps_sanitized_cause_phase_and_unexpected_symbol():
    from helianthus_vrc_explorer.transport.base import TransportProtocolFailure

    requests = _plan({"operation": "ReadVR91"})
    failure = TransportProtocolFailure(
        request_attempts=3, reconnect_attempts=1, unexpected_symbol=0xAA
    )
    records = acquire_operation_reads(
        _Transport({b"\x08": failure}),
        dst=0x15,
        artifact={},
        requests=requests,
        device_id="70000",
        manufacturer=0xB5,
    )
    assert records[0]["response_state"] == "transport_error"
    assert "phase=command_ack" in records[0]["error"]
    assert "request_attempts=3" in records[0]["error"]
    assert "unexpected_symbol=0xaa" in records[0]["error"]
