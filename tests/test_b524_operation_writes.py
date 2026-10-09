from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.b524_operation_writes import (
    B524NativeWriteQualification,
    B524WriteRetryBlocked,
    _classify_readback,
    concrete_confirmation_text,
    execute_controlled_write,
    operation_write_availability,
    parse_native_write_qualification,
    prepare_event_write,
    prepare_timer_write,
)
from helianthus_vrc_explorer.transport.base import (
    TransportInterface,
    TransportTimeout,
)


class _ScriptedTransport(TransportInterface):
    def __init__(
        self,
        replies: dict[bytes, list[bytes | Exception]],
        *,
        retry_write: bool = False,
        identity_payload: bytes = b"\xb570000\x01\x41\x01\x00",
    ) -> None:
        self.replies = replies
        self.retry_write = retry_write
        self.identity_payload = identity_payload
        self.admitted_payloads: list[bytes] = []

    def send_proto(self, dst, primary, secondary, payload, *, expect_response=True):
        assert (dst, primary, secondary, payload, expect_response) == (
            0x15,
            0x07,
            0x04,
            b"",
            True,
        )
        return self.identity_payload

    def send(self, dst: int, payload: bytes) -> bytes:  # pragma: no cover
        raise AssertionError("send_with_attempt_hook must be used")

    def send_with_attempt_hook(self, dst, payload, attempt_hook):
        assert dst == 0x15
        attempt_hook()
        self.admitted_payloads.append(payload)
        reply = self.replies[payload].pop(0)
        if self.retry_write and payload[0] in {0x04, 0x0A, 0x0C}:
            attempt_hook()
        if isinstance(reply, Exception):
            raise reply
        return reply


def _timer_request():
    return prepare_timer_write(
        channel="dhw",
        instance=0,
        weekday=0,
        slots=((0, 36), (48, 72), None),
        expected_before_raw_hex="00000612909090",
    )


def _qualification(request):
    return B524NativeWriteQualification(
        scope="timer_write_op04",
        manufacturer=0xB5,
        device_id="70000",
        profile="VRC700",
        model="VRC700",
        software_raw_hex="0141",
        selector=dict(request.selector),
        evidence_reference="public-fixture:test-vector",
        native_qualified=True,
    )


def _qualification_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "scope": "timer_write_op04",
        "manufacturer": 0xB5,
        "device_id": "70000",
        "profile": "VRC700",
        "model": "VRC700",
        "software_raw_hex": "0141",
        "selector": {"channel": "dhw", "instance": 0, "weekday": 0},
        "evidence_reference": "public-fixture:test-vector",
        "native_qualified": True,
    }


def test_qualification_document_is_strict_evidence_not_confirmation() -> None:
    qualification = parse_native_write_qualification(_qualification_document())
    assert qualification.scope == "timer_write_op04"
    assert qualification.selector["channel"] == "dhw"

    with pytest.raises(ValueError, match="boolean true"):
        parse_native_write_qualification(
            {
                "schema_version": 1,
                "scope": "timer_write_op04",
                "manufacturer": 0xB5,
                "device_id": "70000",
                "profile": "VRC700",
                "model": "VRC700",
                "software_raw_hex": "0141",
                "selector": {"channel": "dhw"},
                "evidence_reference": "fixture:x",
                "native_qualified": 1,
            }
        )


@pytest.mark.parametrize("schema_version", [True, 1.0, "1", None])
def test_qualification_requires_schema_version_integer_one(schema_version: object) -> None:
    document = _qualification_document()
    document["schema_version"] = schema_version
    with pytest.raises(ValueError, match="integer 1"):
        parse_native_write_qualification(document)


def test_qualification_and_baselines_require_compact_hex() -> None:
    qualification = _qualification_document()
    qualification["software_raw_hex"] = "01 41"
    with pytest.raises(ValueError, match="compact hexadecimal"):
        parse_native_write_qualification(qualification)

    with pytest.raises(ValueError, match="compact hexadecimal"):
        prepare_timer_write(
            channel="dhw",
            instance=0,
            weekday=0,
            slots=((0, 36), (48, 72), None),
            expected_before_raw_hex="00 000612909090",
        )


def test_event_offline_preview_is_complete_but_live_availability_is_unqualified() -> None:
    request = prepare_event_write(
        setpoint=False,
        profile="zone",
        instance=2,
        address=1,
        weekday_code=129,
        values=(0xFF, 1, 2, 3, 4, 5, 6),
        expected_event_raw_hex="00ff000102030405",
        expected_setpoint_raw_hex="002d2e2f30313233",
    )
    assert request.write_payload.hex() == "0a03020181ff010203040506"
    assert [item.operation for item in request.read_requests] == [
        "GetEvent",
        "GetEventSetPoint",
    ]
    assert request.expected_after[0].hex() == "00ff010203040506"
    availability = operation_write_availability("SetEvent")
    assert availability.state == "schema_unqualified"
    assert availability.live_write_available is False


def test_events_cannot_be_enabled_by_claimed_qualification_or_positive_parser() -> None:
    request = prepare_event_write(
        setpoint=True,
        profile="dhw",
        instance=0,
        address=1,
        weekday_code=0,
        values=(253, 254, 255, 253, 254, 255, 253),
        expected_event_raw_hex="0000010203040506",
        expected_setpoint_raw_hex="00fdfefffdfefffd",
    )
    fake_qualification = B524NativeWriteQualification(
        scope="event_setpoint_write_op0c",
        manufacturer=0xB5,
        device_id="BASV2",
        profile="events-candidate",
        model="candidate",
        software_raw_hex="0141",
        selector=dict(request.selector),
        evidence_reference="parser-only",
        native_qualified=True,
    )
    transport = _ScriptedTransport({})
    with pytest.raises(ValueError, match="candidate codec"):
        execute_controlled_write(
            transport,
            dst=0x15,
            request=request,
            qualification=fake_qualification,
            concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
        )
    assert transport.admitted_payloads == []


def test_wrong_concrete_confirmation_fails_before_any_io() -> None:
    request = _timer_request()
    transport = _ScriptedTransport({})
    with pytest.raises(ValueError, match="concrete confirmation"):
        execute_controlled_write(
            transport,
            dst=0x15,
            request=request,
            qualification=_qualification(request),
            concrete_confirmation="yes",
        )
    assert transport.admitted_payloads == []


def test_baseline_mismatch_prevents_write() -> None:
    request = _timer_request()
    read_payload = request.read_requests[0].payload
    transport = _ScriptedTransport({read_payload: [bytes.fromhex("00001224909090")]})
    result = execute_controlled_write(
        transport,
        dst=0x15,
        request=request,
        qualification=_qualification(request),
        concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
    )
    assert result["outcome"] == "baseline_mismatch"
    assert request.write_payload not in transport.admitted_payloads


def test_pre_read_failure_preserves_evidence_and_prevents_write() -> None:
    request = _timer_request()
    read_payload = request.read_requests[0].payload
    transport = _ScriptedTransport({read_payload: [TransportTimeout("pre-read")]})
    result = execute_controlled_write(
        transport,
        dst=0x15,
        request=request,
        qualification=_qualification(request),
        concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
    )
    assert result["outcome"] == "pre_read_failed"
    assert result["pre_read"][0]["response_state"] == "transport_error"
    assert result["pre_read"][0]["error"] == "TransportTimeout"
    assert request.write_payload not in transport.admitted_payloads


def test_wrong_connected_identity_blocks_write_even_when_baseline_would_match() -> None:
    request = _timer_request()
    read_payload = request.read_requests[0].payload
    transport = _ScriptedTransport(
        {read_payload: [request.expected_before[0]]},
        identity_payload=b"\xb5B7S00\x01\x41\x01\x00",
    )
    with pytest.raises(ValueError, match="do not match qualification"):
        execute_controlled_write(
            transport,
            dst=0x15,
            request=request,
            qualification=_qualification(request),
            concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
        )
    assert transport.admitted_payloads == []


def test_write_retry_is_blocked_after_exactly_one_admitted_send_then_read_back() -> None:
    request = _timer_request()
    read_payload = request.read_requests[0].payload
    transport = _ScriptedTransport(
        {
            read_payload: [request.expected_before[0], request.expected_after[0]],
            request.write_payload: [b"\x7f"],
        },
        retry_write=True,
    )
    result = execute_controlled_write(
        transport,
        dst=0x15,
        request=request,
        qualification=_qualification(request),
        concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
    )

    assert result["outcome"] == "verified"
    assert result["write_attempts"] == 1
    assert result["write_error"] == B524WriteRetryBlocked.__name__
    assert transport.admitted_payloads.count(request.write_payload) == 1
    assert result["write_feedback_interpretation"] == "unknown"
    assert result["automatic_rollback"] is False


def test_timeout_after_single_send_is_ambiguous_and_never_retries_write() -> None:
    request = _timer_request()
    read_payload = request.read_requests[0].payload
    transport = _ScriptedTransport(
        {
            read_payload: [request.expected_before[0], TransportTimeout("readback")],
            request.write_payload: [TransportTimeout("write feedback")],
        }
    )
    result = execute_controlled_write(
        transport,
        dst=0x15,
        request=request,
        qualification=_qualification(request),
        concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
    )
    assert result["outcome"] == "ambiguous"
    assert result["write_attempts"] == 1
    assert transport.admitted_payloads.count(request.write_payload) == 1
    assert result["write_error"] == "TransportTimeout"
    assert result["readback"][0]["response_state"] == "transport_error"
    assert result["readback"][0]["error"] == "TransportTimeout"


def test_unchanged_timer_edit_is_rejected_before_send_or_readback() -> None:
    request = prepare_timer_write(
        channel="dhw",
        instance=0,
        weekday=0,
        slots=((0, 36), (48, 72), None),
        expected_before_raw_hex="00002430489090",
    )
    assert request.expected_before == request.expected_after
    transport = _ScriptedTransport(
        {
            request.read_requests[0].payload: [
                request.expected_before[0],
                request.expected_before[0],
            ],
            request.write_payload: [TransportTimeout("write feedback")],
        }
    )
    with pytest.raises(ValueError, match="unchanged"):
        execute_controlled_write(
            transport,
            dst=0x15,
            request=request,
            qualification=_qualification(request),
            concrete_confirmation=concrete_confirmation_text(request, dst=0x15),
        )
    assert transport.admitted_payloads == []


def test_event_pair_classification_reports_partial_without_rollback() -> None:
    request = prepare_event_write(
        setpoint=False,
        profile="system",
        instance=0,
        address=1,
        weekday_code=0,
        values=(0, 1, 2, 3, 4, 5, 6),
        expected_event_raw_hex="000a0b0c0d0e0f10",
        expected_setpoint_raw_hex="001415161718191a",
    )
    unrelated_setpoint_change = bytes.fromhex("001415161718191b")
    assert (
        _classify_readback(request, (request.expected_after[0], unrelated_setpoint_change))
        == "partial"
    )
