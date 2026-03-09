from __future__ import annotations

from helianthus_vrc_explorer.scanner.b555 import scan_b555
from helianthus_vrc_explorer.scanner.scan import scan_vrc
from helianthus_vrc_explorer.transport.base import TransportError


class _ProtoOnlyTransport:
    def __init__(self, responses: dict[bytes, bytes | Exception]) -> None:
        self._responses = responses
        self.calls: list[bytes] = []

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        _ = dst
        _ = expect_response
        assert (primary, secondary) == (0xB5, 0x55)
        self.calls.append(payload)
        response = self._responses.get(payload)
        if response is None:
            raise TransportError(f"unmapped payload: {payload.hex()}")
        if isinstance(response, Exception):
            raise response
        return response


class _NoopTransport:
    def send(self, dst: int, payload: bytes) -> bytes:
        _ = dst
        _ = payload
        raise AssertionError("send should not be called")

    def send_proto(
        self,
        dst: int,
        primary: int,
        secondary: int,
        payload: bytes,
        *,
        expect_response: bool = True,
    ) -> bytes:
        _ = dst
        _ = primary
        _ = secondary
        _ = payload
        _ = expect_response
        raise AssertionError("send_proto should not be called")


def test_scan_b555_skips_unavailable_programs_and_bounds_slots() -> None:
    unavailable = bytes.fromhex("030101000000ffff00")
    responses = {
        bytes.fromhex("a30000"): bytes.fromhex("000205010102021400"),
        bytes.fromhex("a40000"): bytes.fromhex("000301000000000000"),
        bytes.fromhex("a500000000"): bytes.fromhex("0000000600e100"),
        bytes.fromhex("a500000001"): bytes.fromhex("0006001800c800"),
        bytes.fromhex("a500000100"): bytes.fromhex("00010002009600"),
        bytes.fromhex("a30001"): unavailable,
        bytes.fromhex("a30100"): unavailable,
        bytes.fromhex("a30101"): unavailable,
        bytes.fromhex("a30200"): unavailable,
        bytes.fromhex("a30201"): unavailable,
        bytes.fromhex("a3ff02"): bytes.fromhex("00030a0a0101234100"),
        bytes.fromhex("a4ff02"): bytes.fromhex("000100000000000000"),
        bytes.fromhex("a5ff020000"): bytes.fromhex("00000018006202"),
        bytes.fromhex("a3ff03"): bytes.fromhex("00030a000000ffff00"),
        bytes.fromhex("a4ff03"): bytes.fromhex("000100000000000000"),
        bytes.fromhex("a5ff030000"): bytes.fromhex("0000001800ffff"),
        bytes.fromhex("a3ff04"): unavailable,
    }
    transport = _ProtoOnlyTransport(responses)

    artifact = scan_b555(transport, dst=0x15)

    meta = artifact["meta"]
    assert meta["destination_address"] == "0x15"
    assert meta["read_count"] == 17
    assert meta["error_count"] == 0
    assert meta["incomplete"] is False

    programs = artifact["programs"]
    z1_heating = programs["z1_heating"]
    assert z1_heating["config"]["max_slots"] == 2
    assert z1_heating["weekdays"]["monday"]["reported_slot_count"] == 3
    assert z1_heating["weekdays"]["monday"]["read_slot_count"] == 2
    assert set(z1_heating["weekdays"]["monday"]["slots"]) == {"0x00", "0x01"}
    assert bytes.fromhex("a500000002") not in transport.calls

    dhw = programs["dhw"]
    assert dhw["config"]["status"] == "0x00"
    assert dhw["slots_per_weekday"]["days"]["monday"] == 1
    assert dhw["weekdays"]["monday"]["slots"]["0x00"]["temperature_c"] == 61.0

    cc = programs["cc"]
    assert cc["weekdays"]["monday"]["slots"]["0x00"]["temperature_raw"] == "0xffff"
    assert cc["weekdays"]["monday"]["slots"]["0x00"]["temperature_c"] is None

    assert programs["z1_cooling"]["skipped_reason"] == "config_status_0x03"
    assert programs["silent"]["skipped_reason"] == "config_status_0x03"
    assert bytes.fromhex("a4ff04") not in transport.calls


def test_scan_b555_does_not_materialize_weekdays_when_a4_is_unavailable() -> None:
    unavailable = bytes.fromhex("030000000000000000")
    transport = _ProtoOnlyTransport(
        {
            bytes.fromhex("a30000"): bytes.fromhex("000205010102021400"),
            bytes.fromhex("a40000"): unavailable,
            bytes.fromhex("a30001"): unavailable,
            bytes.fromhex("a30100"): unavailable,
            bytes.fromhex("a30101"): unavailable,
            bytes.fromhex("a30200"): unavailable,
            bytes.fromhex("a30201"): unavailable,
            bytes.fromhex("a3ff02"): unavailable,
            bytes.fromhex("a3ff03"): unavailable,
            bytes.fromhex("a3ff04"): unavailable,
        }
    )

    artifact = scan_b555(transport, dst=0x15)

    z1_heating = artifact["programs"]["z1_heating"]
    assert z1_heating["slots_per_weekday"]["status"] == "0x03"
    assert z1_heating["slots_per_weekday"]["available"] is False
    assert "days" not in z1_heating["slots_per_weekday"]
    assert z1_heating["weekdays"] == {}
    assert z1_heating["skipped_reason"] == "slots_status_0x03"
    assert bytes.fromhex("a500000000") not in transport.calls


def test_scan_vrc_adds_b555_dump_when_opted_in(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": False}, "groups": {}}

    def _fake_scan_b555(*_args, **_kwargs):
        return {"meta": {"incomplete": False, "read_count": 3}, "programs": {}}

    def _fake_scan_b509(*_args, **_kwargs):
        return {"meta": {"incomplete": False, "read_count": 0}, "devices": {}}

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b555", _fake_scan_b555)
    monkeypatch.setattr(scan_mod, "scan_b509", _fake_scan_b509)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b555_dump=True)

    assert artifact["b555_dump"]["meta"]["read_count"] == 3
    assert artifact["b509_dump"]["meta"]["read_count"] == 0


def test_scan_vrc_skips_b555_when_b524_is_incomplete(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": True}, "groups": {}}

    def _unexpected_scan_b555(*_args, **_kwargs):
        raise AssertionError("B555 should be skipped when B524 is incomplete")

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b555", _unexpected_scan_b555)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b555_dump=True)

    assert "b555_dump" not in artifact


def test_scan_vrc_propagates_incomplete_b555_and_skips_b509(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": False}, "groups": {}}

    def _fake_scan_b555(*_args, **_kwargs):
        return {
            "meta": {
                "incomplete": True,
                "incomplete_reason": "user_interrupt",
                "read_count": 5,
            },
            "programs": {},
        }

    def _unexpected_scan_b509(*_args, **_kwargs):
        raise AssertionError("B509 should be skipped after incomplete B555 dump")

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b555", _fake_scan_b555)
    monkeypatch.setattr(scan_mod, "scan_b509", _unexpected_scan_b509)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b555_dump=True)

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "b555_user_interrupt"
    assert artifact["b555_dump"]["meta"]["read_count"] == 5
    assert "b509_dump" not in artifact
