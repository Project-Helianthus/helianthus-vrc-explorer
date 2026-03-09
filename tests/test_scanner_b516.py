from __future__ import annotations

import struct

from helianthus_vrc_explorer.scanner.b516 import DEFAULT_B516_SELECTORS, scan_b516
from helianthus_vrc_explorer.scanner.scan import scan_vrc
from helianthus_vrc_explorer.transport.base import TransportError, TransportTimeout


def _build_b516_reply(payload: bytes, value_wh: float) -> bytes:
    return bytes((payload[1], 0xAA, 0xBB, payload[4], payload[5], payload[6], payload[7])) + (
        struct.pack("<f", value_wh)
    )


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
        assert (primary, secondary) == (0xB5, 0x16)
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


def test_scan_b516_preserves_raw_evidence_selector_context_and_errors() -> None:
    responses: dict[bytes, bytes | Exception] = {}
    for index, spec in enumerate(DEFAULT_B516_SELECTORS, start=1):
        responses[spec.payload] = _build_b516_reply(spec.payload, value_wh=index * 100.0)

    gas_hot_water = next(
        spec for spec in DEFAULT_B516_SELECTORS if spec.key == "system.gas.hot_water"
    )
    previous_electric_dhw = next(
        spec for spec in DEFAULT_B516_SELECTORS if spec.key == "year.previous.electricity.hot_water"
    )
    responses[gas_hot_water.payload] = TransportTimeout("timed out")
    responses[previous_electric_dhw.payload] = bytes.fromhex("03aabb030400")

    artifact = scan_b516(_ProtoOnlyTransport(responses), dst=0x15)

    meta = artifact["meta"]
    assert meta["destination_address"] == "0x15"
    assert meta["read_count"] == len(DEFAULT_B516_SELECTORS)
    assert meta["error_count"] == 2
    assert meta["incomplete"] is False

    gas_heating = artifact["entries"]["system.gas.heating"]
    assert gas_heating["period"] == "system"
    assert gas_heating["source"] == "gas"
    assert gas_heating["usage"] == "heating"
    assert gas_heating["request_hex"] == bytes.fromhex("1000ffff04030030").hex()
    assert (
        gas_heating["reply_hex"]
        == _build_b516_reply(bytes.fromhex("1000ffff04030030"), 100.0).hex()
    )
    assert gas_heating["echo_period"] == "0x0"
    assert gas_heating["echo_source"] == "0x4"
    assert gas_heating["echo_usage"] == "0x3"
    assert gas_heating["echo_window"] == "0x00"
    assert gas_heating["echo_qualifier"] == "0x0"
    assert gas_heating["value_wh"] == 100.0
    assert gas_heating["value_kwh"] == 0.1
    assert gas_heating["error"] is None

    gas_hot_water_entry = artifact["entries"]["system.gas.hot_water"]
    assert gas_hot_water_entry["request_hex"] == gas_hot_water.payload.hex()
    assert gas_hot_water_entry["reply_hex"] is None
    assert gas_hot_water_entry["error"] == "timeout"

    previous_electric_dhw_entry = artifact["entries"]["year.previous.electricity.hot_water"]
    assert previous_electric_dhw_entry["request_hex"] == previous_electric_dhw.payload.hex()
    assert previous_electric_dhw_entry["reply_hex"] == "03aabb030400"
    assert previous_electric_dhw_entry["error"].startswith("parse_error:")


def test_scan_vrc_adds_b516_dump_when_opted_in(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": False}, "groups": {}}

    def _fake_scan_b516(*_args, **_kwargs):
        return {"meta": {"incomplete": False, "read_count": 12}, "entries": {}}

    def _fake_scan_b509(*_args, **_kwargs):
        return {"meta": {"incomplete": False, "read_count": 0}, "devices": {}}

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b516", _fake_scan_b516)
    monkeypatch.setattr(scan_mod, "scan_b509", _fake_scan_b509)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b516_dump=True)

    assert artifact["b516_dump"]["meta"]["read_count"] == 12
    assert artifact["b509_dump"]["meta"]["read_count"] == 0


def test_scan_vrc_skips_b516_when_b524_is_incomplete(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": True}, "groups": {}}

    def _unexpected_scan_b516(*_args, **_kwargs):
        raise AssertionError("B516 should be skipped when B524 is incomplete")

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b516", _unexpected_scan_b516)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b516_dump=True)

    assert "b516_dump" not in artifact


def test_scan_vrc_propagates_incomplete_b516_and_skips_b509(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.scan as scan_mod

    def _fake_scan_b524(*_args, **_kwargs):
        return {"meta": {"incomplete": False}, "groups": {}}

    def _fake_scan_b516(*_args, **_kwargs):
        return {
            "meta": {
                "incomplete": True,
                "incomplete_reason": "user_interrupt",
                "read_count": 7,
            },
            "entries": {},
        }

    def _unexpected_scan_b509(*_args, **_kwargs):
        raise AssertionError("B509 should be skipped after incomplete B516 dump")

    monkeypatch.setattr(scan_mod, "scan_b524", _fake_scan_b524)
    monkeypatch.setattr(scan_mod, "scan_b516", _fake_scan_b516)
    monkeypatch.setattr(scan_mod, "scan_b509", _unexpected_scan_b509)

    artifact = scan_vrc(_NoopTransport(), dst=0x15, b509_ranges=[], b516_dump=True)

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "b516_user_interrupt"
    assert artifact["b516_dump"]["meta"]["read_count"] == 7
    assert "b509_dump" not in artifact
