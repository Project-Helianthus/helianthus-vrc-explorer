from __future__ import annotations

from helianthus_vrc_explorer.scanner.b516 import scan_b516
from helianthus_vrc_explorer.scanner.scan import scan_vrc
from helianthus_vrc_explorer.transport.base import TransportError, TransportTimeout


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


def test_scan_b516_collects_entries_and_preserves_errors() -> None:
    responses = {
        bytes.fromhex("1000ffff04030030"): bytes.fromhex("00aabb0403003000004842"),
        bytes.fromhex("1000ffff04040030"): TransportTimeout("timeout"),
        bytes.fromhex("1000ffff03030030"): bytes.fromhex("00aabb0303003000002041"),
        bytes.fromhex("1000ffff03040030"): bytes.fromhex("00aabb030400300000a040"),
        bytes.fromhex("1003ffff04030032"): bytes.fromhex("03aabb0403003200002041"),
        bytes.fromhex("1003ffff04040032"): bytes.fromhex("03aabb040400320000a040"),
        bytes.fromhex("1003ffff03030032"): bytes.fromhex("03aabb030300320000f041"),
        bytes.fromhex("1003ffff03040032"): bytes.fromhex("03aabb0304003200002042"),
        bytes.fromhex("1003ffff04030030"): bytes.fromhex("03aabb0403003000002041"),
        bytes.fromhex("1003ffff04040030"): bytes.fromhex("03aabb040400300000a040"),
        bytes.fromhex("1003ffff03030030"): bytes.fromhex("03aabb030300300000f041"),
        bytes.fromhex("1003ffff03040030"): bytes.fromhex("03aabb0304003000002042"),
    }
    transport = _ProtoOnlyTransport(responses)

    artifact = scan_b516(transport, dst=0x15)

    meta = artifact["meta"]
    assert meta["destination_address"] == "0x15"
    assert meta["selector_count"] == 12
    assert meta["read_count"] == 12
    assert meta["error_count"] == 1
    assert meta["incomplete"] is False

    entries = artifact["entries"]
    assert entries["system.gas.heating"]["value_wh"] == 50.0
    assert entries["system.gas.hot_water"]["error"] == "timeout"
    assert entries["year.current.gas.heating"]["echo_period"] == "0x3"
    assert entries["year.previous.electricity.hot_water"]["value_kwh"] == 0.04


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

    artifact = scan_vrc(
        _NoopTransport(),
        dst=0x15,
        b509_ranges=[],
        b516_dump=True,
    )

    assert artifact["b516_dump"]["meta"]["read_count"] == 12
    assert artifact["b509_dump"]["meta"]["read_count"] == 0


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

    artifact = scan_vrc(
        _NoopTransport(),
        dst=0x15,
        b509_ranges=[],
        b516_dump=True,
    )

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "b516_user_interrupt"
    assert artifact["b516_dump"]["meta"]["read_count"] == 7
    assert "b509_dump" not in artifact
