from __future__ import annotations

import json
from pathlib import Path

from helianthus_vrc_explorer.scanner.scan import scan_vrc
from helianthus_vrc_explorer.transport.base import (
    TransportError,
    TransportInterface,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class _HybridTransport(TransportInterface):
    def __init__(self, fixture_path: Path) -> None:
        self._b524 = DummyTransport(fixture_path)

    def send(self, dst: int, payload: bytes) -> bytes:
        return self._b524.send(dst, payload)

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
        if primary != 0xB5 or secondary != 0x09:
            raise TransportError("unexpected proto selector")
        if len(payload) != 3 or payload[0] != 0x0D:
            raise TransportError("unexpected b509 payload")
        register = (payload[1] << 8) | payload[2]
        if register == 0x2700:
            return bytes.fromhex("00")
        if register == 0x2701:
            return bytes.fromhex("004574616a00")
        if register == 0x2702:
            raise TransportTimeout("timeout")
        raise TransportError("unmapped register")


class _TransientFirstProbeHybridTransport(_HybridTransport):
    def send(self, dst: int, payload: bytes) -> bytes:
        if payload == bytes((0x00, 0x00, 0x00)):
            return bytes.fromhex("00")
        return super().send(dst, payload)

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
        if primary != 0xB5 or secondary != 0x09:
            raise TransportError("unexpected proto selector")
        if len(payload) != 3 or payload[0] != 0x0D:
            raise TransportError("unexpected b509 payload")
        register = (payload[1] << 8) | payload[2]
        if register == 0x2700:
            return bytes.fromhex("00")
        raise TransportError("unmapped register")


def _write_fixture_group_02(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x05"}},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0002": {"raw_hex": "0100"},
                            "0x000f": {"raw_hex": "9a99d93f"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def test_scan_vrc_adds_b509_dump_section(tmp_path: Path) -> None:
    transport = _HybridTransport(_write_fixture_group_02(tmp_path))
    artifact = scan_vrc(transport, dst=0x15, b509_ranges=[(0x2700, 0x2702)], b509_dump=True)

    b509_dump = artifact.get("b509_dump")
    assert isinstance(b509_dump, dict)

    b509_meta = b509_dump.get("meta")
    assert isinstance(b509_meta, dict)
    assert b509_meta["ranges"] == ["0x2700..0x2702"]
    assert b509_meta["read_count"] == 3
    assert b509_meta["error_count"] == 1

    devices = b509_dump.get("devices")
    assert isinstance(devices, dict)
    regs = devices["0x15"]["registers"]
    assert regs["0x2700"]["reply_hex"] == "00"
    assert regs["0x2701"]["reply_hex"] == "004574616a00"
    assert regs["0x2702"]["error"] == "timeout"


def test_scan_vrc_keeps_b509_when_first_directory_probe_is_status_only(tmp_path: Path) -> None:
    artifact = scan_vrc(
        _TransientFirstProbeHybridTransport(_write_fixture_group_02(tmp_path)),
        dst=0x15,
        b509_ranges=[(0x2700, 0x2700)],
        b509_dump=True,
    )

    assert "b524_supported" not in artifact["meta"]
    assert "b524_skip_reason" not in artifact["meta"]
    assert "0x02" in artifact.get("operations", {}).get("0x02", {}).get("groups", {})
    assert artifact["meta"]["incomplete"] is False

    b509_dump = artifact.get("b509_dump")
    assert isinstance(b509_dump, dict)
    devices = b509_dump["devices"]
    assert devices["0x15"]["registers"]["0x2700"]["reply_hex"] == "00"
