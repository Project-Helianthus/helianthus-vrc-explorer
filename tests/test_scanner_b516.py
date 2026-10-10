from __future__ import annotations

import struct
from datetime import date

from helianthus_vrc_explorer.protocol.b516 import build_b516_year_payload, pack_b516_date
from helianthus_vrc_explorer.scanner.b516 import DEFAULT_B516_SELECTORS, scan_b516
from helianthus_vrc_explorer.scanner.scan import scan_vrc
from helianthus_vrc_explorer.transport.base import TransportError, TransportTimeout


def _reply(
    *,
    time_base: int = 0x0,
    return_code: int = 0x0,
    source: int,
    usage: int,
    day: int = 0,
    month: int = 0,
    year: int = 2000,
    value_wh: float = 0.0,
) -> bytes:
    date_word = pack_b516_date(day=day, month=month, year=year)
    status_byte = (return_code << 4) | (time_base & 0x3)
    return bytes(
        (
            status_byte,
            0xAA,
            0xBB,
            source,
            usage,
            date_word & 0xFF,
            (date_word >> 8) & 0xFF,
        )
    ) + struct.pack("<f", value_wh)


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


def _system_responses(*, day: int, month: int, year: int) -> dict[bytes, bytes]:
    """Build OK total replies, each echoing the same regulator date."""
    responses: dict[bytes, bytes] = {}
    for index, spec in enumerate(DEFAULT_B516_SELECTORS, start=1):
        # spec.payload bytes 4 and 5 are the energy type (source) and
        # operation mode (usage) the device would echo back unchanged.
        responses[spec.payload] = _reply(
            source=spec.payload[4],
            usage=spec.payload[5],
            day=day,
            month=month,
            year=year,
            value_wh=index * 100.0,
        )
    return responses


def test_scan_b516_derives_reference_year_from_regulator_echo_and_builds_year_requests() -> None:
    responses = _system_responses(day=7, month=4, year=2026)

    year_current_gas_heating = build_b516_year_payload(source=0x4, usage=0x3, year=2026)
    year_previous_gas_heating = build_b516_year_payload(source=0x4, usage=0x3, year=2025)
    responses[year_current_gas_heating] = _reply(
        time_base=0x3, source=0x4, usage=0x3, year=2026, value_wh=500.0
    )
    responses[year_previous_gas_heating] = _reply(
        time_base=0x3, source=0x4, usage=0x3, year=2025, value_wh=400.0
    )
    # Fill in the remaining 6 yearly selectors so the scan does not error.
    for source, usage in ((0x4, 0x4), (0x3, 0x3), (0x3, 0x4)):
        for year in (2026, 2025):
            responses[build_b516_year_payload(source=source, usage=usage, year=year)] = _reply(
                time_base=0x3, source=source, usage=usage, year=year, value_wh=1.0
            )

    artifact = scan_b516(_ProtoOnlyTransport(responses), dst=0x15)

    assert artifact["meta"]["reference_date_source"] == "regulator_echo"
    assert artifact["meta"]["reference_date"] == {"day": 7, "month": 4, "year": 2026}
    assert artifact["meta"]["read_count"] == 12
    assert artifact["meta"]["error_count"] == 0

    current_entry = artifact["entries"]["year.current.gas.heating"]
    assert current_entry["request_hex"] == year_current_gas_heating.hex()
    assert current_entry["year"] == 2026
    assert current_entry["request_date"] == {"day": 0, "month": 0, "year": 2026}
    assert current_entry["status"] == "ok"
    assert current_entry["value_wh"] == 500.0

    previous_entry = artifact["entries"]["year.previous.gas.heating"]
    assert previous_entry["request_hex"] == year_previous_gas_heating.hex()
    assert previous_entry["year"] == 2025
    assert previous_entry["value_wh"] == 400.0


def test_scan_b516_falls_back_to_host_clock_when_no_plausible_echo() -> None:
    # Every total reply echoes a non-plausible (zero) date, e.g. all-FF
    # qualifiers or a device that never reports day/month on totals.
    responses = _system_responses(day=0, month=0, year=2024)
    for source, usage in ((0x4, 0x3), (0x4, 0x4), (0x3, 0x3), (0x3, 0x4)):
        for year in (2030, 2029):
            responses[build_b516_year_payload(source=source, usage=usage, year=year)] = _reply(
                time_base=0x3, source=source, usage=usage, year=year, value_wh=1.0
            )

    artifact = scan_b516(_ProtoOnlyTransport(responses), dst=0x15, clock=lambda: date(2030, 6, 15))

    assert artifact["meta"]["reference_date_source"] == "host_clock"
    assert artifact["meta"]["reference_date"] == {"day": 15, "month": 6, "year": 2030}
    current_entry = artifact["entries"]["year.current.gas.heating"]
    assert current_entry["year"] == 2030
    previous_entry = artifact["entries"]["year.previous.gas.heating"]
    assert previous_entry["year"] == 2029


def test_scan_b516_not_ok_reply_has_no_value_and_is_not_counted_as_error() -> None:
    responses = _system_responses(day=7, month=4, year=2026)
    gas_heating_total = DEFAULT_B516_SELECTORS[0]
    assert gas_heating_total.key == "system.gas.heating"
    responses[gas_heating_total.payload] = _reply(
        return_code=0x1,
        source=gas_heating_total.payload[4],
        usage=gas_heating_total.payload[5],
        day=7,
        month=4,
        year=2026,
        value_wh=0.0,
    )
    for source, usage in ((0x4, 0x3), (0x4, 0x4), (0x3, 0x3), (0x3, 0x4)):
        for year in (2026, 2025):
            responses[build_b516_year_payload(source=source, usage=usage, year=year)] = _reply(
                time_base=0x3, source=source, usage=usage, year=year, value_wh=1.0
            )

    artifact = scan_b516(_ProtoOnlyTransport(responses), dst=0x15)

    entry = artifact["entries"]["system.gas.heating"]
    assert entry["status"] == "not_ok"
    assert entry["return_code"] == "0x1"
    assert entry["value_wh"] is None
    assert entry["value_kwh"] is None
    assert entry["error"] is None
    # A non-OK reply is a valid device answer, not a transport error.
    assert artifact["meta"]["error_count"] == 0


def test_scan_b516_preserves_raw_evidence_and_transport_errors() -> None:
    responses = _system_responses(day=7, month=4, year=2026)
    for source, usage in ((0x4, 0x3), (0x4, 0x4), (0x3, 0x3), (0x3, 0x4)):
        for year in (2026, 2025):
            responses[build_b516_year_payload(source=source, usage=usage, year=year)] = _reply(
                time_base=0x3, source=source, usage=usage, year=year, value_wh=1.0
            )

    gas_hot_water = next(
        spec for spec in DEFAULT_B516_SELECTORS if spec.key == "system.gas.hot_water"
    )
    previous_electric_dhw = build_b516_year_payload(source=0x3, usage=0x4, year=2025)
    responses[gas_hot_water.payload] = TransportTimeout("timed out")
    responses[previous_electric_dhw] = bytes.fromhex("03aabb030400")

    artifact = scan_b516(_ProtoOnlyTransport(responses), dst=0x15)

    meta = artifact["meta"]
    assert meta["destination_address"] == "0x15"
    assert meta["read_count"] == 12
    assert meta["error_count"] == 2
    assert meta["incomplete"] is False

    gas_heating = artifact["entries"]["system.gas.heating"]
    assert gas_heating["period"] == "system"
    assert gas_heating["source"] == "gas"
    assert gas_heating["usage"] == "heating"
    assert gas_heating["request_hex"] == bytes.fromhex("1000ffff04030030").hex()
    assert gas_heating["echo_period"] == "0x0"
    assert gas_heating["echo_source"] == "0x4"
    assert gas_heating["echo_usage"] == "0x3"
    assert gas_heating["status"] == "ok"
    assert gas_heating["value_wh"] == 100.0
    assert gas_heating["value_kwh"] == 0.1
    assert gas_heating["error"] is None

    gas_hot_water_entry = artifact["entries"]["system.gas.hot_water"]
    assert gas_hot_water_entry["request_hex"] == gas_hot_water.payload.hex()
    assert gas_hot_water_entry["reply_hex"] is None
    assert gas_hot_water_entry["error"] == "timeout"

    previous_electric_dhw_entry = artifact["entries"]["year.previous.electricity.hot_water"]
    assert previous_electric_dhw_entry["request_hex"] == previous_electric_dhw.hex()
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

    artifact = scan_vrc(
        _NoopTransport(),
        dst=0x15,
        b509_ranges=[],
        b516_dump=True,
        b509_dump=True,
    )

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
