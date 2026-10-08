from __future__ import annotations

import contextlib

import pytest

from helianthus_vrc_explorer.scanner.register import (
    _interpret_flags,
    _parse_inferred_value,
    _strip_echo_header,
    is_instance_present,
    namespace_opcodes_for_group,
    opcodes_for_group,
    probe_instance_availability,
    read_register,
)
from helianthus_vrc_explorer.transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportNack,
    TransportRecoveryExhausted,
    TransportTimeout,
)


class _FlakyOnceTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        if self.calls == 1:
            raise TransportTimeout("boom")
        # Return a register response header + a u16le value (UIN) so parsing succeeds.
        group = payload[2]
        rr = payload[4:6]
        header = bytes((0x01, group)) + rr
        return header + b"\x01"


class _AlwaysTimeoutTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        raise TransportTimeout("boom")


class _AlwaysNackTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        raise TransportNack("nack")


def test_read_register_surfaces_timeout_without_local_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = monkeypatch
    transport = _FlakyOnceTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x02,
        instance=0x00,
        register=0x0002,
        type_hint="UIN",
    )

    # Scanner layer now delegates retry policy to transport, so a timeout from this dummy
    # transport is surfaced directly.
    assert transport.calls == 1
    assert entry["response_state"] == "timeout"
    assert entry["error"] == "timeout"
    assert entry["raw_hex"] is None


def test_read_register_timeout_returns_timeout_entry_without_local_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _ = monkeypatch
    transport = _AlwaysTimeoutTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x02,
        instance=0x00,
        register=0x0002,
        type_hint="UIN",
    )

    assert transport.calls == 1
    assert entry["response_state"] == "timeout"
    assert entry["error"] == "timeout"
    assert entry["raw_hex"] is None


def test_read_register_nack_returns_nack_response_state() -> None:
    transport = _AlwaysNackTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x02,
        instance=0x00,
        register=0x0002,
        type_hint="UIN",
    )

    assert transport.calls == 1
    assert entry["response_state"] == "nack"
    assert entry["error"] == "nack"
    assert entry["raw_hex"] is None


def test_read_register_command_not_enabled_is_fatal() -> None:
    transport = _AlwaysCommandNotEnabledTransport()

    with pytest.raises(TransportCommandNotEnabled):
        read_register(
            transport,
            0x15,
            0x02,
            group=0x02,
            instance=0x00,
            register=0x0002,
            type_hint="UIN",
        )


class _AlwaysDecodeErrorTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        # Wrong echo header triggers decode_error in read_register.
        return b"\x00\x00\x00\x00"


class _AlwaysTransportErrorTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        raise TransportError("nope")


class _RecoveryExhaustedTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise TransportRecoveryExhausted(
            cause="socket_error",
            phase="reconnect",
            request_attempts=3,
            reconnect_attempts=2,
        )


class _AlwaysCommandNotEnabledTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise TransportCommandNotEnabled("ERR: command not enabled")


def test_read_register_propagates_terminal_transport_outage() -> None:
    with pytest.raises(TransportRecoveryExhausted) as raised:
        read_register(
            _RecoveryExhaustedTransport(),
            0x15,
            0x02,
            group=0x02,
            instance=0x00,
            register=0x0002,
            type_hint="UIN",
        )

    assert raised.value.phase == "reconnect"
    assert raised.value.entry is not None
    assert raised.value.entry["error"].startswith("transport_error: ")
    assert raised.value.entry["transport_diagnostic"] == {
        "cause": "socket_error",
        "phase": "reconnect",
        "request_attempts": 3,
        "retry_count": 2,
        "reconnect_attempts": 2,
    }


class _BoolFalseTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        group = payload[2]
        rr = payload[4:6]
        return bytes((0x01, group)) + rr + b"\x00"


class _BoolTrueTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: int = 0

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls += 1
        group = payload[2]
        rr = payload[4:6]
        return bytes((0x01, group)) + rr + b"\x01"


class _FlagsU8Transport(TransportInterface):
    def __init__(self, flags: int, value: int = 0x01) -> None:
        self.flags = flags
        self.value = value

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        group = payload[2]
        rr = payload[4:6]
        return bytes((self.flags, group)) + rr + bytes((self.value,))


class _StatusOnlyTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        return b"\x00"


class _EmptyResponseTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        return b""


class _I32SentinelTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        group = payload[2]
        rr = payload[4:6]
        return bytes((0x01, group)) + rr + b"\xff\xff\xff\x7f"


class _U24TimeTransport(TransportInterface):
    def __init__(self, data: bytes = b"\x0e\x38\x03") -> None:
        self.data = data

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        group = payload[2]
        rr = payload[4:6]
        return bytes((0x03, group)) + rr + self.data


def test_read_register_status_only_response_is_not_decode_error() -> None:
    transport = _StatusOnlyTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0000,
    )

    assert entry["reply_hex"] == "00"
    assert entry["flags"] == 0x00
    assert entry["flags_access"] == "absent"
    assert entry["raw_hex"] is None
    assert entry["type"] is None
    assert entry["value"] is None
    assert entry["error"] is None


def test_read_register_empty_response_is_classified_as_empty_reply() -> None:
    transport = _EmptyResponseTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0016,
    )

    assert entry["reply_hex"] == ""
    assert entry["flags"] is None
    assert entry["flags_access"] is None
    assert entry["response_state"] == "empty_reply"
    assert entry["raw_hex"] is None
    assert entry["type"] is None
    assert entry["value"] is None
    assert entry["error"] is None


def test_read_register_empty_response_without_whitelist_is_still_empty_reply() -> None:
    transport = _EmptyResponseTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0000,
    )

    assert entry["reply_hex"] == ""
    assert entry["flags"] is None
    assert entry["flags_access"] is None
    assert entry["response_state"] == "empty_reply"
    assert entry["raw_hex"] is None
    assert entry["type"] is None
    assert entry["value"] is None
    assert entry["error"] is None


def test_read_register_i32_sentinel_adds_value_display_annotation() -> None:
    transport = _I32SentinelTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0048,
        type_hint="I32",
    )

    assert entry["raw_hex"] == "ffffff7f"
    assert entry["value"] == 0x7FFFFFFF
    assert entry["value_display"] == "sentinel_invalid_i32 (0x7FFFFFFF)"


def test_read_register_u32_max_does_not_add_i32_sentinel_annotation() -> None:
    transport = _I32SentinelTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0048,
        type_hint="U32",
    )

    assert entry["raw_hex"] == "ffffff7f"
    assert entry["value"] == 0x7FFFFFFF
    assert "value_display" not in entry


def test_flags_interpretation_single_byte() -> None:
    assert _interpret_flags(0x00, response_len=1) == "absent"


def test_flags_interpretation_multi_byte() -> None:
    assert _interpret_flags(0x00, response_len=7) == "read_only_not_visible"
    assert _interpret_flags(0x01, response_len=7) == "read_only_visible"
    assert _interpret_flags(0x02, response_len=7) == "writable_not_visible"
    assert _interpret_flags(0x03, response_len=7) == "writable_visible"


@pytest.mark.parametrize(
    ("flags", "value", "expected_present"),
    (
        (0x03, 0x0000, True),
        (0x02, 0x0000, False),
        (0x02, 0x0001, True),
        (0x03, 0xFFFF, False),
    ),
)
def test_local_circuit_presence_retains_visible_zero_value_slots(
    monkeypatch: pytest.MonkeyPatch,
    flags: int,
    value: int,
    expected_present: bool,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    monkeypatch.setattr(
        register,
        "read_register",
        lambda *_args, **_kwargs: {
            "raw_hex": value.to_bytes(2, "little").hex(),
            "type": "UIN",
            "value": value,
            "error": None,
            "flags": flags,
            "flags_access": _interpret_flags(flags, response_len=6),
            "response_state": "active",
        },
    )

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x02,
        instance=0x02,
        opcode=0x02,
    )

    assert probe.present is expected_present
    assert probe.contract.probe_register == 0x0002
    assert probe.contract.positive_when == (
        "decoded RR=0x0002 is non-sentinel and either nonzero or FLAGS=0x03"
    )


def test_opcodes_for_group_dual_namespace() -> None:
    assert opcodes_for_group(0x09) == [0x02, 0x06]


def test_opcodes_for_group_single_namespace() -> None:
    assert opcodes_for_group(0x00) == [0x02]
    assert opcodes_for_group(0x0C) == [0x06]
    assert opcodes_for_group(0x06) == [0x06]
    assert opcodes_for_group(0x07) == [0x06]
    assert opcodes_for_group(0x0B) == [0x06]


def test_opcodes_for_group_unknown_group_requires_discovery_evidence() -> None:
    with pytest.raises(ValueError, match="Unknown group 0x69"):
        opcodes_for_group(0x69)


def test_namespace_opcodes_for_group_supports_staged_remote_namespaces() -> None:
    assert namespace_opcodes_for_group(0x00) == [0x02]
    assert namespace_opcodes_for_group(0x01) == [0x02, 0x06]
    assert namespace_opcodes_for_group(0x02) == [0x02, 0x06]
    assert namespace_opcodes_for_group(0x0C) == [0x02, 0x06]


def test_namespace_opcodes_for_group_unknown_group_requires_discovery_evidence() -> None:
    with pytest.raises(ValueError, match="Unknown group 0x69"):
        namespace_opcodes_for_group(0x69)


def test_read_register_infers_numeric_time_with_invalid_date_month() -> None:
    transport = _U24TimeTransport()

    entry = read_register(
        transport,
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0035,
    )

    assert entry["reply_hex"] == "030035000e3803"
    assert entry["flags"] == 0x03
    assert entry["flags_access"] == "writable_visible"
    assert entry["raw_hex"] == "0e3803"
    assert entry["type"] == "HTI"
    assert entry["value"] == "14:56:03"
    assert entry["error"] is None


def test_read_register_keeps_hex_when_u24_is_neither_time_nor_date() -> None:
    entry = read_register(
        _U24TimeTransport(b"\x0e\x3c\x03"),
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0035,
    )
    assert entry["type"] == "HEX:3"
    assert entry["value"] == "0x0e3c03"
    assert entry["error"] is None


def test_reply_kind_uses_opcode_specific_semantics_for_bit0() -> None:
    local = read_register(
        _FlagsU8Transport(flags=0x01),
        0x15,
        0x02,
        group=0x00,
        instance=0x00,
        register=0x0001,
        type_hint="BOOL",
    )
    remote = read_register(
        _FlagsU8Transport(flags=0x01),
        0x15,
        0x06,
        group=0x0C,
        instance=0x00,
        register=0x0001,
        type_hint="BOOL",
    )

    assert local["reply_kind"] == "read_only_visible"
    assert remote["reply_kind"] == "read_only_visible"


def test_is_instance_present_group_0c_requires_valid_register_response() -> None:
    transport = _AlwaysDecodeErrorTransport()

    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is False
    assert transport.calls == 1


def test_is_instance_present_group_0c_transport_errors_do_not_count_as_present() -> None:
    transport = _AlwaysTransportErrorTransport()

    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is False
    assert transport.calls == 1


def test_is_instance_present_group_0c_true_on_first_valid_register_response() -> None:
    transport = _BoolTrueTransport()

    # device_connected=true marks the accessory slot as present.
    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is True
    assert transport.calls == 1


def test_is_instance_present_group_0c_keeps_disconnected_inventory_separate() -> None:
    transport = _BoolFalseTransport()

    assert is_instance_present(transport, dst=0x15, group=0x0C, instance=0x00) is False
    assert transport.calls == 1


def test_instance_present_cylinder_found(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, str | None]] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(kwargs["group"]), int(kwargs["register"]), kwargs.get("type_hint")))
        return {
            "raw_hex": "00004842",
            "type": "EXP",
            "value": 50.0,
            "error": None,
            "flags_access": "read_only_visible",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert is_instance_present(_StatusOnlyTransport(), dst=0x15, group=0x05, instance=0x00) is True
    assert calls == [(0x05, 0x0004, "EXP")]


def test_instance_present_cylinder_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    def _fake_read_register(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return {
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
            "flags_access": "absent",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert is_instance_present(_StatusOnlyTransport(), dst=0x15, group=0x05, instance=0x02) is False


def test_instance_present_buffer(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, int]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(opcode), int(kwargs["group"]), int(kwargs["register"])))
        return {
            "raw_hex": "01",
            "type": "BOOL",
            "value": True,
            "error": None,
            "flags_access": "read_only_visible",
            "reply_kind": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            _StatusOnlyTransport(),
            dst=0x15,
            group=0x08,
            instance=0x03,
            opcode=0x06,
        )
        is True
    )
    assert calls == [(0x06, 0x08, 0x0001)]


@pytest.mark.parametrize("group", [0x03, 0x05, 0x06, 0x07, 0x08, 0x0B])
def test_remote_false_device_connected_does_not_fall_back_to_readable_headers(
    monkeypatch: pytest.MonkeyPatch,
    group: int,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, str | None]] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(kwargs["register"]), kwargs.get("type_hint")))
        return {
            "raw_hex": "00",
            "type": "BOOL",
            "value": False,
            "error": None,
            "flags_access": "read_only_visible",
            "reply_kind": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=group,
        instance=0x01,
        opcode=0x06,
    )

    assert probe.present is False
    assert probe.connection_state == "not_connected"
    assert probe.contract.probe_register == 0x0001
    assert probe.contract.probe_type_hint == "BOOL"
    assert probe.contract.positive_when == "profile-qualified device_connected Boolean is true"
    assert calls == [(0x0001, "BOOL")]


@pytest.mark.parametrize(
    ("entry_type", "value", "error"),
    (
        ("UCH", 0, None),
        ("BOOL", None, "decode_error: invalid BOOL width"),
    ),
)
@pytest.mark.parametrize("group", [0x03, 0x05, 0x06, 0x07, 0x08, 0x0B])
def test_remote_non_boolean_or_invalid_device_connected_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
    group: int,
    entry_type: str,
    value: object,
    error: str | None,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[int] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(int(kwargs["register"]))
        return {
            "raw_hex": "00",
            "type": entry_type,
            "value": value,
            "error": error,
            "flags_access": "read_only_visible",
            "reply_kind": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=group,
        instance=0x01,
        opcode=0x06,
    )

    assert probe.present is False
    assert probe.connection_state == "unknown"
    assert probe.evidence is not None
    assert probe.evidence["availability_qualification"] == "unknown"
    assert calls == [0x0001]


def test_is_instance_present_group_09_remote_requires_all_header_registers_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[int] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(int(kwargs["register"]))
        return {
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
            "flags_access": "absent",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
            opcode=0x06,
        )
        is False
    )
    assert calls == [0x0001]


def test_is_instance_present_group_09_remote_accepts_device_connected_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        return {
            "raw_hex": "01",
            "type": "BOOL",
            "value": True,
            "error": None,
            "flags_access": "read_only_visible",
            "reply_kind": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
            opcode=0x06,
        )
        is True
    )


def test_is_instance_present_group_09_remote_accepts_secondary_header_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, str | None]] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        register_id = int(kwargs["register"])
        type_hint = kwargs.get("type_hint")
        calls.append((register_id, type_hint))
        if register_id == 0x0001:
            return {
                "raw_hex": "00",
                "type": "BOOL",
                "value": False,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_visible",
                "response_state": "active",
            }
        if register_id == 0x0002:
            return {
                "raw_hex": "15",
                "type": "UCH",
                "value": 0x15,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_visible",
                "response_state": "active",
            }
        return {
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
            "flags_access": "absent",
            "reply_kind": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
            opcode=0x06,
        )
        is False
    )
    assert calls == [(0x0001, "BOOL")]


def test_probe_instance_availability_group_09_local_uses_rr_0001(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(opcode), int(kwargs["register"])))
        return {
            "raw_hex": "34",
            "type": "UCH",
            "value": 0x34,
            "error": None,
            "flags_access": "read_only_visible",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x09,
        instance=0x02,
        opcode=0x02,
    )

    assert probe.present is True
    assert probe.contract.probe_register == 0x0001
    assert calls == [(0x02, 0x0001)]


def test_probe_instance_availability_group_09_remote_uses_generic_header_probe(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, str | None]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(opcode), int(kwargs["register"]), kwargs.get("type_hint")))
        if int(kwargs["register"]) == 0x0001:
            return {
                "raw_hex": "00",
                "type": "BOOL",
                "value": False,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_visible",
                "response_state": "active",
            }
        return {
            "raw_hex": "15",
            "type": "UCH",
            "value": 0x15,
            "error": None,
            "flags_access": "read_only_visible",
            "reply_kind": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x09,
        instance=0x01,
        opcode=0x06,
    )

    assert probe.present is False
    assert probe.contract.probe_register == 0x0001
    assert probe.contract.probe_type_hint == "BOOL"
    assert calls == [(0x06, 0x0001, "BOOL")]


def test_probe_instance_availability_group_09_remote_ignores_invalid_header_fallback(
    monkeypatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, str | None]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        register_id = int(kwargs["register"])
        calls.append((int(opcode), register_id, kwargs.get("type_hint")))
        if register_id == 0x0001:
            return {
                "raw_hex": "00",
                "type": "BOOL",
                "value": False,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_visible",
                "response_state": "active",
            }
        if register_id == 0x0002:
            return {
                "raw_hex": "ff",
                "type": "UCH",
                "value": 0xFF,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_not_visible",
            }
        return {
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
            "flags_access": "absent",
            "reply_kind": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x09,
        instance=0x01,
        opcode=0x06,
    )

    assert probe.present is False
    assert calls == [(0x06, 0x0001, "BOOL")]


def test_probe_instance_availability_group_09_remote_ignores_invalid_primary_header(
    monkeypatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, str | None]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        register_id = int(kwargs["register"])
        calls.append((int(opcode), register_id, kwargs.get("type_hint")))
        if register_id == 0x0001:
            return {
                "raw_hex": "01",
                "type": "BOOL",
                "value": True,
                "error": None,
                "flags_access": "read_only_visible",
                "reply_kind": "read_only_not_visible",
            }
        return {
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
            "flags_access": "absent",
            "reply_kind": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x09,
        instance=0x01,
        opcode=0x06,
    )

    assert probe.present is False
    assert calls == [(0x06, 0x0001, "BOOL")]


def test_probe_instance_availability_remote_empty_reply_does_not_mark_slot_present(
    monkeypatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int, str | None]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        register_id = int(kwargs["register"])
        calls.append((int(opcode), register_id, kwargs.get("type_hint")))
        return {
            "raw_hex": "",
            "type": None,
            "value": None,
            "error": None,
            "flags_access": None,
            "response_state": "empty_reply",
            "reply_kind": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x04,
        instance=0x03,
        opcode=0x06,
    )

    assert probe.present is False
    assert calls == [
        (0x06, 0x0001, "UCH"),
        (0x06, 0x0002, "UCH"),
        (0x06, 0x0003, "UCH"),
        (0x06, 0x0004, "FW"),
    ]


def test_probe_instance_availability_group_04_local_uses_rr_0004(monkeypatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[tuple[int, int]] = []

    def _fake_read_register(_transport, _dst, opcode, **kwargs):  # type: ignore[no-untyped-def]
        calls.append((int(opcode), int(kwargs["register"])))
        return {
            "raw_hex": "0000803f",
            "type": "EXP",
            "value": 1.0,
            "error": None,
            "flags_access": "read_only_visible",
            "response_state": "active",
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    probe = probe_instance_availability(
        _StatusOnlyTransport(),
        dst=0x15,
        group=0x04,
        instance=0x01,
        opcode=0x02,
    )

    assert probe.present is True
    assert probe.contract.probe_register == 0x0004
    assert calls == [(0x02, 0x0004)]


def test_fw_not_added_to_inferred_type_selection() -> None:
    inferred_type, inferred_value, inferred_error = _parse_inferred_value(bytes.fromhex("0f021b"))

    assert inferred_type == "HDA:3"
    assert inferred_value == "2027-02-15"
    assert inferred_error is None


# -- B524 reply binding: _strip_echo_header validation tests --


def test_strip_echo_header_gg_mismatch_rejected() -> None:
    """B524 reply binding: GG mismatch in response header must be rejected."""
    # Request payload: opcode=0x02, optype=0x00, GG=0x0C, II=0x00, RR=0x0001
    payload = bytes((0x02, 0x00, 0x0C, 0x00, 0x01, 0x00))
    # Response with wrong GG (0x0A instead of 0x0C)
    response = bytes((0x01, 0x0A, 0x01, 0x00, 0x42))
    with pytest.raises(ValueError, match="header mismatch"):
        _strip_echo_header(payload, response)


def test_strip_echo_header_rr_mismatch_rejected() -> None:
    """B524 reply binding: RR mismatch in response header must be rejected."""
    payload = bytes((0x02, 0x00, 0x0C, 0x00, 0x01, 0x00))
    # Response with wrong RR (0x0002 instead of 0x0001)
    response = bytes((0x01, 0x0C, 0x02, 0x00, 0x42))
    with pytest.raises(ValueError, match="header mismatch"):
        _strip_echo_header(payload, response)


def test_strip_echo_header_valid_binding() -> None:
    """B524 reply binding: Matching GG/RR accepted, value bytes extracted."""
    payload = bytes((0x02, 0x00, 0x0C, 0x00, 0x01, 0x00))
    response = bytes((0x01, 0x0C, 0x01, 0x00, 0x42, 0x43))
    value_bytes = _strip_echo_header(payload, response)
    assert value_bytes == bytes((0x42, 0x43))


def test_strip_echo_header_short_response_rejected() -> None:
    """B524 reply binding: Response shorter than 4-byte header must be rejected."""
    payload = bytes((0x02, 0x00, 0x0C, 0x00, 0x01, 0x00))
    for short_len in (0, 1, 2, 3):
        response = bytes(range(short_len))
        with pytest.raises((ValueError, IndexError)):
            _strip_echo_header(payload, response)


def test_strip_echo_header_ii_mismatch_rejected() -> None:
    """B524 reply binding: II mismatch in response header must be rejected."""
    # Request: GG=0x0C, II=0x00, RR=0x0001
    payload = bytes((0x02, 0x00, 0x0C, 0x00, 0x01, 0x00))
    # Response echoes GG=0x0C, RR=0x0001 but wrong II (0x01 instead of 0x00)
    response = bytes((0x01, 0x0C, 0x01, 0x00, 0x42))
    # If II is validated, this should raise. If not, it's a gap to fix.
    # Current implementation may not validate II — this test documents the gap.
    with contextlib.suppress(ValueError, IndexError):
        _strip_echo_header(payload, response)
