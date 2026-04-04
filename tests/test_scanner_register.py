from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.register import (
    _interpret_flags,
    _parse_inferred_value,
    is_instance_present,
    namespace_opcodes_for_group,
    opcodes_for_group,
    read_register,
)
from helianthus_vrc_explorer.transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
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
    assert entry["error"] == "timeout"
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


class _AlwaysCommandNotEnabledTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise TransportCommandNotEnabled("ERR: command not enabled")


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


class _StatusOnlyTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        return b"\x00"


class _UnparseableU24Transport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        group = payload[2]
        rr = payload[4:6]
        # 3-byte value that is neither HTI nor HDA:3 (invalid BCD) -> should fallback to HEX:3.
        return bytes((0x03, group)) + rr + b"\x0e\x38\x03"


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


def test_flags_interpretation_single_byte() -> None:
    assert _interpret_flags(0x00, response_len=1) == "absent"


def test_flags_interpretation_multi_byte() -> None:
    assert _interpret_flags(0x00, response_len=7) == "volatile_ro"
    assert _interpret_flags(0x01, response_len=7) == "stable_ro"
    assert _interpret_flags(0x02, response_len=7) == "technical_rw"
    assert _interpret_flags(0x03, response_len=7) == "user_rw"


def test_opcodes_for_group_dual_namespace() -> None:
    assert opcodes_for_group(0x09) == [0x02, 0x06]


def test_opcodes_for_group_single_namespace() -> None:
    assert opcodes_for_group(0x00) == [0x02]
    assert opcodes_for_group(0x0C) == [0x06]


def test_namespace_opcodes_for_group_supports_staged_remote_namespaces() -> None:
    assert namespace_opcodes_for_group(0x01) == [0x02, 0x06]
    assert namespace_opcodes_for_group(0x02) == [0x02, 0x06]
    assert namespace_opcodes_for_group(0x0C) == [0x06]


def test_read_register_infers_hex_for_unparseable_u24_values() -> None:
    transport = _UnparseableU24Transport()

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
    assert entry["flags_access"] == "user_rw"
    assert entry["raw_hex"] == "0e3803"
    assert entry["type"] == "HEX:3"
    assert entry["value"] == "0x0e3803"
    assert entry["error"] is None


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


def test_is_instance_present_group_0c_false_when_device_connected_is_false() -> None:
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
            "flags_access": "stable_ro",
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
            "type": "UCH",
            "value": 1,
            "error": None,
            "flags_access": "stable_ro",
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


def test_is_instance_present_group_09_rejects_nan_values(monkeypatch: pytest.MonkeyPatch) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    calls: list[int] = []

    def _fake_read_register(*_args, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(int(kwargs["register"]))
        return {
            "raw_hex": "00000000",
            "type": "EXP",
            "value": float("nan"),
            "error": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
        )
        is False
    )
    assert calls == [0x0007, 0x000F]


def test_is_instance_present_group_09_accepts_non_nan_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import helianthus_vrc_explorer.scanner.register as register

    values = iter([float("nan"), 1.0])

    def _fake_read_register(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return {
            "raw_hex": "00000000",
            "type": "EXP",
            "value": next(values),
            "error": None,
        }

    monkeypatch.setattr(register, "read_register", _fake_read_register)

    assert (
        is_instance_present(
            transport=_StatusOnlyTransport(),
            dst=0x15,
            group=0x09,
            instance=0x00,
        )
        is True
    )


def test_fw_not_added_to_inferred_type_selection() -> None:
    inferred_type, inferred_value, inferred_error = _parse_inferred_value(bytes.fromhex("0f021b"))

    assert inferred_type == "HDA:3"
    assert inferred_value == "2027-02-15"
    assert inferred_error is None
