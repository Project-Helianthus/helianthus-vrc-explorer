from __future__ import annotations

import struct
from collections import defaultdict

import pytest

from helianthus_vrc_explorer.protocol.b524 import build_register_write_payload
from helianthus_vrc_explorer.scanner.b524_parameter_writes import (
    B524NativeIdentity,
    B524ParameterTarget,
    B524WriteRetryBlocked,
    execute_parameter_write,
    prepare_parameter_write,
    read_browser_identity,
    read_parameter_edit_context,
    recheck_parameter_write,
)
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout

PROFILE = {
    "profile": "controller_b524",
    "profile_id": "basv2_sw0507_hw1704_api1",
    "eid": "BASV2",
    "software_raw_hex": "0507",
    "hardware_raw_hex": "1704",
    "model": "VRC test fixture",
    "firmware": "SW 0507 / HW 1704",
    "api_version": 1.0,
    "api_revision": 1.0,
    "controller_class_raw": "15",
    "controller_firmware_raw": "080500",
}
IDENTITY = B524NativeIdentity(
    manufacturer=0xB5,
    eid="BASV2",
    software_raw_hex="0507",
    hardware_raw_hex="1704",
)
TARGET = B524ParameterTarget(
    destination=0x15,
    opcode=0x02,
    group=0x02,
    instance=0x00,
    register=0x0014,
)


def _description(*, step: int | None = 1) -> dict[str, object]:
    return {
        "qualification": "matched",
        "description_opcode": "0x01",
        "read_opcode": "0x02",
        "group": "0x02",
        "instance": "0x00",
        "register": "0x0014",
        "type": "UCH",
        "width": 1,
        "min": 0,
        "max": 10,
        "step": step,
        "target_profile": dict(PROFILE),
    }


def _entry(*, raw_hex: str = "03", access: str = "writable_visible") -> dict[str, object]:
    return {
        "type": "UCH",
        "raw_hex": raw_hex,
        "flags_access": access,
        "parameter_description": _description(),
    }


def _reply(target: B524ParameterTarget, value_hex: str, *, flags: int = 3) -> bytes:
    return (
        bytes((flags, target.group))
        + target.register.to_bytes(2, "little")
        + bytes.fromhex(value_hex)
    )


class ScriptedTransport(TransportInterface):
    def __init__(
        self,
        target_replies: list[bytes | BaseException],
        *,
        identity: bytes = b"\xb5BASV2\x05\x07\x17\x04",
        retry_write: bool = False,
    ) -> None:
        self.identity = identity
        self.retry_write = retry_write
        self.target_replies = list(target_replies)
        self.requests: list[bytes] = []
        self.attempted_writes: list[bytes] = []
        self.counts: defaultdict[bytes, int] = defaultdict(int)

    def send_proto(self, dst, primary, secondary, payload, *, expect_response=True):
        assert (dst, primary, secondary, payload, expect_response) == (
            0x15,
            0x07,
            0x04,
            b"",
            True,
        )
        return self.identity

    def send(self, dst: int, payload: bytes) -> bytes:
        assert dst == 0x15
        self.requests.append(payload)
        self.counts[payload] += 1
        if payload == bytes.fromhex("000600") or payload == bytes.fromhex("000700"):
            return struct.pack("<f", 1.0)
        if payload == bytes.fromhex("060009010200"):
            return bytes.fromhex("0109020015")
        if payload == bytes.fromhex("060009010400"):
            return bytes.fromhex("01090400080500")
        if payload == TARGET.read_payload:
            reply = self.target_replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply
        raise AssertionError(f"unexpected request {payload.hex()}")

    def send_with_attempt_hook(self, dst, payload, attempt_hook):
        attempt_hook()
        self.attempted_writes.append(payload)
        if self.retry_write:
            attempt_hook()
        return b"\x00"


def _resolve_description(target, live_profile):
    assert target == TARGET
    assert live_profile == PROFILE
    return _description()


def _preparation(*, description=None, allow_incomplete_limits=False):
    return prepare_parameter_write(
        target=TARGET,
        entry=_entry(),
        description=_description() if description is None else description,
        profile=PROFILE,
        identity=IDENTITY,
        desired_value=5,
        allow_incomplete_limits=allow_incomplete_limits,
    )


def test_write_encoder_places_ot01_before_exact_selector_and_typed_value() -> None:
    assert build_register_write_payload(0x02, 0x02, 0x00, 0x0014, b"\x05") == bytes.fromhex(
        "02010200140005"
    )
    assert build_register_write_payload(0x06, 0x09, 0x01, 0x0020, b"\x00\x00\x20\x41") == (
        bytes.fromhex("06010901200000002041")
    )


def test_prepare_rejects_readonly_unknown_codec_and_generic_instance_even_with_exception() -> None:
    with pytest.raises(ValueError, match="concrete instance"):
        B524ParameterTarget(0x15, 0x06, 0x09, 0xFF, 0x0014)

    for entry, message in (
        (_entry(access="read_only_visible"), "writable"),
        ({**_entry(), "type": "mystery"}, "codec"),
    ):
        with pytest.raises(ValueError, match=message):
            prepare_parameter_write(
                target=TARGET,
                entry=entry,
                description=None,
                profile=PROFILE,
                identity=IDENTITY,
                desired_value=5,
                allow_incomplete_limits=True,
            )


def test_incomplete_limit_exception_requires_separate_exact_confirmation() -> None:
    preparation = prepare_parameter_write(
        target=TARGET,
        entry=_entry(),
        description=_description(step=None),
        profile=PROFILE,
        identity=IDENTITY,
        desired_value=5,
        allow_incomplete_limits=True,
    )
    assert preparation.incomplete_limits_confirmation_text is not None
    transport = ScriptedTransport([_reply(TARGET, "03")])

    with pytest.raises(ValueError, match="incomplete-limits confirmation"):
        execute_parameter_write(
            transport,
            preparation,
            concrete_confirmation=preparation.confirmation_text,
            incomplete_limits_confirmation=None,
            resolve_description=lambda target, profile: _description(step=None),
        )
    assert transport.requests == []
    assert transport.attempted_writes == []


def test_unknown_catalog_pretty_names_do_not_replace_native_identity_gate() -> None:
    native_profile = {
        "profile": "custom_explicit",
        "eid": "BASV2",
        "software_raw_hex": "0507",
        "hardware_raw_hex": "1704",
        "api_version": 1.0,
        "api_revision": 1.0,
    }
    preparation = prepare_parameter_write(
        target=TARGET,
        entry=_entry(),
        description=None,
        profile=native_profile,
        identity=IDENTITY,
        desired_value=5,
        allow_incomplete_limits=True,
    )
    assert preparation.profile == native_profile
    assert preparation.incomplete_limits_confirmation_text is not None


def test_profile_requires_complete_native_identity_even_for_incomplete_limits_exception() -> None:
    with pytest.raises(ValueError, match="missing native identity"):
        prepare_parameter_write(
            target=TARGET,
            entry=_entry(),
            description=None,
            profile={"profile": "custom_explicit"},
            identity=IDENTITY,
            desired_value=5,
            allow_incomplete_limits=True,
        )


def test_unknown_native_profile_cannot_reuse_cached_limits_as_if_exact() -> None:
    native_profile = {
        "profile": "custom_explicit",
        "eid": "BASV2",
        "software_raw_hex": "0507",
        "hardware_raw_hex": "1704",
    }
    description = _description()
    description["target_profile"] = native_profile
    description["qualification"] = "profile_qualified"
    description["source"] = "profile"
    with pytest.raises(ValueError, match="cached parameter limits require an exact native"):
        prepare_parameter_write(
            target=TARGET,
            entry=_entry(),
            description=description,
            profile=native_profile,
            identity=IDENTITY,
            desired_value=5,
            allow_incomplete_limits=True,
        )


def test_fresh_matched_limits_are_valid_for_current_unknown_native_profile() -> None:
    native_profile = {
        "profile": "custom_explicit",
        "eid": "BASV2",
        "software_raw_hex": "0507",
        "hardware_raw_hex": "1704",
    }
    description = _description()
    description["target_profile"] = native_profile
    description["source"] = "live"
    preparation = prepare_parameter_write(
        target=TARGET,
        entry=_entry(),
        description=description,
        profile=native_profile,
        identity=IDENTITY,
        desired_value=5,
    )
    assert preparation.incomplete_limits_confirmation_text is None


def test_only_live_or_exact_profile_qualified_descriptions_are_accepted() -> None:
    bundled = _description()
    bundled["qualification"] = "bundled"
    bundled["source"] = "profile"
    with pytest.raises(ValueError, match="not live or exact-profile qualified"):
        prepare_parameter_write(
            target=TARGET,
            entry=_entry(),
            description=bundled,
            profile=PROFILE,
            identity=IDENTITY,
            desired_value=5,
            allow_incomplete_limits=True,
        )

    exact_profile = _description()
    exact_profile["qualification"] = "profile_qualified"
    exact_profile["source"] = "profile"
    exact_profile["profile"] = exact_profile.pop("target_profile")
    preparation = prepare_parameter_write(
        target=TARGET,
        entry=_entry(),
        description=exact_profile,
        profile=PROFILE,
        identity=IDENTITY,
        desired_value=5,
    )
    assert preparation.description is not None
    assert preparation.description["qualification"] == "profile_qualified"
    assert preparation.description["source"] == "profile"


def test_remote_write_requires_separate_native_class_and_firmware() -> None:
    remote = B524ParameterTarget(0x15, 0x06, 0x09, 0x01, 0x0014)
    with pytest.raises(ValueError, match="device_class_raw, device_firmware_raw"):
        prepare_parameter_write(
            target=remote,
            entry=_entry(),
            description=None,
            profile={"profile": "custom_explicit"},
            identity=IDENTITY,
            desired_value=5,
            allow_incomplete_limits=True,
        )


def test_known_string_codec_can_use_separately_confirmed_missing_limits_exception() -> None:
    string_target = B524ParameterTarget(0x15, 0x02, 0x00, 0x00, 0x0010)
    preparation = prepare_parameter_write(
        target=string_target,
        entry={
            "type": "STR:*",
            "raw_hex": "6f6c6400",
            "flags_access": "writable_visible",
        },
        description=None,
        profile={
            "profile": "custom_explicit",
            "eid": "BASV2",
            "software_raw_hex": "0507",
            "hardware_raw_hex": "1704",
        },
        identity=IDENTITY,
        desired_value="new",
        allow_incomplete_limits=True,
    )
    assert preparation.desired_raw == b"new\x00"
    assert preparation.write_payload == bytes.fromhex("0201000010006e657700")
    assert preparation.incomplete_limits_confirmation_text is not None


def test_fresh_identity_access_baseline_one_write_and_desired_readback() -> None:
    preparation = _preparation()
    transport = ScriptedTransport([_reply(TARGET, "03"), _reply(TARGET, "05")])

    result = execute_parameter_write(
        transport,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )

    assert result.outcome == "desired"
    assert result.write_attempts == 1
    assert result.readback_raw_hex == "05"
    assert transport.attempted_writes == [bytes.fromhex("02010200140005")]
    assert bytes.fromhex("0102001400") not in transport.requests
    assert bytes.fromhex("0702001400") not in transport.requests


def test_connect_and_preconfirmation_context_use_fresh_native_evidence_without_describe() -> None:
    transport = ScriptedTransport([_reply(TARGET, "04")])
    assert read_browser_identity(transport, 0x15) == IDENTITY

    context = read_parameter_edit_context(
        transport,
        target=TARGET,
        entry={**_entry(), "name": "installer_threshold"},
        profile=PROFILE,
        identity=IDENTITY,
    )

    assert context.identity == IDENTITY
    assert context.entry["name"] == "installer_threshold"
    assert context.entry["raw_hex"] == "04"
    assert context.entry["value"] == 4
    assert context.entry["flags_access"] == "writable_visible"
    assert context.profile == PROFILE
    assert bytes.fromhex("0102001400") not in transport.requests
    assert bytes.fromhex("0702001400") not in transport.requests


def test_changed_baseline_requires_fresh_confirmation_and_admits_no_write() -> None:
    preparation = _preparation()
    transport = ScriptedTransport([_reply(TARGET, "04")])

    result = execute_parameter_write(
        transport,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )

    assert result.outcome == "reconfirmation_required"
    assert result.baseline_raw_hex == "04"
    assert result.write_attempts == 0
    assert transport.attempted_writes == []


def test_fresh_identity_mismatch_and_readonly_access_block_before_write() -> None:
    preparation = _preparation()
    wrong_identity = ScriptedTransport([], identity=b"\xb5OTHER\x05\x07\x17\x04")
    with pytest.raises(ValueError, match="does not match"):
        execute_parameter_write(
            wrong_identity,
            preparation,
            concrete_confirmation=preparation.confirmation_text,
            resolve_description=_resolve_description,
        )
    assert wrong_identity.requests == []
    assert wrong_identity.attempted_writes == []

    readonly = ScriptedTransport([_reply(TARGET, "03", flags=1)])
    result = execute_parameter_write(
        readonly,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )
    assert result.outcome == "blocked"
    assert result.read_error == "not_writable"
    assert result.write_attempts == 0
    assert readonly.attempted_writes == []


def test_retrying_transport_is_stopped_before_second_write_then_readback_classifies_other() -> None:
    preparation = _preparation()
    transport = ScriptedTransport([_reply(TARGET, "03"), _reply(TARGET, "04")], retry_write=True)

    result = execute_parameter_write(
        transport,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )

    assert result.outcome == "other"
    assert result.write_attempts == 1
    assert result.write_error == B524WriteRetryBlocked.__name__
    assert transport.attempted_writes == [preparation.write_payload]


def test_timeout_after_admission_does_not_retry_and_unknown_can_be_rechecked_read_only() -> None:
    preparation = _preparation()

    class TimeoutWriteTransport(ScriptedTransport):
        def send_with_attempt_hook(self, dst, payload, attempt_hook):
            attempt_hook()
            self.attempted_writes.append(payload)
            raise TransportTimeout("uncertain write feedback")

    transport = TimeoutWriteTransport(
        [_reply(TARGET, "03"), TransportTimeout("readback"), _reply(TARGET, "05")]
    )
    result = execute_parameter_write(
        transport,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )
    assert result.outcome == "unknown"
    assert result.write_attempts == 1
    assert len(transport.attempted_writes) == 1

    rechecked = recheck_parameter_write(transport, preparation)
    assert rechecked.outcome == "desired"
    assert rechecked.write_attempts == 0
    assert len(transport.attempted_writes) == 1


def test_noop_has_zero_writes() -> None:
    preparation = prepare_parameter_write(
        target=TARGET,
        entry=_entry(raw_hex="03"),
        description=_description(),
        profile=PROFILE,
        identity=IDENTITY,
        desired_value=3,
    )
    transport = ScriptedTransport([])
    result = execute_parameter_write(
        transport,
        preparation,
        concrete_confirmation=preparation.confirmation_text,
        resolve_description=_resolve_description,
    )
    assert result.outcome == "no_op"
    assert result.write_attempts == 0
    assert transport.requests == []
