"""Fail-closed scalar OP02/OP06 parameter writes for the Browser."""

from __future__ import annotations

import math
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from ..protocol.b524 import (
    RegisterOpcode,
    build_directory_probe_payload,
    build_register_read_payload,
    build_register_write_payload,
)
from ..protocol.b524_metadata import validate_parameter_edit
from ..protocol.basv import parse_scan_identification
from ..protocol.parser import (
    ValueEncodeError,
    ValueParseError,
    encode_typed_value,
    parse_typed_value,
)
from ..transport.base import TransportError, TransportInterface
from .b524_operation_writes import B524WriteRetryBlocked

type ParameterWriteOutcome = Literal[
    "desired",
    "other",
    "unknown",
    "reconfirmation_required",
    "no_op",
    "blocked",
]
type DescriptionResolver = Callable[
    ["B524ParameterTarget", Mapping[str, object]], Mapping[str, object] | None
]

_OPTIONAL_NATIVE_PROFILE_FIELDS = (
    "api_version",
    "api_revision",
    "controller_class_raw",
    "controller_firmware_raw",
)
_REMOTE_PROFILE_FIELDS = ("device_class_raw", "device_firmware_raw")
_WRITABLE_ACCESS = frozenset({"writable_not_visible", "writable_visible"})


def _u8(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFF:
        raise ValueError(f"{name} must be an integer in range 0..255")


def _u16(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must be an integer in range 0..65535")


def _compact_hex(value: object, *, name: str, allow_empty: bool = False) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be compact hexadecimal text")
    if not value and allow_empty:
        return b""
    if not value or len(value) % 2:
        raise ValueError(f"{name} must be compact hexadecimal text")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be compact hexadecimal text") from exc
    if result.hex() != value.lower():
        raise ValueError(f"{name} must be compact hexadecimal text")
    return result


@dataclass(frozen=True, slots=True)
class B524NativeIdentity:
    manufacturer: int
    eid: str
    software_raw_hex: str
    hardware_raw_hex: str

    def __post_init__(self) -> None:
        _u8("manufacturer", self.manufacturer)
        if self.manufacturer != 0xB5:
            raise ValueError("native identity must identify manufacturer 0xB5")
        if not isinstance(self.eid, str) or not self.eid.strip():
            raise ValueError("eid must be a non-empty string")
        _compact_hex(self.software_raw_hex, name="software_raw_hex")
        _compact_hex(self.hardware_raw_hex, name="hardware_raw_hex")


@dataclass(frozen=True, slots=True)
class B524ParameterTarget:
    destination: int
    opcode: RegisterOpcode
    group: int
    instance: int
    register: int

    def __post_init__(self) -> None:
        _u8("destination", self.destination)
        if self.destination in {0x00, 0xA9, 0xAA}:
            raise ValueError("destination is a reserved eBUS address")
        if self.opcode not in {0x02, 0x06}:
            raise ValueError("opcode must be 0x02 or 0x06")
        _u8("group", self.group)
        _u8("instance", self.instance)
        if self.instance == 0xFF:
            raise ValueError("a live write requires a concrete instance, not generic II=0xFF")
        _u16("register", self.register)

    @property
    def read_payload(self) -> bytes:
        return build_register_read_payload(
            self.opcode,
            self.group,
            self.instance,
            self.register,
        )

    @property
    def selector_text(self) -> str:
        return (
            f"dst=0x{self.destination:02X} OP=0x{self.opcode:02X} "
            f"GG=0x{self.group:02X} II=0x{self.instance:02X} RR=0x{self.register:04X}"
        )


@dataclass(frozen=True, slots=True)
class B524ParameterWritePreparation:
    target: B524ParameterTarget
    identity: B524NativeIdentity
    type_spec: str
    baseline_value: object
    baseline_raw: bytes
    desired_value: object
    desired_raw: bytes
    write_payload: bytes
    description: dict[str, object] | None
    profile: dict[str, object]
    confirmation_text: str
    incomplete_limits_confirmation_text: str | None
    no_op: bool


@dataclass(frozen=True, slots=True)
class B524ParameterEditContext:
    """Fresh read-only context shown before the user confirms an edit."""

    target: B524ParameterTarget
    entry: dict[str, object]
    profile: dict[str, object]
    identity: B524NativeIdentity


@dataclass(frozen=True, slots=True)
class B524ParameterWriteResult:
    outcome: ParameterWriteOutcome
    target: B524ParameterTarget
    write_attempts: int
    baseline_raw_hex: str | None
    readback_raw_hex: str | None
    write_error: str | None = None
    read_error: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class _RawSnapshot:
    raw: bytes | None
    flags: int | None
    access: str | None
    error: str | None


def _copy_mapping(value: Mapping[str, object], *, name: str) -> dict[str, object]:
    if any(not isinstance(key, str) for key in value):
        raise ValueError(f"{name} keys must be strings")
    return dict(value)


def _validate_profile(profile: Mapping[str, object], *, remote: bool) -> dict[str, object]:
    result = _copy_mapping(profile, name="profile")
    missing = [
        field for field in (_REMOTE_PROFILE_FIELDS if remote else ()) if result.get(field) is None
    ]
    if missing:
        raise ValueError(f"exact target profile is missing: {', '.join(missing)}")
    if remote and result.get("device_identity_required") is not True:
        raise ValueError("remote writes require separate concrete device identity")
    discriminator = result.get("profile")
    if not isinstance(discriminator, str) or not discriminator.strip():
        raise ValueError("exact target profile requires a profile discriminator")
    for field in ("api_version", "api_revision"):
        value = result.get(field)
        if value is None:
            continue
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError(f"exact target profile requires finite {field}")
    for field in (
        "controller_class_raw",
        "controller_firmware_raw",
        *(_REMOTE_PROFILE_FIELDS if remote else ()),
    ):
        if result.get(field) is not None:
            _compact_hex(result[field], name=f"profile.{field}")
    return result


def _validate_profile_identity(profile: Mapping[str, object], identity: B524NativeIdentity) -> None:
    declared = {
        "eid": identity.eid.strip().upper(),
        "software_raw_hex": identity.software_raw_hex.lower(),
        "hardware_raw_hex": identity.hardware_raw_hex.lower(),
    }
    missing = [field for field in declared if profile.get(field) is None]
    if missing:
        raise ValueError("exact target profile is missing native identity: " + ", ".join(missing))
    for field, expected in declared.items():
        value = profile.get(field)
        if not isinstance(value, str) or value.strip().lower() != expected.lower():
            raise ValueError(f"profile {field} contradicts the native identity")


def _selector_matches(description: Mapping[str, object], target: B524ParameterTarget) -> bool:
    expected = {
        "read_opcode": f"0x{target.opcode:02x}",
        "group": f"0x{target.group:02x}",
        "instance": f"0x{target.instance:02x}",
        "register": f"0x{target.register:04x}",
    }
    return all(description.get(key) == value for key, value in expected.items())


def _description_profile(description: Mapping[str, object]) -> object:
    return description.get("target_profile", description.get("profile"))


def _validate_description(
    description: Mapping[str, object] | None,
    *,
    target: B524ParameterTarget,
    profile: Mapping[str, object],
    type_spec: str,
    value: object,
    encoded: bytes,
) -> tuple[dict[str, object] | None, bool]:
    """Return (validated copy, incomplete limits).

    Missing limits and an unknown STEP are the only validation gaps eligible for
    the separately confirmed exception. Known range, width, codec, selector, and
    profile contradictions always fail closed.
    """

    if description is None:
        return None, True
    result = _copy_mapping(description, name="description")
    if result.get("qualification") not in {"matched", "profile_qualified"}:
        raise ValueError("parameter description is not live or exact-profile qualified")
    if result.get("qualification") == "profile_qualified" or result.get("source") == "profile":
        profile_id = profile.get("profile_id")
        if not isinstance(profile_id, str) or not profile_id.strip():
            raise ValueError("cached parameter limits require an exact native target profile")
    if not _selector_matches(result, target):
        raise ValueError("parameter description does not match the exact selector")
    if _description_profile(result) != dict(profile):
        raise ValueError("parameter description does not match the exact target profile")
    normalized_type = type_spec.strip().upper()
    if result.get("type") != normalized_type:
        raise ValueError("parameter description codec does not match the entry codec")
    width = result.get("width")
    if width is not None and width != len(encoded):
        raise ValueError("encoded width does not match the parameter description")

    incomplete = any(
        field not in result or result.get(field) is None for field in ("min", "max", "step")
    )
    validation_copy = dict(result)
    validation_copy["qualification"] = "matched"
    reason = validate_parameter_edit(
        validation_copy,
        type_spec=normalized_type,
        value=value,
        encoded=encoded,
    )
    if reason is None:
        return result, False
    if reason == "unvalidated" and incomplete:
        return result, True
    raise ValueError(reason)


def _confirmation_text(
    target: B524ParameterTarget,
    *,
    type_spec: str,
    baseline_value: object,
    baseline_raw: bytes,
    desired_value: object,
    desired_raw: bytes,
) -> str:
    return (
        f"Write {target.selector_text} as {type_spec}: "
        f"old={baseline_value!r} (raw 0x{baseline_raw.hex()}) -> "
        f"new={desired_value!r} (raw 0x{desired_raw.hex()})"
    )


def prepare_parameter_write(
    *,
    target: B524ParameterTarget,
    entry: Mapping[str, object],
    description: Mapping[str, object] | None,
    profile: Mapping[str, object],
    identity: B524NativeIdentity,
    desired_value: object,
    allow_incomplete_limits: bool = False,
) -> B524ParameterWritePreparation:
    """Prepare an offline scalar edit; this performs no device I/O."""

    access = entry.get("flags_access")
    if access not in _WRITABLE_ACCESS:
        raise ValueError("live parameter writes require fresh writable access")
    type_value = entry.get("type")
    if not isinstance(type_value, str) or not type_value.strip():
        raise ValueError("a known parameter codec is required")
    type_spec = type_value.strip().upper()
    baseline_raw = _compact_hex(entry.get("raw_hex"), name="entry.raw_hex")
    try:
        baseline_value = parse_typed_value(type_spec, baseline_raw)
        desired_raw = encode_typed_value(type_spec, desired_value)
        parsed_desired = parse_typed_value(type_spec, desired_raw)
    except (ValueEncodeError, ValueParseError) as exc:
        raise ValueError("a known, valid parameter codec is required") from exc
    if parsed_desired != desired_value and not (
        isinstance(parsed_desired, float)
        and isinstance(desired_value, (int, float))
        and math.isclose(parsed_desired, float(desired_value), rel_tol=0.0, abs_tol=1e-6)
    ):
        raise ValueError("desired value does not round-trip through the parameter codec")

    exact_profile = _validate_profile(profile, remote=target.opcode == 0x06)
    _validate_profile_identity(exact_profile, identity)
    exact_description, incomplete = _validate_description(
        description,
        target=target,
        profile=exact_profile,
        type_spec=type_spec,
        value=desired_value,
        encoded=desired_raw,
    )
    if incomplete and not allow_incomplete_limits:
        raise ValueError("parameter limits or STEP are incomplete; explicit exception is required")

    write_payload = build_register_write_payload(
        target.opcode,
        target.group,
        target.instance,
        target.register,
        desired_raw,
    )
    confirmation = _confirmation_text(
        target,
        type_spec=type_spec,
        baseline_value=baseline_value,
        baseline_raw=baseline_raw,
        desired_value=desired_value,
        desired_raw=desired_raw,
    )
    incomplete_confirmation = None
    if incomplete:
        missing_limits = [
            field
            for field in ("min", "max", "step")
            if exact_description is None or exact_description.get(field) is None
        ]
        incomplete_confirmation = (
            f"Allow incomplete limits for {target.selector_text} with known codec {type_spec}; "
            f"missing: {', '.join(missing_limits)}; write raw 0x{desired_raw.hex()}"
        )
    return B524ParameterWritePreparation(
        target=target,
        identity=identity,
        type_spec=type_spec,
        baseline_value=baseline_value,
        baseline_raw=baseline_raw,
        desired_value=desired_value,
        desired_raw=desired_raw,
        write_payload=write_payload,
        description=exact_description,
        profile=exact_profile,
        confirmation_text=confirmation,
        incomplete_limits_confirmation_text=incomplete_confirmation,
        no_op=baseline_raw == desired_raw,
    )


def read_browser_identity(
    transport: TransportInterface,
    destination: int,
) -> B524NativeIdentity:
    """Read native 07/04 EID/SW/HW for an explicit Browser connection."""

    _u8("destination", destination)
    if destination in {0x00, 0xA9, 0xAA}:
        raise ValueError("destination is a reserved eBUS address")
    send_proto = getattr(transport, "send_proto", None)
    if not callable(send_proto):
        raise ValueError("transport cannot verify native 07/04 identity")
    try:
        raw = send_proto(destination, 0x07, 0x04, b"", expect_response=True)
        actual = parse_scan_identification(raw)
    except (TransportError, TypeError, ValueError) as exc:
        raise ValueError("connected target identity could not be verified") from exc
    return B524NativeIdentity(
        manufacturer=actual.manufacturer,
        eid=actual.device_id,
        software_raw_hex=actual.sw,
        hardware_raw_hex=actual.hw,
    )


def _verify_identity(
    transport: TransportInterface,
    target: B524ParameterTarget,
    expected: B524NativeIdentity,
) -> B524NativeIdentity:
    actual = read_browser_identity(transport, target.destination)
    if (
        actual.manufacturer != expected.manufacturer
        or actual.eid.strip().upper() != expected.eid.strip().upper()
        or actual.software_raw_hex.lower() != expected.software_raw_hex.lower()
        or actual.hardware_raw_hex.lower() != expected.hardware_raw_hex.lower()
    ):
        raise ValueError("connected target EID/SW/HW identity does not match the prepared write")
    return actual


def _read_snapshot(
    transport: TransportInterface,
    target: B524ParameterTarget,
    *,
    require_writable: bool,
) -> _RawSnapshot:
    try:
        response = transport.send(target.destination, target.read_payload)
    except (TransportError, KeyboardInterrupt) as exc:
        return _RawSnapshot(None, None, None, type(exc).__name__)
    if len(response) < 4:
        return _RawSnapshot(None, None, None, "short_response")
    flags = response[0]
    if response[1] != target.group or int.from_bytes(response[2:4], "little") != target.register:
        return _RawSnapshot(None, flags, None, "selector_echo_mismatch")
    access = {
        0: "read_only_not_visible",
        1: "read_only_visible",
        2: "writable_not_visible",
        3: "writable_visible",
    }.get(flags)
    if access is None:
        return _RawSnapshot(None, flags, None, "unknown_access")
    if require_writable and access not in _WRITABLE_ACCESS:
        return _RawSnapshot(response[4:], flags, access, "not_writable")
    return _RawSnapshot(response[4:], flags, access, None)


def _read_float_information(
    transport: TransportInterface, target: B524ParameterTarget, identifier: int
) -> float:
    response = transport.send(target.destination, build_directory_probe_payload(identifier))
    if len(response) != 4:
        raise ValueError(f"system information 0x{identifier:04X} is unavailable")
    value = struct.unpack("<f", response)[0]
    if not math.isfinite(value):
        raise ValueError(f"system information 0x{identifier:04X} is unavailable")
    return value


def _read_profile_value(
    transport: TransportInterface,
    target: B524ParameterTarget,
    *,
    group: int,
    instance: int,
    register: int,
) -> str:
    profile_target = B524ParameterTarget(
        target.destination,
        0x06,
        group,
        instance,
        register,
    )
    snapshot = _read_snapshot(transport, profile_target, require_writable=False)
    if snapshot.error is not None or snapshot.raw is None:
        raise ValueError(
            f"profile evidence OP=0x06 GG=0x{group:02X} II=0x{instance:02X} "
            f"RR=0x{register:04X} is unavailable"
        )
    return snapshot.raw.hex()


def _fresh_profile(
    transport: TransportInterface,
    target: B524ParameterTarget,
    profile: Mapping[str, object],
) -> dict[str, object]:
    expected = _validate_profile(profile, remote=target.opcode == 0x06)
    live = dict(expected)
    if expected.get("api_version") is not None:
        live["api_version"] = _read_float_information(transport, target, 0x0006)
    if expected.get("api_revision") is not None:
        live["api_revision"] = _read_float_information(transport, target, 0x0007)
    if expected.get("controller_class_raw") is not None:
        live["controller_class_raw"] = _read_profile_value(
            transport, target, group=0x09, instance=0x01, register=0x0002
        )
    if expected.get("controller_firmware_raw") is not None:
        live["controller_firmware_raw"] = _read_profile_value(
            transport, target, group=0x09, instance=0x01, register=0x0004
        )
    if target.opcode == 0x06:
        live["device_class_raw"] = _read_profile_value(
            transport,
            target,
            group=target.group,
            instance=target.instance,
            register=0x0002,
        )
        live["device_firmware_raw"] = _read_profile_value(
            transport,
            target,
            group=target.group,
            instance=target.instance,
            register=0x0004,
        )
    compared_fields = tuple(
        field for field in _OPTIONAL_NATIVE_PROFILE_FIELDS if expected.get(field) is not None
    ) + (_REMOTE_PROFILE_FIELDS if target.opcode == 0x06 else ())
    for field in compared_fields:
        if live.get(field) != expected.get(field):
            raise ValueError(f"fresh native profile evidence changed: {field}")
    return live


def read_parameter_edit_context(
    transport: TransportInterface,
    *,
    target: B524ParameterTarget,
    entry: Mapping[str, object],
    profile: Mapping[str, object],
    identity: B524NativeIdentity,
) -> B524ParameterEditContext:
    """Refresh the pre-confirmation value/access/profile without Describe I/O."""

    actual_identity = _verify_identity(transport, target, identity)
    _validate_profile_identity(profile, actual_identity)
    live_profile = _fresh_profile(transport, target, profile)
    snapshot = _read_snapshot(transport, target, require_writable=False)
    if snapshot.error is not None or snapshot.raw is None or snapshot.access is None:
        raise ValueError("fresh parameter access and baseline could not be read")
    type_spec = entry.get("type")
    if not isinstance(type_spec, str) or not type_spec.strip():
        raise ValueError("a known parameter codec is required")
    try:
        value = parse_typed_value(type_spec, snapshot.raw)
    except ValueParseError as exc:
        raise ValueError("fresh baseline does not match the known parameter codec") from exc
    live_entry = _copy_mapping(entry, name="entry")
    live_entry.update(
        raw_hex=snapshot.raw.hex(),
        value=value,
        flags=snapshot.flags,
        flags_access=snapshot.access,
        response_state="active",
        error=None,
    )
    return B524ParameterEditContext(
        target=target,
        entry=live_entry,
        profile=live_profile,
        identity=actual_identity,
    )


def _description_signature(description: Mapping[str, object] | None) -> tuple[object, ...] | None:
    if description is None:
        return None
    return tuple(
        description.get(field)
        for field in (
            "read_opcode",
            "group",
            "instance",
            "register",
            "type",
            "width",
            "min",
            "max",
            "step",
        )
    ) + (_description_profile(description),)


def _result(
    preparation: B524ParameterWritePreparation,
    outcome: ParameterWriteOutcome,
    *,
    attempts: int,
    baseline: bytes | None,
    readback: bytes | None,
    write_error: str | None = None,
    read_error: str | None = None,
    detail: str | None = None,
) -> B524ParameterWriteResult:
    return B524ParameterWriteResult(
        outcome=outcome,
        target=preparation.target,
        write_attempts=attempts,
        baseline_raw_hex=baseline.hex() if baseline is not None else None,
        readback_raw_hex=readback.hex() if readback is not None else None,
        write_error=write_error,
        read_error=read_error,
        detail=detail,
    )


def execute_parameter_write(
    transport: TransportInterface,
    preparation: B524ParameterWritePreparation,
    *,
    concrete_confirmation: str,
    resolve_description: DescriptionResolver,
    incomplete_limits_confirmation: str | None = None,
) -> B524ParameterWriteResult:
    """Admit one native write after fresh checks, then classify only readback."""

    if concrete_confirmation != preparation.confirmation_text:
        raise ValueError("concrete confirmation does not match the exact target and value")
    if preparation.no_op:
        return _result(
            preparation,
            "no_op",
            attempts=0,
            baseline=preparation.baseline_raw,
            readback=preparation.baseline_raw,
        )
    required_exception = preparation.incomplete_limits_confirmation_text
    if required_exception is not None and incomplete_limits_confirmation != required_exception:
        raise ValueError("incomplete-limits confirmation does not match this exact write")

    _verify_identity(transport, preparation.target, preparation.identity)
    live_profile = _fresh_profile(transport, preparation.target, preparation.profile)
    baseline = _read_snapshot(transport, preparation.target, require_writable=True)
    if baseline.error is not None or baseline.raw is None:
        return _result(
            preparation,
            "blocked",
            attempts=0,
            baseline=baseline.raw,
            readback=None,
            read_error=baseline.error,
            detail="fresh access and baseline could not be verified",
        )
    try:
        parse_typed_value(preparation.type_spec, baseline.raw)
    except ValueParseError:
        return _result(
            preparation,
            "blocked",
            attempts=0,
            baseline=baseline.raw,
            readback=None,
            read_error="baseline_codec_mismatch",
        )
    if baseline.raw != preparation.baseline_raw:
        return _result(
            preparation,
            "reconfirmation_required",
            attempts=0,
            baseline=baseline.raw,
            readback=None,
            detail="fresh baseline changed",
        )

    resolved = resolve_description(preparation.target, live_profile)
    resolved_description, incomplete = _validate_description(
        resolved,
        target=preparation.target,
        profile=live_profile,
        type_spec=preparation.type_spec,
        value=preparation.desired_value,
        encoded=preparation.desired_raw,
    )
    if incomplete != (required_exception is not None) or _description_signature(
        resolved_description
    ) != _description_signature(preparation.description):
        return _result(
            preparation,
            "reconfirmation_required",
            attempts=0,
            baseline=baseline.raw,
            readback=None,
            detail="effective exact-profile metadata changed",
        )

    attempts = 0

    def admit_once() -> None:
        nonlocal attempts
        if attempts >= 1:
            raise B524WriteRetryBlocked(
                "automatic B524 parameter write retry blocked before native transmission"
            )
        attempts += 1

    write_error: str | None = None
    try:
        transport.send_with_attempt_hook(
            preparation.target.destination,
            preparation.write_payload,
            admit_once,
        )
    except (TransportError, B524WriteRetryBlocked, KeyboardInterrupt) as exc:
        write_error = type(exc).__name__

    readback = _read_snapshot(transport, preparation.target, require_writable=False)
    if readback.error is not None or readback.raw is None:
        return _result(
            preparation,
            "unknown",
            attempts=attempts,
            baseline=baseline.raw,
            readback=readback.raw,
            write_error=write_error,
            read_error=readback.error,
        )
    try:
        parse_typed_value(preparation.type_spec, readback.raw)
    except ValueParseError:
        return _result(
            preparation,
            "unknown",
            attempts=attempts,
            baseline=baseline.raw,
            readback=readback.raw,
            write_error=write_error,
            read_error="readback_codec_mismatch",
        )
    outcome: ParameterWriteOutcome = (
        "desired" if readback.raw == preparation.desired_raw else "other"
    )
    return _result(
        preparation,
        outcome,
        attempts=attempts,
        baseline=baseline.raw,
        readback=readback.raw,
        write_error=write_error,
    )


def recheck_parameter_write(
    transport: TransportInterface,
    preparation: B524ParameterWritePreparation,
) -> B524ParameterWriteResult:
    """Read identity and target once more without any write or rollback path."""

    _verify_identity(transport, preparation.target, preparation.identity)
    snapshot = _read_snapshot(transport, preparation.target, require_writable=False)
    if snapshot.error is not None or snapshot.raw is None:
        return _result(
            preparation,
            "unknown",
            attempts=0,
            baseline=preparation.baseline_raw,
            readback=snapshot.raw,
            read_error=snapshot.error,
        )
    read_error: str | None
    try:
        parse_typed_value(preparation.type_spec, snapshot.raw)
    except ValueParseError:
        outcome: ParameterWriteOutcome = "unknown"
        read_error = "readback_codec_mismatch"
    else:
        outcome = "desired" if snapshot.raw == preparation.desired_raw else "other"
        read_error = None
    return _result(
        preparation,
        outcome,
        attempts=0,
        baseline=preparation.baseline_raw,
        readback=snapshot.raw,
        read_error=read_error,
    )


__all__ = [
    "B524NativeIdentity",
    "B524ParameterEditContext",
    "B524ParameterTarget",
    "B524ParameterWritePreparation",
    "B524ParameterWriteResult",
    "B524WriteRetryBlocked",
    "DescriptionResolver",
    "execute_parameter_write",
    "prepare_parameter_write",
    "read_browser_identity",
    "read_parameter_edit_context",
    "recheck_parameter_write",
]
