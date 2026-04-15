from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Final, Literal, NotRequired, TypedDict, cast

from ..protocol.b524 import RegisterOpcode, build_register_read_payload
from ..protocol.parser import ValueParseError, parse_typed_value
from ..transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportNack,
    TransportTimeout,
    emit_trace_label,
)
from .director import GROUP_CONFIG
from .identity import make_register_identity, operation_label

logger = logging.getLogger(__name__)

_PRINTABLE_LATIN1: Final[set[int]] = set(range(0x20, 0x7F)) | set(range(0xA0, 0x100))
_I32_INVALID_SENTINEL: Final[int] = 0x7FFFFFFF
_I32_INVALID_SENTINEL_RAW_HEX: Final[str] = "ffffff7f"
# VE24-R3: U32 sentinel — same raw pattern, different semantic type.
_U32_INVALID_SENTINEL: Final[int] = 0xFFFFFFFF
_U32_INVALID_SENTINEL_RAW_HEX: Final[str] = "ffffffff"
_REMOTE_HEADER_PROBE_REGISTERS: Final[tuple[tuple[int, str], ...]] = (
    (0x0001, "BOOL"),
    (0x0002, "UCH"),
    (0x0003, "UCH"),
    (0x0004, "FW"),
)


class RegisterEntry(TypedDict):
    # B524 register read opcode family used for this entry: 0x02 (local) or 0x06 (remote).
    read_opcode: str
    # Human-readable opcode family label.
    read_opcode_label: str
    # Full raw reply payload (after ebusd length-prefix stripping), if available.
    # For register reads this is typically: <FLAGS> <GG> <RR_LO> <RR_HI> <VALUE_BYTES...>
    reply_hex: str | None
    # FLAGS byte extracted from the reply, if present.
    flags: int | None
    # Protocol-level DT byte interpretation:
    # bit1=config-vs-simple; bit0 meaning depends on opcode namespace.
    reply_kind: str | None
    # Access semantics derived from FLAGS and payload shape.
    flags_access: str | None
    # Wire-level response state for the request.
    # One of: "active", "empty_reply", "nack", "timeout", or None for non-protocol transport
    # failures where a state could not be determined.
    response_state: NotRequired[str | None]
    # Optional register name annotations.
    ebusd_name: str | None
    myvaillant_name: str | None
    raw_hex: str | None
    type: str | None
    value: object | None
    error: str | None
    # Optional constraint dictionary annotation sourced from opcode 0x01 (01 GG RR).
    constraint_tt: NotRequired[str]
    constraint_type: NotRequired[str]
    constraint_min: NotRequired[int | float | str | None]
    constraint_max: NotRequired[int | float | str | None]
    constraint_step: NotRequired[int | float | None]
    constraint_source: NotRequired[str]
    constraint_scope: NotRequired[str]
    constraint_provenance: NotRequired[str]
    constraint_mismatch_reason: NotRequired[str]
    register_class: NotRequired[str]
    enum_raw_name: NotRequired[str]
    enum_resolved_name: NotRequired[str]
    value_display: NotRequired[str]


@dataclass(frozen=True, slots=True)
class NamespaceAvailabilityContract:
    source: Literal["heuristic_probe", "always_present"]
    namespace_relationship: Literal["single_namespace", "independent"]
    probe_register: int | None
    probe_type_hint: str | None
    positive_when: str
    description: str


@dataclass(frozen=True, slots=True)
class InstanceAvailabilityProbe:
    present: bool
    contract: NamespaceAvailabilityContract
    evidence: RegisterEntry | None


def opcodes_for_group(group: int) -> list[RegisterOpcode]:
    """Return active B524 register opcode families for a group."""

    config = GROUP_CONFIG.get(group)
    if config is None:
        raise ValueError(
            "Unknown group 0x"
            f"{group:02X} has no implicit opcode defaults. "
            "Use discovery evidence to classify namespace opcodes."
        )
    return [cast(RegisterOpcode, opcode) for opcode in config["opcodes"]]


def namespace_opcodes_for_group(group: int) -> list[RegisterOpcode]:
    """Return namespace-capable opcode families for a group.

    This can be broader than `opcodes_for_group` while scanner heuristics are
    still staged. It is intended for opcode-first model/config decisions.
    """

    config = GROUP_CONFIG.get(group)
    if config is None:
        raise ValueError(
            "Unknown group 0x"
            f"{group:02X} has no implicit namespace defaults. "
            "Use discovery evidence to classify namespace opcodes."
        )
    raw_opcodes = config.get("namespace_opcodes", config["opcodes"])
    return [cast(RegisterOpcode, opcode) for opcode in raw_opcodes]


def _namespace_relationship(group: int) -> Literal["single_namespace", "independent"]:
    config = GROUP_CONFIG.get(group)
    if config is None:
        return "single_namespace"
    namespace_opcodes = config.get("namespace_opcodes", config["opcodes"])
    return "independent" if len(namespace_opcodes) > 1 else "single_namespace"


def namespace_availability_contract(
    *,
    group: int,
    opcode: RegisterOpcode,
) -> NamespaceAvailabilityContract:
    """Return the explicit availability contract for a namespace.

    The contract documents whether presence is derived from a namespace-specific
    probe or from a conscious always-present fallback.
    """

    relationship = _namespace_relationship(group)

    if group == 0x02 and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0002,
            probe_type_hint="UIN",
            positive_when="value not in {0x0000, 0xFFFF}",
            description="Heating circuit CircuitType must decode to a non-empty u16.",
        )

    if group == 0x03 and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x001C,
            probe_type_hint="UCH",
            positive_when="value != 0xFF",
            description="Zone index 0xFF marks an absent zone slot.",
        )

    if group == 0x05 and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0004,
            probe_type_hint="EXP",
            positive_when="decoded EXP value is not null",
            description="Cylinder availability requires a decodable float payload.",
        )

    if group == 0x04 and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0004,
            probe_type_hint="EXP",
            positive_when="decoded EXP value is not null",
            description="Solar circuit availability requires a decodable float payload.",
        )

    if opcode == 0x06:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0001,
            probe_type_hint="BOOL",
            positive_when="any generic header register RR=0x0001..0x0004 decodes and is not absent",
            description=(
                "Remote namespace presence is derived from the generic header block "
                "RR=0x0001..0x0004; RR=0x0001 (device_connected) is the universal "
                "presence indicator for all device-slot groups."
            ),
        )

    if group in {0x09, 0x0A} and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0001,
            probe_type_hint="UCH",
            positive_when="register read succeeds and is not absent",
            description="Local namespace presence is derived from a readable local slot register.",
        )

    if group in {0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11} and opcode == 0x02:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0000,
            probe_type_hint=None,
            positive_when="register read succeeds and is not absent",
            description="Exploratory local namespace presence requires actual local evidence.",
        )

    if group in {0x06, 0x07, 0x0B, 0x0D, 0x0E, 0x0F, 0x10, 0x11}:
        return NamespaceAvailabilityContract(
            source="always_present",
            namespace_relationship=relationship,
            probe_register=None,
            probe_type_hint=None,
            positive_when="all configured slots are treated as present",
            description=(
                "Exploratory research group without a verified namespace-specific heuristic."
            ),
        )

    logger.debug(
        "No explicit availability contract for GG=0x%02X OP=0x%02X; using always-present fallback",
        group,
        opcode,
    )
    return NamespaceAvailabilityContract(
        source="always_present",
        namespace_relationship=relationship,
        probe_register=None,
        probe_type_hint=None,
        positive_when="all configured slots are treated as present",
        description="Fallback contract for namespaces without a verified probe heuristic.",
    )


def _interpret_flags(flags: int, *, response_len: int, opcode: int = 0x02) -> str:
    """Interpret the leading FLAGS byte of a B524 register reply.

    The flags byte uses 2 effective bits (bits 2-7 are always zero) with
    the same {0,1,2,3} structure on both opcodes but different semantics:

    OP=0x02 (controller registers):
        bit1 = writable, bit0 = stable vs volatile
        0 = volatile_ro, 1 = stable_ro, 2 = technical_rw, 3 = user_rw

    OP=0x06 (device-slot registers):
        bit1 = config (instance-independent), bit0 = valid data (vs sentinel)
        0 = volatile_sentinel, 1 = volatile_valid, 2 = config_sentinel, 3 = config_valid
    """

    if response_len == 1:
        if flags == 0x00:
            return "absent"
        return "unknown_status"

    if opcode == 0x06:
        match flags:
            case 0x00:
                return "invalid"
            case 0x01:
                return "valid"
            case 0x02:
                return "config_sentinel"
            case 0x03:
                return "config_valid"
            case _:
                return "unknown"

    match flags:
        case 0x00:
            return "state_volatile"
        case 0x01:
            return "state_stable"
        case 0x02:
            return "config_installer"
        case 0x03:
            return "config_user"
        case _:
            return "unknown"


def _reply_kind(
    flags: int | None,
    *,
    response_len: int,
    opcode: RegisterOpcode,
) -> str | None:
    """Return protocol-level DT byte semantics for the register reply."""

    if flags is None:
        return None
    if response_len == 1:
        return None
    if flags not in {0x00, 0x01, 0x02, 0x03}:
        return None
    class_kind = "config" if flags & 0x02 else "simple"
    if opcode == 0x06:
        # Remote namespace: bit0 indicates validity vs sentinel/invalid payload.
        value_kind = "valid" if flags & 0x01 else "invalid"
        return f"{class_kind}_{value_kind}"
    # Local namespace: bit0 indicates stable vs volatile.
    value_kind = "stable" if flags & 0x01 else "volatile"
    return f"{class_kind}_{value_kind}"


def _looks_like_nul_terminated_latin1(value_bytes: bytes) -> bool:
    """Heuristic for identifying C strings when the schema is missing.

    We only treat values as strings when they look like NUL-terminated latin1 and
    the bytes before the first NUL are "printable-ish". This avoids misclassifying
    packed binary values.
    """

    if not value_bytes:
        return False

    try:
        nul_index = value_bytes.index(0x00)
    except ValueError:
        return False

    # After the first NUL, allow only more NUL padding.
    if any(b != 0x00 for b in value_bytes[nul_index:]):
        return False

    prefix = value_bytes[:nul_index]
    if not prefix:
        return False
    return all(b in _PRINTABLE_LATIN1 for b in prefix)


def _strip_echo_header(payload: bytes, response: bytes) -> bytes:
    """Strip the 4-byte header from a register read response.

    Empirically, ebusd's B524 register read replies look like:

        <STATUS> <GG> <RR_LO> <RR_HI> <VALUE_BYTES...>

    This differs from the request selector bytes:

        <OPCODE> <OPTYPE> <GG> <II> <RR_LO> <RR_HI>

    We validate that the response's (GG, RR) match the request and then strip
    the 4-byte response header, returning only the register value bytes.
    """

    if len(response) < 4:
        raise ValueError(f"Short register response: expected >=4 bytes, got {len(response)} bytes")
    header = response[:4]

    expected_group = payload[2]
    expected_rr = payload[4:6]
    group = header[1]
    rr = header[2:4]
    if group != expected_group or rr != expected_rr:
        raise ValueError(
            "Register header mismatch: "
            f"expected_gg={expected_group:02x} expected_rr={expected_rr.hex()} "
            f"got={header.hex()} payload={payload.hex()}"
        )
    return response[4:]


def _parse_inferred_value(value_bytes: bytes) -> tuple[str | None, object | None, str | None]:
    """Infer a type from byte length and parse it.

    Returns:
        (type_spec, value, error)
    """

    n = len(value_bytes)
    if n == 0:
        return None, None, None

    def _hex_fallback() -> tuple[str, object, None]:
        spec = f"HEX:{n}"
        return spec, parse_typed_value(spec, value_bytes), None

    if len(value_bytes) == 4:
        try:
            return "EXP", parse_typed_value("EXP", value_bytes), None
        except ValueParseError:
            # Don't drop bytes on the floor: keep a stable representation.
            return _hex_fallback()

    if len(value_bytes) == 2:
        try:
            return "UIN", parse_typed_value("UIN", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    if len(value_bytes) == 1:
        try:
            return "UCH", parse_typed_value("UCH", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    if len(value_bytes) == 3:
        for spec in ("HDA:3", "HTI"):
            try:
                return spec, parse_typed_value(spec, value_bytes), None
            except ValueParseError:
                continue
        return _hex_fallback()

    if _looks_like_nul_terminated_latin1(value_bytes):
        try:
            return "STR:*", parse_typed_value("STR:*", value_bytes), None
        except ValueParseError:
            return _hex_fallback()

    return _hex_fallback()


def _sentinel_value_display(
    *, value: object | None, raw_hex: str | None, value_type: str | None
) -> str | None:
    if isinstance(value, bool):
        return None
    # I32 sentinel: 0x7FFFFFFF
    if value_type == "I32":
        if raw_hex != _I32_INVALID_SENTINEL_RAW_HEX:
            return None
        if isinstance(value, int) and value == _I32_INVALID_SENTINEL:
            return "sentinel_invalid_i32 (0x7FFFFFFF)"
        return None
    # VE24-R3: U32 sentinel: 0xFFFFFFFF
    if value_type == "U32":
        if raw_hex != _U32_INVALID_SENTINEL_RAW_HEX:
            return None
        if isinstance(value, int) and value == _U32_INVALID_SENTINEL:
            return "sentinel_invalid_u32 (0xFFFFFFFF)"
        return None
    return None


def read_register(
    transport: TransportInterface,
    dst: int,
    opcode: RegisterOpcode,
    group: int,
    instance: int,
    register: int,
    *,
    type_hint: str | None = None,
) -> RegisterEntry:
    """Read a B524 register and parse it into an artifact-ready entry."""

    register_key = make_register_identity(
        opcode=opcode, group=group, instance=instance, register=register
    )
    read_opcode = f"0x{opcode:02x}"
    read_opcode_label = operation_label(opcode=opcode, optype=0x00)
    emit_trace_label(
        transport,
        "Reading "
        f"key=(op=0x{register_key[0]:02X},gg=0x{register_key[1]:02X},"
        f"ii=0x{register_key[2]:02X},rr=0x{register_key[3]:04X}) "
        f"dst=0x{dst:02X}",
    )
    payload = build_register_read_payload(opcode, group=group, instance=instance, register=register)
    try:
        response = transport.send(dst, payload)
    except TransportNack:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": None,
            "flags": None,
            "reply_kind": None,
            "flags_access": None,
            "response_state": "nack",
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": "nack",
        }
    except TransportTimeout:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": None,
            "flags": None,
            "reply_kind": None,
            "flags_access": None,
            "response_state": "timeout",
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": "timeout",
        }
    except TransportError as exc:
        if isinstance(exc, TransportCommandNotEnabled):
            raise
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": None,
            "flags": None,
            "reply_kind": None,
            "flags_access": None,
            "response_state": None,
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            # VE18-R2: Sanitise — strip endpoint details from error text.
            "error": f"transport_error: {type(exc).__name__}",
        }

    if len(response) == 0:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": "",
            "flags": None,
            "reply_kind": None,
            "flags_access": None,
            "response_state": "empty_reply",
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
        }

    reply_hex = response.hex()
    flags: int | None = response[0] if response else None
    reply_kind = _reply_kind(flags, response_len=len(response), opcode=opcode)
    flags_access: str | None = (
        _interpret_flags(flags, response_len=len(response), opcode=opcode)
        if flags is not None
        else None
    )

    # Some registers respond with a single status byte (no GG/RR echo and no value bytes).
    # We treat this as a valid "absent register" reply rather than a decoder bug.
    if len(response) == 1:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": reply_hex,
            "flags": flags,
            "reply_kind": reply_kind,
            "flags_access": flags_access,
            "response_state": "active",
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": None,
        }

    try:
        value_bytes = _strip_echo_header(payload, response)
    except ValueError as exc:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": reply_hex,
            "flags": flags,
            "reply_kind": reply_kind,
            "flags_access": flags_access,
            "response_state": "active",
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": f"decode_error: {exc}",
        }

    raw_hex = value_bytes.hex()
    if type_hint is not None:
        try:
            value = parse_typed_value(type_hint, value_bytes)
            typed_entry: RegisterEntry = {
                "read_opcode": read_opcode,
                "read_opcode_label": read_opcode_label,
                "reply_hex": reply_hex,
                "flags": flags,
                "reply_kind": reply_kind,
                "flags_access": flags_access,
                "response_state": "active",
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": value,
                "error": None,
            }
            sentinel_display = _sentinel_value_display(
                value=value,
                raw_hex=raw_hex,
                value_type=type_hint,
            )
            if sentinel_display is not None:
                typed_entry["value_display"] = sentinel_display
            return typed_entry
        except ValueParseError as exc:
            return {
                "read_opcode": read_opcode,
                "read_opcode_label": read_opcode_label,
                "reply_hex": reply_hex,
                "flags": flags,
                "reply_kind": reply_kind,
                "flags_access": flags_access,
                "response_state": "active",
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": None,
                "error": f"parse_error: {exc}",
            }

    inferred_type, inferred_value, inferred_error = _parse_inferred_value(value_bytes)
    entry: RegisterEntry = {
        "read_opcode": read_opcode,
        "read_opcode_label": read_opcode_label,
        "reply_hex": reply_hex,
        "flags": flags,
        "reply_kind": reply_kind,
        "flags_access": flags_access,
        "response_state": "active",
        "ebusd_name": None,
        "myvaillant_name": None,
        "raw_hex": raw_hex,
        "type": inferred_type,
        "value": inferred_value,
        "error": inferred_error,
    }
    sentinel_display = _sentinel_value_display(
        value=inferred_value,
        raw_hex=raw_hex,
        value_type=inferred_type,
    )
    if sentinel_display is not None:
        entry["value_display"] = sentinel_display
    elif inferred_type == "EXP" and inferred_value is None:
        entry["value_display"] = "NaN"
    return entry


def probe_instance_availability(
    transport: TransportInterface,
    dst: int,
    group: int,
    instance: int,
    *,
    opcode: RegisterOpcode | None = None,
) -> InstanceAvailabilityProbe:
    """Probe one instance slot and retain the evidence used for presence."""

    if opcode is None:
        opcode = opcodes_for_group(group)[0]

    contract = namespace_availability_contract(group=group, opcode=opcode)
    if contract.source == "always_present":
        return InstanceAvailabilityProbe(present=True, contract=contract, evidence=None)

    assert contract.probe_register is not None
    entry = read_register(
        transport,
        dst,
        opcode,
        group=group,
        instance=instance,
        register=contract.probe_register,
        type_hint=contract.probe_type_hint,
    )

    present = False
    response_state = entry.get("response_state")

    if response_state in {"nack", "timeout"}:
        return InstanceAvailabilityProbe(present=False, contract=contract, evidence=entry)

    if group == 0x02 and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        if entry["error"] is None and entry.get("flags_access") != "absent":
            value = entry["value"]
            present = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value
                not in {
                    0x0000,
                    0xFFFF,
                }
            )
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group == 0x03 and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        if entry["error"] is None and entry.get("flags_access") != "absent":
            value = entry["value"]
            present = isinstance(value, int) and not isinstance(value, bool) and value != 0xFF
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group == 0x05 and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        present = (
            entry["error"] is None
            and entry.get("flags_access") != "absent"
            and entry["value"] is not None
        )
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group == 0x04 and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        present = (
            entry["error"] is None
            and entry.get("flags_access") != "absent"
            and entry["value"] is not None
        )
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if opcode == 0x06:
        header_evidence = entry
        entry_reply_kind = entry.get("reply_kind")
        present = (
            entry["error"] is None
            and entry.get("flags_access") != "absent"
            and isinstance(entry_reply_kind, str)
            and entry_reply_kind.endswith("_valid")
            and entry["value"] is True
        )
        # VE13 analysis: The audit recommended skipping RR=0x0002-0x0004
        # when BOOL at RR=0x0001 returns False.  However, the secondary
        # header evidence fallback is intentional: some remote devices
        # report device_connected=False but still have valid header registers.
        # Existing tests (test_is_instance_present_group_09_remote_accepts_
        # secondary_header_evidence) validate this fallback behavior.
        # VE13 finding is NOT applied — behavior is correct as-is.
        if not present:
            for register_id, type_hint in _REMOTE_HEADER_PROBE_REGISTERS[1:]:
                header_entry = read_register(
                    transport,
                    dst,
                    opcode,
                    group=group,
                    instance=instance,
                    register=register_id,
                    type_hint=type_hint,
                )
                header_reply_kind = header_entry.get("reply_kind")
                if (
                    header_entry["error"] is None
                    and header_entry.get("flags_access") != "absent"
                    and isinstance(header_reply_kind, str)
                    and header_reply_kind.endswith("_valid")
                ):
                    present = True
                    header_evidence = header_entry
                    break
        return InstanceAvailabilityProbe(
            present=present,
            contract=contract,
            evidence=header_evidence,
        )

    if group in {0x09, 0x0A} and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        present = entry["error"] is None and entry.get("flags_access") != "absent"
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group in {0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11} and opcode == 0x02:
        if response_state == "empty_reply":
            return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)
        present = entry["error"] is None and entry.get("flags_access") != "absent"
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    return InstanceAvailabilityProbe(present=True, contract=contract, evidence=entry)


def is_instance_present(
    transport: TransportInterface,
    dst: int,
    group: int,
    instance: int,
    *,
    opcode: RegisterOpcode | None = None,
) -> bool:
    """Presence heuristic for instanced groups.

    Source of truth: `AGENTS.md` (keep in sync).
    """
    return probe_instance_availability(
        transport,
        dst=dst,
        group=group,
        instance=instance,
        opcode=opcode,
    ).present
