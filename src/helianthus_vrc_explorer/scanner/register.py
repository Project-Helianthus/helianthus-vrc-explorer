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
    TransportTimeout,
    emit_trace_label,
)
from .director import GROUP_CONFIG
from .identity import make_register_identity, opcode_label

logger = logging.getLogger(__name__)

_PRINTABLE_LATIN1: Final[set[int]] = set(range(0x20, 0x7F)) | set(range(0xA0, 0x100))


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
    # Access semantics derived from FLAGS and payload shape.
    flags_access: str | None
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
    constraint_min: NotRequired[int | float | str]
    constraint_max: NotRequired[int | float | str]
    constraint_step: NotRequired[int | float]
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
    return "independent" if len(opcodes_for_group(group)) > 1 else "single_namespace"


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

    if group in {0x08, 0x09, 0x0A, 0x0C} and opcode == 0x06:
        return NamespaceAvailabilityContract(
            source="heuristic_probe",
            namespace_relationship=relationship,
            probe_register=0x0001,
            probe_type_hint="BOOL",
            positive_when="decoded BOOL value is true",
            description="Remote namespace presence is derived from RR=0x0001 device-connected.",
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

    if group in {0x06, 0x07, 0x0B, 0x0D, 0x0E, 0x0F, 0x10, 0x11}:
        return NamespaceAvailabilityContract(
            source="always_present",
            namespace_relationship=relationship,
            probe_register=None,
            probe_type_hint=None,
            positive_when="all configured slots are treated as present",
            description=(
                "Exploratory exhaustive group without a verified namespace-specific heuristic."
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


def _interpret_flags(flags: int, *, response_len: int) -> str:
    """Interpret the leading FLAGS byte of a B524 register reply."""

    if response_len == 1:
        if flags == 0x00:
            return "absent"
        return "unknown_status"

    match flags:
        case 0x00:
            return "volatile_ro"
        case 0x01:
            return "stable_ro"
        case 0x02:
            return "technical_rw"
        case 0x03:
            return "user_rw"
        case _:
            return "unknown"


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
    read_opcode_label = opcode_label(opcode)
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
    except TransportTimeout:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": None,
            "flags": None,
            "flags_access": None,
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
            "flags_access": None,
            "ebusd_name": None,
            "myvaillant_name": None,
            "raw_hex": None,
            "type": None,
            "value": None,
            "error": f"transport_error: {exc}",
        }

    reply_hex = response.hex()
    flags: int | None = response[0] if response else None
    flags_access: str | None = (
        _interpret_flags(flags, response_len=len(response)) if flags is not None else None
    )

    # Some registers respond with a single status byte (no GG/RR echo and no value bytes).
    # We treat this as a valid "absent register" reply rather than a decoder bug.
    if len(response) == 1:
        return {
            "read_opcode": read_opcode,
            "read_opcode_label": read_opcode_label,
            "reply_hex": reply_hex,
            "flags": flags,
            "flags_access": flags_access,
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
            "flags_access": flags_access,
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
            return {
                "read_opcode": read_opcode,
                "read_opcode_label": read_opcode_label,
                "reply_hex": reply_hex,
                "flags": flags,
                "flags_access": flags_access,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": value,
                "error": None,
            }
        except ValueParseError as exc:
            return {
                "read_opcode": read_opcode,
                "read_opcode_label": read_opcode_label,
                "reply_hex": reply_hex,
                "flags": flags,
                "flags_access": flags_access,
                "ebusd_name": None,
                "myvaillant_name": None,
                "raw_hex": raw_hex,
                "type": type_hint,
                "value": None,
                "error": f"parse_error: {exc}",
            }

    inferred_type, inferred_value, inferred_error = _parse_inferred_value(value_bytes)
    return {
        "read_opcode": read_opcode,
        "read_opcode_label": read_opcode_label,
        "reply_hex": reply_hex,
        "flags": flags,
        "flags_access": flags_access,
        "ebusd_name": None,
        "myvaillant_name": None,
        "raw_hex": raw_hex,
        "type": inferred_type,
        "value": inferred_value,
        "error": inferred_error,
    }


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

    if group == 0x02 and opcode == 0x02:
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
        if entry["error"] is None and entry.get("flags_access") != "absent":
            value = entry["value"]
            present = isinstance(value, int) and not isinstance(value, bool) and value != 0xFF
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group == 0x05 and opcode == 0x02:
        present = (
            entry["error"] is None
            and entry.get("flags_access") != "absent"
            and entry["value"] is not None
        )
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group in {0x08, 0x09, 0x0A, 0x0C} and opcode == 0x06:
        present = (
            entry["error"] is None
            and entry.get("flags_access") != "absent"
            and entry["value"] is True
        )
        return InstanceAvailabilityProbe(present=present, contract=contract, evidence=entry)

    if group in {0x09, 0x0A} and opcode == 0x02:
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
