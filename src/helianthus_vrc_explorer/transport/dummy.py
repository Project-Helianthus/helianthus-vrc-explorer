from __future__ import annotations

import json
import struct
from collections import deque
from pathlib import Path
from typing import Any

from ..artifact_schema import migrate_artifact_schema
from ..protocol.parser import ValueEncodeError, encode_typed_value
from ..scanner.director import GROUP_CONFIG
from .base import TransportError, TransportInterface, TransportNack, TransportTimeout


class DummyTransport(TransportInterface):
    """Fixture-backed transport used for --dry-run.

    The dummy transport replays *responses* from a scan artifact fixture (JSON).
    It supports the minimal subset needed for offline scanner tests:

    - System information (opcode 0x00): returns a fixture-provided float32le value
    - Register read (opcode 0x02 / 0x06, optype 0x00): returns `header(4 bytes) + value_bytes`
    - Parameter description (opcode 0x01 / 0x07): returns `GG + RR16 + min/max/step`
    - Explicit B524 operation reads: replays only an exact recorded request payload
    """

    def __init__(self, fixture_path: Path) -> None:
        self._fixture_path = fixture_path
        self._system_information_unavailable: set[int] = set()
        self._system_information: dict[int, bytes] = {}
        self._register_replies: dict[tuple[int, int, int, int], bytes] = {}
        self._register_flags: dict[tuple[int, int, int, int], int] = {}
        self._register_values: dict[tuple[int, int, int, int], bytes] = {}
        self._register_timeouts: set[tuple[int, int, int, int]] = set()
        self._register_nacks: set[tuple[int, int, int, int]] = set()
        self._register_empty_replies: set[tuple[int, int, int, int]] = set()
        self._parameter_descriptions: dict[tuple[int, int, int, int], bytes] = {}
        self._operation_read_observations: dict[bytes, deque[tuple[str, bytes | None]]] = {}
        self._load_fixture()

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        if not payload:
            raise TransportError("Empty payload")

        opcode = payload[0]

        if opcode in {0x03, 0x08, 0x09, 0x0B}:
            return self._handle_operation_read(payload)

        if opcode == 0x00:
            return self._handle_system_information(payload)

        if opcode in {0x01, 0x07}:
            return self._handle_parameter_description(payload)

        if opcode in {0x02, 0x06}:
            return self._handle_register_read(payload)

        raise TransportError(f"Unsupported opcode 0x{opcode:02X} for DummyTransport")

    def _handle_operation_read(self, payload: bytes) -> bytes:
        observations = self._operation_read_observations.get(payload)
        if not observations:
            raise TransportError(
                f"Fixture has no exact B524 operation-read observation for payload={payload.hex()}"
            )
        state, response = observations.popleft()
        if state == "nack":
            raise TransportNack(f"Fixture marks B524 operation payload={payload.hex()} as nack")
        if state == "timeout":
            raise TransportTimeout(
                f"Fixture marks B524 operation payload={payload.hex()} as timeout"
            )
        if state == "transport_error":
            raise TransportError(
                f"Fixture marks B524 operation payload={payload.hex()} as transport_error"
            )
        if state in {"unknown", "unattempted"}:
            raise TransportError(
                f"Fixture has no attempted B524 operation response for payload={payload.hex()}"
            )
        if state == "empty":
            return b""
        if response is None:
            raise TransportError(
                "Fixture operation observation has no replayable raw response for "
                f"payload={payload.hex()} state={state}"
            )
        return response

    def _handle_system_information(self, payload: bytes) -> bytes:
        if len(payload) != 3:
            raise TransportError(f"System-information request expects 3 bytes, got {len(payload)}")
        identifier = int.from_bytes(payload[1:3], byteorder="little", signed=False)
        if identifier in self._system_information_unavailable:
            raise TransportTimeout(
                f"Fixture records unavailable system information {identifier:04x}"
            )
        # Legacy group-directory fixtures carry no reliable OP00 information.
        # A synthetic NaN makes their incompatibility explicit without treating
        # a group descriptor as an instance-count or topology value.
        return self._system_information.get(identifier, struct.pack("<f", float("nan")))

    def _handle_parameter_description(self, payload: bytes) -> bytes:
        if len(payload) != 5:
            raise TransportError(f"Parameter description expects 5 bytes, got {len(payload)}")
        opcode, group, instance = payload[:3]
        register = int.from_bytes(payload[3:5], byteorder="little", signed=False)
        read_opcode = 0x02 if opcode == 0x01 else 0x06
        key = (read_opcode, group, instance, register)
        response = self._parameter_descriptions.get(key)
        if response is None:
            raise TransportTimeout(
                "Fixture missing parameter description for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, "
                f"RR=0x{register:04X}"
            )
        return response

    def _handle_register_read(self, payload: bytes) -> bytes:
        if len(payload) < 2:
            raise TransportError(f"Register payload too short: {len(payload)} bytes")

        opcode = payload[0]
        optype = payload[1]
        if optype != 0x00:
            raise TransportError(
                f"DummyTransport only supports register reads (optype=0x00), got 0x{optype:02X}"
            )

        if len(payload) != 6:
            raise TransportError(f"Register read expects 6 bytes, got {len(payload)}")

        group = payload[2]
        instance = payload[3]
        register = int.from_bytes(payload[4:6], byteorder="little", signed=False)

        key = (opcode, group, instance, register)
        value = self._register_values.get(key)
        if key in self._register_replies:
            return self._register_replies[key]
        if key in self._register_nacks:
            raise TransportNack(
                "Fixture marks register as nack for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, RR=0x{register:04X}"
            )
        if key in self._register_timeouts:
            raise TransportTimeout(
                "Fixture marks register as timeout for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, RR=0x{register:04X}"
            )
        if key in self._register_empty_replies:
            return b""
        if value is None:
            raise TransportTimeout(
                "Fixture missing register raw_hex for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, RR=0x{register:04X}"
            )

        # Empirically, register replies include a 4-byte header:
        #   <FLAGS> <GG> <RR_LO> <RR_HI>
        # Raw-only legacy fixtures retain their historical default FLAGS=01h.
        header = bytes((self._register_flags.get(key, 0x01), group)) + payload[4:6]
        return header + value

    @staticmethod
    def _parse_hex_key_u8(key: str, field: str) -> int:
        try:
            value = int(key, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid {field} key (expected hex): {key!r}") from exc
        if not (0x00 <= value <= 0xFF):
            raise ValueError(f"{field} key out of range 0..255: {key!r}")
        return value

    @staticmethod
    def _parse_hex_key_u16(key: str, field: str) -> int:
        try:
            value = int(key, 16)
        except ValueError as exc:
            raise ValueError(f"Invalid {field} key (expected hex): {key!r}") from exc
        if not (0x0000 <= value <= 0xFFFF):
            raise ValueError(f"{field} key out of range 0..65535: {key!r}")
        return value

    @staticmethod
    def _parse_opcode(value: str, field: str) -> int:
        try:
            opcode = int(value, 0)
        except ValueError as exc:
            raise ValueError(f"Invalid {field} opcode (expected hex): {value!r}") from exc
        if not (0x00 <= opcode <= 0xFF):
            raise ValueError(f"{field} opcode out of range 0..255: {value!r}")
        return opcode

    @staticmethod
    def _fallback_opcodes(*, group: int, default_opcode: int | None) -> tuple[int, ...]:
        if default_opcode is not None:
            return (default_opcode,)

        config = GROUP_CONFIG.get(group)
        if config is not None:
            configured = tuple(int(opcode) for opcode in config["opcodes"])
            if configured:
                return configured

        raise ValueError(
            "Unknown group "
            f"0x{group:02X} fixture requires explicit namespace/read_opcode; "
            "implicit [0x02, 0x06] fallback is forbidden."
        )

    def _load_instances(
        self,
        *,
        group_key: str,
        group: int,
        instances: Any,
        default_opcode: int | None,
    ) -> None:
        if not isinstance(instances, dict):
            raise ValueError(f'Group {group_key!r} field "instances" must be an object')

        for instance_key, instance_value in instances.items():
            if not isinstance(instance_key, str):
                raise ValueError(
                    f"Instance keys must be strings, got {type(instance_key).__name__}"
                )
            instance = self._parse_hex_key_u8(instance_key, "instance")
            if not isinstance(instance_value, dict):
                raise ValueError(f"Instance {instance_key!r} must be a JSON object")

            registers = instance_value.get("registers", {})
            if not isinstance(registers, dict):
                raise ValueError(f'Instance {instance_key!r} field "registers" must be an object')

            for register_key, register_value in registers.items():
                if not isinstance(register_key, str):
                    raise ValueError(
                        f"Register keys must be strings, got {type(register_key).__name__}"
                    )
                register = self._parse_hex_key_u16(register_key, "register")
                if not isinstance(register_value, dict):
                    raise ValueError(f"Register {register_key!r} must be a JSON object")

                read_opcode = register_value.get("read_opcode")
                opcodes: tuple[int, ...]
                if isinstance(read_opcode, str):
                    opcodes = (self._parse_opcode(read_opcode, "register"),)
                else:
                    opcodes = self._fallback_opcodes(group=group, default_opcode=default_opcode)

                self._load_parameter_description(
                    group=group,
                    instance=instance,
                    register=register,
                    opcodes=opcodes,
                    register_value=register_value,
                )

                # Current artifacts retain the complete normalized payload, including
                # writable attributes and short status replies. Replay it verbatim.
                reply_hex = register_value.get("reply_hex")
                if isinstance(reply_hex, str):
                    try:
                        reply = bytes.fromhex(reply_hex)
                    except ValueError as exc:
                        raise ValueError(
                            f"Register {register_key!r} has invalid reply_hex"
                        ) from exc
                    for opcode in opcodes:
                        self._register_replies[(opcode, group, instance, register)] = reply
                    continue
                flags = register_value.get("flags")
                if isinstance(flags, int) and not isinstance(flags, bool) and 0 <= flags <= 255:
                    for opcode in opcodes:
                        self._register_flags[(opcode, group, instance, register)] = flags

                raw_hex = register_value.get("raw_hex")
                if isinstance(raw_hex, str):
                    try:
                        value_bytes = bytes.fromhex(raw_hex)
                    except ValueError as exc:
                        raise ValueError(
                            f"Register {register_key!r} has invalid raw_hex: {raw_hex!r}"
                        ) from exc
                    for opcode in opcodes:
                        self._register_values[(opcode, group, instance, register)] = value_bytes
                    continue

                response_state_raw = register_value.get("response_state")
                response_state = (
                    response_state_raw.strip().lower()
                    if isinstance(response_state_raw, str)
                    else None
                )
                if response_state == "timeout":
                    for opcode in opcodes:
                        self._register_timeouts.add((opcode, group, instance, register))
                    continue
                if response_state in {"nack", "nack_or_crc"}:
                    for opcode in opcodes:
                        self._register_nacks.add((opcode, group, instance, register))
                    continue
                if response_state == "empty_reply":
                    for opcode in opcodes:
                        self._register_empty_replies.add((opcode, group, instance, register))
                    continue

                error = register_value.get("error")
                if isinstance(error, str) and error == "timeout":
                    for opcode in opcodes:
                        self._register_timeouts.add((opcode, group, instance, register))
                    continue
                if (
                    isinstance(error, str)
                    and error.strip().lower() == "transport_error: no_response"
                ):
                    for opcode in opcodes:
                        self._register_empty_replies.add((opcode, group, instance, register))
                    continue
                if (
                    isinstance(register_value.get("reply_hex"), str)
                    and register_value.get("reply_hex") == ""
                ):
                    for opcode in opcodes:
                        self._register_empty_replies.add((opcode, group, instance, register))
                    continue

                raise ValueError(
                    f"Register {register_key!r} must contain raw_hex, response_state "
                    "or timeout/empty-reply metadata."
                )

    def _load_parameter_description(
        self,
        *,
        group: int,
        instance: int,
        register: int,
        opcodes: tuple[int, ...],
        register_value: dict[str, Any],
    ) -> None:
        """Load a qualified normalized description from a fixture register."""
        raw_description = register_value.get("parameter_description")
        if not isinstance(raw_description, dict):
            # Older hand-authored fixtures nested the same normalized object.
            metadata = register_value.get("metadata")
            raw_description = (
                metadata.get("parameter_description") if isinstance(metadata, dict) else None
            )
        if not isinstance(raw_description, dict):
            return

        if raw_description.get("qualification") != "matched":
            # Missing/unsupported/budget-limited metadata is normal in partial scans.
            # Keep the scalar evidence without inventing a description response.
            return
        read_opcode = self._parse_opcode_value(
            raw_description.get("read_opcode"), "parameter description read"
        )
        description_opcode = self._parse_opcode_value(
            raw_description.get("description_opcode"), "parameter description"
        )
        if (
            read_opcode not in {0x02, 0x06}
            or description_opcode
            != {
                0x02: 0x01,
                0x06: 0x07,
            }[read_opcode]
        ):
            raise ValueError("Parameter description has an invalid opcode mapping")
        if read_opcode not in opcodes:
            raise ValueError("Parameter description read opcode does not match fixture register")
        self._validate_description_identity(
            raw_description,
            group=group,
            instance=instance,
            register=register,
        )

        type_spec = raw_description.get("type")
        entry_type = register_value.get("type")
        if not isinstance(type_spec, str) or not isinstance(entry_type, str):
            raise ValueError("Parameter description and fixture register require scalar types")
        if type_spec.strip().upper() != entry_type.strip().upper():
            raise ValueError("Parameter description codec does not match fixture register")
        try:
            minimum = encode_typed_value(type_spec, raw_description["min"])
            maximum = encode_typed_value(type_spec, raw_description["max"])
            if type_spec.strip().upper() in {"HDA:3", "HTI"} and isinstance(
                raw_description.get("step_raw_hex"), str
            ):
                step = bytes.fromhex(raw_description["step_raw_hex"])
            elif type_spec.strip().upper() == "HDA:3":
                days = raw_description["step"]
                if not isinstance(days, int) or isinstance(days, bool) or not 0 <= days <= 65535:
                    raise ValueEncodeError("Date description step must be unsigned 16-bit days")
                step = days.to_bytes(2, "little") + b"\x00"
            else:
                step = encode_typed_value(type_spec, raw_description["step"])
        except (KeyError, ValueEncodeError) as exc:
            raise ValueError(
                "Parameter description metadata requires encodable min/max/step values"
            ) from exc
        if not (len(minimum) == len(maximum) == len(step)):
            raise ValueError("Parameter description metadata has unequal value widths")
        if raw_description.get("width") != len(minimum):
            raise ValueError("Parameter description width does not match its scalar codec")

        self._parameter_descriptions[(read_opcode, group, instance, register)] = (
            bytes((group,)) + register.to_bytes(2, byteorder="little") + minimum + maximum + step
        )

    @staticmethod
    def _parse_opcode_value(value: object, field: str) -> int:
        if not isinstance(value, str):
            raise ValueError(f"{field} opcode must be a hex string")
        return DummyTransport._parse_opcode(value, field)

    def _validate_description_identity(
        self,
        description: dict[str, Any],
        *,
        group: int,
        instance: int,
        register: int,
    ) -> None:
        expected = (
            ("group", group, self._parse_hex_key_u8),
            ("instance", instance, self._parse_hex_key_u8),
            ("register", register, self._parse_hex_key_u16),
        )
        for field, expected_value, parser in expected:
            raw_value = description.get(field)
            if not isinstance(raw_value, str) or parser(raw_value, field) != expected_value:
                raise ValueError(f"Parameter description {field} does not match fixture register")

    def _load_fixture(self) -> None:
        raw = self._fixture_path.read_text(encoding="utf-8")
        data: Any = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Fixture root must be a JSON object")
        data, _migration = migrate_artifact_schema(data)

        operation_reads = data.get("b524_operation_reads")
        if operation_reads is not None:
            if not isinstance(operation_reads, list):
                raise ValueError('Fixture top-level key "b524_operation_reads" must be a list')
            for index, item in enumerate(operation_reads):
                if not isinstance(item, dict):
                    raise ValueError(f"B524 operation observation {index} must be an object")
                request_hex = item.get("request_payload_hex")
                if not isinstance(request_hex, str):
                    raise ValueError(
                        f"B524 operation observation {index} requires request_payload_hex"
                    )
                try:
                    request = bytes.fromhex(request_hex)
                except ValueError as exc:
                    raise ValueError(
                        f"B524 operation observation {index} has invalid request_payload_hex"
                    ) from exc
                if not request or request[0] not in {0x03, 0x08, 0x09, 0x0B}:
                    raise ValueError(
                        f"B524 operation observation {index} has unsupported request payload"
                    )
                state = item.get("response_state")
                if state not in {
                    "value",
                    "empty",
                    "nack",
                    "timeout",
                    "transport_error",
                    "malformed",
                    "unknown",
                    "unattempted",
                }:
                    raise ValueError(
                        f"B524 operation observation {index} has invalid response_state"
                    )
                response_hex = item.get("response_raw_hex")
                response: bytes | None = None
                if response_hex is not None:
                    if not isinstance(response_hex, str):
                        raise ValueError(
                            f"B524 operation observation {index} response_raw_hex "
                            "must be text or null"
                        )
                    try:
                        response = bytes.fromhex(response_hex)
                    except ValueError as exc:
                        raise ValueError(
                            f"B524 operation observation {index} has invalid response_raw_hex"
                        ) from exc
                self._operation_read_observations.setdefault(request, deque()).append(
                    (state, response)
                )

        meta = data.get("meta", {})
        if not isinstance(meta, dict):
            raise ValueError('Fixture top-level key "meta" must be an object')
        dummy_meta = meta.get("dummy_transport", {})
        if not isinstance(dummy_meta, dict):
            raise ValueError('Fixture meta key "dummy_transport" must be an object')
        system_information = meta.get("system_information")
        if system_information is not None:
            if not isinstance(system_information, list):
                raise ValueError('Fixture meta key "system_information" must be a list')
            for item in system_information:
                if not isinstance(item, dict):
                    raise ValueError("System-information entries must be JSON objects")
                raw_identifier = item.get("identifier")
                if isinstance(raw_identifier, str):
                    identifier = self._parse_hex_key_u16(
                        raw_identifier, "system information identifier"
                    )
                elif isinstance(raw_identifier, int) and not isinstance(raw_identifier, bool):
                    identifier = raw_identifier
                    if not (0 <= identifier <= 0xFFFF):
                        raise ValueError("System information identifier out of range 0..65535")
                else:
                    raise ValueError("System-information entry requires a u16 identifier")
                raw_hex = item.get("raw_hex")
                if raw_hex is None:
                    self._system_information_unavailable.add(identifier)
                    continue
                if not isinstance(raw_hex, str):
                    raise ValueError("System-information raw_hex must be a string or null")
                try:
                    raw_value = bytes.fromhex(raw_hex)
                except ValueError as exc:
                    raise ValueError("System-information raw_hex must be valid hex") from exc
                if len(raw_value) == 5 and raw_value[0] == 4:
                    raw_value = raw_value[1:]  # Archived transport-framed reply.
                if len(raw_value) != 4 and item.get("value") is not None:
                    raise ValueError("Available system information must encode one float32le")
                self._system_information[identifier] = raw_value

        # v2.3 operations-first: iterate operations directly to preserve OP context.
        # migrate_artifact_schema always produces v2.3 so operations is always present.
        # Empty operations is valid for directory-only fixtures.
        operations = data.get("operations")
        if not isinstance(operations, dict):
            operations = {}

        for op_key, op_obj in operations.items():
            if not isinstance(op_obj, dict):
                continue
            opcode = self._parse_opcode(op_key, "operation")
            op_groups = op_obj.get("groups")
            if not isinstance(op_groups, dict):
                continue
            for group_key, group_value in op_groups.items():
                if not isinstance(group_key, str) or not isinstance(group_value, dict):
                    continue
                group = self._parse_hex_key_u8(group_key, "group")
                self._load_instances(
                    group_key=group_key,
                    group=group,
                    instances=group_value.get("instances", {}),
                    default_opcode=opcode,
                )
