from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from ..scanner.director import GROUP_CONFIG
from .base import TransportError, TransportInterface, TransportTimeout


class DummyTransport(TransportInterface):
    """Fixture-backed transport used for --dry-run.

    The dummy transport replays *responses* from a scan artifact fixture (JSON).
    It supports the minimal subset needed for offline scanner tests:

    - Directory probe (opcode 0x00): returns a float32le descriptor type for known groups
    - Register read (opcode 0x02 / 0x06, optype 0x00): returns `header(4 bytes) + value_bytes`
    """

    def __init__(self, fixture_path: Path) -> None:
        self._fixture_path = fixture_path
        self._group_descriptor: dict[int, float] = {}
        self._register_values: dict[tuple[int, int, int, int], bytes] = {}
        self._register_timeouts: set[tuple[int, int, int, int]] = set()
        self._directory_terminator_group: int | None = None
        self._load_fixture()

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        if not payload:
            raise TransportError("Empty payload")

        opcode = payload[0]

        if opcode == 0x00:
            return self._handle_directory_probe(payload)

        if opcode in {0x02, 0x06}:
            return self._handle_register_read(payload)

        raise TransportError(f"Unsupported opcode 0x{opcode:02X} for DummyTransport")

    def _handle_directory_probe(self, payload: bytes) -> bytes:
        if len(payload) != 3:
            raise TransportError(f"Directory probe expects 3 bytes, got {len(payload)}")
        if payload[2] != 0x00:
            raise TransportError(f"Directory probe expects final byte 0x00, got 0x{payload[2]:02X}")

        group = payload[1]
        if (
            self._directory_terminator_group is not None
            and group >= self._directory_terminator_group
        ):
            return struct.pack("<f", float("nan"))
        descriptor = self._group_descriptor.get(group, 0.0)
        return struct.pack("<f", float(descriptor))

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

        value = self._register_values.get((opcode, group, instance, register))
        if (opcode, group, instance, register) in self._register_timeouts:
            raise TransportTimeout(
                "Fixture marks register as timeout for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, RR=0x{register:04X}"
            )
        if value is None:
            raise TransportTimeout(
                "Fixture missing register raw_hex for "
                f"opcode=0x{opcode:02X}, GG=0x{group:02X}, II=0x{instance:02X}, RR=0x{register:04X}"
            )

        # Empirically, register replies include a 4-byte header:
        #   <TT> <GG> <RR_LO> <RR_HI>
        # Use TT=0x01 (live) for fixtures unless they explicitly model no-data via timeouts.
        header = bytes((0x01, group)) + payload[4:6]
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

                error = register_value.get("error")
                if isinstance(error, str) and error == "timeout":
                    for opcode in opcodes:
                        self._register_timeouts.add((opcode, group, instance, register))
                    continue

                raise ValueError(
                    f'Register {register_key!r} must contain raw_hex string or have error="timeout"'
                )

    def _load_fixture(self) -> None:
        raw = self._fixture_path.read_text(encoding="utf-8")
        data: Any = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Fixture root must be a JSON object")

        meta = data.get("meta", {})
        if not isinstance(meta, dict):
            raise ValueError('Fixture top-level key "meta" must be an object')
        dummy_meta = meta.get("dummy_transport", {})
        if not isinstance(dummy_meta, dict):
            raise ValueError('Fixture meta key "dummy_transport" must be an object')
        terminator_group = dummy_meta.get("directory_terminator_group")
        if terminator_group is not None:
            if not isinstance(terminator_group, str):
                raise ValueError(
                    "Fixture meta dummy_transport.directory_terminator_group must be a string"
                )
            self._directory_terminator_group = self._parse_hex_key_u8(
                terminator_group, "directory_terminator_group"
            )

        groups = data.get("groups")
        if not isinstance(groups, dict):
            raise ValueError('Fixture must contain top-level key "groups" as an object')

        for group_key, group_value in groups.items():
            if not isinstance(group_key, str):
                raise ValueError(f"Group keys must be strings, got {type(group_key).__name__}")
            group = self._parse_hex_key_u8(group_key, "group")
            if not isinstance(group_value, dict):
                raise ValueError(f"Group {group_key!r} must be a JSON object")

            descriptor = group_value.get(
                "descriptor_type",
                group_value.get("descriptor_observed"),
            )
            if not isinstance(descriptor, (int, float)) or isinstance(descriptor, bool):
                raise ValueError(
                    "Group "
                    f"{group_key!r} must contain numeric descriptor_type or descriptor_observed"
                )
            self._group_descriptor[group] = float(descriptor)

            namespaces = group_value.get("namespaces")
            if namespaces is not None:
                if not isinstance(namespaces, dict):
                    raise ValueError(f'Group {group_key!r} field "namespaces" must be an object')
                for namespace_key, namespace_value in namespaces.items():
                    if not isinstance(namespace_key, str):
                        raise ValueError(
                            f"Namespace keys must be strings, got {type(namespace_key).__name__}"
                        )
                    if not isinstance(namespace_value, dict):
                        raise ValueError(f"Namespace {namespace_key!r} must be a JSON object")
                    opcode = self._parse_opcode(namespace_key, "namespace")
                    self._load_instances(
                        group_key=group_key,
                        group=group,
                        instances=namespace_value.get("instances", {}),
                        default_opcode=opcode,
                    )
                continue

            if bool(group_value.get("dual_namespace")):
                raise ValueError(
                    f'Group {group_key!r} sets "dual_namespace" but is missing "namespaces"'
                )

            self._load_instances(
                group_key=group_key,
                group=group,
                instances=group_value.get("instances", {}),
                default_opcode=None,
            )
