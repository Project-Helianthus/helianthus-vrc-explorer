from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    build_constraint_probe_payload,
    build_directory_probe_payload,
    build_register_read_payload,
)
from helianthus_vrc_explorer.transport.base import (
    TransportError,
    TransportNack,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.dummy import DummyTransport


def _write_min_fixture(tmp_path: Path) -> Path:
    fixture = {
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x000f": {"raw_hex": "3412"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    return fixture_path


def test_dummy_transport_legacy_fixture_op00_returns_unusable_nan(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x02))
    assert struct.unpack("<f", response)[0] != struct.unpack("<f", response)[0]


def test_dummy_transport_system_information_returns_fixture_raw_float(tmp_path: Path) -> None:
    fixture = {
        "meta": {
            "system_information": [
                {
                    "identifier": "0x0000",
                    "name": "circuit_count",
                    "value": 2.0,
                    "raw_hex": "00000040",
                }
            ]
        },
        "operations": {},
    }
    fixture_path = tmp_path / "system_information.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)
    assert transport.send(0x15, build_directory_probe_payload(0x0000)) == bytes.fromhex("00000040")


def test_dummy_transport_missing_system_information_returns_nan(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x03))
    assert struct.unpack("<f", response)[0] != struct.unpack("<f", response)[0]


def test_dummy_transport_replays_exact_operation_payload_states(tmp_path: Path) -> None:
    fixture = {
        "meta": {},
        "operations": {},
        "b524_operation_reads_schema_version": 1,
        "b524_operation_reads": [
            {
                "request_payload_hex": "0301000100",
                "response_raw_hex": "00002430909090",
                "response_state": "value",
            },
            {
                "request_payload_hex": "0900000100",
                "response_raw_hex": "",
                "response_state": "empty",
            },
            {
                "request_payload_hex": "0b01000100",
                "response_raw_hex": None,
                "response_state": "nack",
            },
            {
                "request_payload_hex": "0900000200",
                "response_raw_hex": None,
                "response_state": "timeout",
            },
            {
                "request_payload_hex": "08",
                "response_raw_hex": None,
                "response_state": "transport_error",
            },
            {
                "request_payload_hex": "0900000300",
                "response_raw_hex": "0102",
                "response_state": "malformed",
            },
        ],
    }
    fixture_path = tmp_path / "operation_reads.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    transport = DummyTransport(fixture_path)

    assert transport.send(0x15, bytes.fromhex("0301000100")) == bytes.fromhex("00002430909090")
    assert transport.send(0x15, bytes.fromhex("0900000100")) == b""
    with pytest.raises(TransportNack):
        transport.send(0x15, bytes.fromhex("0b01000100"))
    with pytest.raises(TransportTimeout):
        transport.send(0x15, bytes.fromhex("0900000200"))
    with pytest.raises(TransportError, match="transport_error"):
        transport.send(0x15, bytes.fromhex("08"))
    assert transport.send(0x15, bytes.fromhex("0900000300")) == bytes.fromhex("0102")


def test_dummy_transport_does_not_invent_unrecorded_operation_response(tmp_path: Path) -> None:
    fixture = {
        "meta": {},
        "operations": {},
        "b524_operation_reads_schema_version": 1,
        "b524_operation_reads": [
            {
                "request_payload_hex": "0900000100",
                "response_raw_hex": "0000000000000000",
                "response_state": "value",
            }
        ],
    }
    fixture_path = tmp_path / "operation_reads.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    transport = DummyTransport(fixture_path)

    with pytest.raises(TransportError, match="no exact"):
        transport.send(0x15, bytes.fromhex("0900000200"))


def test_dummy_transport_replays_duplicate_operation_observations_in_recorded_order(
    tmp_path: Path,
) -> None:
    payload = bytes.fromhex("0900000100")
    fixture = {
        "meta": {},
        "operations": {},
        "b524_operation_reads_schema_version": 1,
        "b524_operation_reads": [
            {
                "request_payload_hex": payload.hex(),
                "response_raw_hex": "0001020304050607",
                "response_state": "value",
            },
            {
                "request_payload_hex": payload.hex(),
                "response_raw_hex": "08090a0b0c0d0e0f",
                "response_state": "value",
            },
            {
                "request_payload_hex": payload.hex(),
                "response_raw_hex": None,
                "response_state": "nack",
            },
        ],
    }
    fixture_path = tmp_path / "duplicate_operation_reads.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    transport = DummyTransport(fixture_path)

    assert transport.send(0x15, payload) == bytes.fromhex("0001020304050607")
    assert transport.send(0x15, payload) == bytes.fromhex("08090a0b0c0d0e0f")
    with pytest.raises(TransportNack):
        transport.send(0x15, payload)
    with pytest.raises(TransportError, match="no exact"):
        transport.send(0x15, payload)


def test_dummy_transport_parameter_description_supports_qualified_nested_fixture(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "operations": {
            "0x02": {
                "groups": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x000f": {
                                        "raw_hex": "0500",
                                        "type": "UIN",
                                        "metadata": {
                                            "parameter_description": {
                                                "qualification": "matched",
                                                "description_opcode": "0x01",
                                                "read_opcode": "0x02",
                                                "group": "0x02",
                                                "instance": "0x00",
                                                "register": "0x000f",
                                                "type": "UIN",
                                                "width": 2,
                                                "min": 0,
                                                "max": 20,
                                                "step": 2,
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    fixture_path = tmp_path / "parameter_description.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)

    assert transport.send(0x15, build_constraint_probe_payload(0x02, 0x000F)) == bytes.fromhex(
        "020f00000014000200"
    )


def test_dummy_transport_parameter_description_supports_direct_scan_replay_entries(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "operations": {
            "0x02": {
                "groups": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x000f": {
                                        "raw_hex": "0500",
                                        "type": "UIN",
                                        "parameter_description": {
                                            "qualification": "matched",
                                            "description_opcode": "0x01",
                                            "read_opcode": "0x02",
                                            "group": "0x02",
                                            "instance": "0x00",
                                            "register": "0x000f",
                                            "type": "UIN",
                                            "width": 2,
                                            "min": 0,
                                            "max": 20,
                                            "step": 2,
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "0x06": {
                "groups": {
                    "0x09": {
                        "instances": {
                            "0x01": {
                                "registers": {
                                    "0x0004": {
                                        "raw_hex": "02",
                                        "type": "UCH",
                                        "parameter_description": {
                                            "qualification": "matched",
                                            "description_opcode": "0x07",
                                            "read_opcode": "0x06",
                                            "group": "0x09",
                                            "instance": "0x01",
                                            "register": "0x0004",
                                            "type": "UCH",
                                            "width": 1,
                                            "min": 0,
                                            "max": 10,
                                            "step": 1,
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
    }
    fixture_path = tmp_path / "direct_parameter_description.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)

    assert transport.send(0x15, build_constraint_probe_payload(0x02, 0x000F)) == bytes.fromhex(
        "020f00000014000200"
    )
    assert transport.send(
        0x15, build_constraint_probe_payload(0x09, 0x0004, instance=0x01, opcode=0x07)
    ) == bytes.fromhex("090400000a01")


def test_dummy_transport_register_read_returns_header_plus_value(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    payload = build_register_read_payload(0x02, group=0x02, instance=0x00, register=0x000F)
    response = transport.send(0x15, payload)
    assert response == bytes.fromhex("01020f003412")


def test_dummy_transport_missing_register_raises_timeout(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    payload = build_register_read_payload(0x02, group=0x02, instance=0x00, register=0x0010)
    with pytest.raises(TransportTimeout):
        transport.send(0x15, payload)


def test_dummy_transport_legacy_artifact_does_not_promote_descriptor_to_system_info(
    dual_namespace_scan_path: Path,
) -> None:
    transport = DummyTransport(dual_namespace_scan_path)

    response = transport.send(0x15, build_directory_probe_payload(0x09))

    assert struct.unpack("<f", response)[0] != struct.unpack("<f", response)[0]


def test_dummy_transport_artifact_v2_separates_local_and_remote_registers(
    dual_namespace_scan_path: Path,
) -> None:
    transport = DummyTransport(dual_namespace_scan_path)

    local_payload = build_register_read_payload(0x02, group=0x09, instance=0x00, register=0x0004)
    remote_payload = build_register_read_payload(0x06, group=0x09, instance=0x00, register=0x0004)

    assert transport.send(0x15, local_payload) == bytes.fromhex("01090400031702")
    assert transport.send(0x15, remote_payload) == bytes.fromhex("01090400021703")


def test_dummy_transport_legacy_remote_only_group_defaults_to_group_opcode(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "groups": {
            "0x0C": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0004": {"raw_hex": "080500", "read_opcode": "0x06"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_remote_only.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)
    remote_payload = build_register_read_payload(0x06, group=0x0C, instance=0x00, register=0x0004)
    local_payload = build_register_read_payload(0x02, group=0x0C, instance=0x00, register=0x0004)

    assert transport.send(0x15, remote_payload) == bytes.fromhex("010c0400080500")
    with pytest.raises(TransportTimeout):
        transport.send(0x15, local_payload)


def test_dummy_transport_legacy_dual_group_flat_fixture_supports_both_opcodes(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0004": {"raw_hex": "021703"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_dual_flat.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)
    local_payload = build_register_read_payload(0x02, group=0x09, instance=0x00, register=0x0004)

    # v2.3: flat group without read_opcode defaults to OP=0x02 only
    assert transport.send(0x15, local_payload) == bytes.fromhex("01090400021703")


def test_dummy_transport_artifact_v2_namespaces_do_not_require_dual_namespace_flag(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "groups": {
            "0x09": {
                "descriptor_observed": 1.0,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0004": {"raw_hex": "031702"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0004": {"raw_hex": "021703"},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_namespaces_only.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)
    local_payload = build_register_read_payload(0x02, group=0x09, instance=0x00, register=0x0004)
    remote_payload = build_register_read_payload(0x06, group=0x09, instance=0x00, register=0x0004)

    assert transport.send(0x15, local_payload) == bytes.fromhex("01090400031702")
    assert transport.send(0x15, remote_payload) == bytes.fromhex("01090400021703")


def test_dummy_transport_legacy_empty_namespaces_keeps_flat_instances_reachable(
    tmp_path: Path,
) -> None:
    fixture = {
        "schema_version": "2.0",
        "meta": {},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "namespaces": {},
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x000f": {"raw_hex": "3412"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_empty_namespaces_flat_instances.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = DummyTransport(fixture_path)
    payload = build_register_read_payload(0x02, group=0x02, instance=0x00, register=0x000F)

    assert transport.send(0x15, payload) == bytes.fromhex("01020f003412")


def test_dummy_transport_unknown_group_flat_fixture_requires_explicit_namespace(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {},
        "groups": {
            "0x69": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_unknown_flat.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    # v2.3: migration assigns OP=0x02 by default to flat unknown groups,
    # so DummyTransport no longer raises for this case.
    transport = DummyTransport(fixture_path)
    # The register should be loadable under opcode 0x02
    response = transport.send(0x15, bytes((0x02, 0x00, 0x69, 0x00, 0x00, 0x00)))
    assert response[4:] == bytes.fromhex("00")


@pytest.mark.parametrize("opcode,read_opcode", [(1, 2), (7, 6)])
@pytest.mark.parametrize("nested", [False, True])
def test_date_description_replays_day_step_separately_from_dates(
    tmp_path: Path, opcode: int, read_opcode: int, nested: bool
) -> None:
    from helianthus_vrc_explorer.protocol.b524_metadata import decode_parameter_description

    reply = bytes.fromhex("03050001011a05011a020000")
    desc = decode_parameter_description(
        reply, opcode=opcode, group=3, instance=1, register=5, type_spec="HDA:3"
    )
    entry = {"type": "HDA:3", "raw_hex": "03011a", "flags": 3}
    entry["metadata" if nested else "parameter_description"] = (
        {"parameter_description": desc} if nested else desc
    )
    fixture = {
        "schema_version": "2.3",
        "meta": {},
        "operations": {
            f"0x{read_opcode:02x}": {
                "groups": {"0x03": {"instances": {"0x01": {"registers": {"0x0005": entry}}}}}
            }
        },
    }
    path = tmp_path / "date.json"
    path.write_text(json.dumps(fixture))
    transport = DummyTransport(path)
    assert (
        transport.send(0x15, build_constraint_probe_payload(3, 5, instance=1, opcode=opcode))
        == reply
    )


def test_current_artifact_round_trip_preserves_writable_and_unavailable_metadata(
    tmp_path: Path,
) -> None:
    from helianthus_vrc_explorer.protocol.b524_metadata import decode_parameter_description
    from helianthus_vrc_explorer.scanner.scan import scan_b524

    reply = bytes.fromhex("000100") + struct.pack("<fff", 0, 20, 0.5)
    desc = decode_parameter_description(
        reply, opcode=1, group=0, instance=0, register=1, type_spec="EXP"
    )
    entry = {
        "read_opcode": "0x02",
        "flags": 3,
        "type": "EXP",
        "raw_hex": struct.pack("<f", 4.5).hex(),
        "reply_hex": (bytes.fromhex("03000100") + struct.pack("<f", 4.5)).hex(),
        "parameter_description": desc,
    }
    unavailable = {
        "read_opcode": "0x02",
        "flags": 3,
        "type": "UIN",
        "raw_hex": "0200",
        "reply_hex": "030002000200",
        "parameter_description": {"qualification": "unavailable", "reason": "unsupported"},
    }
    short = {
        "read_opcode": "0x02",
        "flags": 0,
        "raw_hex": None,
        "type": None,
        "reply_hex": "00",
        "response_state": "active",
    }
    fixture = {
        "schema_version": "2.3",
        "meta": {},
        "operations": {
            "0x02": {
                "groups": {
                    "0x00": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": entry,
                                    "0x0002": unavailable,
                                    "0x0003": short,
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    path = tmp_path / "roundtrip.json"
    path.write_text(json.dumps(fixture))
    transport = DummyTransport(path)
    assert transport.send(0x15, build_register_read_payload(2, 0, 0, 1)).hex() == entry["reply_hex"]
    assert transport.send(0x15, build_register_read_payload(2, 0, 0, 3)) == b"\x00"
    artifact = scan_b524(transport, dst=0x15)
    regs = artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]
    assert regs["0x0001"]["parameter_description"]["qualification"] == "matched"
    assert regs["0x0001"]["flags"] == 3
    assert regs["0x0002"]["parameter_description"]["qualification"] == "unavailable"
    # A second generated artifact, including absent/status/timeout entries, also loads.
    path.write_text(json.dumps(artifact))
    assert DummyTransport(path).send(0x15, build_constraint_probe_payload(0, 1)) == reply


@pytest.mark.parametrize("circuit_raw_hex", [None, "00", "0102"])
def test_partial_system_information_keeps_valid_fixture_registers(
    tmp_path: Path, circuit_raw_hex: str | None
) -> None:
    from helianthus_vrc_explorer.scanner.scan import scan_b524

    path = _write_min_fixture(tmp_path)
    fixture = json.loads(path.read_text())
    fixture["meta"]["system_information"] = [
        {
            "identifier": "0x0000",
            "name": "circuit_count",
            "value": None,
            "state": "unavailable",
            "raw_hex": circuit_raw_hex,
        },
        {
            "identifier": "0x0001",
            "name": "zone_count",
            "value": 2.0,
            "state": "available",
            "raw_hex": "0400000040",
        },
        {
            "identifier": "0x0002",
            "name": "solar_circuit_count",
            "value": None,
            "state": "unavailable",
            "raw_hex": "00",
        },
    ]
    fixture["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0002"] = {
        "type": "UIN",
        "raw_hex": "0100",
        "flags": 1,
    }
    fixture["groups"]["0x02"]["instances"]["0x01"] = fixture["groups"]["0x02"]["instances"].pop(
        "0x00"
    )
    path.write_text(json.dumps(fixture))
    transport = DummyTransport(path)
    if circuit_raw_hex is None:
        with pytest.raises(TransportTimeout):
            transport.send(0x15, build_directory_probe_payload(0))
    else:
        assert transport.send(0x15, build_directory_probe_payload(0)).hex() == circuit_raw_hex
    assert transport.send(0x15, build_directory_probe_payload(1)) == bytes.fromhex("00000040")
    assert transport.send(0x15, build_directory_probe_payload(2)) == b"\x00"
    artifact = scan_b524(transport, dst=0x15)
    assert artifact["meta"]["system_information"][0]["raw_hex"] == circuit_raw_hex
    assert artifact["meta"]["system_information"][0]["value"] is None
    assert artifact["meta"]["system_information"][0]["state"] == "unavailable"
    assert artifact["meta"]["system_information"][1]["value"] == 2.0
    assert artifact["meta"]["system_information"][2]["value"] is None
    assert artifact["meta"]["system_information"][2]["raw_hex"] == "00"
    circuit_counts = artifact["meta"]["instance_counts"]["0x02:0x02"]
    assert circuit_counts["expected"] is None
    assert circuit_counts["probed_instances"] == 9
    regs = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x01"]["registers"]
    assert regs["0x000f"]["value"] == 0x1234
    path.write_text(json.dumps(artifact))
    replay_transport = DummyTransport(path)
    if circuit_raw_hex is not None:
        assert (
            replay_transport.send(0x15, build_directory_probe_payload(0)).hex() == circuit_raw_hex
        )
    assert replay_transport.send(0x15, build_directory_probe_payload(2)) == b"\x00"
    assert replay_transport.send(0x15, build_register_read_payload(2, 2, 1, 0xF)).endswith(
        b"\x34\x12"
    )
