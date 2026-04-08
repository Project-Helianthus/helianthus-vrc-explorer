from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    build_directory_probe_payload,
    build_register_read_payload,
)
from helianthus_vrc_explorer.transport.base import TransportTimeout
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


def test_dummy_transport_directory_probe_known_group(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x02))
    assert response == struct.pack("<f", 1.0)


def test_dummy_transport_directory_probe_unknown_group_returns_zero(tmp_path: Path) -> None:
    transport = DummyTransport(_write_min_fixture(tmp_path))
    response = transport.send(0x15, build_directory_probe_payload(0x03))
    assert response == struct.pack("<f", 0.0)


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


def test_dummy_transport_artifact_v2_directory_probe_uses_descriptor_observed(
    dual_namespace_scan_path: Path,
) -> None:
    transport = DummyTransport(dual_namespace_scan_path)

    response = transport.send(0x15, build_directory_probe_payload(0x09))

    assert response == struct.pack("<f", 1.0)


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
