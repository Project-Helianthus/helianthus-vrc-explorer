from __future__ import annotations

from helianthus_vrc_explorer.schema.b524_register_names import (
    b524_register_name,
    bundled_b524_register_names,
)


def test_bundled_op02_register_catalog_is_complete_and_opcode_scoped() -> None:
    names = bundled_b524_register_names()

    assert len(names) == 363
    assert all(opcode == 0x02 for opcode, _group, _register in names)
    assert names[(0x02, 0x00, 0x0001)] == "system_dhw_bivalence_point"
    assert names[(0x02, 0x02, 0x0001)] == "circuit_circuit_type"
    assert names[(0x02, 0x09, 0x0004)] == "ventilation_status_special_operating_mode"


def test_op02_canonical_names_do_not_override_shared_op06_identities() -> None:
    assert (
        b524_register_name(opcode=0x02, group=0x09, register=0x0004)
        == "ventilation_status_special_operating_mode"
    )
    assert b524_register_name(opcode=0x06, group=0x09, register=0x0004) == "device_firmware_version"


def test_op06_device_headers_are_universal_for_every_group() -> None:
    expected = {
        0x0001: "device_connected",
        0x0002: "device_class_address",
        0x0003: "device_error_code",
        0x0004: "device_firmware_version",
    }

    for group in range(0x100):
        for register, name in expected.items():
            assert b524_register_name(opcode=0x06, group=group, register=register) == name
        assert b524_register_name(opcode=0x06, group=group, register=0x0005) is None
