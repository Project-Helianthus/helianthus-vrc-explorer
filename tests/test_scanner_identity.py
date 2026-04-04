from __future__ import annotations

from helianthus_vrc_explorer.scanner.identity import make_register_identity, opcode_label


def test_make_register_identity_is_opcode_first() -> None:
    assert make_register_identity(opcode=0x06, group=0x02, instance=0x01, register=0x0015) == (
        0x06,
        0x02,
        0x01,
        0x0015,
    )


def test_opcode_label_uses_local_remote_conventions() -> None:
    assert opcode_label(0x02) == "local"
    assert opcode_label(0x06) == "remote"
    assert opcode_label(0xA5) == "0xa5"
