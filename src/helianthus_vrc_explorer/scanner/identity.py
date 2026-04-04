from __future__ import annotations

# Canonical register identity key for B524 namespace-aware surfaces.
# Order is opcode-first to avoid GG-centric collisions.
type RegisterIdentity = tuple[int, int, int, int]


def make_register_identity(
    *, opcode: int, group: int, instance: int, register: int
) -> RegisterIdentity:
    return (opcode, group, instance, register)


def opcode_label(opcode: int) -> str:
    if opcode == 0x02:
        return "local"
    if opcode == 0x06:
        return "remote"
    return f"0x{opcode:02x}"
