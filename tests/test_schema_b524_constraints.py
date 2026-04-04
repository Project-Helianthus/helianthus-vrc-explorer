from __future__ import annotations

from helianthus_vrc_explorer.scanner.identity import make_register_identity
from helianthus_vrc_explorer.schema.b524_constraints import (
    constraint_scope_metadata,
    load_default_b524_constraints_catalog,
    lookup_static_constraint,
)


def test_load_default_b524_constraints_catalog() -> None:
    catalog, source = load_default_b524_constraints_catalog()

    assert source == "static_constraints:b524_constraints_catalog.csv"

    hc_room_setpoint = catalog[0x02][0x0002]
    assert hc_room_setpoint.tt == 0x09
    assert hc_room_setpoint.kind == "u16_range"
    assert hc_room_setpoint.min_value == 0
    assert hc_room_setpoint.max_value == 4
    assert hc_room_setpoint.step_value == 1
    assert hc_room_setpoint.source == "static_catalog"
    assert hc_room_setpoint.scope == "gg_rr_invariant"
    assert hc_room_setpoint.provenance == "catalog_seeded_from_opcode_0x01"

    zone_desired_temp = catalog[0x03][0x0002]
    assert zone_desired_temp.tt == 0x0F
    assert zone_desired_temp.kind == "f32_range"
    assert zone_desired_temp.min_value == 15.0
    assert zone_desired_temp.max_value == 30.0
    assert zone_desired_temp.step_value == 0.5


def test_lookup_static_constraint_accepts_canonical_register_identity() -> None:
    catalog, _source = load_default_b524_constraints_catalog()

    entry = lookup_static_constraint(
        catalog,
        identity=make_register_identity(
            opcode=0x06,
            group=0x02,
            instance=0x00,
            register=0x0002,
        ),
    )

    assert entry is not None
    assert entry.kind == "u16_range"


def test_lookup_static_constraint_is_opcode_invariant_for_same_group_register() -> None:
    catalog, _source = load_default_b524_constraints_catalog()
    pairs = [(0x02, 0x0002), (0x03, 0x0002), (0x09, 0x0002)]
    for group, register in pairs:
        local = lookup_static_constraint(
            catalog,
            identity=make_register_identity(
                opcode=0x02,
                group=group,
                instance=0x00,
                register=register,
            ),
        )
        remote = lookup_static_constraint(
            catalog,
            identity=make_register_identity(
                opcode=0x06,
                group=group,
                instance=0x01,
                register=register,
            ),
        )
        assert local is not None
        assert remote is not None
        assert local == remote


def test_constraint_scope_metadata_declares_gg_rr_invariant_policy() -> None:
    metadata = constraint_scope_metadata()
    assert metadata["decision"] == "gg_rr_invariant"
    assert metadata["protocol"] == "opcode_0x01"
