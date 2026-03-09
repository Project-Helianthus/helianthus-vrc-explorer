from __future__ import annotations

from helianthus_vrc_explorer.schema.b524_constraints import load_default_b524_constraints_catalog


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

    zone_desired_temp = catalog[0x03][0x0002]
    assert zone_desired_temp.tt == 0x0F
    assert zone_desired_temp.kind == "f32_range"
    assert zone_desired_temp.min_value == 15.0
    assert zone_desired_temp.max_value == 30.0
    assert zone_desired_temp.step_value == 0.5
