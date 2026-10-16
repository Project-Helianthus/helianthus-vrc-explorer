import pytest

from helianthus_vrc_explorer.scanner.b524_parameter_writes import (
    B524ParameterTarget,
    prepare_parameter_write,
)
from helianthus_vrc_explorer.ui.html_report import render_html_report
from tests.test_b524_parameter_writes import IDENTITY, PROFILE


@pytest.mark.parametrize("register", [0x0001, 0x0002])
def test_static_hints_cannot_supply_write_limits(register: int) -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import _apply_constraint_metadata
    from helianthus_vrc_explorer.schema.b524_constraints import (
        load_default_b524_constraints_catalog,
        lookup_static_constraint,
    )

    target = B524ParameterTarget(0x15, 2, 0, 0, register)
    catalog, _ = load_default_b524_constraints_catalog()
    constraint = lookup_static_constraint(catalog, identity=(2, 0, 0, register))
    entry = {"type": "EXP", "raw_hex": "00000000", "flags_access": "writable_visible"}
    if register == 1:
        assert constraint is None
    else:
        assert constraint is not None
        _apply_constraint_metadata(entry, constraint)
        assert entry["constraint_qualified"] is False
    with pytest.raises(ValueError, match="limits or STEP are incomplete"):
        prepare_parameter_write(
            target=target,
            entry=entry,
            description=None,
            profile=PROFILE,
            identity=IDENTITY,
            desired_value=1.0,
        )


def test_static_constraint_tooltip_maps_historical_qualification() -> None:
    html = render_html_report({"meta": {}, "operations": {}})
    assert "unscoped_catalog (unqualified): historical short-probe hints" in html
    assert 'entry.constraint_qualification === "legacy_unqualified"' in html
    assert "constraint_qualified=${entry.constraint_qualified}" in html
