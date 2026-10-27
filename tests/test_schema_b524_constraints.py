from pathlib import Path

import pytest

from helianthus_vrc_explorer.scanner.identity import make_register_identity
from helianthus_vrc_explorer.schema.b524_constraints import (
    constraint_scope_metadata,
    load_b524_constraints_catalog_from_path,
    load_default_b524_constraints_catalog,
    lookup_static_constraint,
)


def test_catalog_keys_are_opcode_group_little_endian_register() -> None:
    catalog, source = load_default_b524_constraints_catalog()
    assert source == "static_constraints:b524_constraints_catalog.csv"
    assert len(catalog) == 46
    assert all(opcode == 2 for opcode, _group, _register in catalog)
    entry = catalog[(2, 2, 2)]
    assert (entry.tt, entry.kind, entry.min_value, entry.max_value, entry.step_value) == (
        9,
        "u16_range",
        0,
        4,
        1,
    )
    assert entry.scope == "unscoped_catalog"
    assert entry.source == "static_catalog"
    assert entry.provenance == "catalog_seeded_from_opcode_0x01"
    assert catalog[(2, 0, 0x0080)].min_value == -10
    assert (2, 0, 0x8000) not in catalog


@pytest.mark.parametrize("opcode", [2, 6])
@pytest.mark.parametrize("instance", [0, 1, 255])
def test_removed_dhw_row_never_resolves(opcode: int, instance: int) -> None:
    catalog, _ = load_default_b524_constraints_catalog()
    assert lookup_static_constraint(catalog, identity=(opcode, 0, instance, 1)) is None


@pytest.mark.parametrize("opcode,found", [(2, True), (6, False)])
def test_lookup_uses_opcode_key(opcode: int, found: bool) -> None:
    catalog, _ = load_default_b524_constraints_catalog()
    identity = make_register_identity(opcode=opcode, group=3, instance=0, register=2)
    assert (lookup_static_constraint(catalog, identity=identity) is not None) is found


@pytest.mark.parametrize("opcode", ["0x06", "0x01"])
def test_catalog_rejects_other_opcodes(tmp_path: Path, opcode: str) -> None:
    path = tmp_path / "constraints.csv"
    path.write_text(f"opcode,group,register,type,min,max,step\n{opcode},0,2,u8_range,0,1,1\n")
    with pytest.raises(ValueError, match="opcode"):
        load_b524_constraints_catalog_from_path(path)


def test_catalog_requires_explicit_opcode(tmp_path: Path) -> None:
    path = tmp_path / "constraints.csv"
    path.write_text("group,register,type,min,max,step\n0,2,u8_range,0,1,1\n")
    with pytest.raises(ValueError, match="opcode"):
        load_b524_constraints_catalog_from_path(path)


def test_catalog_rejects_duplicate_tuple_key(tmp_path: Path) -> None:
    path = tmp_path / "constraints.csv"
    path.write_text("opcode,group,register,type,min,max,step\n" + "2,0,2,u8_range,0,1,1\n" * 2)
    with pytest.raises(ValueError, match="Duplicate"):
        load_b524_constraints_catalog_from_path(path)


def test_scope_metadata_uses_registry_markers() -> None:
    metadata = constraint_scope_metadata()
    assert metadata["constraint_qualified"] is False
    assert metadata["constraint_scope"] == "unscoped_catalog"
    assert "historical short-probe hints" in metadata["rationale"]


def test_resource_failure_uses_sanitized_source_catalog(monkeypatch) -> None:
    from helianthus_vrc_explorer.schema import b524_constraints

    def unavailable(_package):
        raise FileNotFoundError("resource unavailable")

    monkeypatch.setattr(b524_constraints.resources, "files", unavailable)
    catalog, source = load_default_b524_constraints_catalog()
    assert source == "static_constraints:b524_constraints_catalog.csv"
    assert (2, 0, 1) not in catalog
    assert (2, 0, 2) in catalog


def test_source_and_packaged_catalog_match() -> None:
    root = Path(__file__).resolve().parents[1]
    source = root / "data/b524_constraints_catalog.csv"
    packaged = root / "src/helianthus_vrc_explorer/data/b524_constraints_catalog.csv"
    assert source.read_bytes() == packaged.read_bytes()
