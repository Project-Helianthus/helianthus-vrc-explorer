from __future__ import annotations

import csv
from copy import deepcopy
from importlib import resources

import pytest

from helianthus_vrc_explorer.artifact_schema import ArtifactSchemaError, migrate_artifact_schema
from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
    b524_docs_catalog_correspondence,
)
from helianthus_vrc_explorer.schema.b524_register_names import (
    apply_b524_canonical_register_names,
    bundled_b524_register_names,
)


def test_exact_settled_names_and_all_provisional_rows():
    resource = resources.files("helianthus_vrc_explorer.data")
    with resource.joinpath("b524_docs_catalog_names.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    names = bundled_b524_register_names()
    assert len(rows) == len(names) == 368
    provisional = 0
    for row in rows:
        op, group, register = (int(row[x], 0) for x in ("opcode", "group", "register"))
        annotation = b524_docs_catalog_correspondence(
            opcode=op, group=group, instance=0, register=register
        )
        if row["open_question"]:
            provisional += 1
            assert names[op, group, register] == row["previous_name"]
            assert annotation.provisional and annotation.open_question == row["open_question"]
        else:
            assert names[op, group, register] == row["name"]
    assert provisional == 142
    assert names[2, 2, 0x1D] == "circuit_dhw_quick_mode"


@pytest.mark.parametrize("axis", ["opcode", "group", "instance", "register"])
def test_full_selector_separation(axis):
    # Each native identity field varies independently; dropping any axis conflates the rows.
    args = dict(opcode=2, group=0, instance=0, register=0xE)
    first = b524_docs_catalog_correspondence(**args)
    args[axis] += 1
    second = b524_docs_catalog_correspondence(**args)
    assert second is None or first.selector != second.selector
    with (
        resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_docs_catalog_names.csv")
        .open() as handle
    ):
        expected = {
            tuple(int(row[k], 0) for k in ("opcode", "group", "register")): row
            for row in csv.DictReader(handle)
        }
    template = expected.get((args["opcode"], args["group"], args["register"]))
    if template is None:
        assert second is None
    else:
        assert second.name == template["name"]
        assert second.selector == tuple(args.values())


def test_apply_preserves_native_and_partial_last_known_good_fields():
    entry = dict(
        register_name="max_room_humidity",
        raw_hex="0000803f",
        reply_hex="010000803f",
        value=1,
        unit="%",
        scale=1,
        width=4,
        polarity="positive",
        access="read",
        evidence_grade="Hypothesis",
        quality="stale",
        generation=3,
        lineage=["synthetic"],
        last_known_good={"value": 1},
        myvaillant_name_vrc720="sourceAnnotation",
    )
    tree = {"0x02": {"groups": {"0x00": {"instances": {"0x01": {"registers": {"0x000E": entry}}}}}}}
    before = deepcopy(entry)
    apply_b524_canonical_register_names(tree)
    assert entry.pop("register_name") == "room_humidity_limit_maximum"
    before.pop("register_name")
    assert entry == before


@pytest.mark.parametrize("ambiguous", [False, True])
def test_withdrawn_key_is_rejected_without_mutation(ambiguous):
    entry = {"myvaillant_name": "max_room_humidity"}
    if ambiguous:
        entry["register_name"] = "room_humidity_limit_maximum"
    source = {
        "schema_version": "2.5",
        "operations": {
            "0x02": {"groups": {"0x00": {"instances": {"0x00": {"registers": {"0x000E": entry}}}}}}
        },
    }
    before = deepcopy(source)
    with pytest.raises(ArtifactSchemaError, match="Withdrawn artifact key"):
        migrate_artifact_schema(source)
    assert source == before
    with pytest.raises(ValueError, match="Withdrawn artifact key"):
        apply_b524_canonical_register_names(source["operations"])
    assert source == before


def test_generator_adopts_only_settled_rows(tmp_path):
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "generator345", root / "scripts/generate_b524_docs_catalog_names.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from tests.test_issue_301_docs_names import docs_checkout

    checkout = docs_checkout()
    output = tmp_path / "names.csv"
    output.write_bytes(
        resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_register_names.csv")
        .read_bytes()
    )
    # Start with an obsolete settled spelling so a no-op generator cannot pass.
    output.write_text(
        output.read_text().replace(
            "dhw_outdoor_bivalence_temperature_limit", "obsolete_settled_name"
        )
    )
    module.generate_register_names(checkout, output)
    assert (
        output.read_bytes()
        == resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_register_names.csv")
        .read_bytes()
    )
