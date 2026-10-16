from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
    b524_docs_catalog_correspondence,
)

ROOT = Path(__file__).resolve().parents[1]
DOCS = Path(os.environ.get("DOCS_EBUS_CHECKOUT", ROOT.parent / "parity-07/docs-ebus"))
ANNOTATIONS = (
    "vaillant_friendly_name",
    "vaillant_name_vrc720",
    "vaillant_name_vrc700",
    "myvaillant_name_vrc720",
    "myvaillant_name_vrc700",
    "ebusd_name",
)


def rows(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def test_shared_annotations_match_docs():
    path = DOCS / "protocols/vaillant/fixtures/b524-register-name-correspondence.csv"
    if not path.exists():
        pytest.skip("Set DOCS_EBUS_CHECKOUT to compare the external docs correspondence")

    def key(row):
        return tuple(int(row[c], 0) for c in ("opcode", "group", "register"))

    docs = {key(row): row for row in rows(path)}
    explorer = {
        key(row): row
        for row in rows(
            ROOT / "src/helianthus_vrc_explorer/data/b524_register_name_correspondence.csv"
        )
    }
    mismatches = [
        f"{selector} {column}: explorer={explorer[selector][column]!r}, "
        f"docs={docs[selector][column]!r}"
        for selector in sorted(docs.keys() & explorer.keys())
        for column in ANNOTATIONS
        if explorer[selector][column] != docs[selector][column]
    ]
    assert not mismatches, "\n".join(mismatches)


def test_docs_names_are_secondary_and_full_selector_scoped():
    first = b524_docs_catalog_correspondence(opcode=2, group=0, instance=0, register=7)
    second = b524_docs_catalog_correspondence(opcode=2, group=0, instance=1, register=7)
    assert first.name == "unknown_11"
    assert first.previous_name == "system_off"
    assert first.provisional
    assert first.open_question
    assert first.selector == (2, 0, 0, 7)
    assert second.selector == (2, 0, 1, 7)
    assert first != second
    assert b524_docs_catalog_correspondence(opcode=6, group=0, instance=0, register=7) is None


def test_generator_reproduces_packaged_catalog(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generator301", ROOT / "scripts/generate_b524_docs_catalog_names.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not (DOCS / module.SOURCE).exists():
        pytest.skip("Set DOCS_EBUS_CHECKOUT for catalog regeneration parity")
    output = tmp_path / "names.csv"
    module.generate(DOCS, output)
    assert (
        output.read_bytes()
        == (ROOT / "src/helianthus_vrc_explorer/data/b524_docs_catalog_names.csv").read_bytes()
    )


def test_generator_rejects_ambiguous_catalog_without_external_checkout(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "generator301", ROOT / "scripts/generate_b524_docs_catalog_names.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = tmp_path / "names.csv"
    # Malformed external input cannot produce an ambiguous catalog.
    checkout = tmp_path / "docs"
    source = checkout / module.SOURCE
    source.parent.mkdir(parents=True)
    source.write_text(
        "opcode,group,register,name,previous_name,open_question\n0x02,0x00,0x0001,a,,\n0x02,0x00,0x0001,b,,\n"
    )
    with pytest.raises(ValueError, match="Duplicate"):
        module.generate(checkout, output)


def test_imported_annotations_have_family_attribution():
    from helianthus_vrc_explorer.schema.b524_register_name_correspondence import (
        OBSERVED_NAME_CAVEAT,
        b524_register_name_correspondence,
    )

    ventilation = b524_register_name_correspondence(opcode=2, group=0, register=0x16)
    pv = b524_register_name_correspondence(opcode=2, group=0, register=0xA2)
    assert ventilation.myvaillant_name_vrc700 == ("operationModeVentilation",)
    assert pv.myvaillant_name_vrc720 == ("smartPhotovoltaicBufferOffset",)
    assert "Hypothesis" in OBSERVED_NAME_CAVEAT
