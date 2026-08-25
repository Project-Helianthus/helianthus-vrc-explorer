from __future__ import annotations

import csv
import importlib.util
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_generator_module():
    script_path = _repo_root() / "scripts" / "generate_models_csv.py"
    spec = importlib.util.spec_from_file_location("generate_models_csv", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_models_csv_parses_and_has_entries() -> None:
    models_path = _repo_root() / "data" / "models.csv"
    with models_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["model_number", "marketing_name", "ebus_model", "notes"]
        rows = list(reader)

    assert len(rows) > 0

    model_numbers = [row["model_number"] for row in rows]
    assert all(m.isdigit() for m in model_numbers)
    assert len(set(model_numbers)) == len(model_numbers)

    # Stable ordering is required (deterministic diffs).
    assert model_numbers == sorted(model_numbers, key=int)


def test_generate_models_csv_reads_canonical_data_file(tmp_path: Path) -> None:
    module = _load_generator_module()
    canonical_csv = _repo_root() / "data" / "models.csv"
    out_path = tmp_path / "models.csv"

    rows = module.load_models_rows_from_csv(canonical_csv)
    module.write_models_csv(rows, out_path)

    expected = canonical_csv.read_text(encoding="utf-8")
    actual = out_path.read_text(encoding="utf-8")
    assert actual == expected


def test_packaged_models_csv_stays_in_sync_with_repo_copy() -> None:
    repo_csv = _repo_root() / "data" / "models.csv"
    packaged_csv = _repo_root() / "src" / "helianthus_vrc_explorer" / "data" / "models.csv"
    assert packaged_csv.read_text(encoding="utf-8") == repo_csv.read_text(encoding="utf-8")
