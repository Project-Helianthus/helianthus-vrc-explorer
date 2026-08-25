from __future__ import annotations

import argparse
import csv
from pathlib import Path

EXPECTED_HEADER = ["model_number", "marketing_name", "ebus_model", "notes"]


def load_models_rows_from_csv(models_csv_path: Path) -> list[dict[str, str]]:
    with models_csv_path.open(newline="", encoding="utf-8") as models_csv:
        reader = csv.DictReader(models_csv)
        rows = [{key: (row.get(key) or "").strip() for key in EXPECTED_HEADER} for row in reader]
    if reader.fieldnames != EXPECTED_HEADER:
        raise ValueError(
            f"Unexpected CSV header in {models_csv_path}. "
            f"expected={EXPECTED_HEADER} got={reader.fieldnames}"
        )

    seen_model_numbers: set[str] = set()
    for row in rows:
        model_number = row["model_number"]
        if not model_number.isdigit():
            raise ValueError(f"Invalid model_number (expected digits): {model_number!r}")
        if model_number in seen_model_numbers:
            raise ValueError(f"Duplicate model_number: {model_number}")
        seen_model_numbers.add(model_number)

    if [row["model_number"] for row in rows] != sorted(
        (row["model_number"] for row in rows), key=int
    ):
        raise ValueError(f"Model rows in {models_csv_path} must be ordered by model_number")
    return rows


def write_models_csv(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(EXPECTED_HEADER)
        for row in rows:
            writer.writerow([row[k] for k in EXPECTED_HEADER])


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Regenerate the packaged model CSV from data/models.csv."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=repo_root / "data" / "models.csv",
        help="Canonical model CSV input path.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "src" / "helianthus_vrc_explorer" / "data" / "models.csv",
        help="Packaged model CSV output path.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    rows = load_models_rows_from_csv(args.input)
    write_models_csv(rows, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
