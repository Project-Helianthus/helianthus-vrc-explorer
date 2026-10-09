from __future__ import annotations

import argparse
import csv
from pathlib import Path

EXPECTED_HEADER = ["eid", "spn", "model_name", "protocol_family"]


def load_rows(input_path: Path) -> list[dict[str, str]]:
    with input_path.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        rows = [{key: (row.get(key) or "").strip() for key in EXPECTED_HEADER} for row in reader]
    if reader.fieldnames != EXPECTED_HEADER:
        raise ValueError(f"Unexpected CSV header: {reader.fieldnames}")
    return rows


def write_rows(rows: list[dict[str, str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination, lineterminator="\n")
        writer.writerow(EXPECTED_HEADER)
        writer.writerows([row[key] for key in EXPECTED_HEADER] for row in rows)


def main(argv: list[str] | None = None) -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Regenerate packaged regulator EID/SPN catalog.")
    parser.add_argument("--input", type=Path, default=root / "data/regulator_eid_spn.csv")
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "src/helianthus_vrc_explorer/data/regulator_eid_spn.csv",
    )
    args = parser.parse_args(argv)
    write_rows(load_rows(args.input), args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
