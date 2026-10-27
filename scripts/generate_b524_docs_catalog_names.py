"""Copy the docs-owned naming catalog, retaining its instance-independent scope."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

FIELDS = ("opcode", "group", "register", "name", "previous_name", "open_question")
SOURCE = Path("protocols/vaillant/fixtures/b524-op02-register-names.csv")


def generate(checkout: Path, output: Path) -> None:
    with (checkout / SOURCE).open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != FIELDS:
            raise ValueError("Unexpected docs-ebus naming catalog header")
        rows = list(reader)
    seen = set()
    for row in rows:
        key = tuple(int(row[field], 0) for field in FIELDS[:3])
        if not (key[0] == 2 and 0 <= key[1] <= 255 and 0 <= key[2] <= 65535):
            raise ValueError(f"Invalid docs catalog selector: {key}")
        if key in seen:
            raise ValueError(f"Duplicate docs catalog selector: {key}")
        seen.add(key)
        if not row["name"] or any(value is None for value in row.values()):
            raise ValueError(f"Incomplete docs catalog row: {key}")
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("docs_checkout", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "src/helianthus_vrc_explorer/data/b524_docs_catalog_names.csv",
    )
    args = parser.parse_args()
    generate(args.docs_checkout, args.output)


if __name__ == "__main__":
    main()
