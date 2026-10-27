"""Export sanitized, profile-qualified metadata from a read-only scan artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from helianthus_vrc_explorer.artifact_schema import migrate_artifact_schema
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    export_description_baseline,
    export_installation_observations,
    merge_description_baselines,
    merge_installation_observations,
)


def _dump_catalog(value: Any, indent: int = 0) -> str:
    """Render the catalog like the checked-in file: two-space objects, scalar lists inline."""

    pad = "  " * (indent + 1)
    if isinstance(value, dict) and value:
        body = ",\n".join(
            f"{pad}{json.dumps(key)}: {_dump_catalog(item, indent + 1)}"
            for key, item in value.items()
        )
        return "{\n" + body + "\n" + "  " * indent + "}"
    if isinstance(value, list) and value and not any(isinstance(i, (dict, list)) for i in value):
        return json.dumps(value)
    if isinstance(value, list) and value:
        body = ",\n".join(f"{pad}{_dump_catalog(item, indent + 1)}" for item in value)
        return "[\n" + body + "\n" + "  " * indent + "]"
    return json.dumps(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--allow-legacy-interpretation",
        action="store_true",
        help="Explicitly export known Explorer legacy interpretations with provenance.",
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help="Update an existing baseline without removing other rows.",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        help=(
            "Also merge the scan's instance capacities, observed counts and present remote "
            "device identities into this description profile catalog. They are installation "
            "observations, never profile limits."
        ),
    )
    args = parser.parse_args()
    artifact, _migration = migrate_artifact_schema(json.loads(args.artifact.read_text()))
    bundle = export_description_baseline(
        artifact, allow_legacy_interpretation=args.allow_legacy_interpretation
    )
    if args.merge and args.output.exists():
        bundle = merge_description_baselines(
            json.loads(args.output.read_text(encoding="utf-8")),
            bundle,
            allow_legacy_interpretation=args.allow_legacy_interpretation,
        )
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Exported {len(bundle['descriptions'])} qualified descriptions")
    if args.catalog is not None:
        catalog = merge_installation_observations(
            json.loads(args.catalog.read_text(encoding="utf-8")),
            export_installation_observations(artifact),
        )
        args.catalog.write_text(_dump_catalog(catalog) + "\n", encoding="utf-8")
        print("Merged installation observations into the description profile catalog")


if __name__ == "__main__":
    main()
