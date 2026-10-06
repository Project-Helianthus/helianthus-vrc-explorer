"""Export sanitized, profile-qualified metadata from a read-only scan artifact."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from helianthus_vrc_explorer.artifact_schema import migrate_artifact_schema
from helianthus_vrc_explorer.schema.parameter_descriptions import export_description_baseline


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    artifact, _migration = migrate_artifact_schema(json.loads(args.artifact.read_text()))
    bundle = export_description_baseline(artifact)
    args.output.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    print(f"Exported {len(bundle['descriptions'])} qualified descriptions")


if __name__ == "__main__":
    main()
