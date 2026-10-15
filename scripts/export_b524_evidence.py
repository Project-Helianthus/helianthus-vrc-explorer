#!/usr/bin/env python3
"""Export Explorer's sanitized BASV0 source pair and separate application overlay.

The small application baseline cannot reconstruct the complete native evidence.
This refresh mode consumes the retained source pair and independent identity
manifest. It never reads docs-ebus or contacts a device. Fixture refresh is #299.
"""

from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

from helianthus_vrc_explorer.evidence_export import (
    build_native_evidence,
    serialize_native_evidence,
    write_native_evidence,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--description-input",
        type=Path,
        default=ROOT / "fixtures/b524-basv0-description-profile-v1.json",
    )
    parser.add_argument(
        "--observations-input",
        type=Path,
        default=ROOT / "fixtures/b524-basv0-register-observations-v1.json",
    )
    parser.add_argument(
        "--identity-manifest",
        type=Path,
        default=ROOT / "src/helianthus_vrc_explorer/data/b524_description_profiles.json",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--allow-legacy-interpretation",
        action="store_true",
        help="Explicitly publish the known Explorer legacy plain-byte interpretation.",
    )
    args = parser.parse_args()
    try:
        documents = build_native_evidence(
            json.loads(args.description_input.read_text(encoding="utf-8")),
            json.loads(args.observations_input.read_text(encoding="utf-8")),
            json.loads(args.identity_manifest.read_text(encoding="utf-8")),
            allow_legacy_interpretation=args.allow_legacy_interpretation,
        )
        write_native_evidence(documents, args.output_dir)
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"Native export failed: {exc}\n")
    for name, content in serialize_native_evidence(documents).items():
        print(f"{sha256(content).hexdigest()}  {args.output_dir / name}")


if __name__ == "__main__":
    main()
