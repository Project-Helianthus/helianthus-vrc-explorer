#!/usr/bin/env python3
"""Export an offline, observation-only inventory from a 2.3/2.4 scan artifact.

Usage: python3 scripts/export_controller_observations.py ARTIFACT > inventory.json
Only family, full selectors, evidence grades, response states and numeric decoded
parameter-description observations are retained. Current values (including text,
clocks and identifiers), raw bytes, names and arbitrary metadata are omitted.
Missing qualifiers and absent raw descriptions are unknown. Qualifiers and grades
are source claims, never qualification by this tool. This is not native profile
input or write-bound evidence; decoded limits cannot authorize writes. The source
is never modified. Legacy groups-first artifacts must be handled separately.

Selector contract: protocols/vaillant/ebus-vaillant-B524.md in docs-ebus,
section 3.1: (opcode, GG, II, RR), with independent operation namespaces.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

GRADES = frozenset({"Proven", "Hypothesis", "Unknown"})
QUALIFICATIONS = frozenset(
    {"matched", "unqualified", "unavailable", "bundled", "profile_qualified", "qualified"}
)
# Public scalar codec vocabulary used by protocol/b524_metadata.py.
CODECS = frozenset(
    {"UCH", "BOOL", "I8", "UIN", "I16", "U32", "I32", "EXP", "DATE_DMY_U8X3", "TIME_HMS_U8X3"}
)
STATES = frozenset({"active", "empty_reply", "nack", "nack_or_crc", "timeout"})


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise ValueError("Expected an object in artifact structure")
    return value


def _choice(value: object, allowed: frozenset[str], unknown: str = "unknown") -> str:
    return value if isinstance(value, str) and value in allowed else unknown


def _selector(value: object, digits: int) -> str:
    if not isinstance(value, str) or not re.fullmatch(rf"0[xX][0-9a-fA-F]{{{digits}}}", value):
        raise ValueError("Invalid selector encoding")
    return f"0x{int(value, 16):0{digits}x}"


def _numeric(value: object) -> int | float | str:
    # Bounded finite numeric description fields only; never copy nested values.
    if type(value) is int and abs(value) <= 2**53:
        return value
    if type(value) is float and math.isfinite(value) and abs(value) <= 2**53:
        return value
    return "unknown"


def _decoded(entry: dict) -> tuple[dict, str]:
    description = _object(entry.get("parameter_description", {}))
    raw = (
        "omitted"
        if description.get("reply_hex") or description.get("raw_description_hex")
        else ("unknown")
    )
    return {
        "type": _choice(description.get("type"), CODECS),
        "min": _numeric(description.get("min")),
        "max": _numeric(description.get("max")),
        "step": _numeric(description.get("step")),
        "width": _numeric(description.get("width")),
        "qualification": _choice(description.get("qualification"), QUALIFICATIONS),
        "step_qualification": _choice(
            description.get("step_qualification"), frozenset({"decoded", "unknown"})
        ),
        "codec_provenance": _choice(
            description.get("codec_provenance"),
            frozenset({"selector_qualified", "length_inferred"}),
        ),
        "evidence_grade": _choice(description.get("evidence_grade"), GRADES, "Unknown"),
    }, raw


def export_observations(artifact: object) -> dict:
    """Project an artifact through fixed field and scalar-value allowlists."""
    source = _object(artifact)
    if source.get("schema_version") not in ("2.3", "2.4"):
        raise ValueError("Expected an operations-first 2.3/2.4 scan artifact")
    operations = _object(source.get("operations"))
    identity = _object(_object(source.get("meta", {})).get("identity", {}))
    observations = []
    seen = set()
    for op, operation in operations.items():
        opcode = _selector(op, 2)
        for gg, group in _object(_object(operation).get("groups", {})).items():
            group_key = _selector(gg, 2)
            for ii, instance in _object(_object(group).get("instances", {})).items():
                instance_key = _selector(ii, 2)
                for rr, value in _object(_object(instance).get("registers", {})).items():
                    register = _selector(rr, 4)
                    selector = (opcode, group_key, instance_key, register)
                    if selector in seen:
                        raise ValueError("Duplicate canonical selector")
                    seen.add(selector)
                    entry = _object(value)
                    if "read_opcode" in entry and _selector(entry["read_opcode"], 2) != opcode:
                        raise ValueError("Conflicting register opcode")
                    decoded, raw = _decoded(entry)
                    observations.append(
                        {
                            "selector": dict(
                                zip(
                                    ("opcode", "group", "instance", "register"),
                                    selector,
                                    strict=True,
                                )
                            ),
                            "evidence_grade": _choice(
                                entry.get("evidence_grade"), GRADES, "Unknown"
                            ),
                            "response_state": _choice(entry.get("response_state"), STATES),
                            "raw_description": raw,
                            "decoded_observation": decoded,
                        }
                    )
    observations.sort(key=lambda row: tuple(row["selector"].values()))
    return {
        "schema_version": "controller-observations/1",
        "kind": "observation-only",
        "native_profile_input": False,
        "write_bound_evidence": False,
        "qualification": "unknown",
        "family": _choice(identity.get("protocol_family"), frozenset({"VRC700", "VRC720"})),
        "current_values": "omitted",
        "raw_descriptions": "omitted",
        "observations": observations,
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path, help="Existing offline operations-first JSON scan")
    args = parser.parse_args()
    try:
        source = json.loads(
            args.artifact.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
        output = json.dumps(export_observations(source), sort_keys=True, indent=2, allow_nan=False)
    except (OSError, ValueError, RecursionError):
        # Do not echo paths, malformed source text or arbitrary metadata to stderr.
        parser.exit(2, "Observation export failed: unreadable or malformed artifact\n")
    sys.stdout.write(output + "\n")


if __name__ == "__main__":
    main()
