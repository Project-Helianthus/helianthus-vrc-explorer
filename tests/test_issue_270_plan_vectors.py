from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from helianthus_vrc_explorer.scanner.plan import estimate_register_requests, make_plan_key
from helianthus_vrc_explorer.scanner.scan_policy import parse_scan_plan

VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "b524_scan_plan_v1_cases.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS["accepted"], ids=lambda case: case["name"])
def test_published_positive_plan_vectors(case: dict[str, Any]) -> None:
    plan = parse_scan_plan(case["input"])
    assert estimate_register_requests(plan) == case["expected_requests"]
    if "normalized" in case:
        expected = case["normalized"]
        row = plan[make_plan_key(expected["group"], expected["opcode"])]
        assert row.instances == tuple(expected["instances"])
        assert row.registers == tuple(expected["registers"])


@pytest.mark.parametrize("case", VECTORS["rejected"], ids=lambda case: case["name"])
def test_published_negative_plan_vectors(case: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=case["error"]):
        parse_scan_plan(case["input"])
