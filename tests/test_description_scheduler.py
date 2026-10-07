from __future__ import annotations

import pytest

from helianthus_vrc_explorer.scanner.description_scheduler import (
    DescriptionCandidate,
    schedule_descriptions,
)


def _candidate(
    read_opcode: int,
    group: int,
    instance: int,
    register: int,
    type_spec: str | None = "UIN",
) -> DescriptionCandidate:
    return DescriptionCandidate(read_opcode, group, instance, register, type_spec)


def test_default_schedule_includes_every_eligible_parameter_in_both_families() -> None:
    candidates = [
        *(_candidate(0x02, 0x01, 0x00, register) for register in range(200)),
        *(_candidate(0x06, 0x09, 0x00, register) for register in range(200)),
    ]

    result = schedule_descriptions(candidates)

    assert len(result.scheduled) == 400
    assert sum(candidate.read_opcode == 0x02 for candidate in result.scheduled) == 200
    assert sum(candidate.read_opcode == 0x06 for candidate in result.scheduled) == 200
    assert result.family_counts[0x02].eligible == 200
    assert result.family_counts[0x02].skipped == 0
    assert result.family_counts[0x06].eligible == 200
    assert result.family_counts[0x06].skipped == 0


def test_unused_family_reservation_is_borrowed_and_odd_budget_favors_local() -> None:
    candidates = [
        _candidate(0x02, 0x01, 0x00, 0),
        *(_candidate(0x06, 0x09, 0x00, register) for register in range(10)),
    ]

    result = schedule_descriptions(candidates, budget=5)

    assert [candidate.read_opcode for candidate in result.scheduled] == [
        0x02,
        0x06,
        0x06,
        0x06,
        0x06,
    ]
    assert result.family_counts[0x02].scheduled == 1
    assert result.family_counts[0x06].scheduled == 4

    balanced = schedule_descriptions(
        [
            *(_candidate(0x02, 0x01, 0x00, register) for register in range(10)),
            *(_candidate(0x06, 0x09, 0x00, register) for register in range(10)),
        ],
        budget=5,
    )
    assert balanced.family_counts[0x02].scheduled == 3
    assert balanced.family_counts[0x06].scheduled == 2


def test_family_schedule_round_robins_namespaces_with_stable_rr_order() -> None:
    candidates = [
        _candidate(0x02, 0x02, 0x01, 3),
        _candidate(0x02, 0x01, 0x00, 2),
        _candidate(0x02, 0x02, 0x01, 1),
        _candidate(0x02, 0x01, 0x00, 0),
        _candidate(0x02, 0x03, 0x00, 4),
    ]

    result = schedule_descriptions(candidates, budget=5)

    assert [
        (candidate.group, candidate.instance, candidate.register) for candidate in result.scheduled
    ] == [
        (0x01, 0x00, 0),
        (0x02, 0x01, 1),
        (0x03, 0x00, 4),
        (0x01, 0x00, 2),
        (0x02, 0x01, 3),
    ]


def test_native_identity_is_deduplicated_and_codec_conflict_becomes_unknown() -> None:
    candidates = [
        _candidate(0x02, 0x02, 0x01, 0x1234, "UIN"),
        _candidate(0x02, 0x02, 0x01, 0x1234, "uin"),
        _candidate(0x02, 0x02, 0x01, 0x1234, "EXP"),
        _candidate(0x06, 0x02, 0x01, 0x1234, "UIN"),
    ]

    result = schedule_descriptions(candidates, budget=4)

    assert result.scheduled == (
        _candidate(0x02, 0x02, 0x01, 0x1234, None),
        _candidate(0x06, 0x02, 0x01, 0x1234, "UIN"),
    )
    assert result.family_counts[0x02].eligible == 1
    assert result.family_counts[0x06].eligible == 1


def test_budget_skipped_lists_candidates_in_the_same_deterministic_order() -> None:
    candidates = [
        _candidate(0x02, 0x01, 0x00, 0),
        _candidate(0x02, 0x01, 0x00, 1),
        _candidate(0x02, 0x02, 0x00, 0),
        _candidate(0x06, 0x09, 0x00, 0),
        _candidate(0x06, 0x09, 0x00, 1),
    ]

    result = schedule_descriptions(candidates, budget=2)

    assert result.scheduled == (candidates[0], candidates[3])
    assert result.budget_skipped == (candidates[2], candidates[1], candidates[4])


@pytest.mark.parametrize("budget", [-1, True, 1.5])
def test_invalid_budget_is_rejected(budget: object) -> None:
    with pytest.raises(ValueError):
        schedule_descriptions([], budget=budget)  # type: ignore[arg-type]
