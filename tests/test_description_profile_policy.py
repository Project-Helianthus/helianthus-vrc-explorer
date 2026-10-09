from helianthus_vrc_explorer.scanner.b524_orchestration import (
    _select_live_description_candidates,
)
from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.ui.planner_selection import default_description_policy
from test_effective_parameter_descriptions import _artifact


def _with_known_remote(artifact: dict) -> dict:
    artifact["operations"]["0x06"] = {
        "groups": {
            "0x0a": {
                "instances": {
                    "0x01": {
                        "registers": {
                            "0x0002": {
                                "type": "HEX:1",
                                "raw_hex": "35",
                                "value": "0x35",
                            },
                            "0x0004": {
                                "type": "FW",
                                "raw_hex": "021100",
                                "value": "02.11.00",
                            },
                            # Deliberately absent from the bundled GG0A rows.
                            "0x0009": {"type": None, "flags": 3},
                        }
                    }
                }
            }
        }
    }
    return artifact


def test_known_recommended_missing_codec_and_remote_row_schedule_zero_describes() -> None:
    artifact = _with_known_remote(_artifact())
    candidates = [
        DescriptionCandidate(0x02, 0x02, 0x00, 0x0009, None),
        DescriptionCandidate(0x06, 0x0A, 0x01, 0x0009, None),
    ]
    entries = {candidate.native_identity: {} for candidate in candidates}
    policy = default_description_policy("recommended", exact_profile_known=True)

    selected, selected_entries, remote_statuses = _select_live_description_candidates(
        artifact, candidates, entries, policy=policy
    )

    assert selected == []
    assert selected_entries == {}
    assert remote_statuses == [
        {
            "group": "0x0a",
            "instance": "0x01",
            "status": "exact",
            "profile_id": "basv2_sw0507_hw1704_api1",
            "device_class": "remote",
        }
    ]


def test_unknown_remote_firmware_forces_only_remote_writable_describe() -> None:
    artifact = _with_known_remote(_artifact())
    artifact["operations"]["0x06"]["groups"]["0x0a"]["instances"]["0x01"]["registers"][
        "0x0004"
    ].update(raw_hex="991100", value="99.11.00")
    candidates = [
        DescriptionCandidate(0x02, 0x02, 0x00, 0x0009, "EXP"),
        DescriptionCandidate(0x06, 0x0A, 0x01, 0x0009, None),
    ]
    entries = {candidate.native_identity: {} for candidate in candidates}
    policy = default_description_policy("recommended", exact_profile_known=True).with_override(
        "remote", "profile"
    )
    assert policy.remote_override is True

    selected, selected_entries, remote_statuses = _select_live_description_candidates(
        artifact, candidates, entries, policy=policy
    )

    assert selected == [candidates[1]]
    assert list(selected_entries) == [candidates[1].native_identity]
    assert remote_statuses[0]["status"] == "unknown"
