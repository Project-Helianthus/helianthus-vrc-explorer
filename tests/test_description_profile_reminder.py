"""Wording of the description-profile reminder and the Browser remote-description line.

A remote status row is identified by four fields. Each is varied independently in
`test_each_row_field_reaches_the_description`, and each variation fails against the
production mutation named next to it:

- group: label built without the group, or with a fixed group
- instance: label built without the instance, or with a fixed instance
- designation: label drops the designation, or reads the wrong artifact key
- status: the status value is not printed, or printed as a constant
"""

from __future__ import annotations

import struct
from copy import deepcopy
from importlib import resources
from io import StringIO
from typing import Any

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.schema.description_profile_reminder import (
    compose_description_profile_reminder,
    controller_profile_known,
    describe_non_exact_remote_rows,
    remote_exact_counts,
    remote_rows_with_designation,
)
from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.ui.browse_textual import (
    _browse_help_text,
    _build_identity_header_renderable,
)
from helianthus_vrc_explorer.ui.live import NullScanObserver
from tests.test_effective_parameter_descriptions import _artifact

KNOWN = {"status": "exact", "profile_id": "basv2_sw0507_hw1704_api1", "device_class": "local"}
UNKNOWN = {"status": "unknown", "profile_id": None, "device_class": "local"}
PROFILE = "basv2_sw0507_hw1704_api1"


def row(group: str, instance: str, status: str, **extra: Any) -> dict[str, Any]:
    profile_id = None if extra.pop("controller_unknown", False) else PROFILE
    return {
        "group": group,
        "instance": instance,
        "status": status,
        "profile_id": profile_id,
        "device_class": "remote",
        **extra,
    }


EXACT_ROW = row("0x0a", "0x01", "exact")
NOT_OBSERVED = row("0x09", "0x01", "unqualified", designation="Radio Sensors VRC7xx")
NOT_IN_CATALOG = row("0x0a", "0x02", "unknown")


# --- composition -----------------------------------------------------------------------


def test_all_exact_needs_no_reminder() -> None:
    assert (
        compose_description_profile_reminder(KNOWN, [EXACT_ROW, row("0x0a", "0x03", "exact")])
        is None
    )
    assert compose_description_profile_reminder(KNOWN, []) is None


def test_not_observed_rows_are_named_and_get_the_full_advice() -> None:
    text = compose_description_profile_reminder(KNOWN, [EXACT_ROW, NOT_OBSERVED])

    assert text == (
        "Controller description profile is in the catalog; 1 of 2 remote descriptions are exact. "
        "Not exact: GG 0x09 II 0x01 (Radio Sensors VRC7xx) status unqualified, "
        "remote identity not observed. "
        "Use Full to observe the missing remote identity and read live writable descriptions "
        "within known bounds, then save/share JSON manually if useful."
    )


def test_not_in_catalog_rows_say_so_and_keep_only_the_share_advice() -> None:
    text = compose_description_profile_reminder(KNOWN, [EXACT_ROW, NOT_IN_CATALOG])

    assert text == (
        "Controller description profile is in the catalog; 1 of 2 remote descriptions are exact. "
        "Not exact: GG 0x0a II 0x02 status unknown, "
        "remote identity observed but not in the catalog. "
        "Save/share JSON manually if useful."
    )
    assert "Full" not in text


def test_mixed_rows_name_each_reason_and_give_both_advices() -> None:
    text = compose_description_profile_reminder(KNOWN, [NOT_OBSERVED, EXACT_ROW, NOT_IN_CATALOG])

    assert text is not None
    assert "1 of 3 remote descriptions are exact" in text
    assert (
        "GG 0x09 II 0x01 (Radio Sensors VRC7xx) status unqualified, remote identity not observed"
        in text
    )
    assert "GG 0x0a II 0x02 status unknown, remote identity observed but not in the catalog" in text
    assert "GG 0x0a II 0x01" not in text
    assert text.endswith(
        "Use Full to observe the missing remote identity and read live writable descriptions "
        "within known bounds, then save/share JSON manually if useful."
    )


def test_controller_unknown_is_stated_and_rows_are_not_called_unobserved() -> None:
    rows = [
        row("0x09", "0x01", "unknown", controller_unknown=True),
        row("0x0a", "0x01", "exact", controller_unknown=True),
    ]
    text = compose_description_profile_reminder(UNKNOWN, rows)

    assert text == (
        "Controller description profile is not in the catalog; 1 of 2 remote descriptions are "
        "exact. Not exact: GG 0x09 II 0x01 status unknown, controller profile not in the catalog. "
        "Use Full for live writable descriptions within known bounds, "
        "then save/share JSON manually if useful."
    )
    assert "identity" not in text


def test_controller_unknown_without_remote_rows_keeps_the_controller_advice() -> None:
    assert compose_description_profile_reminder(UNKNOWN, []) == (
        "Controller description profile is not in the catalog. "
        "Use Full for live writable descriptions within known bounds, "
        "then save/share JSON manually if useful."
    )
    assert compose_description_profile_reminder(None, []) is not None


def test_controller_in_catalog_but_not_exact_is_still_reported() -> None:
    status = {"status": "unqualified", "profile_id": PROFILE, "device_class": "local"}

    assert compose_description_profile_reminder(status, []) == (
        "Controller description profile is in the catalog but not exact. "
        "Save/share JSON manually if useful."
    )


def test_known_controller_never_produces_the_old_unknown_remote_sentence() -> None:
    for rows in ([NOT_OBSERVED], [NOT_IN_CATALOG], [NOT_OBSERVED, NOT_IN_CATALOG]):
        text = compose_description_profile_reminder(KNOWN, rows)
        assert text is not None
        assert "Unknown remote description profile" not in text
        assert "controller profile is not" not in text.lower()


def test_unrecognised_status_values_are_listed_without_the_full_advice() -> None:
    text = compose_description_profile_reminder(
        KNOWN, [row("0x0a", "0x01", "pending"), {"group": "0x0a", "instance": "0x02"}]
    )

    assert text is not None
    assert "GG 0x0a II 0x01 status pending, not exact" in text
    assert "GG 0x0a II 0x02 status missing, not exact" in text
    assert "Full" not in text


def test_controller_profile_known_follows_status_or_catalog_id_only() -> None:
    assert controller_profile_known(KNOWN) is True
    assert controller_profile_known({"status": "exact"}) is True
    assert controller_profile_known({"status": "unknown", "profile_id": PROFILE}) is True
    assert controller_profile_known(UNKNOWN) is False
    assert controller_profile_known({}) is False
    assert controller_profile_known(None) is False


def test_remote_exact_counts_ignore_malformed_rows() -> None:
    rows: list[object] = [EXACT_ROW, NOT_OBSERVED, "garbage", None, {"status": "exact"}]
    assert remote_exact_counts(rows) == (2, 3)
    assert remote_exact_counts([]) == (0, 0)


@pytest.mark.parametrize(
    ("field", "varied", "old_token", "new_token"),
    [
        ("group", "0x0b", "GG 0x09 ", "GG 0x0b "),
        ("instance", "0x05", " II 0x01", " II 0x05"),
        ("designation", "Mixer", "(Radio Sensors VRC7xx)", "(Mixer)"),
        ("status", "unknown", "status unqualified", "status unknown"),
    ],
)
def test_each_row_field_reaches_the_description(
    field: str, varied: str, old_token: str, new_token: str
) -> None:
    changed = {**NOT_OBSERVED, field: varied}
    base_line = describe_non_exact_remote_rows(KNOWN, [NOT_OBSERVED])[0]
    changed_line = describe_non_exact_remote_rows(KNOWN, [changed])[0]

    assert old_token in base_line
    assert old_token not in changed_line
    assert new_token in changed_line
    # The other three fields are untouched by the variation.
    for other, value in NOT_OBSERVED.items():
        if other in {"group", "instance", "designation", "status"} and other != field:
            assert str(value) in changed_line


# --- designation lookup ----------------------------------------------------------------


def _artifact_with_remote_groups() -> dict[str, Any]:
    return {
        "operations": {
            "0x06": {
                "groups": {
                    "0x09": {
                        "name": "Radio Sensors VRC7xx",
                        "instances": {"0x01": {"present": True}, "0x02": {"designation": "Hall"}},
                    },
                    "0x0A": {"name": "Unknown", "instances": {"0x01": {}}},
                }
            }
        }
    }


def test_designation_comes_from_the_instance_then_the_group_name() -> None:
    artifact = _artifact_with_remote_groups()
    stored = [
        row("0x09", "0x01", "unqualified"),
        row("0x09", "0x02", "unqualified"),
        row("0x0a", "0x01", "unqualified"),
        row("0x0c", "0x01", "unqualified"),
    ]
    snapshot = deepcopy(stored)

    annotated = remote_rows_with_designation(artifact, stored)

    assert [item.get("designation") for item in annotated] == [
        "Radio Sensors VRC7xx",
        "Hall",
        None,  # the scanner's "Unknown" group placeholder is not a designation
        None,
    ]
    assert stored == snapshot  # the stored meta rows are not modified
    assert "designation" not in stored[0]


def test_existing_designation_on_a_row_is_kept_and_garbage_rows_are_dropped() -> None:
    artifact = _artifact_with_remote_groups()
    annotated = remote_rows_with_designation(
        artifact, [row("0x09", "0x01", "unqualified", designation="Kept"), "garbage", None]
    )
    assert [item["designation"] for item in annotated] == ["Kept"]


# --- Browser header and help ------------------------------------------------------------


def _identity_artifact(rows: object | None) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "identity": {
            "device_id": "BASV0",
            "hw": "8803",
            "manufacturer": "0xB5",
            "model": "n/a",
        }
    }
    if rows is not None:
        meta["description_remote_profile_statuses"] = rows
    return {"schema_version": "2.3", "meta": meta, "operations": {}}


def _header_text(artifact: dict[str, Any]) -> str:
    renderable = _build_identity_header_renderable(artifact)
    if renderable is None:
        return ""
    output = StringIO()
    Console(file=output, force_terminal=False, width=140).print(renderable)
    return output.getvalue()


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ([EXACT_ROW, NOT_OBSERVED, NOT_IN_CATALOG], "remote descriptions: 1 of 3 exact"),
        ([EXACT_ROW, row("0x0a", "0x02", "exact")], "remote descriptions: 2 of 2 exact"),
        ([NOT_OBSERVED], "remote descriptions: 0 of 1 exact"),
        ([EXACT_ROW, "garbage", None], "remote descriptions: 1 of 1 exact"),
    ],
)
def test_header_shows_how_many_remote_descriptions_are_exact(
    rows: list[object], expected: str
) -> None:
    artifact = _identity_artifact(rows)
    baseline = deepcopy(artifact)

    text = _header_text(artifact)

    assert expected in text
    assert "Profile" in text  # the identity rows are still shown
    assert artifact == baseline


@pytest.mark.parametrize("rows", [None, [], "not a list", ["garbage"]])
def test_header_has_no_remote_line_without_remote_rows(rows: object) -> None:
    assert "remote descriptions" not in _header_text(_identity_artifact(rows))


def test_header_shows_the_remote_line_even_without_a_recognised_profile() -> None:
    artifact = _identity_artifact([EXACT_ROW, NOT_OBSERVED])
    artifact["meta"]["identity"]["hw"] = "9999"

    text = _header_text(artifact)

    assert "remote descriptions: 1 of 2 exact" in text
    assert "Profile" not in text
    assert _header_text(_identity_artifact(None) | {"meta": {"identity": {"hw": "9999"}}}) == ""


def test_help_explains_the_line_in_one_sentence_and_lists_non_exact_rows() -> None:
    artifact = _artifact()
    artifact["meta"]["description_remote_profile_statuses"] = [
        EXACT_ROW,
        NOT_OBSERVED,
        NOT_IN_CATALOG,
    ]
    artifact["operations"]["0x06"] = {
        "groups": {"0x09": {"name": "Radio Sensors VRC7xx", "instances": {"0x01": {}}}}
    }

    help_text = _browse_help_text(artifact)

    assert (
        "remote descriptions: N of M exact counts the remote devices whose identity is in the "
        "bundled catalog; it says nothing about the controller profile." in help_text
    )
    assert "Not exact:" in help_text
    assert (
        "- GG 0x09 II 0x01 (Radio Sensors VRC7xx) status unqualified, remote identity not observed"
        in help_text
    )
    assert (
        "- GG 0x0a II 0x02 status unknown, remote identity observed but not in the catalog"
        in help_text
    )
    assert "GG 0x0a II 0x01" not in help_text
    assert "q quit" in help_text


def test_help_without_remote_rows_has_only_the_sentence() -> None:
    for artifact in (None, _artifact(), {"meta": {"description_remote_profile_statuses": []}}):
        help_text = _browse_help_text(artifact)
        assert "remote descriptions: N of M exact" in help_text
        assert "Not exact" not in help_text


def test_help_caps_a_long_list_and_points_to_the_stored_rows() -> None:
    artifact = _artifact()
    artifact["meta"]["description_remote_profile_statuses"] = [
        row("0x09", f"0x{ii:02x}", "unqualified") for ii in range(1, 9)
    ]

    help_text = _browse_help_text(artifact)

    assert "- GG 0x09 II 0x06 " in help_text
    assert "- GG 0x09 II 0x07 " not in help_text
    assert "- and 2 more in meta.description_remote_profile_statuses" in help_text


# --- scanner wiring --------------------------------------------------------------------

IDENTITY = {
    "eid": "BASV2",
    "device_id": "BASV2",
    "sw": "0507",
    "hw": "1704",
    "manufacturer": "0xb5",
}
# (group, instance) -> (class byte, firmware bytes) observed from the synthetic remote devices.
REMOTE_IDENTITY = {
    (0x0A, 1): (b"\x35", bytes.fromhex("021100")),
    (0x0A, 2): (b"\x35", bytes.fromhex("991100")),
}


class SyntheticRegulator(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:
        if payload[0] == 0x00:
            return struct.pack("<f", 1.0)
        if payload[0] in (0x02, 0x06):
            group, instance = payload[2], payload[3]
            head = bytes((3, group)) + payload[4:6]
            register = int.from_bytes(payload[4:6], "little")
            observed = REMOTE_IDENTITY.get((group, instance))
            if payload[0] == 0x06 and observed is not None and register in (2, 4):
                return head + observed[0 if register == 2 else 1]
            return head + struct.pack("<f", 1)
        return b""


class LogObserver(NullScanObserver):
    def __init__(self) -> None:
        super().__init__()
        self.warnings: list[str] = []

    def log(self, message: str, *, level: str = "info") -> None:
        if level == "warn":
            self.warnings.append(message)


def _scan(plan: dict, identity: dict[str, str]) -> tuple[dict[str, Any], list[str]]:
    resource = resources.files("helianthus_vrc_explorer.data").joinpath(
        "myvaillant_register_map.csv"
    )
    with resources.as_file(resource) as path:
        myvaillant_map = MyvaillantRegisterMap.from_path(path)
    observer = LogObserver()
    artifact = scan_b524(
        SyntheticRegulator(),
        dst=0x15,
        planner_preset="custom",
        explicit_plan=plan,
        observer=observer,
        operation_identity=identity,
        myvaillant_map=myvaillant_map,
    )
    reminders = [w for w in observer.warnings if "description profile" in w.lower()]
    return artifact, reminders


def _remote_plan(*devices: tuple[int, tuple[int, ...]]) -> dict:
    return {
        make_plan_key(group, 6): GroupScanPlan(
            group=group, opcode=6, rr_max=9, instances=instances, registers=(2, 4, 9)
        )
        for group, instances in devices
    }


def test_scan_names_the_non_exact_remote_rows_once_with_their_reason() -> None:
    artifact, reminders = _scan(_remote_plan((0x09, (1,)), (0x0A, (1, 2))), IDENTITY)

    statuses = artifact["meta"]["description_remote_profile_statuses"]
    assert {(r["group"], r["instance"]): r["status"] for r in statuses} == {
        ("0x09", "0x01"): "unqualified",
        ("0x0a", "0x01"): "exact",
        ("0x0a", "0x02"): "unknown",
    }
    # Stored rows keep exactly their existing keys.
    assert all(
        set(r) == {"group", "instance", "status", "profile_id", "device_class"} for r in statuses
    )
    assert len(reminders) == 1
    text = reminders[0]
    assert text.startswith("Controller description profile is in the catalog; 1 of 3 remote")
    assert "GG 0x09 II 0x01 status unqualified, remote identity not observed" in text
    assert "GG 0x0a II 0x02 status unknown, remote identity observed but not in the catalog" in text
    assert "GG 0x0a II 0x01" not in text
    assert "Unknown remote description profile" not in text

    reminder_meta = artifact["meta"]["description_profile_reminder"]
    assert reminder_meta == {
        "shown_once": True,
        "recommendation": "full_within_known_scope",
        "sharing": "save_and_share_json_manually",
        "automatic_upload": False,
        "summary": text,
    }


def test_scan_with_only_observed_unlisted_remote_identity_gives_no_full_advice() -> None:
    artifact, reminders = _scan(_remote_plan((0x0A, (2,))), IDENTITY)

    assert [r["status"] for r in artifact["meta"]["description_remote_profile_statuses"]] == [
        "unknown"
    ]
    assert len(reminders) == 1
    assert "Full" not in reminders[0]
    assert reminders[0].endswith("Save/share JSON manually if useful.")


def test_scan_with_all_remote_rows_exact_logs_no_reminder() -> None:
    artifact, reminders = _scan(_remote_plan((0x0A, (1,))), IDENTITY)

    assert [r["status"] for r in artifact["meta"]["description_remote_profile_statuses"]] == [
        "exact"
    ]
    assert reminders == []
    assert "description_profile_reminder" not in artifact["meta"]


def test_scan_with_unknown_controller_logs_one_controller_level_reminder() -> None:
    artifact, reminders = _scan(
        _remote_plan((0x09, (1,)), (0x0A, (1,))), {**IDENTITY, "hw": "9999"}
    )

    assert len(reminders) == 1  # shown once: the remote stage does not repeat it
    assert reminders[0] == (
        "Controller description profile is not in the catalog. "
        "Use Full for live writable descriptions within known bounds, "
        "then save/share JSON manually if useful."
    )
    assert artifact["meta"]["description_profile_reminder"]["summary"] == reminders[0]
