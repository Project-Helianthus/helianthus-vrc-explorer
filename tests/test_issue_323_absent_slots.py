"""Absent remote slots must not count as non-exact devices (issue 323, change A).

A Full scan probes every declared remote slot, so a small installation stores many rows
for slots that hold no device. Those rows are `absent`: kept in the stored rows, but left
out of the exact count, the reminder and the Full advice. The fixture inventory is the
sanitized exporter output of one such scan (13 groups x 8 slots = 104 remote slots, six
of them connected).

Identity under test and the production mutation each variation catches:

Remote slot presence (`remote_slot_not_connected`, used by `description_catalog_status`):
- connection_state: "not_connected" is absent; "connected", "unknown" and a missing state
  are not. Catches treating any non-connected state, or an unread probe, as absent.
- present: a probe that says present=True is never absent, even with a stale state.
  Catches deciding from `connection_state` alone.
- group, instance: a probe stored under another group or instance does not make this slot
  absent. Catches looking the probe up with a fixed or wrong key.

Present device identity (catalogue match for an exact remote row):
- group: the same class/firmware in a group the catalogue does not list is unknown.
  Catches matching on class and firmware only.
- device class, device firmware: either one changed is unknown. Catches matching on a
  single field.
- instance: another instance of a catalogued group/class/firmware stays exact. Catches
  requiring the observed instance.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from io import StringIO
from typing import Any

import pytest
from rich.console import Console

from helianthus_vrc_explorer.schema.description_profile_reminder import (
    ABSENT,
    compose_description_profile_reminder,
    remote_absent_count,
    remote_exact_counts,
    remote_rows_need_reminder,
    remote_rows_with_designation,
    remote_rows_with_presence,
    remote_slot_not_connected,
)
from helianthus_vrc_explorer.schema.parameter_descriptions import description_catalog_status
from helianthus_vrc_explorer.ui.browse_textual import (
    _browse_help_text,
    _build_identity_header_renderable,
)
from helianthus_vrc_explorer.ui.live import NullScanObserver
from tests.basv2_full_scan import (
    PRESENT_DEVICES,
    PROFILE_ID,
    remote_artifact,
    remote_slots,
    remote_status_rows,
    scan,
)

CONTROLLER = {"status": "exact", "profile_id": PROFILE_ID, "device_class": "local"}
ROW_KEYS = {"group", "instance", "status", "profile_id", "device_class"}
BOILER = ("0x01", "0x01")
THERMOSTAT = ("0x0a", "0x01")
CLOCK = ("0x0e", "0x01")


def _header_text(artifact: dict[str, Any]) -> str:
    renderable = _build_identity_header_renderable(artifact)
    assert renderable is not None
    output = StringIO()
    Console(file=output, force_terminal=False, width=140).print(renderable)
    return output.getvalue()


def _with_rows(artifact: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    artifact["meta"]["description_remote_profile_statuses"] = rows
    return artifact


def _status(artifact: dict[str, Any], slot: tuple[str, str]) -> str:
    selector = {
        "read_opcode": "0x06",
        "group": slot[0],
        "instance": slot[1],
        "register": "0x0009",
    }
    return str(description_catalog_status(artifact, selector)["status"])


# --- the 104-row case -------------------------------------------------------------------


def test_the_fixture_reproduces_the_104_remote_slots() -> None:
    slots = remote_slots()
    assert len(slots) == 104
    assert {group for group, _ in slots} == {
        "0x01", "0x02", "0x03", "0x05", "0x06", "0x07", "0x08",
        "0x09", "0x0a", "0x0b", "0x0c", "0x0e", "0x0f",
    }  # fmt: skip
    assert {instance for _, instance in slots} == {f"0x0{ii}" for ii in range(1, 9)}
    assert set(PRESENT_DEVICES) <= slots


def test_stored_rows_keep_every_slot_and_mark_the_empty_ones_absent() -> None:
    rows = remote_status_rows(remote_artifact())

    assert len(rows) == 104
    assert Counter(row["status"] for row in rows) == {"exact": 6, ABSENT: 98}
    assert {(row["group"], row["instance"]) for row in rows} == remote_slots()
    assert {(r["group"], r["instance"]) for r in rows if r["status"] == "exact"} == set(
        PRESENT_DEVICES
    )
    # Absent rows keep the same keys and the controller profile id as every other row.
    assert all(set(row) == ROW_KEYS for row in rows)
    assert {row["profile_id"] for row in rows} == {PROFILE_ID}
    assert {row["device_class"] for row in rows} == {"remote"}


def test_reminder_is_silent_and_counts_present_devices_only() -> None:
    rows = remote_status_rows(remote_artifact())

    assert compose_description_profile_reminder(CONTROLLER, rows) is None
    assert remote_exact_counts(rows) == (6, 6)
    assert remote_absent_count(rows) == 98
    assert remote_rows_need_reminder(rows) is False


def test_header_counts_present_devices_and_help_notes_the_empty_slots() -> None:
    artifact = remote_artifact()
    rows = remote_status_rows(artifact)
    _with_rows(artifact, rows)
    stored = deepcopy(artifact)

    text = _header_text(artifact)

    assert "remote descriptions: 6 of 6 exact" in text
    assert "104" not in text
    help_text = _browse_help_text(artifact)
    assert "98 empty remote slot(s), with no device connected, are stored as absent" in help_text
    assert "Not exact" not in help_text
    assert artifact == stored  # the display never rewrites the stored rows


def test_a_full_scan_stores_absent_rows_and_logs_no_reminder() -> None:
    class Observer(NullScanObserver):
        def __init__(self) -> None:
            super().__init__()
            self.warnings: list[str] = []

        def log(self, message: str, *, level: str = "info") -> None:
            if level == "warn":
                self.warnings.append(message)

    observer = Observer()
    artifact, _ = scan("full", observer=observer)

    meta = artifact["meta"]
    rows = meta["description_remote_profile_statuses"]
    assert Counter(row["status"] for row in rows) == {"exact": 6, ABSENT: 98}
    assert {(row["group"], row["instance"]) for row in rows} == remote_slots()
    assert [w for w in observer.warnings if "description profile" in w.lower()] == []
    assert "description_profile_reminder" not in meta
    assert "remote descriptions: 6 of 6 exact" in _header_text(artifact)


# --- a present device that is not exact keeps its advice ---------------------------------


def _fire(devices: dict, **kwargs: Any) -> tuple[list[dict[str, Any]], str | None]:
    rows = remote_status_rows(remote_artifact(devices, **kwargs))
    return rows, compose_description_profile_reminder(CONTROLLER, rows)


def test_a_present_device_with_an_observed_but_unlisted_identity_keeps_only_the_share_advice():
    devices = {**PRESENT_DEVICES, THERMOSTAT: ("35", "991100")}
    rows, text = _fire(devices)

    assert {row["status"] for row in rows if (row["group"], row["instance"]) == THERMOSTAT} == {
        "unknown"
    }
    assert Counter(row["status"] for row in rows) == {"exact": 5, "unknown": 1, ABSENT: 98}
    assert text == (
        "Controller description profile is in the catalog; 5 of 6 remote descriptions are "
        "exact. Not exact: GG 0x0a II 0x01 status unknown, remote identity observed but not "
        "in the catalog. Save/share JSON manually if useful."
    )
    assert "Full" not in text
    assert "absent" not in text.lower()
    assert remote_rows_need_reminder(rows) is True


def test_a_present_device_with_unreadable_identity_keeps_the_full_advice() -> None:
    rows, text = _fire(PRESENT_DEVICES, unreadable_identity={CLOCK})

    assert {row["status"] for row in rows if (row["group"], row["instance"]) == CLOCK} == {
        "unqualified"
    }
    assert text is not None
    assert "5 of 6 remote descriptions are exact" in text
    assert "GG 0x0e II 0x01 status unqualified, remote identity not observed" in text
    assert text.endswith(
        "Use Full to observe the missing remote identity and read live writable descriptions "
        "within known bounds, then save/share JSON manually if useful."
    )
    assert "GG 0x01" not in text and "98" not in text


def test_an_unreadable_presence_probe_is_neither_absent_nor_silent() -> None:
    rows, text = _fire(PRESENT_DEVICES, undecided_presence={("0x02", "0x03")})

    undecided = [r for r in rows if (r["group"], r["instance"]) == ("0x02", "0x03")]
    assert [r["status"] for r in undecided] == ["unqualified"]
    assert Counter(row["status"] for row in rows) == {"exact": 6, "unqualified": 1, ABSENT: 97}
    assert text is not None
    assert "GG 0x02 II 0x03 status unqualified, remote identity not observed" in text
    assert "6 of 7 remote descriptions are exact" in text
    assert "Use Full" in text


@pytest.mark.parametrize(
    ("field", "moved", "expected"),
    [
        # Catches matching on class and firmware without the group.
        ("group", ("0x0b", "0x01"), "unknown"),
        # Catches matching on the firmware alone.
        ("class", BOILER, "unknown"),
        # Catches matching on the class alone.
        ("firmware", BOILER, "unknown"),
        # Catches requiring the instance the reference installation happened to use.
        ("instance", ("0x01", "0x02"), "exact"),
    ],
)
def test_each_identity_field_decides_whether_a_present_device_is_exact(
    field: str, moved: tuple[str, str], expected: str
) -> None:
    # The boiler's group has no bundled description rows, so only the catalogue's remote
    # device observations can recognise it: the variations isolate that match.
    class_raw, firmware_raw = PRESENT_DEVICES[BOILER]
    if field == "class":
        class_raw = "09"
    if field == "firmware":
        firmware_raw = "0c0101"
    devices = {slot: ident for slot, ident in PRESENT_DEVICES.items() if slot != BOILER}
    devices[moved] = (class_raw, firmware_raw)

    rows = remote_status_rows(remote_artifact(devices))

    by_slot = {(r["group"], r["instance"]): r["status"] for r in rows}
    assert by_slot[moved] == expected
    if moved != BOILER:
        # The slot the boiler left is empty again, and is absent rather than unqualified.
        assert by_slot[BOILER] == ABSENT


# --- what makes a slot absent ------------------------------------------------------------


def _artifact_with_probe(probe: dict[str, Any] | None, *, group: str, instance: str) -> dict:
    artifact: dict[str, Any] = {"operations": {"0x06": {"groups": {}}}}
    if probe is not None:
        artifact["operations"]["0x06"]["groups"][group] = {"availability_probes": {instance: probe}}
    return artifact


@pytest.mark.parametrize(
    ("probe", "group", "instance", "absent"),
    [
        ({"present": False, "connection_state": "not_connected"}, "0x0a", "0x02", True),
        # connection_state
        ({"present": False, "connection_state": "connected"}, "0x0a", "0x02", False),
        ({"present": None, "connection_state": "unknown"}, "0x0a", "0x02", False),
        ({"present": False}, "0x0a", "0x02", False),
        # present
        ({"present": True, "connection_state": "not_connected"}, "0x0a", "0x02", False),
        # group and instance of the stored probe
        ({"present": False, "connection_state": "not_connected"}, "0x0b", "0x02", False),
        ({"present": False, "connection_state": "not_connected"}, "0x0a", "0x03", False),
        # no probe at all (a custom plan does not probe presence)
        (None, "0x0a", "0x02", False),
    ],
)
def test_only_a_clean_not_connected_probe_for_the_same_slot_makes_it_absent(
    probe: dict[str, Any] | None, group: str, instance: str, absent: bool
) -> None:
    artifact = _artifact_with_probe(probe, group=group, instance=instance)

    assert remote_slot_not_connected(artifact, "0x0a", "0x02") is absent


def test_absent_wins_over_identity_for_an_empty_slot_but_never_for_a_connected_one() -> None:
    artifact = remote_artifact()
    assert _status(artifact, ("0x02", "0x05")) == ABSENT
    assert _status(artifact, THERMOSTAT) == "exact"
    # Same slot, probe flipped to connected with the sentinel identity left in place.
    artifact["operations"]["0x06"]["groups"]["0x02"]["availability_probes"]["0x05"] = {
        "present": True,
        "connection_state": "connected",
    }
    assert _status(artifact, ("0x02", "0x05")) == "unqualified"


# --- artifacts stored before the status existed ------------------------------------------


def _legacy_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    """The rows the previous version stored: empty slots were `unqualified`."""

    unlisted = {BOILER, CLOCK, ("0x0f", "0x01")}
    status = {
        slot: "unknown"
        if slot in unlisted
        else "exact"
        if slot in PRESENT_DEVICES
        else "unqualified"
        for slot in remote_slots()
    }
    return [
        {
            "group": group,
            "instance": instance,
            "status": status[(group, instance)],
            "profile_id": PROFILE_ID,
            "device_class": "remote",
        }
        for group, instance in sorted(status)
    ]


def test_rows_stored_before_the_absent_status_are_relabelled_for_display_only() -> None:
    artifact = remote_artifact()
    legacy = _legacy_rows(artifact)
    assert Counter(row["status"] for row in legacy) == {"unqualified": 98, "unknown": 3, "exact": 3}
    _with_rows(artifact, legacy)
    stored = deepcopy(artifact)

    shown = remote_rows_with_presence(artifact, legacy)

    assert Counter(row["status"] for row in shown) == {ABSENT: 98, "unknown": 3, "exact": 3}
    assert remote_exact_counts(shown) == (3, 6)
    assert "remote descriptions: 3 of 6 exact" in _header_text(artifact)
    assert "104" not in _header_text(artifact)
    text = compose_description_profile_reminder(
        CONTROLLER, remote_rows_with_designation(artifact, shown)
    )
    assert text is not None
    assert text.startswith(
        "Controller description profile is in the catalog; 3 of 6 remote descriptions are exact."
    )
    for group in ("0x01", "0x0e", "0x0f"):
        assert f"GG {group} II 0x01 status unknown, remote identity observed" in text
    assert "unqualified" not in text and "Full" not in text
    help_text = _browse_help_text(artifact)
    assert "98 empty remote slot(s)" in help_text
    assert help_text.count("status unknown") == 3
    assert artifact == stored


def test_relabelling_never_turns_an_exact_row_or_an_undecided_slot_into_absent() -> None:
    artifact = remote_artifact(undecided_presence={("0x02", "0x03")})
    rows = [
        {"group": "0x0a", "instance": "0x01", "status": "exact"},
        {"group": "0x02", "instance": "0x03", "status": "unqualified"},
        {"group": "0x02", "instance": "0x04", "status": "unqualified"},
        {"group": "0x0a", "instance": "0x01", "status": "unknown"},
    ]
    # Even a not-connected probe leaves an exact row alone.
    artifact["operations"]["0x06"]["groups"]["0x0a"]["availability_probes"]["0x01"] = {
        "present": False,
        "connection_state": "not_connected",
    }

    shown = remote_rows_with_presence(artifact, rows)

    assert [row["status"] for row in shown] == ["exact", "unqualified", ABSENT, ABSENT]
    assert remote_rows_with_presence(artifact, ["garbage", None]) == []
