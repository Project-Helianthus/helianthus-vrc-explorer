"""Bundled installation observations for the BASV2 profile (issue 323, change B).

The catalogue entry of `basv2_sw0507_hw1704_api1` records what one reference installation
showed in a Full scan: per-group instance capacities and observed counts, and the present
remote devices with their class and firmware. They are installation observations, never
profile limits. They let a Recommended scan bound circuit and zone slots by the live
capacity, and a remote device in them is exact.

Keys under test and the production mutation each variation catches:

Observation lookup (`bundled_instance_observation`):
- profile id: BASV0, an unknown id and None return nothing. Catches reading the first
  profile that has a block instead of the scanned one.
- read opcode, group: the OP06 row of a group number never answers for the OP02 group with
  the same number, and vice versa. Catches a lookup that ignores the namespace.
- qualification: a block without the installation-observation qualification is ignored.
  Catches trusting an unqualified block as a plan.

Planner window (`run_b524_scan`, recommended preset):
- live capacity: readable and positive, it alone sets the circuit/zone window when the
  bundle records a capacity for the group; zero skips; unreadable, non-integer or negative
  keeps every declared slot. Catches letting a bundled number set, widen or zero a window.
- bundled capacity (0, 2, 3 or none): never changes the window when the live value is
  unreadable. Catches `max(bundled, live or 0)`.
- preset: Full audits every slot whatever the live and bundled capacity.

Remote device rows (`_remote_device_in_catalog`, via `description_catalog_status`):
- profile id: the same tuple under another controller profile is not recognised.
- group, class, firmware: see test_issue_323_absent_slots for the per-field variations.

Importer (`export_installation_observations`, `merge_installation_observations`):
- every exported field is allowlisted: a sentinel in each unread field must not appear.
- group row key (read opcode, group): a newer row replaces only the same OP/GG.
- device row key (group, instance, class, firmware): a device seen again with other
  firmware adds a row; the same device seen again changes nothing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from helianthus_vrc_explorer.schema import parameter_descriptions
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    INSTALLATION_OBSERVATION_QUALIFICATION,
    bundled_instance_observation,
    description_catalog_status,
    export_installation_observations,
    load_description_profile_catalog,
    merge_installation_observations,
)
from tests.basv2_full_scan import (
    PRESENT_DEVICES,
    PROFILE_ID,
    SYSTEM_INFORMATION,
    Regulator,
    local_slots,
    remote_artifact,
    scan,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "src/helianthus_vrc_explorer/data/b524_description_profiles.json"
IMPORTER = ROOT / "scripts/import_b524_descriptions.py"

# (read opcode, group) -> (semantics, capacity, expected, observed) as the Full scan saw them.
OBSERVED_GROUPS: dict[tuple[int, int], tuple[str, int | None, int | None, int]] = {
    (2, 0x02): ("capacity", 3, None, 2),  # circuits
    (2, 0x03): ("capacity", 3, None, 2),  # zones
    (2, 0x04): ("expected_population", None, 1, 1),  # solar circuit
    (2, 0x05): ("expected_population", None, 1, 1),  # solar cylinder
    (2, 0x08): ("expected_population", None, 0, 0),  # DeltaT
    (2, 0x09): ("expected_population", None, 0, 0),  # ventilation
    (6, 0x01): ("expected_population", None, 1, 1),
    (6, 0x02): ("expected_population", None, 0, 0),
    (6, 0x06): ("expected_population", None, 0, 0),
    (6, 0x07): ("expected_population", None, 0, 0),
    (6, 0x09): ("expected_population", None, 1, 1),
    (6, 0x0B): ("expected_population", None, 0, 0),
    (6, 0x0C): ("expected_population", None, 1, 1),
}


def _profile(catalog: dict[str, Any], profile_id: str = PROFILE_ID) -> dict[str, Any]:
    return next(row for row in catalog["profiles"] if row["id"] == profile_id)


# --- the catalogue entry ----------------------------------------------------------------


def test_catalogue_records_every_count_group_as_an_installation_observation() -> None:
    profile = _profile(load_description_profile_catalog())
    block = profile["instance_observations"]

    assert block["observed_instance_qualification"] == INSTALLATION_OBSERVATION_QUALIFICATION
    assert INSTALLATION_OBSERVATION_QUALIFICATION == "installation_observation_not_profile_limit"
    assert {
        (int(row["read_opcode"], 16), int(row["group"], 16)): (
            row["semantics"],
            row["capacity"],
            row["expected"],
            row["observed"],
        )
        for row in block["groups"]
    } == OBSERVED_GROUPS
    # The block does not restate profile limits: no RR bound, no slot range, no instance list.
    assert {key for row in block["groups"] for key in row} == {
        "read_opcode",
        "group",
        "identifier",
        "semantics",
        "capacity",
        "expected",
        "observed",
    }
    # The existing local circuit observation keeps its own qualification.
    assert profile["local_circuit_profile"]["observed_instance_qualification"] == (
        INSTALLATION_OBSERVATION_QUALIFICATION
    )


def test_catalogue_records_the_six_present_remote_devices_with_their_identity() -> None:
    block = _profile(load_description_profile_catalog())["remote_device_observations"]

    assert block["observed_instance_qualification"] == INSTALLATION_OBSERVATION_QUALIFICATION
    assert {
        (row["group"], row["instance"]): (row["device_class_raw"], row["device_firmware_raw"])
        for row in block["devices"]
    } == PRESENT_DEVICES
    assert {key for row in block["devices"] for key in row} == {
        "group",
        "instance",
        "device_class_raw",
        "device_firmware_raw",
    }


def test_other_profiles_carry_no_installation_observations() -> None:
    catalog = load_description_profile_catalog()
    for profile in catalog["profiles"]:
        if profile["id"] != PROFILE_ID:
            assert "instance_observations" not in profile
            assert "remote_device_observations" not in profile


@pytest.mark.parametrize(("opcode", "group"), sorted(OBSERVED_GROUPS))
def test_lookup_returns_the_observed_group(opcode: int, group: int) -> None:
    semantics, capacity, expected, observed = OBSERVED_GROUPS[(opcode, group)]

    assert bundled_instance_observation(PROFILE_ID, read_opcode=opcode, group=group) == {
        "semantics": semantics,
        "capacity": capacity,
        "expected": expected,
        "observed": observed,
    }


@pytest.mark.parametrize(
    ("profile_id", "opcode", "group"),
    [
        ("basv0_sw0217_hw8803_api1", 2, 0x02),  # another profile
        ("no_such_profile", 2, 0x02),
        (None, 2, 0x02),
        (PROFILE_ID, 6, 0x0A),  # a remote group without an OP00 count
        (PROFILE_ID, 6, 0x03),  # OP06 has no count for GG03 although OP02 has one
        (PROFILE_ID, 6, 0x04),  # OP02 GG04 has a count; OP06 GG04 does not
        (PROFILE_ID, 2, 0x01),  # native DHW is not an instanced group
        (PROFILE_ID, 2, 0x06),  # OP06 GG06 has a count; OP02 GG06 does not
        (PROFILE_ID, 0, 0x02),  # wrong namespace
    ],
)
def test_lookup_is_keyed_by_profile_namespace_and_group(
    profile_id: str | None, opcode: int, group: int
) -> None:
    assert bundled_instance_observation(profile_id, read_opcode=opcode, group=group) is None


def test_a_block_without_the_observation_qualification_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    catalog = load_description_profile_catalog()
    for key in ("instance_observations", "remote_device_observations"):
        _profile(catalog)[key]["observed_instance_qualification"] = "profile_limit"
    monkeypatch.setattr(parameter_descriptions, "load_description_profile_catalog", lambda: catalog)

    assert bundled_instance_observation(PROFILE_ID, read_opcode=2, group=0x02) is None
    artifact = remote_artifact()
    selector = {"read_opcode": "0x06", "group": "0x01", "instance": "0x01", "register": "0x0009"}
    assert description_catalog_status(artifact, selector)["status"] == "unknown"


def test_malformed_rows_are_ignored_rather_than_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    catalog = load_description_profile_catalog()
    groups = _profile(catalog)["instance_observations"]["groups"]
    groups[0]["capacity"] = True  # a bool is not a count
    groups[1]["capacity"] = 999
    groups[2]["semantics"] = "profile_limit"
    monkeypatch.setattr(parameter_descriptions, "load_description_profile_catalog", lambda: catalog)

    first = bundled_instance_observation(PROFILE_ID, read_opcode=2, group=0x02)
    assert first is not None and first["capacity"] is None
    second = bundled_instance_observation(PROFILE_ID, read_opcode=2, group=0x03)
    assert second is not None and second["capacity"] is None
    assert bundled_instance_observation(PROFILE_ID, read_opcode=2, group=0x04) is None


def test_the_same_remote_tuple_under_another_controller_profile_is_not_recognised() -> None:
    artifact = remote_artifact()
    artifact["meta"]["identity"]["hw"] = "9999"  # not a catalogued controller
    selector = {"read_opcode": "0x06", "group": "0x0a", "instance": "0x01", "register": "0x0009"}

    assert description_catalog_status(artifact, selector)["status"] == "unknown"


# --- the importer reproduces the data ---------------------------------------------------


def test_exporting_a_recommended_scan_reproduces_the_catalogue_blocks() -> None:
    artifact, _ = scan("recommended")

    observations = export_installation_observations(artifact)

    profile = _profile(load_description_profile_catalog())
    assert observations["profile_id"] == PROFILE_ID
    assert observations["instance_observations"] == profile["instance_observations"]
    assert observations["remote_device_observations"] == profile["remote_device_observations"]


def test_exporting_requires_an_exact_catalogued_controller() -> None:
    artifact, _ = scan("recommended")
    artifact["meta"]["identity"]["hw"] = "9999"

    with pytest.raises(ValueError, match="exact catalogued controller profile"):
        export_installation_observations(artifact)


def test_export_skips_groups_whose_discovery_was_incomplete() -> None:
    artifact, _ = scan("recommended")
    artifact["meta"]["instance_counts"]["0x02:0x04"]["discovery_complete"] = False
    artifact["meta"]["instance_counts"]["0x02:0x04"]["observed"] = 0

    observations = export_installation_observations(artifact)

    keys = {
        (row["read_opcode"], row["group"])
        for row in observations["instance_observations"]["groups"]
    }
    assert ("0x02", "0x04") not in keys
    assert ("0x02", "0x05") in keys
    merged = merge_installation_observations(load_description_profile_catalog(), observations)
    assert (
        _profile(merged)["instance_observations"]
        == _profile(load_description_profile_catalog())["instance_observations"]
    )


def test_export_judges_a_legacy_row_without_the_flag_from_its_stored_probes() -> None:
    artifact, _ = scan("recommended")
    counts = artifact["meta"]["instance_counts"]
    for row in counts.values():
        row.pop("discovery_complete", None)
    complete = {
        (r["read_opcode"], r["group"])
        for r in export_installation_observations(artifact)["instance_observations"]["groups"]
    }
    assert ("0x02", "0x03") in complete

    probes = artifact["operations"]["0x02"]["groups"]["0x03"]["availability_probes"]
    first = next(iter(probes.values()))
    first["connection_state"] = "unknown"
    first["present"] = False
    counts["0x02:0x03"]["observed"] = 0
    kept = {
        (r["read_opcode"], r["group"])
        for r in export_installation_observations(artifact)["instance_observations"]["groups"]
    }
    assert ("0x02", "0x03") not in kept
    assert ("0x02", "0x02") in kept


def test_export_keeps_nothing_it_does_not_allowlist() -> None:
    artifact, _ = scan("recommended")
    sentinel = "PRIVATE_SENTINEL"
    meta = artifact["meta"]
    meta["identity"]["serial"] = sentinel
    meta["ebusd_host"] = sentinel
    meta["scan_timestamp"] = sentinel
    for row in meta["instance_counts"].values():
        row["serial"] = sentinel
        row["note"] = sentinel
    for group in artifact["operations"]["0x06"]["groups"].values():
        group["designation"] = sentinel
        for probe in group.get("availability_probes", {}).values():
            probe["raw_hex"] = sentinel
            probe["reply_hex"] = sentinel
        for instance in group["instances"].values():
            instance["designation"] = sentinel
            for register in instance["registers"].values():
                register["clock"] = sentinel
    # A text value in a numeric slot must drop the row, never be copied.
    meta["instance_counts"]["0x02:0x04"]["observed"] = sentinel
    meta["instance_counts"]["0x02:0x05"]["identifier"] = sentinel
    meta["instance_counts"]["0x02:0x08"]["semantics"] = sentinel

    observations = export_installation_observations(artifact)

    assert sentinel not in json.dumps(observations)
    groups = {
        (row["read_opcode"], row["group"]): row
        for row in observations["instance_observations"]["groups"]
    }
    assert ("0x02", "0x04") not in groups  # observed was text
    assert ("0x02", "0x08") not in groups  # semantics was text
    assert groups[("0x02", "0x05")]["identifier"] is None  # identifier was text, row kept


def test_a_connected_device_with_unreadable_identity_is_recorded_as_unknown() -> None:
    artifact, _ = scan("recommended")
    registers = artifact["operations"]["0x06"]["groups"]["0x0e"]["instances"]["0x01"]["registers"]
    registers["0x0004"] = {"type": "FWU", "value": None, "raw_hex": "ffffff", "error": "x"}

    devices = export_installation_observations(artifact)["remote_device_observations"]["devices"]

    clock = next(row for row in devices if row["group"] == "0x0e")
    assert clock == {
        "group": "0x0e",
        "instance": "0x01",
        "device_class_raw": "0f",
        "device_firmware_raw": None,
    }
    merged = merge_installation_observations(
        load_description_profile_catalog(), export_installation_observations(artifact)
    )
    block = _profile(merged)["remote_device_observations"]
    assert clock in block["devices"]  # recorded, and never matches a scanned device


# --- merging ----------------------------------------------------------------------------


def test_merging_the_same_observations_changes_nothing() -> None:
    catalog = load_description_profile_catalog()
    observations = export_installation_observations(scan("recommended")[0])

    merged = merge_installation_observations(catalog, observations)

    assert merged == catalog
    assert merge_installation_observations(merged, observations) == merged


def test_merge_touches_only_the_two_blocks_of_the_scanned_profile() -> None:
    catalog = load_description_profile_catalog()
    bare = deepcopy(catalog)
    for key in ("instance_observations", "remote_device_observations"):
        del _profile(bare)[key]
    observations = export_installation_observations(scan("recommended")[0])

    merged = merge_installation_observations(bare, observations)

    assert merged == catalog
    assert bare != catalog  # the input was not modified
    for key in ("controller", "bundle_signature", "local_circuit_profile", "profile", "id"):
        assert _profile(merged)[key] == _profile(catalog)[key]
    assert _profile(merged, "basv0_sw0217_hw8803_api1") == _profile(
        catalog, "basv0_sw0217_hw8803_api1"
    )


def test_a_newer_group_row_replaces_only_its_own_opcode_and_group() -> None:
    catalog = load_description_profile_catalog()
    observations = export_installation_observations(scan("recommended")[0])
    changed = deepcopy(observations)
    for row in changed["instance_observations"]["groups"]:
        if (row["read_opcode"], row["group"]) == ("0x02", "0x03"):
            row["capacity"], row["observed"] = 4, 3
    # A same-numbered group in the other namespace is a different row.
    changed["instance_observations"]["groups"] = [
        row
        for row in changed["instance_observations"]["groups"]
        if (row["read_opcode"], row["group"]) == ("0x02", "0x03")
    ]

    merged = merge_installation_observations(catalog, changed)

    rows = {
        (row["read_opcode"], row["group"]): row
        for row in _profile(merged)["instance_observations"]["groups"]
    }
    assert len(rows) == len(OBSERVED_GROUPS)
    assert (rows[("0x02", "0x03")]["capacity"], rows[("0x02", "0x03")]["observed"]) == (4, 3)
    assert rows[("0x02", "0x02")]["capacity"] == 3
    assert rows[("0x06", "0x01")]["observed"] == 1


@pytest.mark.parametrize(
    ("field", "value", "adds_a_row"),
    [
        ("device_firmware_raw", "0c0101", True),  # same slot, other firmware: a second variant
        ("device_class_raw", "09", True),
        ("instance", "0x02", True),  # a second instance of the same device
        ("group", "0x0b", True),
        (None, None, False),  # the same device again
    ],
)
def test_device_rows_are_keyed_by_group_instance_class_and_firmware(
    field: str | None, value: str | None, adds_a_row: bool
) -> None:
    catalog = load_description_profile_catalog()
    observations = export_installation_observations(scan("recommended")[0])
    boiler = next(
        row
        for row in observations["remote_device_observations"]["devices"]
        if row["group"] == "0x01"
    )
    again = dict(boiler)
    if field is not None:
        again[field] = value
    observations["remote_device_observations"]["devices"] = [again]

    merged = merge_installation_observations(catalog, observations)

    devices = _profile(merged)["remote_device_observations"]["devices"]
    assert len(devices) == len(PRESENT_DEVICES) + adds_a_row
    assert boiler in devices  # an earlier observation is never erased
    assert again in devices


def test_merge_refuses_an_unknown_profile_and_an_unqualified_existing_block() -> None:
    catalog = load_description_profile_catalog()
    observations = export_installation_observations(scan("recommended")[0])

    with pytest.raises(ValueError, match="not in the description profile catalog"):
        merge_installation_observations(catalog, {**observations, "profile_id": "other"})

    unqualified = deepcopy(catalog)
    _profile(unqualified)["instance_observations"]["observed_instance_qualification"] = "limit"
    with pytest.raises(ValueError, match="not qualified as observations"):
        merge_installation_observations(unqualified, observations)


def test_the_importer_cli_leaves_the_checked_in_catalogue_unchanged(tmp_path: Path) -> None:
    artifact, _ = scan("recommended")
    source = tmp_path / "scan.json"
    source.write_text(json.dumps(artifact), encoding="utf-8")
    original = source.read_bytes()
    catalog = tmp_path / "catalog.json"
    catalog.write_bytes(CATALOG_PATH.read_bytes())
    baseline = tmp_path / "baseline.json"
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}

    result = subprocess.run(
        [sys.executable, str(IMPORTER), str(source), str(baseline), "--catalog", str(catalog)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Merged installation observations" in result.stdout
    assert catalog.read_bytes() == CATALOG_PATH.read_bytes()  # the importer's fixed point
    assert source.read_bytes() == original  # the scan is read-only input
    assert json.loads(baseline.read_text(encoding="utf-8"))["descriptions"] == []


# --- the planner window ------------------------------------------------------------------


def test_the_fixture_exposes_the_blind_slots_a_recommended_scan_used_to_probe() -> None:
    assert local_slots("0x02") == set(range(10))
    assert local_slots("0x03") == set(range(11))


def test_recommended_does_not_truncate_the_slots_by_a_bundled_observation() -> None:
    artifact, regulator = scan("recommended")

    # The bundle documents one installation; another may occupy a slot beyond the first
    # `capacity` ones, so the declared probe window is retained.
    assert regulator.probed(artifact, "0x02", "0x02") == set(range(10))
    assert regulator.probed(artifact, "0x02", "0x03") == set(range(11))
    counts = artifact["meta"]["instance_counts"]
    for key in ("0x02:0x02", "0x02:0x03"):
        assert "planning_basis" not in counts[key]
        assert "slot_window" not in counts[key]
    assert (counts["0x02:0x02"]["observed"], counts["0x02:0x03"]["observed"]) == (2, 2)


def test_the_full_preset_still_audits_every_declared_slot() -> None:
    artifact, regulator = scan("full")

    assert regulator.probed(artifact, "0x02", "0x02") == set(range(10))
    assert regulator.probed(artifact, "0x02", "0x03") == set(range(11))
    assert "planning_basis" not in artifact["meta"]["instance_counts"]["0x02:0x02"]


def _bundle_with_capacity(capacity: int | None):
    """A stand-in catalogue lookup that records `capacity` for circuits and zones only."""

    def lookup(profile_id: object, *, read_opcode: int, group: int) -> dict | None:
        if capacity is None or (read_opcode, group) not in {(2, 0x02), (2, 0x03)}:
            return None
        return {"semantics": "capacity", "capacity": capacity, "expected": None, "observed": 2}

    return lookup


@pytest.mark.parametrize(
    ("live_capacity", "bundled", "circuits", "zones", "windowed"),
    [
        # Live unreadable + bundled 0: never an empty window; every declared slot.
        (None, 0, set(range(10)), set(range(11)), False),
        # Live unreadable + bundled 2: the bundled number is not a limit for this scan.
        (None, 2, set(range(10)), set(range(11)), False),
        # Live unreadable + no bundle: the profile default, as before this change.
        (None, None, set(range(10)), set(range(11)), False),
        # Live 2 + bundled 0: no bundled number shrinks the window either.
        (2.0, 0, set(range(10)), set(range(11)), False),
        # An unreadable value of another kind (not an integer, negative) is unreadable too.
        (2.5, 2, set(range(10)), set(range(11)), False),
        (-1.0, 2, set(range(10)), set(range(11)), False),
        # Live readable + no bundle: no window, as before this change.
        (2.0, None, set(range(10)), set(range(11)), False),
    ],
)
def test_a_bundled_capacity_never_becomes_an_empty_or_smaller_window_without_a_live_one(
    monkeypatch: pytest.MonkeyPatch,
    live_capacity: float | None,
    bundled: int | None,
    circuits: set[int],
    zones: set[int],
    windowed: bool,
) -> None:
    from helianthus_vrc_explorer.schema import parameter_descriptions

    monkeypatch.setattr(
        parameter_descriptions, "bundled_instance_observation", _bundle_with_capacity(bundled)
    )
    information = {k: v for k, v in SYSTEM_INFORMATION.items() if k not in (0, 1)}
    if live_capacity is not None:
        information |= {0: live_capacity, 1: live_capacity}

    artifact, regulator = scan("recommended", Regulator(system_information=information))

    assert regulator.probed(artifact, "0x02", "0x02") == circuits
    assert regulator.probed(artifact, "0x02", "0x03") == zones
    counts = artifact["meta"]["instance_counts"]
    for key in ("0x02:0x02", "0x02:0x03"):
        assert ("planning_basis" in counts[key]) is windowed
        assert ("slot_window" in counts[key]) is windowed


def test_the_full_preset_audits_every_slot_whatever_the_live_and_bundled_capacity() -> None:
    information = {**SYSTEM_INFORMATION, 0: 2.0, 1: 2.0}

    artifact, regulator = scan("full", Regulator(system_information=information))

    assert regulator.probed(artifact, "0x02", "0x02") == set(range(10))
    assert regulator.probed(artifact, "0x02", "0x03") == set(range(11))
    assert "slot_window" not in artifact["meta"]["instance_counts"]["0x02:0x02"]


def test_a_live_zero_capacity_is_not_widened_by_the_bundled_one() -> None:
    information = {**SYSTEM_INFORMATION, 0: 0.0, 1: 0.0}

    artifact, regulator = scan("recommended", Regulator(system_information=information))

    # No ordinary zone candidate; the circuits keep only what a zero capacity always kept
    # (the independent virtual slot), never a window from the bundled capacity of three.
    assert regulator.probed(artifact, "0x02", "0x03") == set()
    assert regulator.probed(artifact, "0x02", "0x02") <= {0, 9}
    assert "planning_basis" not in artifact["meta"]["instance_counts"]["0x02:0x03"]


def test_bundled_population_is_never_a_probe_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Live DeltaT (0x000b) and ventilation (0x0010) counts are unreadable. The bundled
    # population of the reference installation (zero) must not skip or cap the group.
    unreadable = {k: v for k, v in SYSTEM_INFORMATION.items() if k not in (11, 16)}

    artifact, regulator = scan("recommended", Regulator(system_information=unreadable))

    delta_t = artifact["meta"]["instance_counts"]["0x02:0x08"]
    assert "planning_basis" not in delta_t
    assert regulator.probed(artifact, "0x02", "0x08") == set(range(11))

    # A live count still drives the probe: one DeltaT slot is now expected.
    live = {**SYSTEM_INFORMATION, 11: 1.0}
    artifact, regulator = scan("recommended", Regulator(system_information=live))
    assert "planning_basis" not in artifact["meta"]["instance_counts"]["0x02:0x08"]
    assert regulator.probed(artifact, "0x02", "0x08") != set()


def test_merge_keeps_last_known_capacity_when_the_new_read_is_unavailable() -> None:
    catalog = load_description_profile_catalog()
    observations = export_installation_observations(scan("recommended")[0])
    unreadable = deepcopy(observations)
    for row in unreadable["instance_observations"]["groups"]:
        if (row["read_opcode"], row["group"]) == ("0x02", "0x02"):
            row["capacity"] = row["expected"] = None
    unreadable["instance_observations"]["groups"] = [
        row
        for row in unreadable["instance_observations"]["groups"]
        if (row["read_opcode"], row["group"]) == ("0x02", "0x02")
    ]

    merged = merge_installation_observations(catalog, unreadable)

    assert _profile(merged)["instance_observations"] == _profile(catalog)["instance_observations"]


def test_remote_devices_are_exact_on_the_next_scan_from_the_bundle_alone() -> None:
    artifact, _ = scan("recommended")

    # The Recommended scan reads the remote identity of each present device and the bundle
    # recognises it; no remote row needs a live Describe and no reminder is logged.
    assert "description_profile_reminder" not in artifact["meta"]
    for (group, instance), (class_raw, firmware_raw) in PRESENT_DEVICES.items():
        selector = {
            "read_opcode": "0x06",
            "group": group,
            "instance": instance,
            "register": "0x0009",
        }
        assert description_catalog_status(artifact, selector)["status"] == "exact"
        registers = artifact["operations"]["0x06"]["groups"][group]["instances"][instance][
            "registers"
        ]
        assert registers["0x0002"]["raw_hex"] == class_raw
        assert registers["0x0004"]["raw_hex"] == firmware_raw


def test_device_observation_without_bundled_description_still_schedules_describe() -> None:
    from helianthus_vrc_explorer.scanner.b524_orchestration import (
        _select_live_description_candidates,
    )
    from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
    from helianthus_vrc_explorer.ui.planner_selection import default_description_policy
    from tests.test_description_profile_policy import _with_known_remote
    from tests.test_effective_parameter_descriptions import _artifact

    artifact = _with_known_remote(_artifact())
    group = artifact["operations"]["0x06"]["groups"].pop("0x0a")
    registers = group["instances"]["0x01"]["registers"]
    registers["0x0002"].update(raw_hex="0f", value="0x0f")
    registers["0x0004"].update(raw_hex="010f00", value="01.0f.00")
    artifact["operations"]["0x06"]["groups"]["0x0e"] = group
    candidates = [DescriptionCandidate(0x06, 0x0E, 0x01, 0x0009, None)]
    entries = {candidate.native_identity: {} for candidate in candidates}
    policy = default_description_policy("recommended", exact_profile_known=True)

    selected, _, rows = _select_live_description_candidates(
        artifact, candidates, entries, policy=policy
    )

    assert rows[0]["status"] == "exact"
    assert selected == candidates
