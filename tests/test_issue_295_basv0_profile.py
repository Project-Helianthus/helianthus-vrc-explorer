from __future__ import annotations

import json
from importlib import resources

import pytest

from helianthus_vrc_explorer.scanner.b524_orchestration import (
    _select_live_description_candidates,
)
from helianthus_vrc_explorer.scanner.b524_probe import probe_parameter_description
from helianthus_vrc_explorer.scanner.description_scheduler import DescriptionCandidate
from helianthus_vrc_explorer.scanner.register import probe_instance_availability, read_register
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    attach_bundled_descriptions,
    description_catalog_status,
    effective_parameter_description,
    load_description_baseline,
)
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout
from helianthus_vrc_explorer.ui.planner_selection import default_description_policy


class _Reply(TransportInterface):
    def __init__(self, response: bytes) -> None:
        self.response = response

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        return self.response


def _basv0_artifact(
    *, group: str = "0x00", instance: str = "0x00", register: str = "0x0001"
) -> dict:
    return {
        "schema_version": "2.3",
        "meta": {
            "identity": {"eid": "BASV0", "sw": "0217", "hw": "8803"},
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
            },
        },
        "operations": {
            "0x02": {
                "groups": {
                    group: {
                        "instances": {
                            instance: {
                                "registers": {
                                    register: {
                                        "type": "EXP",
                                        "flags": 3,
                                        "raw_hex": "00000000",
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }


def test_scalar_codec_provenance_distinguishes_selector_hint_from_length_inference() -> None:
    response = bytes.fromhex("03040b0001000000")
    inferred = read_register(_Reply(response), 0x15, 0x02, 0x04, 0x01, 0x000B)
    qualified = read_register(_Reply(response), 0x15, 0x02, 0x04, 0x00, 0x000B, type_hint="U32")

    assert inferred["type"] == "EXP"
    assert inferred["codec_provenance"] == "length_inferred"
    assert qualified["type"] == "U32"
    assert qualified["codec_provenance"] == "selector_qualified"


def test_fresh_length_inferred_describe_is_raw_unqualified_evidence() -> None:
    result = probe_parameter_description(
        _Reply(bytes.fromhex("040b0000000000400d030001000000")),
        dst=0x15,
        opcode=0x02,
        group=0x04,
        instance=0x01,
        register=0x000B,
        type_spec="EXP",
        codec_provenance="length_inferred",
    )

    assert result["qualification"] == "unqualified"
    assert result["codec_provenance"] == "length_inferred"
    assert result["reply_hex"] == "040b0000000000400d030001000000"
    assert result["min"] == 0.0
    assert result["validation_scope"] == "raw_evidence_only"


def test_imported_legacy_solar_float_description_is_not_an_effective_validator() -> None:
    artifact = _basv0_artifact(group="0x04", instance="0x01", register="0x000b")
    selector = {
        "read_opcode": "0x02",
        "group": "0x04",
        "instance": "0x01",
        "register": "0x000b",
    }
    entry = artifact["operations"]["0x02"]["groups"]["0x04"]["instances"]["0x01"]["registers"][
        "0x000b"
    ]
    entry["parameter_description"] = {
        **selector,
        "description_opcode": "0x01",
        "qualification": "matched",
        "type": "EXP",
        "width": 4,
        "min": 0.0,
        "max": 2.802596928649634e-40,
        "step": 1.401298464324817e-45,
    }
    u32_catalog_row = {
        **selector,
        "description_opcode": "0x01",
        "profile": {
            "profile": "controller_b524",
            "profile_id": "basv0_sw0217_hw8803_api1",
            "eid": "BASV0",
            "software_raw_hex": "0217",
            "hardware_raw_hex": "8803",
            "api_version": 1.0,
            "api_revision": 1.0,
        },
        "type": "U32",
        "width": 4,
        "min": 0,
        "max": 200000,
        "step": 1,
    }

    attach_bundled_descriptions(
        artifact, bundle={"schema_version": 1, "descriptions": [u32_catalog_row]}
    )

    assert entry["parameter_description"]["codec_provenance"] == "legacy_unknown"
    assert effective_parameter_description(artifact, selector) is None


@pytest.mark.parametrize("instance", range(0x0B))
def test_basv0_ventilation_two_byte_zero_is_decoded_but_presence_remains_unknown(
    instance: int,
) -> None:
    probe = probe_instance_availability(
        _Reply(bytes.fromhex("020901000000")),
        dst=0x15,
        group=0x09,
        instance=instance,
        opcode=0x02,
        presence_profile="basv0_sw0217_hw8803_api1",
    )

    assert probe.contract.probe_type_hint == "UIN"
    assert probe.present is False
    assert probe.evidence is not None
    assert probe.evidence["error"] is None
    assert probe.evidence["type"] == "UIN"
    assert probe.evidence["value"] == 0
    assert probe.evidence["raw_hex"] == "0000"
    assert probe.evidence["availability_qualification"] == "unknown"


def test_basv0_ventilation_transport_error_remains_unknown() -> None:
    class Timeout(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            raise TransportTimeout("offline")

    probe = probe_instance_availability(
        Timeout(),
        dst=0x15,
        group=0x09,
        instance=0,
        opcode=0x02,
        presence_profile="basv0_sw0217_hw8803_api1",
    )
    assert probe.present is False
    assert probe.evidence is not None
    assert probe.evidence["response_state"] == "timeout"
    assert probe.evidence["availability_qualification"] == "unknown"


def test_basv0_profile_is_exact_without_asserting_installation_topology() -> None:
    artifact = _basv0_artifact()
    status = description_catalog_status(artifact)
    catalog = json.loads(
        resources.files("helianthus_vrc_explorer.data")
        .joinpath("b524_description_profiles.json")
        .read_text(encoding="utf-8")
    )
    profile = next(row for row in catalog["profiles"] if row["id"] == status["profile_id"])

    assert status == {
        "status": "exact",
        "profile_id": "basv0_sw0217_hw8803_api1",
        "device_class": "local",
    }
    assert "local_circuit_profile" not in profile
    assert "installed_instances" not in profile


def test_basv0_bundle_keeps_bivalence_max_20_separate_from_basv2_max_50() -> None:
    rows = load_description_baseline()["descriptions"]
    selector = {
        "read_opcode": "0x02",
        "group": "0x00",
        "instance": "0x00",
        "register": "0x0001",
    }
    by_profile = {
        row["profile"]["profile_id"]: row
        for row in rows
        if all(row.get(key) == value for key, value in selector.items())
    }
    assert by_profile["basv0_sw0217_hw8803_api1"]["max"] == 20.0
    assert by_profile["basv0_sw0217_hw8803_api1"]["codec_basis"] == (
        "public_local_constraint_codec"
    )
    assert by_profile["basv2_sw0507_hw1704_api1"]["max"] == 50.0

    artifact = _basv0_artifact()
    attach_bundled_descriptions(artifact)
    effective = effective_parameter_description(artifact, selector)
    assert effective is not None
    assert effective["source"] == "profile"
    assert effective["max"] == 20.0
    assert effective["codec_provenance"] == "selector_qualified"


def test_known_basv0_recommended_reuses_profile_without_implicit_describe() -> None:
    artifact = _basv0_artifact()
    candidate = DescriptionCandidate(0x02, 0x00, 0x00, 0x0001, "EXP", "selector_qualified")
    entries = {candidate.native_identity: {}}
    selected, selected_entries, remote_statuses = _select_live_description_candidates(
        artifact,
        [candidate],
        entries,
        policy=default_description_policy("recommended", exact_profile_known=True),
    )
    assert selected == []
    assert selected_entries == {}
    assert remote_statuses == []


def test_historic_basv2_bundle_rows_gain_trusted_catalog_provenance() -> None:
    rows = load_description_baseline()["descriptions"]
    legacy = next(row for row in rows if row["profile"]["profile_id"] == "basv2_sw0507_hw1704_api1")
    assert legacy["codec_provenance"] == "selector_qualified"


def test_sanitized_observation_retains_unknowns_without_private_capture_fields() -> None:
    fixture = json.loads(
        resources.files("helianthus_vrc_explorer.fixtures")
        .joinpath("b524-basv0-description-profile-v1.json")
        .read_text(encoding="utf-8")
    )
    assert fixture["observation_id"] == "basv0_sw0217_hw8803_api1"
    assert len(fixture["records"]) == 2093
    forbidden = {"scan_timestamp", "serial", "contributor", "destination_address", "value"}
    assert not forbidden.intersection(fixture)
    assert all(not forbidden.intersection(record) for record in fixture["records"])

    by_selector = {tuple(record["selector"].values()): record for record in fixture["records"]}
    assert by_selector[("02", "00", "00", "0001")]["decoded"]["max"] == 20.0
    assert by_selector[("02", "04", "01", "000B")]["decoded"]["qualification"] == ("unqualified")
    assert by_selector[("02", "09", "00", "0001")]["presence_state"] == "unknown"
    for register in ("006C", "006D", "006F", "0070"):
        assert by_selector[("02", "00", "00", register)]["decoded"] is None


def test_sanitized_scalar_catalog_retains_unknown_and_wire_states_without_values() -> None:
    fixture = json.loads(
        resources.files("helianthus_vrc_explorer.fixtures")
        .joinpath("b524-basv0-register-observations-v1.json")
        .read_text(encoding="utf-8")
    )
    assert fixture["current_values"] == "omitted"
    assert len(fixture["records"]) == 6585
    assert all("value" not in record and "raw_hex" not in record for record in fixture["records"])

    records = fixture["records"]
    assert sum(record["response_state"] == "echo_payload" for record in records) == 5335
    assert sum(record["response_state"] == "status_only" for record in records) == 1155
    assert sum(record["response_state"] == "transport_error" for record in records) == 95
    assert any(
        record["access_flags"] == "00" and record["response_state"] == "echo_payload"
        for record in records
    )
    assert any(
        record["name"] is None
        and record["description"] is None
        and record["response_state"] == "echo_payload"
        for record in records
    )
