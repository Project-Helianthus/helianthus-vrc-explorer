from copy import deepcopy

from helianthus_vrc_explorer.schema.parameter_descriptions import (
    attach_bundled_descriptions,
    description_catalog_status,
    description_profile,
    effective_parameter_description,
    export_description_baseline,
)

SELECTOR = {
    "read_opcode": "0x02",
    "group": "0x02",
    "instance": "0x00",
    "register": "0x0009",
}


def _artifact() -> dict:
    return {
        "schema_version": "2.3",
        "meta": {
            "identity": {
                "eid": "BASV2",
                "sw": "0507",
                "hw": "1704",
                "model": "display text is not authority",
                "firmware": "also display only",
            },
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
            },
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0009": {
                                        "type": "EXP",
                                        "parameter_description": {
                                            "qualification": "matched",
                                            "description_opcode": "0x01",
                                            **SELECTOR,
                                            "type": "EXP",
                                            "width": 4,
                                            "min": 20.0,
                                            "max": 70.0,
                                            "step": 0.5,
                                            "validation_scope": "format_range_and_step",
                                            "reply_hex": "0209000000a04100008c420000003f",
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
    }


def test_exact_native_identity_qualifies_live_and_profile_sources_separately() -> None:
    from helianthus_vrc_explorer.protocol.b524_metadata import validate_parameter_edit

    artifact = _artifact()
    assert description_catalog_status(artifact)["status"] == "exact"
    bundle = export_description_baseline(artifact)
    attach_bundled_descriptions(artifact, bundle=bundle)
    live = effective_parameter_description(artifact, SELECTOR)
    assert live is not None
    assert live["source"] == "live"
    assert live["qualification"] == "matched"

    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    attach_bundled_descriptions(artifact, bundle=bundle)
    profile = effective_parameter_description(artifact, SELECTOR)
    assert profile is not None
    assert profile["source"] == "profile"
    assert profile["qualification"] == "profile_qualified"
    assert profile["verification"] == "not_verified"
    assert (
        validate_parameter_edit(
            profile,
            type_spec="EXP",
            value=20.0,
            encoded=bytes.fromhex("0000a041"),
        )
        is None
    )


def test_pretty_model_or_firmware_text_cannot_qualify_a_bundle() -> None:
    artifact = _artifact()
    bundle = export_description_baseline(artifact)
    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    artifact["meta"]["identity"].update(
        eid="OTHER", sw="9999", hw="9999", model="BASV2", firmware="SW 0507 / HW 1704"
    )
    attach_bundled_descriptions(artifact, bundle=bundle)
    assert effective_parameter_description(artifact, SELECTOR) is None
    assert entry["bundled_parameter_description"]["verification"] == "profile_mismatch"


def test_known_missing_row_stays_missing_and_generic_iiff_is_never_effective() -> None:
    artifact = _artifact()
    bundle = export_description_baseline(artifact)
    missing_selector = {**SELECTOR, "register": "0x0010"}
    assert effective_parameter_description(artifact, missing_selector) is None

    generic = deepcopy(bundle["descriptions"][0])
    generic["instance"] = "0xff"
    generic["device_identity_verified"] = False
    generic["scope"] = "generic_instance_class"
    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    attach_bundled_descriptions(artifact, bundle={"schema_version": 1, "descriptions": [generic]})
    assert effective_parameter_description(artifact, SELECTOR) is None


def test_remote_profile_requires_separate_class_and_firmware() -> None:
    artifact = _artifact()
    artifact["operations"]["0x06"] = artifact["operations"].pop("0x02")
    group = artifact["operations"]["0x06"]["groups"].pop("0x02")
    artifact["operations"]["0x06"]["groups"]["0x0a"] = group
    entry = group["instances"].pop("0x00")
    group["instances"]["0x01"] = entry
    registers = entry["registers"]
    registers["0x0009"]["parameter_description"].update(
        read_opcode="0x06", description_opcode="0x07", group="0x0a", instance="0x01"
    )
    remote_selector = {
        **SELECTOR,
        "read_opcode": "0x06",
        "group": "0x0a",
        "instance": "0x01",
    }
    assert description_catalog_status(artifact, remote_selector)["status"] == "unqualified"
    registers["0x0002"] = {"type": "HEX:1", "raw_hex": "35", "value": "0x35"}
    registers["0x0004"] = {"type": "FW", "raw_hex": "021100", "value": "02.11.00"}
    assert description_catalog_status(artifact, remote_selector)["status"] == "exact"

    # Qualification is for the remote class/FW variant, not for a particular
    # bundled register. A missing known row must remain missing.
    assert remote_selector["register"] == "0x0009"
    registers["0x0004"].update(raw_hex="ffffff", value="unknown")
    assert description_catalog_status(artifact, remote_selector)["status"] == "unqualified"


def test_unknown_catalog_controller_accepts_fresh_live_but_rejects_cached_limits() -> None:
    artifact = _artifact()
    known_bundle = export_description_baseline(artifact)
    artifact["meta"]["identity"].update(eid="NEWV1", sw="0102", hw="0304")

    attach_bundled_descriptions(artifact, bundle=known_bundle)
    live = effective_parameter_description(artifact, SELECTOR)
    assert live is not None
    assert live["source"] == "live"
    assert live["target_profile"]["profile_id"] is None

    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    attach_bundled_descriptions(artifact, bundle=known_bundle)
    assert effective_parameter_description(artifact, SELECTOR) is None


def test_bundled_description_binds_current_native_profile_without_rewriting_evidence() -> None:
    artifact = _artifact()
    bundle = export_description_baseline(artifact)
    baseline_profile = deepcopy(bundle["descriptions"][0]["profile"])
    baseline_profile.update(
        model="Historic presentation",
        firmware="Historic presentation",
        controller_class_raw="15",
        controller_firmware_raw="080500",
    )
    bundle["descriptions"][0]["profile"] = baseline_profile
    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    del entry["parameter_description"]
    attach_bundled_descriptions(artifact, bundle=bundle)
    effective = effective_parameter_description(artifact, SELECTOR)
    assert effective is not None
    assert effective["target_profile"] == description_profile(artifact, SELECTOR)
    assert effective["profile"] == baseline_profile
    assert effective["qualification"] == "profile_qualified"
    assert effective["verification"] == "not_verified"
    assert "target_profile" not in entry["bundled_parameter_description"]
    artifact["meta"]["identity"]["sw"] = "0508"
    assert effective_parameter_description(artifact, SELECTOR) is None
