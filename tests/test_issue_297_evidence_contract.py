"""Offline part 1 contract; native fixtures and overlay parity land separately."""

from copy import deepcopy

import pytest

from helianthus_vrc_explorer.artifact_schema import iter_register_entries, migrate_artifact_schema
from helianthus_vrc_explorer.protocol.b524_metadata import (
    decode_parameter_description,
    validate_parameter_edit,
)
from helianthus_vrc_explorer.protocol.parser import encode_typed_value
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    _enrich_bundle_profiles,
    export_description_baseline,
)
from tests.test_bundled_descriptions import _artifact


@pytest.mark.parametrize("version", [None, "2.0", "2.1", "2.2", "2.3"])
@pytest.mark.parametrize("codec", ["HDA:3", "HTI"])
def test_known_legacy_scan_interpretation_is_copy_only(version, codec) -> None:
    source = {
        "meta": {"producer": "helianthus-vrc-explorer"},
        "groups": {
            "0x00": {
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {
                                "type": codec,
                                "raw_hex": "101020",
                                "value": "historical",
                            }
                        }
                    }
                }
            }
        },
    }
    if version is not None:
        source["schema_version"] = version
    before = deepcopy(source)
    adapted, _ = migrate_artifact_schema(source)
    entry = list(iter_register_entries(adapted))[0][-1]
    assert entry["type"] == {"HDA:3": "DATE_DMY_U8X3", "HTI": "TIME_HMS_U8X3"}[codec]
    assert entry["codec_migration"]["source_label"] == codec
    assert entry["value"] == "historical"
    assert entry["raw_hex"] == "101020"
    assert source == before


@pytest.mark.parametrize("codec", ["HDA:3", "HTI"])
@pytest.mark.parametrize("known_source", [False, True])
def test_legacy_baseline_labels_need_established_row_provenance(codec, known_source) -> None:
    # Retained v1 input vocabulary; never update these legacy labels to neutral tokens.
    row = {
        "type": codec,
        "raw_hex": "101020",
        "value": "historical",
        "profile": {"profile": "controller_b524", "api_version": 1.0, "api_revision": 1.0},
        "source": "read_only_observed_baseline" if known_source else "external_ebusd",
        "decoder_revision": "b524-description/v2",
    }
    original = {"schema_version": 1, "descriptions": [row]}
    before = deepcopy(original)
    adapted = _enrich_bundle_profiles(original)
    result = adapted["descriptions"][0]
    if known_source:
        assert result["type"] in {"DATE_DMY_U8X3", "TIME_HMS_U8X3"}
        assert result["codec_migration"]["source_label"] == codec
        assert result["codec_migration"]["source_version"] == 1
        assert result["validation_scope"] == "display_only"
    else:
        assert result["type"] == codec
        assert "codec_migration" not in result
    assert result["raw_hex"] == "101020" and result["value"] == "historical"
    assert result["profile"]["api_version_raw"] == "1"
    assert result["profile"]["api_revision_raw"] == "1"
    assert original == before


@pytest.mark.parametrize(
    "codec,lower,upper,candidate",
    [
        ("DATE_DMY_U8X3", "2026-01-01", "2026-01-05", "2099-12-31"),
        ("TIME_HMS_U8X3", "01:00:00", "02:00:00", "23:59:59"),
    ],
)
def test_calendar_candidate_outside_fixture_bounds_is_display_only(codec, lower, upper, candidate):
    desc = decode_parameter_description(
        bytes.fromhex("000100")
        + encode_typed_value(codec, lower)
        + encode_typed_value(codec, upper)
        + b"\xff\xff\xff",
        opcode=1,
        group=0,
        instance=0,
        register=1,
        type_spec=codec,
    )
    assert desc["step"] is None and desc["step_raw_hex"] == "ffffff"
    assert desc["validation_scope"] == "display_only"
    assert (
        validate_parameter_edit(
            desc, type_spec=codec, value=candidate, encoded=encode_typed_value(codec, candidate)
        )
        == "unvalidated"
    )
    assert "width" in validate_parameter_edit(
        desc, type_spec=codec, value=candidate, encoded=b"\x01"
    )
    assert (
        validate_parameter_edit(desc, type_spec=codec, value=candidate, encoded=b"\xff" * 3)
        != "unvalidated"
    )


def test_export_of_migrated_interpretation_requires_explicit_choice() -> None:
    artifact = _artifact()
    artifact["meta"]["producer"] = "helianthus-vrc-explorer"
    entry = list(iter_register_entries(artifact))[0][-1]
    entry["type"] = "HDA:3"
    desc = decode_parameter_description(
        bytes.fromhex("0209000101001f0c63000000"),
        opcode=1,
        group=2,
        instance=1,
        register=9,
        type_spec="DATE_DMY_U8X3",
    )
    entry["parameter_description"] = {**desc, "type": "HDA:3"}
    artifact, _ = migrate_artifact_schema(artifact)
    with pytest.raises(ValueError, match="explicit opt-in"):
        export_description_baseline(artifact)
    bundle = export_description_baseline(artifact, allow_legacy_interpretation=True)
    assert len(bundle["descriptions"]) == 1
    assert bundle["descriptions"][0]["codec_migration"]["source_label"] == "HDA:3"


def test_explicit_external_producer_prevents_migration_even_with_copied_contract() -> None:
    from helianthus_vrc_explorer.scanner.b524_artifact import _artifact_contract_metadata

    artifact = _artifact()
    artifact["meta"].update(producer="ebusd", artifact_contract=_artifact_contract_metadata())
    entry = list(iter_register_entries(artifact))[0][-1]
    entry["type"] = "HTI"
    result, _ = migrate_artifact_schema(artifact)
    assert list(iter_register_entries(result))[0][-1]["type"] == "HTI"


def test_existing_explorer_replay_provenance_qualifies_legacy_labels() -> None:
    artifact = _artifact()
    artifact["meta"].update(
        schema_sources=["replay_trace:enhanced_v1"], replay_trace={"format": "enhanced_v1"}
    )
    list(iter_register_entries(artifact))[0][-1]["type"] = "HTI"
    result, _ = migrate_artifact_schema(artifact)
    assert list(iter_register_entries(result))[0][-1]["type"] == "TIME_HMS_U8X3"


def test_merging_migrated_baselines_requires_explicit_interpretation_export() -> None:
    from helianthus_vrc_explorer.schema.parameter_descriptions import merge_description_baselines

    bundle = export_description_baseline(_artifact())
    row = bundle["descriptions"][0]
    row["type"] = "HTI"
    # Explicit v1 input provenance is retained while the label migrates on a copy.
    bundle["schema_version"] = 1
    row["decoder_revision"] = "b524-description/v2"
    row["source"] = "read_only_observed_baseline"
    before = deepcopy(bundle)
    empty = {"schema_version": 1, "descriptions": []}
    with pytest.raises(ValueError, match="explicit opt-in"):
        merge_description_baselines(bundle, empty)
    result = merge_description_baselines(bundle, empty, allow_legacy_interpretation=True)
    assert result["descriptions"][0]["type"] == "TIME_HMS_U8X3"
    assert result["descriptions"][0]["codec_migration"]["source_label"] == "HTI"
    assert bundle == before


def test_legacy_override_labels_migrate_separately_and_retain_original_path() -> None:
    artifact = _artifact()
    artifact["meta"].update(
        producer="helianthus-vrc-explorer",
        type_overrides={"0x00": {"operations": {"0x02": {"0x0035": "HTI"}}}},
    )
    before = deepcopy(artifact)
    result, _ = migrate_artifact_schema(artifact)
    meta = result["meta"]
    assert meta["type_overrides"]["0x00"]["operations"]["0x02"]["0x0035"] == "TIME_HMS_U8X3"
    assert meta["type_override_migrations"][0]["source_label"] == "HTI"
    assert meta["type_override_migrations"][0]["path"] == ["0x00", "operations", "0x02", "0x0035"]
    assert artifact == before
    twice, _ = migrate_artifact_schema(result)
    assert twice == result


@pytest.mark.parametrize("version", [1, 2])
def test_application_baseline_versions_are_readable_and_new_merge_is_v2(version):
    from helianthus_vrc_explorer.schema.parameter_descriptions import merge_description_baselines

    bundle = export_description_baseline(_artifact())
    assert type(bundle["schema_version"]) is int and bundle["schema_version"] == 2
    bundle["schema_version"] = version
    adapted = _enrich_bundle_profiles(bundle)
    assert adapted["descriptions"][0]["profile"]["api_revision_raw"] == "1"
    merged = merge_description_baselines(bundle, {"schema_version": 2, "descriptions": []})
    assert type(merged["schema_version"]) is int and merged["schema_version"] == 2


@pytest.mark.parametrize("version", [0, 3, "2", True])
def test_application_baseline_rejects_unknown_or_noninteger_version(version):
    with pytest.raises(ValueError, match="baseline version"):
        _enrich_bundle_profiles({"schema_version": version, "descriptions": []})


def test_scan_24_version_boundary_and_23_copy_migration():
    from helianthus_vrc_explorer.artifact_schema import ArtifactSchemaError

    artifact = {"schema_version": "2.3", "operations": {}, "meta": {}}
    adapted, report = migrate_artifact_schema(artifact)
    assert adapted["schema_version"] == "2.4" and report.changed
    assert artifact["schema_version"] == "2.3"
    again, report = migrate_artifact_schema(adapted)
    assert again == adapted and not report.changed
    with pytest.raises(ArtifactSchemaError, match="Unsupported schema_version"):
        migrate_artifact_schema({"schema_version": "2.5"})
