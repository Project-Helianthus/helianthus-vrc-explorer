"""Issue #297 native export and application-policy boundary, using offline inputs."""

import json
import os
import shutil
import subprocess
import sys
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from helianthus_vrc_explorer.evidence_export import (
    build_native_evidence,
    serialize_native_evidence,
    validate_scope_overlay,
    write_native_evidence,
)
from helianthus_vrc_explorer.protocol.b524_metadata import validate_parameter_edit
from helianthus_vrc_explorer.schema.parameter_descriptions import (
    attach_native_descriptions,
    effective_parameter_description,
)

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTION = "b524-basv0-description-profile-v1.json"
OBSERVATIONS = "b524-basv0-register-observations-v1.json"
OVERLAY = "b524-basv0-validation-scope-v1.json"
# Native /v1 byte parity; fixture refresh itself belongs to #299.
DIGESTS = {
    DESCRIPTION: "23f8f3a95315920b4746b7d7e70b648e73c1da8bb2734450e9ac34e77b6ae1cb",
    OBSERVATIONS: "70a9194788779a7d1e47ef05a83e1d583b83b72cc8643b744b44ee5f5570db86",
    OVERLAY: "a4d6157363a75b2f3a64ef75a14be426e518dbd7453e171880d63aee17e24687",
}


def inputs():
    return (
        json.loads((ROOT / "fixtures" / DESCRIPTION).read_text()),
        json.loads((ROOT / "fixtures" / OBSERVATIONS).read_text()),
        json.loads(
            (ROOT / "src/helianthus_vrc_explorer/data/b524_description_profiles.json").read_text()
        ),
    )


def exported():
    return build_native_evidence(*inputs(), allow_legacy_interpretation=True)


def test_export_matches_pinned_native_bytes_without_changing_inputs():
    source = inputs()
    before = deepcopy(source)
    documents = build_native_evidence(*source, allow_legacy_interpretation=True)
    encoded = serialize_native_evidence(documents)
    assert {name: sha256(data).hexdigest() for name, data in encoded.items()} == DIGESTS
    assert source == before
    assert "validation_scope" not in encoded[DESCRIPTION].decode()
    assert b'"native_headers": "omitted"' in encoded[OBSERVATIONS]
    assert b'"response_payloads": "omitted"' in encoded[OBSERVATIONS]
    assert len(documents[DESCRIPTION]["records"]) == 2093
    assert len(documents[OBSERVATIONS]["records"]) == 6585
    # A normalized native pair does not require another legacy interpretation opt-in.
    assert (
        build_native_evidence(documents[DESCRIPTION], documents[OBSERVATIONS], source[2])
        == documents
    )


def test_legacy_native_export_needs_opt_in_and_independent_identity():
    description, observations, manifest = inputs()
    with pytest.raises(ValueError, match="explicit opt-in"):
        build_native_evidence(description, observations, manifest)
    for field in ("api_version_raw", "api_revision_raw"):
        broken = deepcopy(manifest)
        broken["profiles"][0]["controller"].pop(field)
        broken["profiles"][0]["controller"].pop(field.removesuffix("_raw"))
        with pytest.raises(ValueError, match="identity"):
            build_native_evidence(
                description, observations, broken, allow_legacy_interpretation=True
            )
    manifest["profiles"][0]["controller"]["api_revision_raw"] = "2"
    with pytest.raises(ValueError, match="identity"):
        build_native_evidence(description, observations, manifest, allow_legacy_interpretation=True)


@pytest.mark.parametrize(
    "fault", ["duplicate", "missing", "orphan", "description_duplicate", "wrong_scope"]
)
def test_overlay_is_a_bijection_with_derived_source_classification(fault):
    documents = exported()
    native, overlay = documents[DESCRIPTION], documents[OVERLAY]
    if fault == "duplicate":
        overlay["records"].append(deepcopy(overlay["records"][0]))
    elif fault == "missing":
        overlay["records"].pop()
    elif fault == "orphan":
        overlay["records"][0]["selector"]["register"] = "FFFF"
    elif fault == "description_duplicate":
        native["records"].append(deepcopy(native["records"][0]))
    else:
        overlay["records"][0]["validation_scope"] = "raw_evidence_only"
    with pytest.raises(ValueError):
        validate_scope_overlay(native, overlay)


def consumer():
    selector = {"read_opcode": "0x02", "group": "0x00", "instance": "0x00", "register": "0x0001"}
    entry = {"type": "EXP", "response_state": "active", "raw_hex": "00000000"}
    instance = {"present": True, "registers": {"0x0001": entry}}
    artifact = {
        "meta": {
            "identity": {"eid": "BASV0", "sw": "0217", "hw": "8803"},
            "profile_context": {"profile": "controller_b524", "api_version": 1, "api_revision": 1},
        },
        "operations": {"0x02": {"groups": {"0x00": {"instances": {"0x00": instance}}}}},
    }
    return artifact, selector, instance


def test_native_overlay_recomputes_current_presence_and_identity_each_time():
    documents = exported()
    artifact, selector, instance = consumer()
    attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])
    for present, scope in [
        (True, "format_range_and_step"),
        (False, "display_only"),
        (None, "display_only"),
        (True, "format_range_and_step"),
    ]:
        instance["present"] = present
        result = effective_parameter_description(artifact, selector)
        assert result["validation_scope"] == scope
        error = validate_parameter_edit(
            result, type_spec="EXP", value=100, encoded=bytes.fromhex("0000c842")
        )
        assert error == (
            "Value is outside the described range" if present is True else "unvalidated"
        )
    artifact["meta"]["identity"]["sw"] = "9999"
    assert effective_parameter_description(artifact, selector) is None


def test_native_import_requires_overlay_and_does_not_trust_record_policy():
    documents = exported()
    artifact, _, _ = consumer()
    documents[DESCRIPTION]["records"][0]["validation_scope"] = "format_range_and_step"
    with pytest.raises(ValueError, match="validation_scope"):
        attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])


def _run_docs_python(docs, arguments):
    # Execute scripts by path from their own root so sibling imports and relative
    # resources follow docs-ebus semantics, independently of Explorer's imports.
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    system_path = os.pathsep.join(
        part
        for part in os.get_exec_path()
        if Path(part).resolve() != (Path(sys.prefix) / "bin").resolve()
    )
    system_python = shutil.which("python3", path=system_path)
    failures = []
    for interpreter in dict.fromkeys([sys.executable, system_python]):
        if interpreter is None:
            continue
        result = subprocess.run(
            [interpreter, *arguments], cwd=docs, env=env, capture_output=True, text=True
        )
        if result.returncode and "ModuleNotFoundError:" in result.stderr:
            failures.append(f"{interpreter}: {result.stderr.strip()}")
            continue
        assert result.returncode == 0, result.stdout + result.stderr
        return
    pytest.skip(
        "docs-ebus gate dependency unavailable in Explorer and system python3 "
        f"({system_python or 'not found outside the venv'}): " + "; ".join(failures)
    )


def test_docs_ebus_native_gate(tmp_path):
    configured = os.environ.get("DOCS_EBUS_ROOT")
    if not configured:
        pytest.skip(
            "Set DOCS_EBUS_ROOT to a docs-ebus checkout for native schemas, "
            "semantic validation and byte comparisons"
        )
    docs = Path(configured).resolve()
    write_native_evidence(exported(), tmp_path)
    _run_docs_python(
        docs,
        [
            str(docs / "scripts/validate_b524_basv0_description_profile.py"),
            str(tmp_path / DESCRIPTION),
            "--observations",
            str(tmp_path / OBSERVATIONS),
            "--scopes",
            str(tmp_path / OVERLAY),
        ],
    )
    for name in DIGESTS:
        location = "development/fixtures" if name == OVERLAY else "protocols/vaillant/fixtures"
        assert (tmp_path / name).read_bytes() == (docs / location / name).read_bytes()
    # The semantic validator is not a JSON Schema engine. Use the checkout's schemas too.
    _run_docs_python(
        docs,
        [
            "-c",
            "import json, sys\n"
            "from pathlib import Path\n"
            "from jsonschema import Draft202012Validator\n"
            "for name in sys.argv[2:]:\n"
            "    location = 'development/fixtures' if 'validation-scope' in name "
            "else 'protocols/vaillant/fixtures'\n"
            "    schema = Path(location) / name.replace('-v1.json', '-schema-v1.json')\n"
            "    Draft202012Validator(json.loads(schema.read_text())).validate(\n"
            "        json.loads((Path(sys.argv[1]) / name).read_text()))\n",
            str(tmp_path),
            *DIGESTS,
        ],
    )


def test_native_calendar_scope_stays_display_only_with_current_presence():
    documents = exported()
    artifact, selector, instance = consumer()
    selector["register"] = "0x0034"
    instance["registers"] = {"0x0034": {"type": "DATE_DMY_U8X3"}}
    attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])
    result = effective_parameter_description(artifact, selector)
    assert result["validation_scope"] == "display_only"
    assert (
        validate_parameter_edit(
            result, type_spec="DATE_DMY_U8X3", value="2099-12-31", encoded=bytes.fromhex("1f0c63")
        )
        == "unvalidated"
    )


def test_export_refuses_misaligned_observation_links_and_duplicate_selectors():
    description, observations, manifest = inputs()
    linked = next(row for row in observations["records"] if row["description"])
    linked["description"]["record_index"] = 1
    with pytest.raises(ValueError, match="link/selector"):
        build_native_evidence(description, observations, manifest, allow_legacy_interpretation=True)
    description, observations, manifest = inputs()
    observations["records"].append(deepcopy(observations["records"][0]))
    with pytest.raises(ValueError, match="Duplicate observation"):
        build_native_evidence(description, observations, manifest, allow_legacy_interpretation=True)


def test_source_presence_is_never_inherited_from_the_overlay():
    documents = exported()
    artifact, selector, instance = consumer()
    instance.pop("present")
    attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])
    assert documents[OVERLAY]["records"][0]["validation_scope"] == "format_range_and_step"
    assert effective_parameter_description(artifact, selector)["validation_scope"] == "display_only"


def test_export_cli_uses_own_inputs_and_publishes_identical_bytes(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/export_b524_evidence.py"),
            "--output-dir",
            str(tmp_path),
            "--allow-legacy-interpretation",
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert {name: sha256((tmp_path / name).read_bytes()).hexdigest() for name in DIGESTS} == DIGESTS
    assert all(digest in result.stdout for digest in DIGESTS.values())


def test_current_always_present_fallback_does_not_establish_observed_presence():
    documents = exported()
    artifact, selector, _ = consumer()
    artifact["operations"]["0x02"]["groups"]["0x00"]["availability_contract"] = {
        "source": "always_present"
    }
    attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])
    assert effective_parameter_description(artifact, selector)["validation_scope"] == "display_only"


def test_native_application_adapter_rejects_decoding_that_disagrees_with_bytes():
    documents = exported()
    artifact, _, _ = consumer()
    documents[DESCRIPTION]["records"][0]["decoded"]["max"] = 50.0
    with pytest.raises(ValueError, match="retained bytes"):
        attach_native_descriptions(artifact, documents[DESCRIPTION], documents[OVERLAY])
