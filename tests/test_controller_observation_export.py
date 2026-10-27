"""Synthetic privacy and admission checks for the offline observation handoff."""

import importlib.util
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/export_controller_observations.py"


def export(artifact):
    spec = importlib.util.spec_from_file_location("controller_export", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.export_observations(artifact)


def artifact():
    entry = {
        "value": "PRIVATE_SENTINEL",
        "raw_hex": "PRIVATE_SENTINEL",
        "parameter_description": {
            "type": "EXP",
            "min": 10.0,
            "max": 70.0,
            "step": 0.5,
            "width": 4,
            "qualification": "matched",
            "evidence_grade": "Hypothesis",
            "reply_hex": "PRIVATE_SENTINEL",
        },
        "evidence_grade": "Proven",
        "response_state": "active",
    }
    group = {"instances": {"0x00": {"registers": {"0x0009": entry}}}}
    return {
        "schema_version": "2.4",
        "meta": {"identity": {"protocol_family": "VRC720", "model": "PRIVATE_SENTINEL"}},
        "operations": {op: {"groups": {"0x02": deepcopy(group)}} for op in ("0x06", "0x02")},
    }


def test_selector_identity_grades_and_unknowns_are_independent():
    source = artifact()
    before = deepcopy(source)
    result = export(source)
    assert source == before
    assert result["family"] == "VRC720"
    assert result["native_profile_input"] is False
    assert result["write_bound_evidence"] is False
    records = result["observations"]
    assert [r["selector"]["opcode"] for r in records] == ["0x02", "0x06"]
    assert records[0]["selector"] == {
        "opcode": "0x02",
        "group": "0x02",
        "instance": "0x00",
        "register": "0x0009",
    }
    assert records[0]["evidence_grade"] == "Proven"
    decoded = records[0]["decoded_observation"]
    assert decoded["evidence_grade"] == "Hypothesis"
    assert decoded["qualification"] == "matched"
    assert decoded["step_qualification"] == "unknown"
    assert decoded["min"] == 10.0
    assert records[0]["raw_description"] == "omitted"
    del source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0009"][
        "parameter_description"
    ]
    record = export(source)["observations"][0]
    assert record["raw_description"] == "unknown"
    assert record["decoded_observation"]["qualification"] == "unknown"


@pytest.mark.parametrize("key", ["reply_hex", "raw_description_hex"])
@pytest.mark.parametrize(
    ("value", "expected"),
    [("", "omitted"), ("PRIVATE_SENTINEL", "omitted"), (None, "unknown"), (True, "unknown")],
)
def test_raw_description_presence_uses_string_type(key, value, expected):
    source = artifact()
    entry = source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    entry["parameter_description"] = {key: value}
    result = export(source)
    assert result["observations"][0]["raw_description"] == expected
    assert "PRIVATE_SENTINEL" not in json.dumps(result)


def test_privacy_allowlists_at_every_level():
    source = artifact()

    def poison(node):
        if isinstance(node, dict):
            for value in list(node.values()):
                poison(value)
            if any(key.startswith("0x") for key in node):
                return
            for key in (
                "serial",
                "address",
                "locator",
                "timestamp",
                "contributor",
                "metadata",
                "description",
                "name",
                "raw_description_hex",
                "unknown_future_field",
            ):
                node[key] = "PRIVATE_SENTINEL"

    poison(source)
    # Never echo arbitrary strings even in otherwise recognized fields.
    entry = source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    entry["response_state"] = "PRIVATE_SENTINEL"
    entry["evidence_grade"] = {"serial": "PRIVATE_SENTINEL"}
    entry["parameter_description"]["type"] = "PRIVATE_SENTINEL"
    entry["parameter_description"]["qualification"] = "PRIVATE_SENTINEL"
    entry["parameter_description"]["min"] = "PRIVATE_SENTINEL"
    source["meta"]["identity"]["protocol_family"] = "PRIVATE_SENTINEL"
    result = export(source)
    assert "PRIVATE_SENTINEL" not in json.dumps(result)
    assert result["family"] == "unknown"
    assert result["observations"][0]["decoded_observation"]["min"] == "unknown"


@pytest.mark.parametrize(
    "source",
    [
        None,
        [],
        {},
        {"schema_version": "2.2", "operations": {}},
        {"schema_version": "2.4", "operations": []},
        {"schema_version": "2.4", "operations": {"0x02": {"groups": []}}},
        {"schema_version": "2.4", "operations": {"private selector": {}}},
    ],
)
def test_malformed_structure_is_controlled(source):
    with pytest.raises(ValueError):
        export(source)


def test_nested_malformed_and_duplicate_selectors_fail():
    source = artifact()
    group = source["operations"]["0x02"]["groups"]["0x02"]
    group["instances"]["0x00"]["registers"]["0x0009"] = []
    with pytest.raises(ValueError):
        export(source)
    source = artifact()
    source["operations"]["0X02"] = source["operations"]["0x02"]
    with pytest.raises(ValueError):
        export(source)


@pytest.mark.parametrize("opcode", ["0x01", "0xff", "0XFF"])
@pytest.mark.parametrize("with_registers", [False, True])
def test_non_register_operations_are_rejected(opcode, with_registers):
    source = artifact()
    source["operations"][opcode] = (
        deepcopy(source["operations"]["0x02"]) if with_registers else {"groups": {}}
    )
    with pytest.raises(ValueError, match="Unsupported register opcode"):
        export(source)


def test_native_and_write_admission_reject_observations():
    from helianthus_vrc_explorer.artifact_schema import ArtifactSchemaError, migrate_artifact_schema
    from helianthus_vrc_explorer.evidence_export import build_native_evidence
    from helianthus_vrc_explorer.scanner.b524_operation_writes import (
        parse_native_write_qualification,
    )

    result = export(artifact())
    with pytest.raises(ValueError, match="Unsupported sanitized native source pair"):
        build_native_evidence(result, result, {})
    with pytest.raises(ArtifactSchemaError):
        migrate_artifact_schema(result)
    with pytest.raises(ValueError):
        parse_native_write_qualification(result)


def test_cli_determinism_help_errors_and_source_preservation(tmp_path):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(artifact()), encoding="utf-8")
    original = source.read_bytes()
    command = [sys.executable, str(SCRIPT), str(source)]
    first = subprocess.run(command, capture_output=True, check=False)
    assert first.returncode == 0, first.stderr
    source.write_text(json.dumps(artifact(), sort_keys=True), encoding="utf-8")
    second = subprocess.run(command, capture_output=True, check=False)
    assert first.stdout == second.stdout
    source.write_bytes(original)
    subprocess.run(command, capture_output=True, check=True)
    assert source.read_bytes() == original
    help_result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True)
    assert help_result.returncode == 0
    assert b"observation-only" in help_result.stdout
    assert b"native profile" in help_result.stdout
    assert b"2.3/2.4" in help_result.stdout
    source.write_text('{"PRIVATE_SENTINEL":', encoding="utf-8")
    failed = subprocess.run(command, capture_output=True)
    assert failed.returncode == 2
    assert failed.stdout == b""
    assert b"PRIVATE_SENTINEL" not in failed.stderr
    assert b"Traceback" not in failed.stderr


def test_partial_last_known_observation_and_unknown_grade_are_retained():
    source = artifact()
    entry = source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    entry["response_state"] = "timeout"
    entry.pop("evidence_grade")
    before = deepcopy(source)
    record = export(source)["observations"][0]
    assert record["response_state"] == "timeout"
    assert record["decoded_observation"]["max"] == 70.0
    assert record["evidence_grade"] == "Unknown"
    assert source == before


@pytest.mark.parametrize(
    "text",
    [
        '{"schema_version":"2.4","operations":{},"operations":{}}',
        '{"schema_version":"2.4","operations":{"0x02":{"groups":{"0x02":[]}}}}',
    ],
)
def test_cli_rejects_duplicate_json_fields_and_malformed_nested_objects(tmp_path, text):
    source = tmp_path / "input.json"
    source.write_text(text, encoding="utf-8")
    result = subprocess.run([sys.executable, str(SCRIPT), str(source)], capture_output=True)
    assert result.returncode == 2
    assert not result.stdout
    assert result.stderr == b"Observation export failed: unreadable or malformed artifact\n"


def test_recognized_codec_and_nonfinite_limits_without_qualification_promotion():
    source = artifact()
    entry = source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    entry["parameter_description"].update(
        type="UIN", min=float("nan"), max=float("inf"), step=True, width={"private": "text"}
    )
    decoded = export(source)["observations"][0]["decoded_observation"]
    assert decoded["type"] == "UIN"
    assert [decoded[key] for key in ("min", "max", "step", "width")] == ["unknown"] * 4
    assert decoded["evidence_grade"] == "Hypothesis"
    entry["read_opcode"] = "0x06"
    with pytest.raises(ValueError, match="Conflicting register opcode"):
        export(source)


@pytest.mark.parametrize(
    ("key", "other"),
    [("read_opcode", "0x06"), ("group", "0x03"), ("instance", "0x01"), ("register", "0x000a")],
)
def test_misplaced_description_selector_is_not_bound_to_enclosing_entry(key, other):
    source = artifact()
    entry = source["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0009"
    ]
    entry["parameter_description"].update(
        {"read_opcode": "0x02", "group": "0x02", "instance": "0x00", "register": "0x0009"}
    )
    assert export(deepcopy(source))["observations"][0]["decoded_observation"]["min"] == 10.0
    entry["parameter_description"][key] = other
    record = export(source)["observations"][0]
    assert record["raw_description"] == "unknown"
    assert record["decoded_observation"]["min"] == "unknown"
    assert record["decoded_observation"]["qualification"] == "unknown"
