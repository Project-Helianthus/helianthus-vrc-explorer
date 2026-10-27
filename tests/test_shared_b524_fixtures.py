"""Standalone shared native evidence checks; corruptions are synthetic only."""

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "shared_b524", ROOT / "scripts/check_shared_b524_fixtures.py"
)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def test_public_copy_passes_without_sibling_checkout():
    checker.validate_bundle(checker.DEFAULT_ROOT)
    manifest = json.loads((checker.DEFAULT_ROOT / "manifest.json").read_text())
    assert manifest["evidence_grade"] == {
        "retained_description_bytes": "Proven",
        "codec_basis_and_presence": "Hypothesis",
        "omitted_context": "Unknown",
    }
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_shared_b524_fixtures.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("fault", ["digest", "omission", "identity", "join", "limits", "empty"])
def test_semantic_corruptions_are_rejected(fault):
    description, observations = checker.load_documents(checker.DEFAULT_ROOT)
    if fault == "digest":
        manifest = json.loads((checker.DEFAULT_ROOT / "manifest.json").read_text())
        manifest["digests_base64"][checker.DESCRIPTION] = "invalid"
        with pytest.raises(ValueError, match="digest"):
            checker.validate_digests(checker.DEFAULT_ROOT, manifest)
        return
    if fault == "omission":
        observations["response_payloads"] = ""
    elif fault == "identity":
        observations["observation_id"] = "synthetic_other_observation"
    elif fault == "join":
        linked = next(row for row in observations["records"] if row["description"])
        linked["description"]["record_index"] += 1
    elif fault == "limits":
        description["records"][0]["decoded"]["max"] += 1
    else:
        missing = next(row for row in description["records"] if row["raw_description_hex"] is None)
        missing["raw_description_hex"] = ""
    # Bypass byte authentication deliberately: semantic checks must reject independently.
    with pytest.raises(ValueError):
        checker.validate_documents(checker.DEFAULT_ROOT, description, observations)


@pytest.mark.parametrize(
    ("fault", "message"),
    [
        ("missing_link", "drops its description link"),
        ("missing_metadata", "available description lacks raw metadata"),
    ],
)
def test_record_omission_relations_require_semantic_validator(monkeypatch, fault, message):
    description, observations = checker.load_documents(checker.DEFAULT_ROOT)
    validator = checker.load_validator(checker.DEFAULT_ROOT / checker.VALIDATOR)
    monkeypatch.setattr(checker, "load_validator", lambda path: validator)
    if fault == "missing_link":
        matched = next(
            row
            for row in observations["records"]
            if row["description"] and row["description"]["acquisition_state"] == "matched"
        )
        matched["description"] = None
    else:
        unavailable = next(
            row
            for row in observations["records"]
            if row["description"] and row["description"]["acquisition_state"] == "unavailable"
        )
        unavailable["description"]["acquisition_state"] = "matched"
    # These faults pass JSON schema; require the loaded semantic validator's error.
    with pytest.raises(validator.ValidationError, match=message):
        checker.validate_documents(checker.DEFAULT_ROOT, description, observations)


def test_refresh_missing_source_preserves_last_known_copy(tmp_path):
    target = tmp_path / "copy"
    target.mkdir()
    retained = target / "manifest.json"
    retained.write_text("last-known-good")
    with pytest.raises((ValueError, OSError)):
        checker.refresh(tmp_path / "missing", target)
    assert retained.read_text() == "last-known-good"


def test_digest_authenticates_file_bytes_including_final_newline(tmp_path):
    shutil.copytree(checker.DEFAULT_ROOT, tmp_path / "bundle")
    root = tmp_path / "bundle"
    fixture = root / checker.NATIVE / checker.DESCRIPTION
    fixture.write_bytes(fixture.read_bytes().rstrip(b"\n"))
    with pytest.raises(ValueError, match="digest mismatch"):
        checker.validate_bundle(root)


def test_refresh_and_semantic_failure_preserve_public_bytes(tmp_path):
    with tempfile.TemporaryDirectory(prefix="b524-refresh-test-") as directory:
        source = Path(directory) / "source"
        shutil.copytree(checker.DEFAULT_ROOT, source)
        upstream = source / str(checker.VALIDATOR).removesuffix(".txt")
        upstream.write_bytes((source / checker.VALIDATOR).read_bytes())
        (source / "protocols/LICENSE").write_bytes((source / "LICENSE-CC0").read_bytes())
        (source / "LICENSE").write_bytes((source / "LICENSE-AGPL").read_bytes())

        def publish_pins():
            pins = [
                sha256((source / checker.NATIVE / name).read_bytes()).hexdigest()
                for name in (checker.DESCRIPTION, checker.OBSERVATIONS)
            ]
            (source / checker.PROFILE_PAGE).write_text("\n".join(f"`{pin}`" for pin in pins))

        publish_pins()
        target = tmp_path / "target"
        checker.refresh(source, target)
        before = {
            file.relative_to(target): file.read_bytes()
            for file in target.rglob("*")
            if file.is_file()
        }
        for name in (checker.DESCRIPTION, checker.OBSERVATIONS):
            assert (target / checker.NATIVE / name).read_bytes() == (
                checker.DEFAULT_ROOT / checker.NATIVE / name
            ).read_bytes()
        description, observations = checker.load_documents(source)
        observations["records"][0]["observed_payload_width"] = 1
        (source / checker.NATIVE / checker.OBSERVATIONS).write_text(json.dumps(observations))
        publish_pins()
        with pytest.raises(ValueError):
            checker.refresh(source, target)
        assert before == {
            file.relative_to(target): file.read_bytes()
            for file in target.rglob("*")
            if file.is_file()
        }


def test_refresh_copy_failure_leaves_last_known_good_bundle(tmp_path, monkeypatch):
    source = tmp_path / "source"
    shutil.copytree(checker.DEFAULT_ROOT, source)
    (source / str(checker.VALIDATOR).removesuffix(".txt")).write_bytes(
        (source / checker.VALIDATOR).read_bytes()
    )
    (source / "protocols/LICENSE").write_bytes((source / "LICENSE-CC0").read_bytes())
    (source / "LICENSE").write_bytes((source / "LICENSE-AGPL").read_bytes())
    pins = [
        sha256((source / checker.NATIVE / name).read_bytes()).hexdigest()
        for name in (checker.DESCRIPTION, checker.OBSERVATIONS)
    ]
    (source / checker.PROFILE_PAGE).write_text("\n".join(f"`{pin}`" for pin in pins))
    target = tmp_path / "target"
    target.mkdir()
    (target / "manifest.json").write_text("last-known-good")
    real = shutil.copyfile

    def failing(src, dst, *args, **kwargs):
        if Path(dst).name == checker.OBSERVATIONS and ".target-new-" in str(dst):
            raise OSError("disk full")
        return real(src, dst, *args, **kwargs)

    monkeypatch.setattr(shutil, "copyfile", failing)
    with pytest.raises(OSError):
        checker.refresh(source, target)
    assert (target / "manifest.json").read_text() == "last-known-good"
    assert sorted(path.name for path in tmp_path.iterdir()) == ["source", "target"]
