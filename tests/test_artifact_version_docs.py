from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CURRENT_SCAN_VERSION = re.compile(r"^Current scan artifact schema: `([^`]+)`\.$", re.MULTILINE)


def _scan_schema_version() -> str:
    source = _ROOT / "src/helianthus_vrc_explorer/artifact_schema.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    values = [
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "CURRENT_ARTIFACT_SCHEMA_VERSION"
            for target in node.targets
        )
    ]
    if len(values) != 1 or not isinstance(values[0], str):
        raise AssertionError("Expected one literal string scan schema version")
    return values[0]


def _assert_current_scan_version(text: str, expected: str) -> None:
    versions = _CURRENT_SCAN_VERSION.findall(text)
    if versions != [expected]:
        raise AssertionError(f"Expected one current scan schema statement for {expected!r}")


def _current_documents() -> dict[str, str]:
    changelog = (_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = changelog.split("## Unreleased\n", 1)[1].split("\n## ", 1)[0]
    return {
        "CHANGELOG.md (Unreleased)": unreleased,
        "docs/shared-evidence-contract.md": (_ROOT / "docs/shared-evidence-contract.md").read_text(
            encoding="utf-8"
        ),
    }


class ArtifactVersionDocumentationTests(unittest.TestCase):
    def test_current_scan_version_matches_writer(self) -> None:
        version = _scan_schema_version()
        for page, text in _current_documents().items():
            with self.subTest(page=page):
                _assert_current_scan_version(text, version)

    def test_stale_current_statement_is_rejected_in_each_page(self) -> None:
        version = _scan_schema_version()
        for page, text in _current_documents().items():
            with self.subTest(page=page):
                stale = _CURRENT_SCAN_VERSION.sub("Current scan artifact schema: `2.3`.", text)
                self.assertNotEqual(stale, text)
                with self.assertRaises(AssertionError):
                    _assert_current_scan_version(stale, version)

    def test_missing_current_statement_is_rejected(self) -> None:
        with self.assertRaises(AssertionError):
            _assert_current_scan_version("Historical scan schema: `2.3`.", _scan_schema_version())

    def test_duplicate_current_statements_are_rejected(self) -> None:
        version = _scan_schema_version()
        statement = f"Current scan artifact schema: `{version}`.\n"
        with self.assertRaises(AssertionError):
            _assert_current_scan_version(statement * 2, version)

    def test_other_version_domains_and_history_are_not_scan_versions(self) -> None:
        version = _scan_schema_version()
        text = (
            f"Current scan artifact schema: `{version}`.\n"
            "Application baseline: integer `2`. Native evidence: `/v1`.\n"
            "Historical scan artifacts: `2.3`.\n"
        )
        _assert_current_scan_version(text, version)
