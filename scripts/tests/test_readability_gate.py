"""Synthetic readability ratchet contracts."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "readability", Path(__file__).resolve().parents[1] / "check_readability.py"
)
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ReadabilityGateTests(unittest.TestCase):
    def record(self, **changes):
        return {"path": "sample.py", "symbol": "work", "rule": "C901", "count": 12} | changes

    def test_clean_tree_passes(self):
        gate.compare([], [])

    def test_existing_debt_passes(self):
        gate.compare([self.record()], [self.record()])

    def test_new_debt_fails(self):
        with self.assertRaises(ValueError):
            gate.compare([self.record()], [])

    def test_grown_debt_fails(self):
        with self.assertRaises(ValueError):
            gate.compare([self.record(count=13)], [self.record()])

    def test_reduced_debt_passes(self):
        gate.compare([self.record(count=11)], [self.record()])

    def test_deleted_debt_requires_baseline_removal(self):
        with self.assertRaises(ValueError):
            gate.compare([], [self.record()])
        gate.compare([], [])

    def test_every_identity_field_is_enforced(self):
        # Dropping path, symbol, or rule from the key would admit its mutation.
        for changes in ({"path": "other.py"}, {"symbol": "other"}, {"rule": "PLR0915"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                gate.compare([self.record(**changes)], [self.record()])

    def test_duplicate_records_fail(self):
        for current, baseline in (([self.record()] * 2, []), ([], [self.record()] * 2)):
            with self.assertRaises(ValueError):
                gate.compare(current, baseline)

    def test_malformed_records_fail(self):
        for change in (
            {"path": "../sample.py"},
            {"path": "/sample.py"},
            {"count": True},
            {"count": 0},
            {"symbol": ""},
            {"rule": "F401"},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                gate.compare([self.record(**change)], [])

    def test_tool_failure_fails_even_with_json(self):
        with self.assertRaises(ValueError):
            gate.parse_output(2, "[]")

    def test_malformed_json_fails(self):
        for value in ("not json", "{}", "[{}]", '[{"code": null}]'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.parse_output(1, value)

    def test_missing_tool_fails(self):
        from unittest.mock import patch

        with (
            patch.object(gate.subprocess, "run", side_effect=FileNotFoundError),
            self.assertRaises(ValueError),
        ):
            gate.run_ruff(Path.cwd())

    def test_moved_symbol_retains_identity(self):
        source = "def work():\n    pass\n"
        self.assertEqual(gate.symbol_at(source, 1), gate.symbol_at("\n" + source, 2))
        self.assertNotEqual(
            gate.symbol_at("class Container:\n    def work(self):\n        pass\n", 2),
            gate.symbol_at(source, 1),
        )

    def test_counts_are_observed_and_naming_occurrences_accumulate(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "sample.py"
            path.write_text("def work():\n    pass\n")
            diagnostic = dict(
                code="C901",
                filename=str(path),
                location={"row": 1},
                message="work is too complex (12 > 10)",
            )
            self.assertEqual(gate.collect([diagnostic], root), [self.record()])
            diagnostic.update(code="N806", message="variable name")
            self.assertEqual(
                gate.collect([diagnostic, diagnostic], root), [self.record(rule="N806", count=2)]
            )
            diagnostic.update(code="F401")
            with self.assertRaises(ValueError):
                gate.collect([diagnostic], root)

    def test_baseline_schema_and_duplicate_json_keys_fail_closed(self):
        import tempfile

        for text in (
            "{}",
            '{"version": 1, "records": [], "extra": 0}',
            '{"version": true, "records": []}',
            '{"version": 1, "records": [], "records": []}',
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "baseline.json"
                path.write_text(text)
                with self.assertRaises(ValueError):
                    gate.load_baseline(path)

    def test_wrong_version_and_timeout_fail_closed(self):
        import subprocess
        from unittest.mock import patch

        for result in (
            subprocess.CompletedProcess([], 0, "ruff wrong"),
            subprocess.CompletedProcess([], 1, "ruff " + gate.VERSION),
        ):
            with (
                self.subTest(result=result),
                patch.object(gate.subprocess, "run", return_value=result),
                self.assertRaises(ValueError),
            ):
                gate.run_ruff(Path.cwd())
        with (
            patch.object(gate.subprocess, "run", side_effect=subprocess.TimeoutExpired("ruff", 30)),
            self.assertRaises(ValueError),
        ):
            gate.run_ruff(Path.cwd())


if __name__ == "__main__":
    unittest.main()
