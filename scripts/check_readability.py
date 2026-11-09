"""Offline readability ratchet; existing lint rules remain unconditional.

Review baseline edits manually. Counts measure reported naming occurrences or
Ruff's observed complexity/statements, keyed by path, qualified symbol and rule.
Resolved records must be removed; reductions never require baseline growth.
"""

import argparse
import ast
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.15.10"
RULES = {"C901", "PLR0915"}


def readability_rule(rule):
    return isinstance(rule, str) and (rule in RULES or re.fullmatch(r"N\d{3}", rule))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(value):
    try:
        return json.loads(value, object_pairs_hook=unique_object)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed JSON") from exc


def index(records):
    if not isinstance(records, list):
        raise ValueError("records must be an array")
    result = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "symbol", "rule", "count"}:
            raise ValueError("malformed baseline record")
        path, symbol, rule, count = (record[k] for k in ("path", "symbol", "rule", "count"))
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
            or PurePosixPath(path).as_posix() != path
            or not path.endswith(".py")
            or not isinstance(symbol, str)
            or not symbol.strip()
            or not readability_rule(rule)
            or type(count) is not int
            or count < 1
        ):
            raise ValueError("invalid baseline identity or count")
        key = (path, symbol, rule)
        if key in result:
            raise ValueError(f"duplicate record: {key}")
        result[key] = count
    return result


def compare(current, baseline):
    observed, allowed = index(current), index(baseline)
    errors = [f"unused baseline record: {key}" for key in allowed.keys() - observed.keys()]
    for key, count in observed.items():
        if key not in allowed or count > allowed[key]:
            errors.append(f"new or increased debt: {key}, observed {count}")
    if errors:
        raise ValueError("\n".join(sorted(errors)))


def symbol_at(source, row):
    names = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if child.lineno <= row <= child.end_lineno:
                    names.append(child.name)
                    visit(child)
            else:
                visit(child)

    visit(ast.parse(source))
    return ".".join(names) or "<module>"


def parse_output(returncode, output):
    if returncode not in (0, 1):
        raise ValueError(f"Ruff failed with exit {returncode}")
    diagnostics = read_json(output)
    if not isinstance(diagnostics, list):
        raise ValueError("Ruff output must be an array")
    if bool(diagnostics) != bool(returncode):
        raise ValueError("Ruff status disagrees with diagnostics")
    for item in diagnostics:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("code"), str)
            or not isinstance(item.get("filename"), str)
            or not isinstance(item.get("message"), str)
            or not isinstance(item.get("location"), dict)
            or type(item["location"].get("row")) is not int
            or item["location"]["row"] < 1
        ):
            raise ValueError("malformed Ruff diagnostic")
    return diagnostics


def run_ruff(root):
    try:
        version = subprocess.run(
            ["ruff", "--version"], capture_output=True, text=True, timeout=30, check=False
        )
        if version.returncode or version.stdout.strip() != f"ruff {VERSION}":
            raise ValueError(f"cached Ruff {VERSION} required")
        result = subprocess.run(
            [
                "ruff",
                "check",
                ".",
                "--no-cache",
                "--no-fix",
                "--output-format",
                "json",
                "--extend-select",
                "N,C901,PLR0915",
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=150,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"cached Ruff unavailable: {type(exc).__name__}") from exc
    return parse_output(result.returncode, result.stdout)


def collect(diagnostics, root):
    counts = {}
    for item in diagnostics:
        rule = item["code"]
        if not readability_rule(rule):
            raise ValueError(f"existing lint rule failed: {rule}")
        try:
            path = Path(item["filename"]).resolve().relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError("Ruff path outside repository") from exc
        source = (root / path).read_text()
        row = item["location"]["row"]
        if row > len(source.splitlines()):
            raise ValueError("Ruff row outside source")
        symbol = symbol_at(source, row)
        count = 1
        if rule in RULES:
            match = re.search(r"\((\d+) > \d+\)", item["message"])
            if not match:
                raise ValueError("missing observed complexity or statement count")
            count = int(match[1])
        key = (path, symbol, rule)
        counts[key] = counts.get(key, 0) + count
    return [dict(path=p, symbol=s, rule=r, count=c) for (p, s, r), c in sorted(counts.items())]


def load_baseline(path):
    payload = read_json(path.read_text())
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "records"}
        or type(payload["version"]) is not int
        or payload["version"] != 1
    ):
        raise ValueError("unsupported baseline schema")
    index(payload["records"])
    return payload["records"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.discover(
            str(ROOT / "scripts/tests"), pattern="test_readability_gate.py"
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() and result.testsRun > 0 else 1
    try:
        baseline = load_baseline(ROOT / "scripts/readability-baseline.json")
        records = collect(run_ruff(ROOT), ROOT)
        compare(records, baseline)
    except (ValueError, OSError, SyntaxError) as exc:
        print(f"Readability check failed: {exc}", file=sys.stderr)
        return 1
    print(f"Readability check passed: {len(records)} measured debt records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
