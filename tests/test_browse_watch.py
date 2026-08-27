from __future__ import annotations

import ast
from pathlib import Path

import pytest

import helianthus_vrc_explorer.ui.browse_textual as browse_textual
from helianthus_vrc_explorer.ui.browse_textual import (
    compute_change_indicator,
    format_watch_interval,
    parse_watch_interval,
    run_browse_from_artifact,
)


def test_parse_watch_interval_accepts_supported_values() -> None:
    assert parse_watch_interval("250ms") == 0.25
    assert parse_watch_interval("500ms") == 0.5
    assert parse_watch_interval("1s") == 1.0
    assert parse_watch_interval("2") == 2.0
    assert parse_watch_interval("5.0") == 5.0
    assert parse_watch_interval("3s") is None


def test_format_watch_interval_formats_seconds_and_milliseconds() -> None:
    assert format_watch_interval(0.25) == "250ms"
    assert format_watch_interval(0.5) == "500ms"
    assert format_watch_interval(1.0) == "1s"
    assert format_watch_interval(2.0) == "2s"


def test_compute_change_indicator_numeric_and_text() -> None:
    assert compute_change_indicator("10", "12") == "▲"
    assert compute_change_indicator("12", "10") == "▼"
    assert compute_change_indicator("10", "10") == "-"
    assert compute_change_indicator("foo", "bar") == "Δ"


def test_textual_browse_classes_are_module_scoped() -> None:
    source_path = Path(browse_textual.__file__ or "")
    tree = ast.parse(source_path.read_text(encoding="utf-8"))

    class FunctionNestedClassCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.function_depth = 0
            self.names: set[str] = set()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.function_depth += 1
            self.generic_visit(node)
            self.function_depth -= 1

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.function_depth += 1
            self.generic_visit(node)
            self.function_depth -= 1

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            if self.function_depth:
                self.names.add(node.name)
            self.generic_visit(node)

    collector = FunctionNestedClassCollector()
    collector.visit(tree)

    for name in {
        "_FocusableStatic",
        "_InputDialog",
        "_HelpDialog",
        "_ConfirmDialog",
        "_BrowseApp",
    }:
        assert name not in collector.names


def test_run_browse_from_artifact_preserves_artifact_and_allow_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    class _FakeApp:
        def __init__(self, artifact: dict[str, object], *, allow_write: bool, store) -> None:  # noqa: ANN001
            captured["artifact"] = artifact
            captured["allow_write"] = allow_write
            captured["store"] = store

        def run(self) -> None:
            captured["ran"] = True

    artifact = {"meta": {"destination_address": "0x15"}, "groups": {}}
    monkeypatch.setattr(browse_textual, "_TEXTUAL_IMPORT_ERROR", None)
    monkeypatch.setattr(browse_textual, "_BrowseApp", _FakeApp)

    assert run_browse_from_artifact(artifact, allow_write=True) is None
    assert captured["artifact"] is artifact
    assert captured["allow_write"] is True
    assert captured["ran"] is True


def test_run_browse_from_artifact_preserves_lazy_textual_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = ModuleNotFoundError("No module named 'textual'")
    error.name = "textual"
    monkeypatch.setattr(browse_textual, "_TEXTUAL_IMPORT_ERROR", error)

    with pytest.raises(ModuleNotFoundError) as raised:
        run_browse_from_artifact({}, allow_write=False)

    assert raised.value is error
