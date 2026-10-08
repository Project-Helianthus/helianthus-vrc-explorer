from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest
from textual.widgets import Tabs

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


def test_textual_browse_exposes_only_config_and_state_without_address_column() -> None:
    bindings = {(binding.key, binding.action) for binding in browse_textual._BrowseApp.BINDINGS}
    assert ("1", "tab_config") in bindings
    assert ("2", "tab_state") in bindings
    assert not any("config_limits" in action for _key, action in bindings)
    assert browse_textual._tab_id("config") == "tab-config"
    assert browse_textual._tab_id("state") == "tab-state"

    source = Path(browse_textual.__file__ or "").read_text(encoding="utf-8")
    assert 'Tab("Config-Limits"' not in source
    assert '"Address",' not in source


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


def test_headless_browse_hides_config_state_tabs_for_system_information() -> None:
    artifact = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "system_information": [
                {
                    "identifier": "0x0000",
                    "name": "circuit_count",
                    "value": 2,
                    "raw_hex": "00000040",
                }
            ],
        },
        "operations": {},
    }

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test() as pilot:
            tree = app.query_one("#browse-tree")
            tree.select_node(app._tree_node_by_ref["b524:section:system_information"])
            await pilot.pause()
            assert app.query_one("#browse-tabs", Tabs).display is False
            assert [row.row_id for row in app._table_rows] == ["b524:system_information:0x0000"]

    asyncio.run(exercise())
