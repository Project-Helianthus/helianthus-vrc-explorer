from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_docs_sync_module():
    script_path = _repo_root() / "scripts" / "docs_sync_help.py"
    spec = importlib.util.spec_from_file_location("docs_sync_help", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_cli_reference_help_renderer_replaces_each_marked_section() -> None:
    module = _load_docs_sync_module()
    source = "\n".join(
        [
            "<!-- BEGIN CLI HELP:root -->",
            "old root",
            "<!-- END CLI HELP:root -->",
            "<!-- BEGIN CLI HELP:scan -->",
            "old scan",
            "<!-- END CLI HELP:scan -->",
        ]
    )

    rendered = module.render_cli_reference_with_help(
        source,
        help_map={"root": "root help\n", "scan": "scan help\n"},
    )

    assert "old root" not in rendered
    assert "old scan" not in rendered
    assert "```text\nroot help\n```" in rendered
    assert "```text\nscan help\n```" in rendered
