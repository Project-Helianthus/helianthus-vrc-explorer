"""The HTML report's styles and scripts ship as package data loaded through importlib.resources."""

from __future__ import annotations

import re
import tomllib
from importlib.resources import files
from pathlib import Path

import pytest

from helianthus_vrc_explorer.ui.html_report import render_html_report

_ASSET_PACKAGE = "helianthus_vrc_explorer.ui.report_assets"
_ASSET_NAMES = ("report.css", "report.js")
_PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _asset(name: str) -> str:
    return files(_ASSET_PACKAGE).joinpath(name).read_bytes().decode("utf-8")


def _between(text: str, opening: str, closing: str) -> str:
    assert text.count(opening) == 1, opening
    start = text.index(opening) + len(opening)
    end = text.index(closing, start)
    return text[start:end]


@pytest.mark.parametrize("name", _ASSET_NAMES)
def test_report_asset_loads_through_importlib_resources(name: str) -> None:
    resource = files(_ASSET_PACKAGE).joinpath(name)
    assert resource.is_file()
    text = _asset(name)
    assert text.strip()
    assert text.endswith("\n")
    assert "\r" not in text


def test_report_assets_hold_the_style_and_script_bodies() -> None:
    css = _asset("report.css")
    js = _asset("report.js")
    assert "<style" not in css and "</style>" not in css
    assert "<script" not in js and "</script>" not in js
    assert ":root {" in css
    assert "function parseTypedValue(" in js
    assert "renderActiveTab();" in js


def test_rendered_report_embeds_the_stylesheet_in_place() -> None:
    html = render_html_report({})
    assert _between(html, "    <style>\n", "    </style>\n") == _asset("report.css")


def test_rendered_report_embeds_the_script_in_place_with_its_placeholders_substituted() -> None:
    js = _asset("report.js")
    html = render_html_report({})
    rendered = _between(html, "    <script>\n", "    </script>\n  </body>")
    tokens = _PLACEHOLDER_RE.findall(js)
    assert tokens, "the script carries the report's client-side placeholders"
    chunks = _PLACEHOLDER_RE.split(js)
    pattern = "(.*?)".join(re.escape(chunk) for chunk in chunks)
    match = re.fullmatch(pattern, rendered, flags=re.DOTALL)
    assert match is not None
    for token, value in zip(tokens, match.groups(), strict=True):
        assert value != token, token
        assert _PLACEHOLDER_RE.search(value) is None, token


def test_rendered_report_substitutes_placeholders_in_a_single_pass() -> None:
    tokens = set(_PLACEHOLDER_RE.findall(_asset("report.js")))
    tokens.update(("__TITLE__", "__IDENTITY_CARD__", "__ARTIFACT_JSON__"))
    for token in sorted(tokens):
        html = render_html_report({}, title=token)
        # A substituted value that spells another placeholder stays literal.
        assert f"<title>{token}</title>" in html
        assert html.count(token) == 1, token


def test_pyproject_declares_the_report_assets_as_package_data() -> None:
    pyproject = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"]["package-data"]
    assert sorted(package_data[_ASSET_PACKAGE]) == sorted(_ASSET_NAMES)
    package_dir = _REPO_ROOT / "src" / Path(*_ASSET_PACKAGE.split("."))
    for name in _ASSET_NAMES:
        assert (package_dir / name).is_file()
    assert (package_dir / "__init__.py").is_file()
