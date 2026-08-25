#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class HelpSection:
    key: str
    argv: tuple[str, ...]


_SECTIONS: tuple[HelpSection, ...] = (
    HelpSection("root", ()),
    HelpSection("scan", ("scan",)),
    HelpSection("browse", ("browse",)),
    HelpSection("discover", ("discover",)),
)

_ANSI_ESCAPE_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _run_help(*argv: str) -> str:
    env = os.environ.copy()
    # Make output stable across environments (CI, local, different terminals).
    # IMPORTANT: do not respect existing COLUMNS/LINES/TERM, as CI may set them and
    # that can change wrapping and box layout in Typer/Rich help output.
    env["COLUMNS"] = "120"
    env["LINES"] = "60"
    env["TERM"] = "xterm-256color"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(_repo_root() / "src") + os.pathsep + env.get("PYTHONPATH", "")

    cmd = [sys.executable, "-m", "helianthus_vrc_explorer", *argv, "--help"]
    res = subprocess.run(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise SystemExit(f"help command failed: {' '.join(cmd)}\n{res.stdout}")
    # Normalize line endings + trim right-padding whitespace (Rich often pads to terminal width,
    # and exact padding can vary by platform/terminal environment).
    text = res.stdout.replace("\r\n", "\n")
    # In CI, Typer/Rich may emit ANSI SGR sequences even when stdout is captured. Strip them so
    # the embedded help blocks are stable and readable in markdown.
    text = _ANSI_ESCAPE_RE.sub("", text)
    lines = [line.rstrip() for line in text.splitlines()]
    return "\n".join(lines).rstrip() + "\n"


def get_help_map() -> dict[str, str]:
    return {section.key: _run_help(*section.argv) for section in _SECTIONS}


def render_cli_reference_with_help(cli_reference_md: str, *, help_map: dict[str, str]) -> str:
    updated = cli_reference_md
    for key, text in help_map.items():
        begin = f"<!-- BEGIN CLI HELP:{key} -->"
        end = f"<!-- END CLI HELP:{key} -->"
        pattern = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        replacement = f"{begin}\n\n```text\n{text}```\n\n{end}"
        if not pattern.search(updated):
            raise SystemExit(f"Missing CLI help markers in CLI reference: {begin} ... {end}")
        updated = pattern.sub(replacement, updated, count=1)
    return updated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Sync CLI --help blocks into docs/cli-reference.md"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail if the CLI reference is out of sync (do not write changes).",
    )
    parser.add_argument(
        "--docs-path",
        type=Path,
        default=_repo_root() / "docs" / "cli-reference.md",
        help="Path to the CLI reference (defaults to docs/cli-reference.md).",
    )
    args = parser.parse_args(argv)

    docs_path: Path = args.docs_path
    original = docs_path.read_text(encoding="utf-8")
    help_map = get_help_map()
    rendered = render_cli_reference_with_help(original, help_map=help_map)

    if rendered == original:
        return 0
    if args.check:
        sys.stderr.write("docs/cli-reference.md is out of sync with CLI --help output.\n")
        # Print a small diff to make CI failures actionable.
        import difflib

        diff = difflib.unified_diff(
            original.splitlines(True),
            rendered.splitlines(True),
            fromfile=str(docs_path),
            tofile=f"{docs_path} (generated)",
        )
        for idx, line in enumerate(diff):
            if idx >= 200:
                sys.stderr.write("... (diff truncated)\n")
                break
            sys.stderr.write(line)
        return 1
    docs_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
