#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

import docs_sync_help


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _extract_readme_scan_key_flags(readme_text: str) -> list[str]:
    needle = "Key scan UX flags:"
    idx = readme_text.find(needle)
    if idx < 0:
        raise SystemExit(f"README.md missing section header: {needle!r}")

    after = readme_text[idx + len(needle) :].splitlines()
    flags: list[str] = []
    for raw in after:
        line = raw.strip()
        if not line:
            break
        # Only consider bullets in this section.
        if not line.startswith("- "):
            continue
        for match in re.findall(r"`(--[a-z0-9-]+)", line):
            flags.append(match)
    # Stable order, de-dup.
    seen: set[str] = set()
    out: list[str] = []
    for flag in flags:
        if flag in seen:
            continue
        seen.add(flag)
        out.append(flag)
    return out


def _assert_flags_exist(*, flags: list[str], help_text: str) -> None:
    missing = [flag for flag in flags if flag not in help_text]
    if missing:
        raise SystemExit(
            "README.md references scan flags not present in `scan --help`: " + ", ".join(missing)
        )


def main() -> int:
    # 1) Doc-gate: ensure the generated CLI reference is in sync.
    if docs_sync_help.main(["--check"]) != 0:
        return 1

    # 2) Doc-gate: ensure README's key scan UX flags match the actual CLI.
    readme_path = _repo_root() / "README.md"
    readme_text = readme_path.read_text(encoding="utf-8")
    flags = _extract_readme_scan_key_flags(readme_text)
    scan_help = docs_sync_help.get_help_map()["scan"]
    _assert_flags_exist(flags=flags, help_text=scan_help)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
