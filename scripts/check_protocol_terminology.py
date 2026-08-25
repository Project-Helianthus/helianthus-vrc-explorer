#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re
import subprocess
import sys

_TERMS_HEX = ("6d6173746572", "736c617665")
_BANNED_TERMS = tuple(bytes.fromhex(value).decode("ascii") for value in _TERMS_HEX)
_BANNED_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(term) for term in _BANNED_TERMS) + r")\b",
    re.IGNORECASE,
)


def _iter_tracked_paths(repo_root: pathlib.Path) -> list[pathlib.Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    paths: list[pathlib.Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        paths.append(repo_root / raw.decode("utf-8"))
    return paths


def _is_binary(path: pathlib.Path) -> bool:
    head = path.read_bytes()[:4096]
    return b"\0" in head


def main() -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    violations: list[str] = []

    for path in _iter_tracked_paths(repo_root):
        if not path.is_file() or _is_binary(path):
            continue
        relative = path.relative_to(repo_root).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            match = _BANNED_PATTERN.search(line)
            if match is None:
                continue
            violations.append(f"{relative}:{line_no}: {match.group(1)}")

    if violations:
        print(
            "Found legacy protocol role terms. Use initiator/target wording instead.",
            file=sys.stderr,
        )
        print("\n".join(violations), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
