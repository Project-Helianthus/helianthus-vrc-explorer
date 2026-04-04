#!/usr/bin/env python3
from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ForbiddenPattern:
    description: str
    path: str
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class RequiredPattern:
    description: str
    path: str
    pattern: re.Pattern[str]


FORBIDDEN_PATTERNS: tuple[ForbiddenPattern, ...] = (
    ForbiddenPattern(
        description="unknown-group implicit [0x02, 0x06] fallback in scanner opcode helpers",
        path="src/helianthus_vrc_explorer/scanner/register.py",
        pattern=re.compile(
            r"if\s+config\s+is\s+None:\s*return\s*\[\s*0x02\s*,\s*0x06\s*\]",
            re.MULTILINE,
        ),
    ),
    ForbiddenPattern(
        description="unknown-group implicit (0x02, 0x06) fallback in dummy transport",
        path="src/helianthus_vrc_explorer/transport/dummy.py",
        pattern=re.compile(
            r"if\s+config\s+is\s+None:\s*return\s*\(\s*0x02\s*,\s*0x06\s*\)",
            re.MULTILINE,
        ),
    ),
    ForbiddenPattern(
        description="GG-only register identity tuple shortcut",
        path="src/helianthus_vrc_explorer/scanner/identity.py",
        pattern=re.compile(r"return\s*\(\s*group\s*,\s*instance\s*,\s*register\s*\)"),
    ),
)


REQUIRED_PATTERNS: tuple[RequiredPattern, ...] = (
    RequiredPattern(
        description="opcode-first register identity return tuple",
        path="src/helianthus_vrc_explorer/scanner/identity.py",
        pattern=re.compile(r"return\s*\(\s*opcode\s*,\s*group\s*,\s*instance\s*,\s*register\s*\)"),
    ),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tracked_paths(repo_root: Path) -> set[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=repo_root,
        check=True,
        capture_output=True,
    )
    return {raw.decode("utf-8") for raw in result.stdout.split(b"\0") if raw}


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def main() -> int:
    repo_root = _repo_root()
    tracked = _tracked_paths(repo_root)
    violations: list[str] = []

    for check in FORBIDDEN_PATTERNS:
        if check.path not in tracked:
            continue
        content = (repo_root / check.path).read_text(encoding="utf-8", errors="ignore")
        for match in check.pattern.finditer(content):
            line = _line_number(content, match.start())
            violations.append(f"{check.path}:{line}: forbidden pattern: {check.description}")

    for check in REQUIRED_PATTERNS:
        if check.path not in tracked:
            violations.append(
                f"{check.path}: missing required file for guard check: {check.description}"
            )
            continue
        content = (repo_root / check.path).read_text(encoding="utf-8", errors="ignore")
        if check.pattern.search(content) is None:
            violations.append(f"{check.path}: missing required pattern: {check.description}")

    if violations:
        print(
            (
                "B524 namespace guardrails failed. Remove GG-centric fallbacks "
                "and keep opcode-first identity."
            ),
            file=sys.stderr,
        )
        print("\n".join(violations), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
