"""Keep public repository content independent of private workspaces."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_HANDOFFS = {".REPORT-344.md", ".pr-body-344.md"}
PRIVATE_ROOTS = (
    "/" + "Users/",
    "/" + "Volumes/",
    "/" + "home/",
    "~" + "/",
    "C:" + "\\Users\\",
)
SIBLING_CHECKOUT = re.compile(r"\bROOT\s*\.\s*parent\s*/|(?:\.\./)+(?:[^\s\"']*/)?docs-ebus\b")
WORK_REPORT = re.compile(r"\.(?:PART.*|(?:REPORT.*|pr-body.*)\.md)$", re.IGNORECASE)


def tracked_paths(root: Path) -> set[Path]:
    """Return files tracked by git; empty outside a checkout."""
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            names = result.stdout.decode("utf-8", errors="replace").split("\0")
            return {root / name for name in names if name}
    return set()


def candidate_paths(root: Path) -> list[Path]:
    """Return tracked and untracked-but-not-ignored files, or every file outside a checkout."""
    if (root / ".git").exists():
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            names = result.stdout.decode("utf-8", errors="replace").split("\0")
            return sorted({root / name for name in names if name})
    return sorted(root.rglob("*"))


def hygiene_violations(root: Path) -> list[str]:
    violations = []
    tracked = tracked_paths(root)
    for path in candidate_paths(root):
        relative = path.relative_to(root)
        # Local-artifact exemptions apply to untracked files only.
        if path not in tracked and (
            relative.parts[0] in {".git", ".tmp"} or relative.as_posix() in LOCAL_HANDOFFS
        ):
            continue
        if WORK_REPORT.fullmatch(path.name):
            violations.append(f"{relative.as_posix()}: work report")
        if path.is_symlink():
            # Inspect the stored link target; it may dangle in a fresh checkout.
            content = os.readlink(path).encode("utf-8", errors="replace")
        elif path.is_file():
            content = path.read_bytes()
        else:
            continue
        if b"\0" in content:
            continue
        text = content.decode("utf-8", errors="replace")
        if any(marker.casefold() in text.casefold() for marker in PRIVATE_ROOTS):
            violations.append(f"{relative.as_posix()}: private checkout path")
        if SIBLING_CHECKOUT.search(text):
            violations.append(f"{relative.as_posix()}: sibling checkout path")
    return violations


class PublicRepositoryHygieneTests(unittest.TestCase):
    def test_public_repository_is_portable(self):
        self.assertEqual(hygiene_violations(ROOT), [])

    def test_private_path_roots_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for marker in PRIVATE_ROOTS:
                with self.subTest(root=marker):
                    (root / "example.md").write_text(marker + "example/project")
                    self.assertEqual(len(hygiene_violations(root)), 1)

    def test_work_report_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (
                ".PART1-REPORT.md",
                ".PART2-REPORT.md",
                ".PART-extra.md",
                ".PART-notes.txt",
                ".REPORT.md",
            ):
                with self.subTest(name=name):
                    path = root / name
                    path.write_text("Local notes")
                    self.assertEqual(len(hygiene_violations(root)), 1)
                    path.unlink()

    def test_sibling_checkout_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for text in ("ROOT" + '.parent / "docs"', ".." + "/docs-ebus"):
                with self.subTest(expression=text):
                    (root / "example.py").write_text(text)
                    self.assertEqual(len(hygiene_violations(root)), 1)

    def test_only_root_local_artifacts_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in (".git/config", ".tmp/example.md", *LOCAL_HANDOFFS):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(PRIVATE_ROOTS[0] + "example/project")
            self.assertEqual(hygiene_violations(root), [])
            for name in ("docs/.tmp/example.md", "docs/.REPORT-344.md", "docs/.git/config"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(PRIVATE_ROOTS[0] + "example/project")
            self.assertEqual(len(hygiene_violations(root)), 4)

    def test_tracked_local_artifacts_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            names = (".tmp/example.md", *sorted(LOCAL_HANDOFFS))
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(PRIVATE_ROOTS[0] + "example/project")
            self.assertEqual(hygiene_violations(root), [])
            subprocess.run(
                ["git", "-C", str(root), "add", "-f", "--", *names],
                check=True,
            )
            violations = hygiene_violations(root)
            for name in names:
                self.assertIn(f"{name}: private checkout path", violations)

    def test_dangling_symlink_targets_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, target in enumerate((PRIVATE_ROOTS[2] + "alice/project", ".." + "/docs-ebus")):
                (root / f"link{index}").symlink_to(target)
            self.assertEqual(len(hygiene_violations(root)), 2)

    def test_public_docs_and_legal_text_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("LICENSE", "README.md", "fixtures/example.json", "src/example.py"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(PRIVATE_ROOTS[0] + "example/project")
            self.assertEqual(len(hygiene_violations(root)), 4)


if __name__ == "__main__":
    unittest.main()
