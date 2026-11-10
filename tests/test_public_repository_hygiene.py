"""Keep public repository content independent of private workspaces."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LOCAL_HANDOFFS = {".REPORT-344.md", ".pr-body-344.md"}
PRIVATE_ROOTS = (
    "/" + "Users/",
    "/" + "Volumes/",
    "/" + "home/",
    "~" + "/",
    "C:" + "\\Users\\",
    "/" + "workspace/",
    "/" + "root/",
)
SIBLING_CHECKOUT = re.compile(r"\bROOT\s*\.\s*parent\s*/|(?:\.\./)+(?:[^\s\"']*/)?docs-ebus\b")
WORK_REPORT = re.compile(r"\.(?:PART.*|(?:REPORT.*|pr-body.*)\.md)$", re.IGNORECASE)
# A path starts at a token boundary, not within a URL or another path, and
# contains a component below the root marker. Bare roots are generic prose.
PATH_BOUNDARY = rb"(?<![A-Za-z0-9_./~:%\\-])"
PRIVATE_PATH = re.compile(
    PATH_BOUNDARY
    + rb"(?:"
    + b"|".join(re.escape(marker.encode()) for marker in PRIVATE_ROOTS if marker != "~" + "/")
    + rb")[A-Za-z0-9_.-]+",
    re.IGNORECASE,
)
HOME_PATH = re.compile(PATH_BOUNDARY + rb"~" + rb"/[A-Za-z0-9_.-]+")
BINARY_HOME_PATH = re.compile(PATH_BOUNDARY + rb"~" + rb"/[A-Za-z0-9_.-]+(?:[/\s\x00]|$)")


def tracked_paths(root: Path) -> set[Path]:
    """Return files tracked by git; empty outside a checkout."""
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached"],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            names = os.fsdecode(result.stdout).split("\0")
            return {root / name for name in names if name}
    return set()


def candidate_paths(root: Path) -> list[Path]:
    """Return tracked files, or every file outside a checkout."""
    if (root / ".git").exists():
        result = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
            ],
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            names = os.fsdecode(result.stdout).split("\0")
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
        binary = b"\0" in content
        # The two-byte home marker can occur by chance in compressed data.
        home_path = BINARY_HOME_PATH if binary else HOME_PATH
        if PRIVATE_PATH.search(content) or home_path.search(content):
            violations.append(f"{relative.as_posix()}: private checkout path")
        if binary:
            continue
        text = content.decode("utf-8", errors="replace")
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

    def test_public_urls_and_generic_roots_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for marker in PRIVATE_ROOTS:
                examples = (
                    f"The generic root `{marker}` is platform dependent.",
                    "https://example.com" + marker + "help",
                    "https://example.com/docs" + marker + "help",
                )
                for text in examples:
                    with self.subTest(text=text):
                        (root / "example.md").write_text(text)
                        self.assertEqual(hygiene_violations(root), [])

    def test_private_paths_in_prose_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for marker in PRIVATE_ROOTS:
                for template in ('Path: "{}"', "path={}", "Use `{}` here"):
                    with self.subTest(marker=marker, template=template):
                        (root / "example.md").write_text(
                            template.format(marker + "example/project")
                        )
                        self.assertEqual(
                            hygiene_violations(root), ["example.md: private checkout path"]
                        )

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

    def test_non_home_workspace_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for workspace in ("workspace", "root"):
                with self.subTest(workspace=workspace):
                    (root / "example.md").write_text(
                        "/" + workspace + "/example-project/artifact.json"
                    )
                    self.assertEqual(
                        hygiene_violations(root), ["example.md: private checkout path"]
                    )

    @unittest.skipUnless(os.name == "posix", "Non-UTF-8 filenames require POSIX")
    def test_tracked_non_utf8_filenames_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            name = os.fsdecode(b"example-\xff.txt")
            path = root / name
            result = subprocess.CompletedProcess([], 0, stdout=b"example-\xff.txt\0")
            # Some POSIX filesystems reject these names; simulate Git's raw output
            # and the file read while exercising both enumeration helpers.
            with patch.object(subprocess, "run", return_value=result):
                self.assertEqual(tracked_paths(root), {path})
                self.assertEqual(candidate_paths(root), [path])
                with (
                    patch.object(Path, "is_file", return_value=True),
                    patch.object(
                        Path,
                        "read_bytes",
                        autospec=True,
                        return_value=(PRIVATE_ROOTS[2] + "example/project").encode(),
                    ) as read_bytes,
                ):
                    self.assertEqual(hygiene_violations(root), [f"{name}: private checkout path"])
                    read_bytes.assert_called_once_with(path)

    def test_tracked_binary_private_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            path = root / "example.bin"
            path.write_bytes(b"\0\xffpublic content~" + b"/\xff~" + b"/e\x95")
            subprocess.run(["git", "-C", str(root), "add", path.name], check=True)
            self.assertEqual(hygiene_violations(root), [])
            for marker in PRIVATE_ROOTS:
                for variant in (marker, marker.upper()):
                    with self.subTest(marker=variant):
                        path.write_bytes(b"\0\xff" + variant.encode("utf-8") + b"example/project")
                        self.assertEqual(
                            hygiene_violations(root),
                            ["example.bin: private checkout path"],
                        )

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

    def test_untracked_and_ignored_checkout_files_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            (root / ".gitignore").write_text(".venv/\n.tox/\nartifacts/\nlocal.conf\n")
            subprocess.run(["git", "-C", str(root), "add", ".gitignore"], check=True)
            for name in (
                ".venv/bin/example",
                ".tox/bin/example",
                "artifacts/example.md",
                "local.conf",
                "untracked.md",
            ):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(PRIVATE_ROOTS[2] + "example/project")
            self.assertEqual(hygiene_violations(root), [])
            subprocess.run(["git", "-C", str(root), "add", "untracked.md"], check=True)
            self.assertEqual(hygiene_violations(root), ["untracked.md: private checkout path"])

    def test_dangling_symlink_targets_are_inspected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
            targets = (PRIVATE_ROOTS[2] + "alice/project", ".." + "/docs-ebus")
            for index, target in enumerate(targets):
                (root / f"link{index}").symlink_to(target)
            subprocess.run(["git", "-C", str(root), "add", "link0", "link1"], check=True)
            self.assertEqual(
                hygiene_violations(root),
                ["link0: private checkout path", "link1: sibling checkout path"],
            )

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
