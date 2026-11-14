#!/usr/bin/env python3
"""Check the isolated public native pair and its published copies.

Refresh the vendored pair from an explicit docs root, or publish the vendored
pair to the public and packaged fixture copies.
"""

from __future__ import annotations

import argparse
import base64
import csv
import ctypes
import errno
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

from jsonschema import Draft202012Validator

REPOSITORY = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = REPOSITORY / "fixtures/b524_shared"
# Public and packaged copies are byte-identical to the vendored, page-pinned pair.
PUBLISHED_COPIES = (REPOSITORY / "fixtures", REPOSITORY / "src/helianthus_vrc_explorer/fixtures")
DESCRIPTION = "b524-basv0-description-profile-v1.json"
OBSERVATIONS = "b524-basv0-register-observations-v1.json"
NATIVE = Path("protocols/vaillant/fixtures")
VALIDATOR = Path("scripts/validate_b524_basv0_description_profile.py.txt")
PROFILE_PAGE = Path("protocols/vaillant/ebus-vaillant-b524-basv0-profile-v1.md")
REGISTER_MAP = Path("protocols/vaillant/ebus-vaillant-b524-register-map.md")
CALENDAR = NATIVE / "b524-op02-calendar-clock-selectors.csv"


def load_validator(path):
    # Keep the AGPL source verbatim as a test resource, outside Explorer's package.
    loader = importlib.machinery.SourceFileLoader("public_b524_validator", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    # Avoid writing bytecode beside read-only source checkouts.
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module


def load_documents(root):
    return tuple(
        json.loads((root / NATIVE / name).read_text()) for name in (DESCRIPTION, OBSERVATIONS)
    )


def validate_digests(root, manifest):
    if set(manifest["digests_base64"]) != {DESCRIPTION, OBSERVATIONS}:
        raise ValueError("digest manifest must authenticate exactly the native pair")
    for name, expected in manifest["digests_base64"].items():
        actual = base64.b64encode(sha256((root / NATIVE / name).read_bytes()).digest()).decode()
        if actual != expected:
            raise ValueError(f"published fixture digest mismatch: {name}")


def validate_documents(root, description, observations):
    for name, document in ((DESCRIPTION, description), (OBSERVATIONS, observations)):
        schema = json.loads(
            (root / NATIVE / name.replace("-v1.json", "-schema-v1.json")).read_text()
        )
        Draft202012Validator.check_schema(schema)
        errors = list(Draft202012Validator(schema).iter_errors(document))
        if errors:
            raise ValueError(f"{name}: {errors[0].message}")
    validator = load_validator(root / VALIDATOR)
    validator.REGISTER_MAP = root / REGISTER_MAP
    validator.CALENDAR_CLOCK_CSV = root / CALENDAR
    validator.validate_documents(description, observations, DESCRIPTION)


def validate_bundle(root):
    manifest = json.loads((root / "manifest.json").read_text())
    validate_digests(root, manifest)
    validate_documents(root, *load_documents(root))


def validate_published_copies(root=DEFAULT_ROOT, copies=PUBLISHED_COPIES):
    """Require every published copy to carry exactly the authenticated vendored bytes."""
    manifest = json.loads((root / "manifest.json").read_text())
    for directory in copies:
        for name in (DESCRIPTION, OBSERVATIONS):
            data = (directory / name).read_bytes()
            actual = base64.b64encode(sha256(data).digest()).decode()
            if actual != manifest["digests_base64"][name]:
                raise ValueError(f"published copy digest mismatch: {directory / name}")
            if data != (root / NATIVE / name).read_bytes():
                raise ValueError(
                    f"published copy differs from the vendored pair: {directory / name}"
                )


def publish_copies(root=DEFAULT_ROOT, copies=PUBLISHED_COPIES):
    """Copy the validated vendored pair to every published location as one transaction.

    The vendored bundle is validated first, so a failing bundle leaves every copy
    untouched. Every output is staged beside its target before any is committed;
    if a later replacement fails, the earlier ones are restored.
    """
    validate_bundle(root)
    targets = [directory / name for directory in copies for name in (DESCRIPTION, OBSERVATIONS)]
    staged = {}
    previous = {}
    committed = []
    try:
        for target in targets:
            name = target.name
            handle, path = tempfile.mkstemp(prefix=f".{name}-", dir=target.parent)
            os.close(handle)
            staged[target] = Path(path)
            shutil.copyfile(root / NATIVE / name, path)
            # Keep the published file's permissions rather than the private temp mode.
            if target.exists():
                shutil.copymode(target, path)
                previous[target] = target.read_bytes(), target.stat().st_mode
            else:
                os.chmod(path, 0o644)
        for target in targets:
            os.replace(staged[target], target)
            committed.append(target)
    except BaseException:
        for target in committed:
            if target in previous:
                data, mode = previous[target]
                handle, path = tempfile.mkstemp(prefix=f".{target.name}-", dir=target.parent)
                with os.fdopen(handle, "wb") as out:
                    out.write(data)
                os.chmod(path, mode & 0o7777)
                os.replace(path, target)
            else:
                target.unlink(missing_ok=True)
        raise
    finally:
        for path in staged.values():
            if path.exists():
                path.unlink()
    validate_published_copies(root, copies)


def refresh(source, target=DEFAULT_ROOT):
    """Validate a staged public subset before replacing any last-known-good files."""
    source = source.resolve()
    if source == target.resolve() or target.resolve().is_relative_to(source):
        raise ValueError("source root must be separate from the vendored target")
    # Full UTF-8 fixture file bytes, including whitespace and final newline, are
    # the canonical digest input specified by the public profile page.
    page = (source / PROFILE_PAGE).read_text()
    pins = re.findall(r"`([0-9a-f]{64})`", page)
    if len(pins) != 2:
        raise ValueError("public profile must cite exactly two native fixture digests")
    upstream_validator = source / str(VALIDATOR).removesuffix(".txt")
    validator = load_validator(upstream_validator)
    with tempfile.TemporaryDirectory(prefix="b524-shared-") as directory:
        staged = Path(directory)
        for name in (DESCRIPTION, OBSERVATIONS):
            for filename in (name, name.replace("-v1.json", "-schema-v1.json")):
                destination = staged / NATIVE / filename
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / NATIVE / filename, destination)
        (staged / VALIDATOR).parent.mkdir(parents=True)
        shutil.copyfile(upstream_validator, staged / VALIDATOR)
        for original, name in (("protocols/LICENSE", "LICENSE-CC0"), ("LICENSE", "LICENSE-AGPL")):
            text = (source / original).read_text()
            (staged / name).write_text(
                "\n".join(line.rstrip() for line in text.splitlines()) + "\n"
            )
        # Preserve only the public Wire columns the upstream semantic validator
        # consumes. No names, prose, model claims or unrelated catalogs are needed.
        inverse = {value: key for key, value in validator.WIRE_CODEC.items()}
        lines = ["# Public Wire-column projection (CC0)"]
        previous = None
        for (operation, group, register), codecs in sorted(validator.register_map_wire().items()):
            if previous != (operation, group):
                lines.extend(
                    [f"## OP=0x{operation}", f"### GG=0x{group}", "| RR | Wire |", "| --- | --- |"]
                )
                previous = operation, group
            for codec in sorted(codecs):
                lines.append(f"| 0x{register} | {inverse[codec]} |")
        (staged / REGISTER_MAP).write_text("\n".join(lines) + "\n")
        # The candidate list's selector, name and width columns are sufficient.
        columns = ["opcode", "group", "instance", "register", "payload_bytes", "name"]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        with (source / CALENDAR).open(newline="") as handle:
            for row in csv.DictReader(handle):
                writer.writerow({key: row[key] for key in columns})
        (staged / CALENDAR).write_text(output.getvalue())
        manifest = {
            "digest_input": "complete published UTF-8 fixture bytes, including final newline",
            "digest_source": PROFILE_PAGE.as_posix(),
            "digests_base64": {
                name: base64.b64encode(bytes.fromhex(pin)).decode()
                for name, pin in zip((DESCRIPTION, OBSERVATIONS), pins, strict=True)
            },
            "evidence_grade": {
                "retained_description_bytes": "Proven",
                "codec_basis_and_presence": "Hypothesis",
                "omitted_context": "Unknown",
            },
        }
        (staged / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        validate_bundle(staged)
        publish(staged, target)


def exchange_directories(left, right):
    """Atomically exchange existing directories, or fail without moving either."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        exchange = libc.renamex_np
        exchange.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = (os.fsencode(left), os.fsencode(right), 2)  # RENAME_SWAP
    elif sys.platform == "linux" and hasattr(libc, "renameat2"):
        exchange = libc.renameat2
        exchange.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        args = (-100, os.fsencode(left), -100, os.fsencode(right), 2)  # AT_FDCWD, RENAME_EXCHANGE
    else:
        raise OSError(errno.ENOTSUP, "atomic directory exchange is unavailable")
    exchange.restype = ctypes.c_int
    if exchange(*args) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(right))


def publish(staged, target):
    """Publish with one atomic rename/exchange; cleanup never removes the configured path."""
    target = target.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fresh = Path(tempfile.mkdtemp(prefix=f".{target.name}-new-", dir=target.parent))
    try:
        if target.exists():
            shutil.copytree(target, fresh, dirs_exist_ok=True)
        for file in sorted(staged.rglob("*")):
            if file.is_file():
                destination = fresh / file.relative_to(staged)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, destination)
        if target.exists():
            exchange_directories(fresh, target)
        else:
            fresh.rename(target)
    finally:
        shutil.rmtree(fresh, ignore_errors=True)


def snapshot_tree(root):
    """Capture every file of the vendored bundle so it can be restored byte for byte."""
    if not root.exists():
        return {}
    return {path.relative_to(root): path.read_bytes() for path in root.rglob("*") if path.is_file()}


def restore_tree(root, snapshot):
    """Put the captured bundle back through the same atomic publication."""
    with tempfile.TemporaryDirectory(prefix="b524-restore-") as directory:
        staged = Path(directory)
        for relative, data in snapshot.items():
            destination = staged / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        publish(staged, root)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root", type=Path, help="explicit read-only docs-ebus refresh source"
    )
    parser.add_argument(
        "--publish-copies",
        action="store_true",
        help="copy the validated vendored pair to the public and packaged fixtures",
    )
    args = parser.parse_args()
    # Keep the last-known-good vendored bundle so a failed run never splits generations.
    previous = snapshot_tree(DEFAULT_ROOT) if args.source_root is not None else None
    try:
        try:
            if args.source_root is not None:
                refresh(args.source_root)
            # A refreshed vendored pair must reach the copies in the same run.
            if args.publish_copies or args.source_root is not None:
                publish_copies()
        except BaseException:
            if previous is not None:
                restore_tree(DEFAULT_ROOT, previous)
            raise
        validate_bundle(DEFAULT_ROOT)
        validate_published_copies()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"shared B524 fixture check failed: {exc}\n")
    print("Shared public B524 fixtures: syntax, digests, semantics and published copies PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
