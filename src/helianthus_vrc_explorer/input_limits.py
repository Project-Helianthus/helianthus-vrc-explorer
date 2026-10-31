"""Size and content limits for input files that are read in full.

Only files the tool reads as input are bounded here (trace replay, ebusd CSV,
myVaillant map CSV). Paths are used as the user typed them; no base-directory
confinement or symlink handling is applied.
"""

from __future__ import annotations

import io
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

MAX_TRACE_REPLAY_BYTES = 100 * 1024 * 1024
MAX_EBUSD_CSV_BYTES = 10 * 1024 * 1024
MAX_MYVAILLANT_MAP_BYTES = 50 * 1024 * 1024


class InputRejectedError(ValueError):
    """Raised when an input file is rejected before it is parsed."""


class InputTooLargeError(InputRejectedError):
    """Raised when an input file exceeds its size limit."""


def _too_large(label: str, limit: int) -> InputTooLargeError:
    return InputTooLargeError(f"{label} exceeds the {limit // (1024 * 1024)} MB input limit")


def _nul_found(label: str) -> InputRejectedError:
    return InputRejectedError(f"{label} contains NUL bytes")


class _LimitedReader(io.RawIOBase):
    """Raw reader that fails once more than ``limit`` bytes have been delivered.

    ``st_size`` does not bound pipes, devices or files that grow while read, so
    the limit is enforced on the bytes actually returned.
    """

    def __init__(self, raw: io.RawIOBase | io.FileIO, limit: int, label: str) -> None:
        self._raw = raw
        self._limit = limit
        self._label = label
        self._total = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        view = memoryview(buffer).cast("B")
        room = self._limit + 1 - self._total
        count = self._raw.readinto(view[:room]) or 0  # type: ignore[attr-defined]
        self._total += count
        if self._total > self._limit:
            raise _too_large(self._label, self._limit)
        return count


def read_bounded_text(path: Path, *, limit: int, label: str) -> str:
    """Read a UTF-8 text file of at most ``limit`` bytes without NUL bytes."""

    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise _too_large(label, limit)
    if b"\x00" in data:
        raise _nul_found(label)
    return data.decode("utf-8")


def iter_bounded_lines(path: Path, *, limit: int, label: str) -> Iterator[str]:
    """Stream the lines of a UTF-8 text file of at most ``limit`` bytes.

    Lines match ``str.splitlines()`` of the whole text. Memory use is bounded by
    the longest line, and the size check happens before the first line is read.
    """

    with path.open("rb", buffering=0) as raw_handle:
        if os.fstat(raw_handle.fileno()).st_size > limit:
            raise _too_large(label, limit)
        bounded = io.BufferedReader(_LimitedReader(raw_handle, limit, label))
        text = io.TextIOWrapper(bounded, encoding="utf-8")
        for raw in text:
            if "\x00" in raw:
                raise _nul_found(label)
            yield from raw.splitlines()
