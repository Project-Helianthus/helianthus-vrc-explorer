from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app
from helianthus_vrc_explorer.input_limits import (
    MAX_EBUSD_CSV_BYTES,
    MAX_MYVAILLANT_MAP_BYTES,
    MAX_TRACE_REPLAY_BYTES,
    InputRejectedError,
    InputTooLargeError,
)
from helianthus_vrc_explorer.replay_trace import (
    UnsupportedTraceFormatError,
    replay_trace_to_artifact,
)
from helianthus_vrc_explorer.schema.ebusd_csv import EbusdCsvSchema
from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap

_GOOD_TRACE = (
    "2026-04-06T10:00:00.000000Z INIT features=0x01\n"
    "2026-04-06T10:00:00.050000Z START initiator=0xF7\n"
    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
    "primary=0xB5 secondary=0x24 payload=020002000100\n"
    "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=6 hex=010201000100\n"
)


def _sparse(path: Path, size: int) -> Path:
    """Create a file of ``size`` bytes without writing that much data."""

    with path.open("wb") as handle:
        handle.seek(size - 1)
        handle.write(b"x")
    assert path.stat().st_size == size
    return path


def test_trace_over_limit_is_rejected_before_reading(tmp_path: Path) -> None:
    trace = _sparse(tmp_path / "big.trace", MAX_TRACE_REPLAY_BYTES + 1)
    with pytest.raises(InputTooLargeError, match="100 MB"):
        replay_trace_to_artifact(trace)


def test_ebusd_csv_over_limit_is_rejected(tmp_path: Path) -> None:
    csv_path = _sparse(tmp_path / "big.csv", MAX_EBUSD_CSV_BYTES + 1)
    with pytest.raises(InputTooLargeError, match="10 MB"):
        EbusdCsvSchema.from_path(csv_path)


def test_myvaillant_map_over_limit_is_rejected(tmp_path: Path) -> None:
    map_path = _sparse(tmp_path / "big.csv", MAX_MYVAILLANT_MAP_BYTES + 1)
    with pytest.raises(InputTooLargeError, match="50 MB"):
        MyvaillantRegisterMap.from_path(map_path)


def test_nul_byte_is_rejected_in_csv_loaders(tmp_path: Path) -> None:
    ebusd = tmp_path / "nul-ebusd.csv"
    ebusd.write_bytes(b"r,,x\x00y\n")
    with pytest.raises(InputRejectedError, match="NUL"):
        EbusdCsvSchema.from_path(ebusd)
    mapping = tmp_path / "nul-map.csv"
    mapping.write_bytes(b"group,instance,register,leaf\n0x03,0x01,0x0016,na\x00me\n")
    with pytest.raises(InputRejectedError, match="NUL"):
        MyvaillantRegisterMap.from_path(mapping)


def test_nul_byte_in_trace_is_unsupported_format(tmp_path: Path) -> None:
    trace = tmp_path / "nul.trace"
    trace.write_bytes(_GOOD_TRACE.encode() + b"2026-04-06T10:00:01Z #2 x\x00y\n")
    with pytest.raises(UnsupportedTraceFormatError, match="NUL"):
        replay_trace_to_artifact(trace)


@pytest.mark.parametrize(
    "content",
    [
        b"not-a-timestamp INIT features=0x01\n",
        b"2026-04-06T10:00:00Z INIT features=0x01\n\xff\xfe bad bytes\n",
        _GOOD_TRACE.encode() + b"2026-04-06T10:00:02Z #" + b"9" * 5000 + b" RETRY type=x\n",
        b"",
    ],
    ids=["bad-timestamp", "invalid-utf8", "oversized-number", "empty"],
)
def test_malformed_trace_raises_unsupported_format_error(tmp_path: Path, content: bytes) -> None:
    trace = tmp_path / "bad.trace"
    trace.write_bytes(content)
    with pytest.raises(UnsupportedTraceFormatError):
        replay_trace_to_artifact(trace)


def test_trace_at_exact_content_and_line_count_is_unchanged(tmp_path: Path) -> None:
    trace = tmp_path / "ok.trace"
    trace.write_text(_GOOD_TRACE, encoding="utf-8")
    artifact = replay_trace_to_artifact(trace)
    assert artifact["meta"]["replay_trace"]["lines"] == 4
    assert artifact["meta"]["replay_trace"]["exchanges"] == 1


def test_csv_loaders_still_parse_valid_files(tmp_path: Path) -> None:
    mapping = tmp_path / "map.csv"
    mapping.write_text("group,instance,register,leaf\n0x03,0x01,0x0016,name\n", encoding="utf-8")
    assert (
        MyvaillantRegisterMap.from_path(mapping).lookup(group=0x03, instance=0x01, register=0x0016)
        is not None
    )


def test_cli_replay_trace_oversize_exits_nonzero_with_one_line(tmp_path: Path) -> None:
    trace = _sparse(tmp_path / "big.trace", MAX_TRACE_REPLAY_BYTES + 1)
    result = CliRunner().invoke(app, ["replay-trace", str(trace), "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert result.exception is None or isinstance(result.exception, SystemExit)
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1
    assert "100 MB" in lines[0]


@pytest.mark.parametrize(
    "bad",
    [b"not-a-timestamp INIT x\n", b"2026-04-06T10:00:00Z INIT\n\xff\n"],
    ids=["bad-timestamp", "invalid-utf8"],
)
def test_cli_replay_trace_malformed_exits_without_traceback(tmp_path: Path, bad: bytes) -> None:
    trace = tmp_path / "bad.trace"
    trace.write_bytes(bad)
    result = CliRunner().invoke(app, ["replay-trace", str(trace), "--output-dir", str(tmp_path)])
    assert result.exit_code == 2
    assert isinstance(result.exception, SystemExit)
    assert "Unsupported trace format" in result.output
