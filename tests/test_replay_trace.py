from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app
from helianthus_vrc_explorer.replay_trace import (
    UnsupportedTraceFormatError,
    replay_trace_to_artifact,
)


def _write_trace(tmp_path: Path, name: str, content: str) -> Path:
    trace_path = tmp_path / name
    trace_path.write_text(content, encoding="utf-8")
    return trace_path


def test_replay_trace_to_artifact_reconstructs_b524_register_reads(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "sample.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:00.100000Z OP Reading "
                    "key=(op=0x02,gg=0x02,ii=0x00,rr=0x0001) dst=0x15"
                ),
                (
                    "2026-04-06T10:00:00.150000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020002000100"
                ),
                "2026-04-06T10:00:00.200000Z #1 PARSED_PROTO len=6 hex=010201000100",
                (
                    "2026-04-06T10:00:00.250000Z OP Reading "
                    "key=(op=0x06,gg=0x09,ii=0x01,rr=0x0001) dst=0x15"
                ),
                (
                    "2026-04-06T10:00:00.300000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060009010100"
                ),
                "2026-04-06T10:00:00.350000Z #2 PARSED_PROTO len=5 hex=0109010001",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    assert artifact["schema_version"] == "2.3"
    assert artifact["meta"]["destination_address"] == "0x15"
    assert artifact["meta"]["replay_trace"]["format"] == "enhanced_v1"

    local_entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"][
        "registers"
    ]["0x0001"]
    remote_entry = artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]["0x01"][
        "registers"
    ]["0x0001"]

    assert local_entry["read_opcode_label"] == "ReadControllerRegister"
    assert local_entry["response_state"] == "active"
    assert local_entry["value"] == 1
    assert remote_entry["read_opcode_label"] == "ReadDeviceSlotRegister"
    assert remote_entry["response_state"] == "active"
    assert remote_entry["value"] == 1


def test_replay_trace_to_artifact_rejects_non_enhanced_trace(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "legacy.trace",
        "2026-04-06T10:00:00.000000Z #1 SEND attempt_payload=020002000100 cmd=read -c b524\n",
    )
    try:
        replay_trace_to_artifact(trace_path)
    except UnsupportedTraceFormatError as exc:
        assert "ENH/ENS" in str(exc) or "INIT/START" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("Expected UnsupportedTraceFormatError for non-ENH trace")


def test_cli_replay_trace_generates_json_and_html(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "cli.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020002000100"
                ),
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=6 hex=010201000100",
            ]
        )
        + "\n",
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["replay-trace", str(trace_path), "--output-dir", str(tmp_path)],
    )
    assert result.exit_code == 0

    output_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    json_path = Path(output_lines[-1])
    assert json_path.exists()
    assert json_path.suffix == ".json"
    html_path = json_path.with_suffix(".html")
    assert html_path.exists()

    artifact = json.loads(json_path.read_text(encoding="utf-8"))
    assert artifact["schema_version"] == "2.3"
    assert artifact["meta"]["replay_trace"]["format"] == "enhanced_v1"


def test_replay_trace_accepts_truncated_hex_and_records_limitation(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "truncated.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020002000100"
                ),
                # Simulate current transport's shortened trace output.
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=52 hex=010201000100...",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    assert artifact["schema_version"] == "2.3"
    limitations = artifact["meta"]["replay_trace"]["limitations"]
    assert any("truncated ('...')" in item for item in limitations)


def test_replay_trace_instance_presence_uses_response_state(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "presence.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                # Instance 0x00: no response lines => timeout => not present
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060009000100"
                ),
                # Instance 0x01: explicit empty reply => present
                (
                    "2026-04-06T10:00:00.200000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060009010100"
                ),
                "2026-04-06T10:00:00.250000Z #2 PARSED_PROTO len=0 hex=",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    instances = artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]

    assert instances["0x00"]["present"] is False
    assert instances["0x00"]["registers"]["0x0001"]["response_state"] == "timeout"
    assert instances["0x01"]["present"] is True
    assert instances["0x01"]["registers"]["0x0001"]["response_state"] == "empty_reply"


def test_replay_trace_marks_nack_when_retry_evidence_is_nack_or_crc(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "nack.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:00.100000Z #7 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060009000100"
                ),
                "2026-04-06T10:00:00.120000Z #7 RETRY type=nack_or_crc n=1/2",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    entry = artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]["0x00"]["registers"][
        "0x0001"
    ]
    assert entry["response_state"] == "nack"


def test_replay_trace_applies_current_namespace_profiles(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "profiles.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                # OP=0x06 GG=0x00 is no longer part of the current profile and must be dropped.
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060000000100"
                ),
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=5 hex=0100010001",
                # OP=0x02 GG=0x04 keeps only II=0x00..0x01 in the current profile.
                (
                    "2026-04-06T10:00:00.200000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020004000400"
                ),
                "2026-04-06T10:00:00.250000Z #2 PARSED_PROTO len=8 hex=010404000000803f",
                (
                    "2026-04-06T10:00:00.300000Z #3 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020004020400"
                ),
                "2026-04-06T10:00:00.350000Z #3 PARSED_PROTO len=8 hex=0104040200000040",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)

    # OP=0x06 GG=0x00 is filtered out because GG=0x00 has no remote (0x06)
    # namespace in its profile.
    assert "0x00" not in artifact.get("operations", {}).get("0x02", {}).get("groups", {})
    local_ns = artifact["operations"]["0x02"]["groups"]["0x04"]
    # II=0x02 exceeds ii_max=0x01 for GG=0x04 OP=0x02 and is filtered out.
    # rr_max / ii_max are derived from observed trace data within profile bounds.
    assert local_ns["ii_max"] == "0x00"
    assert local_ns["rr_max"] == "0x0004"
    assert set(local_ns["instances"]) == {"0x00"}
