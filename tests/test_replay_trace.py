from __future__ import annotations

import json
import struct
from pathlib import Path

from typer.testing import CliRunner

from helianthus_vrc_explorer.cli import app
from helianthus_vrc_explorer.replay_trace import (
    UnsupportedTraceFormatError,
    _enrich_register_names,
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

    assert local_entry["read_opcode_label"] == "GetParameter"
    assert local_entry["response_state"] == "active"
    assert local_entry["value"] == 1
    assert local_entry["myvaillant_name"] == "circuit_circuit_type"
    assert remote_entry["read_opcode_label"] == "GetDeviceParameter"
    assert remote_entry["response_state"] == "active"
    assert remote_entry["value"] == 1
    assert remote_entry["myvaillant_name"] == "device_connected"


def test_replay_preserves_historical_system_registers_above_current_scan_ceiling(
    tmp_path: Path,
) -> None:
    trace_path = _write_trace(
        tmp_path,
        "system-history.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=020000000001",
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=5 hex=0100000101",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    registers = artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]
    assert registers["0x0100"]["raw_hex"] == "01"


def test_replay_preserves_historical_instances_and_unknown_groups(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "historical-selectors.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=0200020a0200",
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=6 hex=030202000100",
                "2026-04-06T10:00:00.200000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=0600090a0100",
                "2026-04-06T10:00:00.250000Z #2 PARSED_PROTO len=5 hex=0109010001",
                "2026-04-06T10:00:00.300000Z #3 SEND_PROTO src=0xF7 dst=0x15 "
                "primary=0xB5 secondary=0x24 payload=0200690a0500",
                "2026-04-06T10:00:00.350000Z #3 PARSED_PROTO len=5 hex=0169050001",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)
    assert (
        artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x0a"]["registers"][
            "0x0002"
        ]["raw_hex"]
        == "0100"
    )
    assert (
        artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]["0x0a"]["registers"][
            "0x0001"
        ]["raw_hex"]
        == "01"
    )
    assert (
        artifact["operations"]["0x02"]["groups"]["0x69"]["instances"]["0x0a"]["registers"][
            "0x0005"
        ]["raw_hex"]
        == "01"
    )


def test_replay_canonical_names_preserve_legacy_metadata_enrichment() -> None:
    operations = {
        "0x02": {
            "groups": {
                "0x00": {
                    "instances": {
                        "0x00": {
                            "registers": {
                                "0x003d": {"raw_hex": "01000000"},
                                "0x0001": {
                                    "raw_hex": "00000000",
                                    "myvaillant_name": "stale_leaf",
                                    "type": "OPAQUE",
                                    "value": "keep",
                                    "register_class": "config",
                                    "ebusd_name": "existing_alias",
                                },
                            }
                        }
                    }
                }
            }
        },
        "0x06": {
            "groups": {
                "0x09": {
                    "instances": {
                        "0x01": {
                            "registers": {
                                "0x0004": {
                                    "raw_hex": "021703",
                                    "ebusd_name": "existing_alias",
                                }
                            }
                        }
                    }
                }
            }
        },
    }

    _enrich_register_names(operations)

    typed_op02 = operations["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]["0x003d"]
    assert typed_op02 == {
        "raw_hex": "01000000",
        "myvaillant_name": "system_yield_solar_total",
        "register_class": "state",
        "ebusd_name": "SolarYieldTotal",
        "type": "U32",
        "value": 1,
    }

    op06_header = operations["0x06"]["groups"]["0x09"]["instances"]["0x01"]["registers"]["0x0004"]
    assert op06_header == {
        "raw_hex": "021703",
        "ebusd_name": "existing_alias",
        "myvaillant_name": "device_firmware_version",
        "register_class": "state",
        "type": "FW",
        "value": "02.17.03",
    }

    stale = operations["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]["0x0001"]
    assert stale == {
        "raw_hex": "00000000",
        "myvaillant_name": "system_dhw_bivalence_point",
        "type": "OPAQUE",
        "value": "keep",
        "register_class": "config",
        "ebusd_name": "existing_alias",
    }


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


def test_replay_preserves_operation_reads_and_raw_write_history(tmp_path: Path) -> None:
    exchanges = [
        ("0301000100", "00002430909090"),
        ("0401000100002430489090", ""),
        ("08", "0102030405060708"),
        ("0903020181", "03ff242a30363c42"),
        ("0a03020181ff242a30363c42", "7f"),
        ("0b03020181", "002d2e2f30313233"),
        ("0c030201812d2e2f30313233", ""),
    ]
    lines = [
        "2026-04-06T10:00:00.000000Z INIT features=0x01",
        "2026-04-06T10:00:00.050000Z START initiator=0xF7",
    ]
    for seq, (payload, reply) in enumerate(exchanges, 1):
        lines.append(
            f"2026-04-06T10:00:{seq:02d}.000000Z #{seq} SEND_PROTO src=0xF7 "
            f"dst=0x15 primary=0xB5 secondary=0x24 payload={payload}"
        )
        lines.append(
            f"2026-04-06T10:00:{seq:02d}.050000Z #{seq} PARSED_PROTO "
            f"len={len(bytes.fromhex(reply))} hex={reply}"
        )
    artifact = replay_trace_to_artifact(
        _write_trace(tmp_path, "operations.trace", "\n".join(lines) + "\n")
    )

    reads = artifact["b524_operation_reads"]
    assert [item["operation"] for item in reads] == [
        "ReadTimer",
        "ReadVR91",
        "GetEvent",
        "GetEventSetPoint",
    ]
    assert reads[0]["decoded"]["slots"][0]["stop_minutes"] == 360
    assert reads[0]["selector"] == {"channel": "dhw", "instance": 0, "weekday": 0}
    assert reads[2]["decoded"]["start1_raw"] == 0xFF
    assert reads[2]["selector"] == {
        "profile": "zone",
        "instance": 2,
        "address": 1,
        "weekday_code": 129,
    }
    assert reads[2]["pair_context"] == {
        "profile": "zone",
        "instance": 2,
        "address": 1,
        "weekday_code": 129,
    }
    assert all(item["selector_correlation"] == "request_context" for item in reads)
    assert all(item["decode_qualification"] == "schema_unqualified" for item in reads)

    writes = artifact["b524_operations"]["raw_write_history"]
    assert [item["opcode_hex"] for item in writes] == ["0x04", "0x0a", "0x0c"]
    assert writes[0]["selector"] == {
        "system_type": 1,
        "instance": 0,
        "address": 1,
        "weekday": 0,
    }
    assert writes[1]["selector"]["weekday_code"] == 129
    assert all(item["selector_correlation"] == "request_context" for item in writes)
    assert [item["response_state"] for item in writes] == ["empty", "value", "empty"]
    assert all(item["feedback_interpretation"] == "unknown" for item in writes)


def test_replay_keeps_unknown_operation_selectors_raw_and_separate(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "unknown_operation_selectors.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:01.000000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0302020181"
                ),
                "2026-04-06T10:00:01.100000Z #1 PARSED_PROTO len=7 hex=00002430909090",
                (
                    "2026-04-06T10:00:02.000000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0902020181"
                ),
                "2026-04-06T10:00:02.100000Z #2 PARSED_PROTO len=8 hex=0001020304050607",
                (
                    "2026-04-06T10:00:03.000000Z #3 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0b02020181"
                ),
                "2026-04-06T10:00:03.100000Z #3 PARSED_PROTO len=8 hex=0001020304050607",
            ]
        )
        + "\n",
    )
    reads = replay_trace_to_artifact(trace_path)["b524_operation_reads"]

    assert reads[0]["selector"] == {}
    assert reads[0]["raw_selector"] == {
        "system_type": 2,
        "instance": 2,
        "address": 1,
        "weekday": 129,
    }
    assert reads[0]["decode_qualification"] == "schema_unqualified"
    assert reads[0]["decoded"] is None
    assert reads[0]["error"] == "unknown_timer_channel"
    assert reads[1]["selector"] == {}
    assert reads[1]["raw_selector"] == {
        "system_type": 2,
        "instance": 2,
        "address": 1,
        "weekday_code": 129,
    }
    assert reads[1]["error"] == "unknown_event_profile"
    assert reads[1]["decoded"] is None
    assert reads[2]["selector"] == {}
    assert reads[2]["raw_selector"] == {
        "system_type": 2,
        "instance": 2,
        "address": 1,
        "weekday_code": 129,
    }
    assert reads[2]["error"] == "unknown_event_profile"
    assert reads[2]["decoded"] is None


def test_replay_keeps_operation_empty_nack_timeout_and_malformed_distinct(tmp_path: Path) -> None:
    trace_path = _write_trace(
        tmp_path,
        "operation_failures.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:01.000000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0900000100"
                ),
                (
                    "2026-04-06T10:00:02.000000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0900000200"
                ),
                "2026-04-06T10:00:02.100000Z #2 RETRY type=nack n=1/1",
                (
                    "2026-04-06T10:00:03.000000Z #3 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0b01000100"
                ),
                "2026-04-06T10:00:03.100000Z #3 PARSED_PROTO len=0 hex=",
                (
                    "2026-04-06T10:00:04.000000Z #4 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0b01000200"
                ),
                "2026-04-06T10:00:04.100000Z #4 PARSED_PROTO len=2 hex=0102",
                (
                    "2026-04-06T10:00:05.000000Z #5 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0900000300"
                ),
                "2026-04-06T10:00:05.100000Z #5 RETRY type=protocol_sync_error n=1/1",
            ]
        )
        + "\n",
    )
    artifact = replay_trace_to_artifact(trace_path)
    assert [item["response_state"] for item in artifact["b524_operation_reads"]] == [
        "timeout",
        "nack",
        "empty",
        "malformed",
        "transport_error",
    ]
    assert artifact["b524_operation_reads"][4]["error"] == "protocol_sync_error"


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
    assert entry["response_state"] == "nack_or_crc"


def test_replay_trace_preserves_historical_namespace_and_instance_observations(
    tmp_path: Path,
) -> None:
    trace_path = _write_trace(
        tmp_path,
        "profiles.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                # OP=0x06 GG=0x00 is no longer scheduled, but remains replay evidence.
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060000000100"
                ),
                "2026-04-06T10:00:00.150000Z #1 PARSED_PROTO len=5 hex=0100010001",
                # OP=0x02 GG=0x04 currently schedules II=0x00..0x01 only.
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

    remote_ns = artifact["operations"]["0x06"]["groups"]["0x00"]
    assert remote_ns["instances"]["0x00"]["registers"]["0x0001"]["raw_hex"] == "01"
    local_ns = artifact["operations"]["0x02"]["groups"]["0x04"]
    # Metadata reflects preserved trace observations; new scan scheduling retains
    # its separate current profile bounds.
    assert local_ns["ii_max"] == "0x02"
    assert local_ns["rr_max"] == "0x0004"
    assert set(local_ns["instances"]) == {"0x00", "0x02"}


def test_replay_trace_reconstructs_system_information_and_complete_descriptions(
    tmp_path: Path,
) -> None:
    trace_path = _write_trace(
        tmp_path,
        "b524_metadata.trace",
        "\n".join(
            [
                "2026-04-06T10:00:00.000000Z INIT features=0x01",
                "2026-04-06T10:00:00.050000Z START initiator=0xF7",
                (
                    "2026-04-06T10:00:00.100000Z #1 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=000000"
                ),
                "2026-04-06T10:00:00.120000Z #1 PARSED_PROTO len=4 hex=00004040",
                (
                    "2026-04-06T10:00:00.140000Z #2 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=020002000500"
                ),
                "2026-04-06T10:00:00.160000Z #2 PARSED_PROTO len=6 hex=010205000a00",
                # OP01 is GG, II, RR16. Its reply has no dtype tag: it is
                # GG, RR16, then three UIN-width values.
                (
                    "2026-04-06T10:00:00.180000Z #3 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0102000500"
                ),
                "2026-04-06T10:00:00.200000Z #3 PARSED_PROTO len=9 hex=02050000000a000200",
                (
                    "2026-04-06T10:00:00.220000Z #4 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=060009010400"
                ),
                "2026-04-06T10:00:00.240000Z #4 PARSED_PROTO len=5 hex=0109040002",
                # OP07 maps only to the matching OP06 identity. The leading
                # 0x09 is GG, not an old u16 type tag.
                (
                    "2026-04-06T10:00:00.260000Z #5 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=0709010400"
                ),
                "2026-04-06T10:00:00.280000Z #5 PARSED_PROTO len=6 hex=090400000a01",
                # The pre-complete OP01 selector cannot identify an II/RR16
                # target, even if its reply happens to resemble a range.
                (
                    "2026-04-06T10:00:00.300000Z #6 SEND_PROTO src=0xF7 dst=0x15 "
                    "primary=0xB5 secondary=0x24 payload=010207"
                ),
                "2026-04-06T10:00:00.320000Z #6 PARSED_PROTO len=7 hex=06020700010203",
            ]
        )
        + "\n",
    )

    artifact = replay_trace_to_artifact(trace_path)

    assert artifact["meta"]["system_information"] == [
        {
            "identifier": "0x0000",
            "name": "circuit_count",
            "value": 3.0,
            "raw_hex": struct.pack("<f", 3.0).hex(),
            "trace_seq": 1,
        }
    ]

    system_entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"][
        "registers"
    ]["0x0005"]
    assert system_entry["parameter_description"] == {
        "qualification": "matched",
        "description_opcode": "0x01",
        "read_opcode": "0x02",
        "group": "0x02",
        "instance": "0x00",
        "register": "0x0005",
        "type": "UIN",
        "width": 2,
        "min": 0,
        "max": 10,
        "step": 2,
        "reply_hex": "02050000000a000200",
        "source": "complete_description",
        "decoder_revision": "b524-description/v2",
        "step_raw_hex": "0200",
        "step_qualification": "decoded",
        "validation_scope": "format_range_and_step",
        "trace_seq": 3,
        "trace_reply_hex": "02050000000a000200",
    }

    device_entry = artifact["operations"]["0x06"]["groups"]["0x09"]["instances"]["0x01"][
        "registers"
    ]["0x0004"]
    assert device_entry["parameter_description"]["description_opcode"] == "0x07"
    assert device_entry["parameter_description"]["read_opcode"] == "0x06"
    assert device_entry["parameter_description"]["type"] == "UCH"
    assert device_entry["parameter_description"]["max"] == 10

    legacy = artifact["b524_operations"]["register_constraints"]
    assert legacy == [
        {
            "trace_seq": 6,
            "request_hex": "010207",
            "reply_hex": "06020700010203",
            "qualification": "legacy_incomplete",
            "reason": "OP01 selector has no instance or RR16 identity",
        }
    ]


def test_mixed_targets_cannot_cross_attach_descriptions_information_or_registers(
    tmp_path: Path,
) -> None:
    lines = [
        "2026-04-06T10:00:00.000000Z INIT features=0x01",
        "2026-04-06T10:00:00.050000Z START initiator=0xF7",
    ]
    records = [
        (0x15, "000000", "0000803f"),  # Selected target: circuit_count=1.
        (0x15, "020002000500", "030205000a00"),
        (0x16, "0102000500", "020500000064000100"),  # Same identity, foreign limits.
        (0x16, "000000", "0000c040"),
        (0x16, "020002000500", "030205005000"),
        (0x16, "060009010400", "0309040002"),
    ]
    for seq, (dst, payload, reply) in enumerate(records, 1):
        lines.append(
            f"2026-04-06T10:00:{seq:02d}.000000Z #{seq} SEND_PROTO src=0xF7 "
            f"dst=0x{dst:02X} primary=0xB5 secondary=0x24 payload={payload}"
        )
        lines.append(
            f"2026-04-06T10:00:{seq:02d}.050000Z #{seq} PARSED_PROTO "
            f"len={len(bytes.fromhex(reply))} hex={reply}"
        )
    artifact = replay_trace_to_artifact(
        _write_trace(tmp_path, "mixed.trace", "\n".join(lines) + "\n")
    )
    assert artifact["meta"]["destination_address"] == "0x15"
    assert artifact["meta"]["system_information"][0]["value"] == 1.0
    assert artifact["meta"]["replay_trace"]["ignored_b524_exchanges"] == 4
    entry = artifact["operations"]["0x02"]["groups"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0005"
    ]
    assert entry["value"] == 10
    assert "parameter_description" not in entry
    assert "0x06" not in artifact["operations"]
    assert artifact["b524_operations"]["parameter_descriptions"] == []
