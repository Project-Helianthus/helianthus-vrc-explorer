from __future__ import annotations

from contextlib import contextmanager

import pytest
from tests.scan_ui_helpers import invoke_scan
from typer.testing import CliRunner

from helianthus_vrc_explorer.scanner.b524_operation_reads import (
    parse_operation_read_plan,
)
from helianthus_vrc_explorer.ui.scan_setup import ScanSetup


def test_normal_scan_passes_resolved_identity_for_automatic_event_policy(
    tmp_path, monkeypatch
) -> None:
    import helianthus_vrc_explorer.cli as cli

    class _Transport:
        @contextmanager
        def session(self):
            yield self

    @contextmanager
    def observer(*_args, **_kwargs):
        yield None

    identity = {
        "manufacturer": "0xB5",
        "device_id": "BASV2",
        "eid": "BASV2",
    }
    captured: dict[str, object] = {}

    def scan_vrc(*_args, **kwargs):
        captured.update(kwargs)
        return {
            "meta": {
                "scan_timestamp": "2026-10-09T00:00:00Z",
                "destination_address": "0x15",
                "incomplete": False,
                "schema_sources": [],
            },
            "operations": {},
        }

    monkeypatch.setattr(cli, "_build_transport", lambda *_args, **_kwargs: _Transport())
    monkeypatch.setattr(cli, "_probe_scan_identity", lambda *_args, **_kwargs: dict(identity))
    monkeypatch.setattr(cli, "make_scan_observer", observer)
    monkeypatch.setattr(cli, "scan_vrc", scan_vrc)

    result = invoke_scan(
        CliRunner(),
        monkeypatch,
        ["--preset", "recommended"],
        setup=ScanSetup(dst="0x15", output_dir=tmp_path),
    )

    assert result.exit_code == 0, result.output
    assert captured["operation_identity"] == identity
    assert "operation_requests" not in captured


def test_internal_operation_plan_parser_encodes_offline_requests() -> None:
    requests = parse_operation_read_plan(
        {
            "schema_version": 1,
            "requests": [
                {
                    "operation": "GetEvent",
                    "profile": "zone",
                    "instance": 2,
                    "address": 1,
                    "weekday_code": 255,
                },
                {"operation": "ReadTimer", "channel": "dhw", "instance": 0, "weekday": 6},
            ],
        }
    )

    assert [request.payload.hex() for request in requests] == [
        "09030201ff",
        "0301000106",
    ]
    assert [request.operation for request in requests] == ["GetEvent", "ReadTimer"]


def test_internal_operation_plan_parser_rejects_event_writes() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        parse_operation_read_plan({"schema_version": 1, "requests": [{"operation": "SetEvent"}]})


def test_internal_operation_plan_parser_requires_explicit_nonempty_scope() -> None:
    with pytest.raises(ValueError, match="at least one"):
        parse_operation_read_plan({"schema_version": 1, "requests": []})
