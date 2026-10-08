from __future__ import annotations

import json
import struct
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console

from helianthus_vrc_explorer.protocol.b524 import build_register_read_payload
from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class RecordingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self.inner = inner
        self.payloads: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return self.inner.send(dst, payload)


def fixture_transport(tmp_path: Path) -> RecordingTransport:
    fixture = {
        "meta": {
            "system_information": [
                {"identifier": "0x0000", "value": 1.0, "raw_hex": struct.pack("<f", 1).hex()}
            ]
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x02": {
                        "instances": {
                            "0x01": {"registers": {"0x0002": {"type": "UIN", "raw_hex": "0100"}}},
                            "0x03": {"registers": {"0x0002": {"type": "UIN", "raw_hex": "0200"}}},
                        }
                    }
                }
            }
        },
    }
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(fixture))
    return RecordingTransport(DummyTransport(path))


def test_full_audits_count_underreporting_across_all_declared_slots(tmp_path: Path) -> None:
    transport = fixture_transport(tmp_path)
    artifact = scan_b524(transport, dst=0x15, planner_preset="full", probe_constraints=False)
    coverage = artifact["meta"]["instance_counts"]["0x02:0x02"]
    assert artifact["meta"]["scan_coverage"]["request_budget"] is None
    assert coverage["expected"] == 1
    assert coverage["observed"] == 2
    assert coverage["mismatch"] is True
    assert coverage["probed_instances"] == 9
    plan = artifact["meta"]["scan_plan"]["groups"]["0x02"]["operations"]["0x02"]
    assert plan["instances"] == [f"0x{ii:02x}" for ii in range(1, 10)]


def test_finite_request_budget_keeps_partial_raw_evidence(tmp_path: Path) -> None:
    transport = fixture_transport(tmp_path)
    artifact = scan_b524(transport, dst=0x15, request_budget=5)
    assert len(transport.payloads) == 5
    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "request_budget_exhausted"
    assert artifact["meta"]["system_information"][0]["raw_hex"] == "0000803f"
    boundary = artifact["meta"]["budget_boundary_evidence"]
    assert len(boundary) == 5
    assert boundary[0]["reply_hex"] == "0000803f"


def test_custom_plan_preserves_exact_unobserved_selectors(tmp_path: Path) -> None:
    transport = fixture_transport(tmp_path)
    plan = {
        make_plan_key(0x69, 0x06): GroupScanPlan(
            group=0x69, opcode=0x06, rr_max=0x0102, instances=(3,), registers=(0x0001, 0x0102)
        )
    }
    artifact = scan_b524(
        transport, dst=0x15, planner_preset="custom", explicit_plan=plan, probe_constraints=False
    )
    scalar = [payload for payload in transport.payloads if payload[0] in {2, 6}]
    assert scalar == [build_register_read_payload(6, 0x69, 3, rr) for rr in (1, 0x102)]
    assert artifact["meta"]["scan_plan"]["estimated_register_requests"] == 2


def test_research_orchestration_discovers_later_instances_through_secondary_anchor() -> None:
    class SecondaryAnchorTransport(TransportInterface):
        def __init__(self) -> None:
            self.payloads: list[bytes] = []

        def send(self, dst: int, payload: bytes) -> bytes:
            self.payloads.append(payload)
            if payload[0] == 0:
                return struct.pack("<f", float("nan"))
            if (
                payload[0] == 2
                and payload[2] == 0x69
                and payload[3] in {1, 3}
                and int.from_bytes(payload[4:6], "little") == 1
            ):
                return bytes.fromhex("0169010001")
            raise TransportTimeout("synthetic unknown selector")

    transport = SecondaryAnchorTransport()
    artifact = scan_b524(
        transport,
        dst=0x15,
        planner_preset="research",
        probe_constraints=False,
        request_budget=100_000,
    )
    instances = artifact["operations"]["0x02"]["groups"]["0x69"]["instances"]
    assert instances["0x03"]["present"] is True
    assert instances["0x03"]["registers"]["0x0001"]["value"] == 1
    assert build_register_read_payload(2, 0x69, 3, 0) in transport.payloads
    assert build_register_read_payload(2, 0x69, 3, 1) in transport.payloads
    assert artifact["meta"]["scan_coverage"]["completed"] is True
    assert artifact["meta"]["scan_coverage"]["device_discovery_complete"] is False
    assert artifact["meta"]["scan_coverage"]["qualification_incomplete"] is True


@pytest.mark.parametrize("preset", ["recommended", "full", "research", "custom"])
def test_cli_and_interactive_defaults_send_identical_selectors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, preset: str
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan

    explicit = None
    if preset == "custom":
        explicit = {
            make_plan_key(0x69, 6): GroupScanPlan(
                group=0x69, opcode=6, instances=(3,), rr_max=0x102, registers=(1, 0x102)
            )
        }
    cli_transport = fixture_transport(tmp_path)
    cli = scan_b524(
        cli_transport,
        dst=0x15,
        planner_ui="disabled",
        planner_preset=preset,
        explicit_plan=explicit,
        probe_constraints=False,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        lambda groups, **kwargs: kwargs["default_plan"],
    )
    monkeypatch.setattr(
        scan,
        "_PlannerHotkeyReader",
        lambda **kwargs: nullcontext(SimpleNamespace(poll=lambda: False)),
    )
    ui_transport = fixture_transport(tmp_path)
    ui = scan_b524(
        ui_transport,
        dst=0x15,
        planner_ui="textual",
        planner_preset=preset,
        explicit_plan=explicit,
        probe_constraints=False,
        observer=MagicMock(spec=ScanObserver),
        console=Console(force_terminal=True),
    )
    assert cli["meta"]["scan_plan"]["groups"] == ui["meta"]["scan_plan"]["groups"]
    assert cli_transport.payloads == ui_transport.payloads
