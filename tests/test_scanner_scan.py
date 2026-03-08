from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan
from helianthus_vrc_explorer.scanner.scan import scan_b524
from helianthus_vrc_explorer.transport.base import TransportInterface
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class RecordingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.register_reads: list[tuple[int, int, int, int]] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        if len(payload) == 6 and payload[0] in {0x02, 0x06} and payload[1] == 0x00:
            opcode = payload[0]
            group = payload[2]
            instance = payload[3]
            register = int.from_bytes(payload[4:6], byteorder="little", signed=False)
            self.register_reads.append((opcode, group, instance, register))
        return self._inner.send(dst, payload)


class InterruptingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface, interrupt_after: int) -> None:
        self._inner = inner
        self._interrupt_after = interrupt_after
        self._calls = 0

    def send(self, dst: int, payload: bytes) -> bytes:
        self._calls += 1
        if self._calls > self._interrupt_after:
            raise KeyboardInterrupt
        return self._inner.send(dst, payload)


class ConstraintAwareTransport(TransportInterface):
    def __init__(
        self,
        inner: TransportInterface,
        *,
        constraints: dict[tuple[int, int], bytes] | None = None,
    ) -> None:
        self._inner = inner
        self._constraints = constraints or {}
        self.constraint_requests: list[tuple[int, int]] = []
        self.register_reads: list[tuple[int, int, int, int]] | None = getattr(
            inner, "register_reads", None
        )

    def send(self, dst: int, payload: bytes) -> bytes:
        if payload and payload[0] == 0x01 and len(payload) == 3:
            group = payload[1]
            register = payload[2]
            self.constraint_requests.append((group, register))
            if (group, register) in self._constraints:
                return self._constraints[(group, register)]
            # Unsupported/absent constraint entries return status-only no-data.
            return b"\x00"
        return self._inner.send(dst, payload)


class _B524UnsupportedTransport(TransportInterface):
    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        self.calls.append(payload)
        if payload == bytes((0x00, 0x00, 0x00)):
            # status-only "no data" on first directory probe => unsupported B524
            return b"\x00"
        raise AssertionError(f"Unexpected payload after unsupported probe: {payload.hex()}")


def _write_fixture_group_02(
    tmp_path: Path,
    *,
    descriptor: float = 1.0,
    terminator_group: str = "0x05",
) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": terminator_group}},
        "groups": {
            "0x02": {
                "descriptor_type": descriptor,
                "instances": {
                    "0x00": {
                        "registers": {
                            # Presence probe (UIN)
                            "0x0002": {"raw_hex": "0100"},
                            # Room influence type (UCH enum)
                            "0x0003": {"raw_hex": "02"},
                            # Sample float32 (EXP) value
                            "0x000f": {"raw_hex": "9a99d93f"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_00(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x01"}},
        "groups": {
            "0x00": {
                "descriptor_type": 3.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_group_00.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_unknown_group_69(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x6a"}},
        "groups": {
            "0x69": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_unknown.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_unknown_descriptor(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x01"}},
        "groups": {
            "0x00": {
                "descriptor_type": 2.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_unknown_descriptor.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_09(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x0a"}},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_group_09.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_08(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x09"}},
        "groups": {
            "0x08": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {"raw_hex": "01"},
                            "0x0000": {"raw_hex": "00"},
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_group_08.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


class _NoopObserver(ScanObserver):
    def phase_start(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:  # noqa: ARG002
        return

    def phase_set_total(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return

    def phase_finish(self, phase: str) -> None:  # noqa: ARG002
        return

    def status(self, message: str) -> None:  # noqa: ARG002
        return

    def log(self, message: str, *, level: str = "info") -> None:  # noqa: ARG002
        return

    def suspend(self):  # type: ignore[override]
        from contextlib import contextmanager

        @contextmanager
        def _cm():
            yield None

        return _cm()


class _RecordingObserver(_NoopObserver):
    def __init__(self) -> None:
        self.phase_starts: list[tuple[str, int]] = []
        self.phase_advances: list[tuple[str, int]] = []
        self.phase_finishes: list[str] = []

    def phase_start(self, phase: str, *, total: int) -> None:
        self.phase_starts.append((phase, total))

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        self.phase_advances.append((phase, advance))

    def phase_finish(self, phase: str) -> None:
        self.phase_finishes.append(phase)


def test_scan_b524_scans_all_instances_and_register_range(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["destination_address"] == "0x15"
    assert artifact["meta"]["incomplete"] is False

    group = artifact["groups"]["0x02"]
    assert group["dual_namespace"] is False
    assert group["descriptor_observed"] == 1.0

    instance_00 = group["instances"]["0x00"]
    assert instance_00["present"] is True

    registers = instance_00["registers"]
    assert registers["0x0002"]["type"] == "UIN"
    assert registers["0x0002"]["value"] == 1
    assert registers["0x0002"]["enum_raw_name"] == "HEATING_OR_COOLING"
    assert registers["0x0002"]["enum_resolved_name"] == "HEATING"
    assert registers["0x0002"]["value_display"] == "HEATING_OR_COOLING (HEATING)"
    assert registers["0x0002"]["raw_hex"] == "0100"
    assert registers["0x0002"]["error"] is None
    assert registers["0x0003"]["enum_raw_name"] == "EXTENDED"
    assert registers["0x0003"]["enum_resolved_name"] == "EXTENDED"
    assert registers["0x0003"]["value_display"] == "EXTENDED (EXTENDED)"

    assert registers["0x000f"]["type"] == "EXP"
    assert registers["0x000f"]["value"] == pytest.approx(1.7, abs=1e-6)

    # Phase B/C: instance discovery must scan all II=0x00..ii_max (no early stop at gaps).
    probed_instances = sorted(
        {ii for (_opcode, gg, ii, rr) in transport.register_reads if gg == 0x02 and rr == 0x0002}
    )
    assert probed_instances == list(range(0x0A + 1))

    # Phase D: register scan must cover RR=0x0000..rr_max for present instances.
    scanned_registers = {
        rr for (_opcode, gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x00
    }
    assert scanned_registers == set(range(0x25 + 1))


def test_scan_b524_skips_flow_when_first_directory_probe_is_status_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = _B524UnsupportedTransport()

    def _unexpected_planner(*_args, **_kwargs):
        raise AssertionError("planner should not run when B524 is unsupported")

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", _unexpected_planner)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert artifact["meta"]["incomplete"] is False
    assert artifact["meta"]["b524_supported"] is False
    assert artifact["meta"]["b524_skip_reason"] == "first_directory_probe_no_data"
    assert artifact["groups"] == {}
    assert transport.calls == [bytes((0x00, 0x00, 0x00))]


def test_scan_b524_collects_constraint_dictionary_entries(tmp_path: Path) -> None:
    transport = ConstraintAwareTransport(
        RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path))),
        constraints={
            # TT=0x09 (u16 range): min=0 max=4 step=1 for GG=0x02 RR=0x02.
            (0x02, 0x02): bytes.fromhex("09020200000004000100"),
        },
    )

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
        probe_constraints=True,
    )

    plan = artifact["meta"]["scan_plan"]["groups"]["0x02"]
    assert plan["rr_max"] == "0x0025"
    assert plan["instances"] == [f"0x{ii:02x}" for ii in range(0x0A + 1)]
    assert (0x02, 0x02) in transport.constraint_requests
    bounds = artifact["meta"]["group_metadata_bounds"]["0x02"]
    assert bounds["rr_max"] == "0x0025"
    assert bounds["ii_max"] == "0x0a"
    assert bounds["source"] == "profile"
    constraints = artifact["meta"]["constraint_dictionary"]["0x02"]["0x02"]
    assert constraints["tt"] == "0x09"
    assert constraints["type"] == "u16_range"
    assert constraints["min"] == 0
    assert constraints["max"] == 4
    assert constraints["step"] == 1
    assert transport.register_reads is not None
    scanned_registers = {
        rr for (_opcode, gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x00
    }
    assert scanned_registers == set(range(0x0025 + 1))


def test_scan_b524_probe_constraints_has_dedicated_progress_phase(tmp_path: Path) -> None:
    transport = ConstraintAwareTransport(
        RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path))),
        constraints={(0x02, 0x02): bytes.fromhex("09020200000004000100")},
    )
    observer = _RecordingObserver()

    scan_b524(
        transport,
        dst=0x15,
        observer=observer,
        console=Console(force_terminal=True),
        planner_ui="classic",
        probe_constraints=True,
    )

    started = {name: total for (name, total) in observer.phase_starts}
    assert "constraint_probe" in started
    assert started["constraint_probe"] > 0
    assert any(phase == "constraint_probe" for (phase, _advance) in observer.phase_advances)
    assert "constraint_probe" in observer.phase_finishes


def test_scan_b524_skips_constraint_dictionary_by_default(tmp_path: Path) -> None:
    transport = ConstraintAwareTransport(
        RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path))),
        constraints={
            (0x02, 0x02): bytes.fromhex("09020200000004000100"),
        },
    )

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert transport.constraint_requests == []
    assert artifact["meta"]["constraint_probe_enabled"] is False
    assert artifact["meta"]["constraint_dictionary"] == {}


def test_scan_b524_group_bounds_come_from_profile_defaults(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
    )

    plan = artifact["meta"]["scan_plan"]["groups"]["0x02"]
    assert plan["rr_max"] == "0x0025"
    bounds = artifact["meta"]["group_metadata_bounds"]["0x02"]
    assert bounds["source"] == "profile"


def test_scan_b524_scans_enabled_unknown_group_via_planner(monkeypatch, tmp_path: Path) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            (0x69, 0x02): GroupScanPlan(
                group=0x69,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            )
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert "0x69" in artifact["groups"]
    registers = artifact["groups"]["0x69"]["instances"]["0x00"]["registers"]
    assert registers["0x0000"]["raw_hex"] == "00"
    issue_suggestion = artifact["meta"]["issue_suggestion"]
    assert issue_suggestion["unknown_groups"] == ["0x69"]
    assert issue_suggestion["suggest_issue"] is True


def test_scan_b524_flags_unknown_descriptor_class_for_issue_suggestion(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_unknown_descriptor(tmp_path)), dst=0x15)
    issue_suggestion = artifact["meta"]["issue_suggestion"]
    assert issue_suggestion["unknown_descriptor_types"] == [2.0]
    assert issue_suggestion["suggest_issue"] is True


def test_scan_b524_scans_absent_instances_when_planner_overrides(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = RecordingTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            (0x02, 0x02): GroupScanPlan(
                group=0x02,
                opcode=0x02,
                rr_max=0x0002,
                instances=(
                    0x00,  # present (fixture)
                    0x01,  # absent (forced by planner override)
                ),
            )
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    group = artifact["groups"]["0x02"]
    assert group["instances"]["0x00"]["present"] is True

    absent = group["instances"]["0x01"]
    assert absent["present"] is False
    assert set(absent["registers"].keys()) == {"0x0000", "0x0001", "0x0002"}

    scanned_registers = {
        rr for (_opcode, gg, ii, rr) in transport.register_reads if gg == 0x02 and ii == 0x01
    }
    assert scanned_registers == set(range(0x0002 + 1))


def test_scan_instanced_group_zero_descriptor(tmp_path: Path) -> None:
    transport = RecordingTransport(
        DummyTransport(_write_fixture_group_02(tmp_path, descriptor=0.0, terminator_group="0x03"))
    )

    artifact = scan_b524(transport, dst=0x15)

    group = artifact["groups"]["0x02"]
    assert group["dual_namespace"] is False
    assert group["descriptor_observed"] == 0.0
    assert group["instances"]["0x00"]["present"] is True
    assert group["instances"]["0x01"]["present"] is False

    probed_instances = sorted(
        {ii for (_opcode, gg, ii, rr) in transport.register_reads if gg == 0x02 and rr == 0x0002}
    )
    assert probed_instances == list(range(0x0A + 1))


def test_scan_singleton_group_nonzero_descriptor(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_group_00(tmp_path)))

    artifact = scan_b524(transport, dst=0x15)

    group = artifact["groups"]["0x00"]
    assert group["dual_namespace"] is False
    assert group["descriptor_observed"] == 3.0
    assert set(group["instances"]) == {"0x00"}
    assert artifact["meta"]["scan_plan"]["groups"]["0x00"]["instances"] == ["0x00"]

    scanned_instances = {ii for (_opcode, gg, ii, _rr) in transport.register_reads if gg == 0x00}
    assert scanned_instances == {0x00}


def test_artifact_schema_version(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_00(tmp_path)), dst=0x15)

    assert artifact["schema_version"] == "2.0"


def test_artifact_dual_namespace_structure(monkeypatch, tmp_path: Path) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = RecordingTransport(DummyTransport(_write_fixture_group_09(tmp_path)))

    def fake_is_instance_present(*_args, **kwargs):  # type: ignore[no-untyped-def]
        return kwargs["instance"] == 0x00

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            (0x09, 0x02): GroupScanPlan(
                group=0x09,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            (0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0000,
                instances=(0x00,),
            ),
        }

    monkeypatch.setattr(scan_mod, "is_instance_present", fake_is_instance_present)
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    group = artifact["groups"]["0x09"]
    assert group["dual_namespace"] is True
    assert "instances" not in group
    assert set(group["namespaces"]) == {"0x02", "0x06"}

    local_ns = group["namespaces"]["0x02"]
    remote_ns = group["namespaces"]["0x06"]
    assert local_ns["label"] == "local"
    assert remote_ns["label"] == "remote"
    assert local_ns["instances"]["0x00"]["registers"]["0x0000"]["read_opcode"] == "0x02"
    assert local_ns["instances"]["0x00"]["registers"]["0x0000"]["read_opcode_label"] == "local"
    assert remote_ns["instances"]["0x00"]["registers"]["0x0000"]["read_opcode"] == "0x06"
    assert remote_ns["instances"]["0x00"]["registers"]["0x0000"]["read_opcode_label"] == "remote"

    scan_plan = artifact["meta"]["scan_plan"]["groups"]["0x09"]
    assert scan_plan["dual_namespace"] is True
    assert set(scan_plan["namespaces"]) == {"0x02", "0x06"}

    scanned_opcodes = {
        opcode
        for (opcode, gg, ii, rr) in transport.register_reads
        if gg == 0x09 and ii == 0x00 and rr == 0x0000
    }
    assert scanned_opcodes == {0x02, 0x06}


def test_artifact_single_namespace_unchanged(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_02(tmp_path)), dst=0x15)

    group = artifact["groups"]["0x02"]
    assert group["dual_namespace"] is False
    assert "namespaces" not in group
    assert set(group["instances"]) >= {"0x00"}


def test_artifact_register_flags_present(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_02(tmp_path)), dst=0x15)

    entry = artifact["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0002"]

    assert entry["flags"] == 0x01
    assert entry["flags_access"] == "stable_ro"
    assert entry["read_opcode_label"] == "local"


def test_group_08_remote_namespace_only_marks_present_instances(
    monkeypatch, tmp_path: Path
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_group_08(tmp_path))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            (0x08, 0x02): GroupScanPlan(
                group=0x08,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            (0x08, 0x06): GroupScanPlan(
                group=0x08,
                opcode=0x06,
                rr_max=0x0000,
                instances=(0x00,),
            ),
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    group = artifact["groups"]["0x08"]
    assert group["dual_namespace"] is True
    assert set(group["namespaces"]["0x02"]["instances"]) == {"0x00"}
    assert set(group["namespaces"]["0x06"]["instances"]) == {"0x00"}


def test_type_hint_propagation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod
    from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap

    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x0a"}},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0004": {"raw_hex": "021703"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "fixture_fw.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    map_path = tmp_path / "myvaillant_map.csv"
    map_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class,type_hint,opcode",
                "0x09,*,0x0004,radio_device_firmware,,state,FW,0x06",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            (0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0004,
                instances=(0x00,),
            ),
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(scan_mod, "is_instance_present", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        DummyTransport(fixture_path),
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
        myvaillant_map=MyvaillantRegisterMap.from_path(map_path),
    )

    entry = artifact["groups"]["0x09"]["namespaces"]["0x06"]["instances"]["0x00"]["registers"][
        "0x0004"
    ]
    assert entry["myvaillant_name"] == "radio_device_firmware"
    assert entry["type"] == "FW"
    assert entry["value"] == "02.17.03"


def test_scan_b524_applies_aggressive_preset_to_textual_default_plan(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))
    captured: dict[str, object] = {}

    def fake_run_textual_scan_plan(
        _groups,
        *,
        request_rate_rps,
        default_plan,
        default_preset,
    ):
        captured["default_preset"] = default_preset
        captured["default_plan"] = default_plan
        captured["request_rate_rps"] = request_rate_rps
        return {}

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="textual",
        planner_preset="aggressive",
    )

    assert captured["default_preset"] == "aggressive"
    default_plan = captured["default_plan"]
    assert isinstance(default_plan, dict)
    assert (0x69, 0x02) in default_plan
    group_plan = default_plan[(0x69, 0x02)]
    assert group_plan.rr_max == 0x30
    assert group_plan.instances == (0x00,)


def test_scan_b524_applies_preset_in_non_interactive_mode(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_unknown_group_69(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="aggressive",
    )

    scan_plan = artifact["meta"]["scan_plan"]["groups"]
    assert "0x69" in scan_plan
    assert scan_plan["0x69"]["rr_max"] == "0x0030"
    assert scan_plan["0x69"]["instances"] == ["0x00"]

    group = artifact["groups"]["0x69"]
    assert set(group["instances"]) == {"0x00"}
    assert group["instances"]["0x00"]["present"] is True


def test_scan_unknown_group_defaults_to_singleton(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_unknown_group_69(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="aggressive",
    )

    group = artifact["groups"]["0x69"]
    assert group["descriptor_observed"] == 1.0
    assert set(group["instances"]) == {"0x00"}
    assert artifact["meta"]["scan_plan"]["groups"]["0x69"]["instances"] == ["0x00"]


def test_scan_b524_textual_failure_falls_back_to_classic_in_auto_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))
    classic_called = {"count": 0}

    def fake_run_textual_scan_plan(*_args, **_kwargs):
        raise RuntimeError("textual init failed")

    def fake_prompt_scan_plan(*_args, **kwargs):
        classic_called["count"] += 1
        default_plan = kwargs.get("default_plan")
        assert isinstance(default_plan, dict)
        return default_plan

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="auto",
        planner_preset="recommended",
    )

    assert artifact["meta"]["incomplete"] is False
    assert classic_called["count"] >= 1


def test_scan_b524_textual_failure_raises_in_forced_textual_mode(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))

    def fake_run_textual_scan_plan(*_args, **_kwargs):
        raise RuntimeError("textual init failed")

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    with pytest.raises(RuntimeError, match="Textual planner requested but failed to start"):
        scan_b524(
            transport,
            dst=0x15,
            observer=_NoopObserver(),
            console=Console(force_terminal=True),
            planner_ui="textual",
        )


def test_scan_b524_replan_before_first_completed_task_does_not_divide_by_zero(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys
    from contextlib import contextmanager

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    class _FakeHotkeys:
        def __init__(self, *, enabled: bool) -> None:
            self._enabled = enabled
            self._seen = False

        def __enter__(self) -> _FakeHotkeys:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def poll(self) -> bool:
            if not self._enabled or self._seen:
                return False
            self._seen = True
            return True

        @contextmanager
        def suspend(self):
            yield None

    transport = DummyTransport(_write_fixture_group_02(tmp_path))

    def fake_prompt_scan_plan(*_args, **kwargs):
        default_plan = kwargs.get("default_plan")
        assert isinstance(default_plan, dict)
        return default_plan

    monkeypatch.setattr(scan_mod, "_PlannerHotkeyReader", _FakeHotkeys)
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    assert artifact["meta"]["incomplete"] is False


def test_scan_b524_replan_textual_failure_prompts_classic_immediately(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys
    from contextlib import contextmanager

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    class _FakeHotkeys:
        def __init__(self, *, enabled: bool) -> None:
            self._enabled = enabled
            self._seen = False

        def __enter__(self) -> _FakeHotkeys:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def poll(self) -> bool:
            if not self._enabled or self._seen:
                return False
            self._seen = True
            return True

        @contextmanager
        def suspend(self):
            yield None

    transport = DummyTransport(_write_fixture_group_02(tmp_path))
    textual_calls = {"count": 0}
    classic_calls = {"count": 0}

    def fake_run_textual_scan_plan(*_args, **kwargs):
        textual_calls["count"] += 1
        default_plan = kwargs.get("default_plan")
        assert isinstance(default_plan, dict)
        if textual_calls["count"] == 1:
            return default_plan
        raise RuntimeError("textual init failed")

    def fake_prompt_scan_plan(*_args, **_kwargs):
        classic_calls["count"] += 1
        return {
            (0x02, 0x02): GroupScanPlan(
                group=0x02,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            )
        }

    monkeypatch.setattr(scan_mod, "_PlannerHotkeyReader", _FakeHotkeys)
    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="auto",
    )

    registers = artifact["groups"]["0x02"]["instances"]["0x00"]["registers"]
    assert set(registers) == {"0x0000"}
    assert textual_calls["count"] == 2
    assert classic_calls["count"] == 1


def test_scan_b524_marks_incomplete_on_keyboard_interrupt(tmp_path: Path) -> None:
    inner = DummyTransport(_write_fixture_group_02(tmp_path))
    transport = InterruptingTransport(inner, interrupt_after=10)

    artifact = scan_b524(transport, dst=0x15)

    assert artifact["meta"]["incomplete"] is True
    assert artifact["meta"]["incomplete_reason"] == "user_interrupt"
