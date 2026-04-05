from __future__ import annotations

import json
from pathlib import Path

import pytest
from rich.console import Console

from helianthus_vrc_explorer.artifact_schema import CURRENT_ARTIFACT_SCHEMA_VERSION
from helianthus_vrc_explorer.scanner.observer import ScanObserver
from helianthus_vrc_explorer.scanner.plan import GroupScanPlan, make_plan_key
from helianthus_vrc_explorer.scanner.scan import (
    _apply_contextual_enum_annotations,
    _planner_source_opcodes,
    _probe_unknown_group_opcodes,
    scan_b524,
)
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


class _TransientFirstProbeTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.calls: list[bytes] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        self.calls.append(payload)
        if payload == bytes((0x00, 0x00, 0x00)):
            # Shared-bus ebusd-tcp can transiently return status-only 0x00 on the first probe.
            return b"\x00"
        return self._inner.send(dst, payload)


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


def _write_fixture_groups_00_and_01(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x02"}},
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
            },
            "0x01": {
                "descriptor_type": 3.0,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    path = tmp_path / "fixture_groups_00_and_01.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_01_namespaces(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x02"}},
        "groups": {
            "0x01": {
                "descriptor_type": 3.0,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "02"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "06"},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    path = tmp_path / "fixture_group_01_namespaces.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_unknown_group_69(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x6a"}},
        "groups": {
            "0x69": {
                "descriptor_type": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    path = tmp_path / "fixture_unknown.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_unknown_group_69_with_ff(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x6a"}},
        "groups": {
            "0x69": {
                "descriptor_type": 1.0,
                "namespaces": {
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                }
                            },
                            "0xff": {
                                "registers": {
                                    "0x0000": {"raw_hex": "7f"},
                                }
                            },
                        }
                    }
                },
            }
        },
    }
    path = tmp_path / "fixture_unknown_ff.json"
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
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                    "0x0001": {"raw_hex": "34"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                    "0x0001": {"raw_hex": "01"},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    path = tmp_path / "fixture_group_09.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_09_presence_divergence(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x0a"}},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0000": {"raw_hex": "00"},
                                    "0x0001": {"raw_hex": "34"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "00"},
                                }
                            }
                        }
                    },
                },
            }
        },
    }
    path = tmp_path / "fixture_group_09_presence_divergence.json"
    path.write_text(json.dumps(fixture), encoding="utf-8")
    return path


def _write_fixture_group_02_dual_namespace(tmp_path: Path) -> Path:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x03"}},
        "groups": {
            "0x00": {
                "descriptor_type": 3.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0001": {"raw_hex": "08 00 00 00"},
                        }
                    }
                },
            },
            "0x02": {
                "descriptor_type": 1.0,
                "dual_namespace": True,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "01", "value": 1},
                                    "0x0002": {"raw_hex": "02", "value": 2},
                                    "0x0003": {"raw_hex": "01", "value": 1},
                                    "0x0006": {"raw_hex": "00", "value": 0},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "02", "value": 2},
                                    "0x0002": {"raw_hex": "03", "value": 3},
                                    "0x0003": {"raw_hex": "02", "value": 2},
                                    "0x0006": {"raw_hex": "01", "value": 1},
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    path = tmp_path / "fixture_group_02_dual_namespace.json"
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


def test_scan_b524_continues_when_first_directory_probe_is_status_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = _TransientFirstProbeTransport(DummyTransport(_write_fixture_group_02(tmp_path)))

    def _unexpected_planner(*_args, **_kwargs):
        raise AssertionError("planner should not run for non-interactive scan")

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", _unexpected_planner)
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=False),
        planner_ui="classic",
    )

    assert artifact["meta"]["incomplete"] is False
    assert "b524_supported" not in artifact["meta"]
    assert "b524_skip_reason" not in artifact["meta"]
    assert "0x02" in artifact["groups"]
    assert artifact["groups"]["0x02"]["instances"]["0x00"]["present"] is True
    assert transport.calls[0] == bytes((0x00, 0x00, 0x00))
    assert bytes((0x00, 0x02, 0x00)) in transport.calls


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
    assert plan["instances"] == ["0x00"]
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
    assert constraints["scope"] == "opcode_0x01_probe"
    assert constraints["provenance"] == "live_probe_from_opcode_0x01"
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
    assert artifact["meta"]["constraint_scope"]["decision"] == "opcode_0x02_default"
    assert artifact["meta"]["constraint_scope"]["protocol"] == "opcode_0x01"
    entry = artifact["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0002"]
    assert entry["constraint_source"] == "static_catalog"
    assert entry["constraint_scope"] == "opcode_0x02_default"
    assert entry["constraint_provenance"] == "catalog_seeded_from_opcode_0x01"
    assert entry["constraint_type"] == "u16_range"
    assert entry["constraint_min"] == 0
    assert entry["constraint_max"] == 4


def test_scan_b524_flags_seeded_constraint_mismatch(tmp_path: Path) -> None:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x05"}},
        "groups": {
            "0x02": {
                "descriptor_type": 1.0,
                "instances": {
                    "0x00": {
                        "registers": {
                            "0x0002": {"raw_hex": "0500"},
                        }
                    }
                },
            }
        },
    }
    fixture_path = tmp_path / "constraint_mismatch.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    artifact = scan_b524(
        DummyTransport(fixture_path),
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    entry = artifact["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0002"]
    assert entry["value"] == 5
    assert entry["constraint_source"] == "static_catalog"
    assert "constraint_mismatch_reason" in entry
    mismatches = artifact["meta"]["constraint_mismatches"]
    assert len(mismatches) == 1
    assert mismatches[0]["group"] == "0x02"
    assert mismatches[0]["register"] == "0x0002"
    assert mismatches[0]["value"] == 5
    assert mismatches[0]["constraint_scope"] == "opcode_0x02_default"
    assert mismatches[0]["constraint_provenance"] == "catalog_seeded_from_opcode_0x01"
    assert mismatches[0]["constraint_probe_protocol"] == "opcode_0x01"
    assert artifact["meta"]["constraint_rescan_recommended"] is True


def test_scan_b524_does_not_flag_remote_seeded_static_constraint_mismatch(
    tmp_path: Path,
) -> None:
    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x0a"}},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "namespaces": {
                    "0x02": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "34"},
                                }
                            }
                        }
                    },
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "01"},
                                    "0x0002": {"raw_hex": "15"},
                                }
                            }
                        }
                    },
                },
            },
        },
    }
    fixture_path = tmp_path / "remote_constraint_scope.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    artifact = scan_b524(
        DummyTransport(fixture_path),
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    remote_entry = artifact["groups"]["0x09"]["namespaces"]["0x06"]["instances"]["0x00"][
        "registers"
    ]["0x0002"]
    assert remote_entry["value"] == 21
    assert "constraint_source" not in remote_entry
    assert "constraint_mismatch_reason" not in remote_entry
    assert artifact["meta"].get("constraint_mismatches") is None


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
            make_plan_key(0x69, 0x02): GroupScanPlan(
                group=0x69,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            make_plan_key(0x69, 0x06): GroupScanPlan(
                group=0x69,
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

    assert "0x69" in artifact["groups"]
    group = artifact["groups"]["0x69"]
    assert group["dual_namespace"] is True
    local_registers = group["namespaces"]["0x02"]["instances"]["0x00"]["registers"]
    remote_registers = group["namespaces"]["0x06"]["instances"]["0x00"]["registers"]
    assert local_registers["0x0000"]["raw_hex"] == "00"
    assert remote_registers["0x0000"]["raw_hex"] == "00"
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
            make_plan_key(0x02, 0x02): GroupScanPlan(
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
    assert group["discovery_advisory"]["kind"] == "directory_probe"
    assert group["discovery_advisory"]["semantic_authority"] is False
    assert group["discovery_advisory"]["descriptor_observed"] == 0.0
    assert group["discovery_advisory"]["descriptor_expected"] == 1.0
    assert group["discovery_advisory"]["descriptor_mismatch"] is True
    assert group["discovery_advisory"]["proven_register_opcodes"] == ["0x02"]
    assert group["instances"]["0x00"]["present"] is True
    assert "0x01" not in group["instances"]

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
    assert group["discovery_advisory"]["kind"] == "directory_probe"
    assert group["discovery_advisory"]["semantic_authority"] is False
    assert group["discovery_advisory"]["descriptor_observed"] == 3.0
    assert group["discovery_advisory"]["descriptor_expected"] == 3.0
    assert "descriptor_mismatch" not in group["discovery_advisory"]
    assert group["discovery_advisory"]["proven_register_opcodes"] == ["0x02"]
    assert set(group["instances"]) == {"0x00"}
    assert "0x00" not in artifact["meta"]["scan_plan"]["groups"]

    scanned_instances = {ii for (_opcode, gg, ii, _rr) in transport.register_reads if gg == 0x00}
    assert scanned_instances == set()


def test_artifact_schema_version(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_00(tmp_path)), dst=0x15)

    assert artifact["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    contract = artifact["meta"]["artifact_contract"]
    assert contract["namespace_identity_keys"] == "opcode_hex"
    assert contract["namespace_labels"] == "presentation_only"
    assert "dual_namespace" in contract["topology_authority"]
    assert (
        contract["b524_row_identity"]["dedupe_key_format"]
        == "<group>:<namespace>:<instance>:<register>"
    )
    assert "round_trip_stability" in contract["b524_row_identity"]


def test_artifact_dual_namespace_structure(monkeypatch, tmp_path: Path) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = RecordingTransport(DummyTransport(_write_fixture_group_09(tmp_path)))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            make_plan_key(0x09, 0x02): GroupScanPlan(
                group=0x09,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            make_plan_key(0x09, 0x06): GroupScanPlan(
                group=0x09,
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

    group = artifact["groups"]["0x09"]
    assert group["name"] == "Unknown 0x09 (local) / Regulators"
    assert group["dual_namespace"] is True
    assert "instances" not in group
    assert set(group["namespaces"]) == {"0x02", "0x06"}

    local_ns = group["namespaces"]["0x02"]
    remote_ns = group["namespaces"]["0x06"]
    assert local_ns["label"] == "local"
    assert remote_ns["label"] == "remote"
    assert local_ns["group_name"] == "Unknown 0x09 (local)"
    assert remote_ns["group_name"] == "Regulators"
    assert local_ns["ii_max"] == "0x0a"
    assert remote_ns["ii_max"] == "0x0a"
    assert (
        group["discovery_advisory"]["instance_discovery_decision"]["decision"]
        == "independent_per_namespace"
    )
    assert local_ns["availability_contract"]["namespace_relationship"] == "independent"
    assert local_ns["availability_contract"]["probe_register"] == "0x0001"
    assert remote_ns["availability_contract"]["probe_register"] == "0x0001"
    assert local_ns["availability_probes"]["0x00"]["raw_hex"] == "34"
    assert remote_ns["availability_probes"]["0x00"]["raw_hex"] == "01"
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
        if gg == 0x09 and ii == 0x00 and rr in {0x0000, 0x0001}
    }
    assert scanned_opcodes == {0x02, 0x06}


def test_dual_namespace_presence_is_independent_and_retains_raw_probe_evidence(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = RecordingTransport(
        DummyTransport(_write_fixture_group_09_presence_divergence(tmp_path))
    )

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            make_plan_key(0x09, 0x02): GroupScanPlan(
                group=0x09,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            make_plan_key(0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0000,
                instances=(),
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

    local_ns = artifact["groups"]["0x09"]["namespaces"]["0x02"]
    remote_ns = artifact["groups"]["0x09"]["namespaces"]["0x06"]

    assert local_ns["availability_contract"]["namespace_relationship"] == "independent"
    assert remote_ns["availability_contract"]["namespace_relationship"] == "independent"
    assert local_ns["availability_probes"]["0x00"]["present"] is True
    assert local_ns["availability_probes"]["0x00"]["raw_hex"] == "34"
    assert remote_ns["availability_probes"]["0x00"]["present"] is False
    assert remote_ns["availability_probes"]["0x00"]["reply_hex"] == "0109010000"
    assert remote_ns["availability_probes"]["0x00"]["type"] == "BOOL"
    assert set(local_ns["instances"]) == {"0x00"}
    assert remote_ns["instances"] == {}
    remote_reads = {
        rr for (opcode, gg, _ii, rr) in transport.register_reads if opcode == 0x06 and gg == 0x09
    }
    assert remote_reads == {0x0001}


def test_artifact_single_namespace_unchanged(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_02(tmp_path)), dst=0x15)

    group = artifact["groups"]["0x02"]
    assert group["dual_namespace"] is False
    assert "namespaces" not in group
    assert group["ii_max"] == "0x0a"
    assert set(group["instances"]) >= {"0x00"}


def test_artifact_register_flags_present(tmp_path: Path) -> None:
    artifact = scan_b524(DummyTransport(_write_fixture_group_02(tmp_path)), dst=0x15)

    entry = artifact["groups"]["0x02"]["instances"]["0x00"]["registers"]["0x0002"]

    assert entry["flags"] == 0x01
    assert entry["flags_access"] == "stable_ro"
    assert entry["read_opcode_label"] == "local"


def test_contextual_enum_annotations_do_not_relabel_remote_namespace(tmp_path: Path) -> None:
    fixture_path = _write_fixture_group_02_dual_namespace(tmp_path)
    artifact = json.loads(fixture_path.read_text(encoding="utf-8"))
    _apply_contextual_enum_annotations(artifact)

    local_registers = artifact["groups"]["0x02"]["namespaces"]["0x02"]["instances"]["0x00"][
        "registers"
    ]
    remote_registers = artifact["groups"]["0x02"]["namespaces"]["0x06"]["instances"]["0x00"][
        "registers"
    ]
    assert local_registers["0x0001"]["enum_resolved_name"] == "DIRECT_HEATING_CIRCUIT"
    assert local_registers["0x0002"]["enum_resolved_name"] == "FIXED_VALUE"
    assert local_registers["0x0003"]["enum_resolved_name"] == "ACTIVE"

    assert "enum_resolved_name" not in remote_registers["0x0001"]
    assert "enum_resolved_name" not in remote_registers["0x0002"]
    assert "enum_resolved_name" not in remote_registers["0x0003"]
    assert "value_display" not in remote_registers["0x0001"]
    assert "value_display" not in remote_registers["0x0002"]
    assert "value_display" not in remote_registers["0x0003"]


def test_group_08_remote_namespace_only_marks_present_instances(
    monkeypatch, tmp_path: Path
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_group_08(tmp_path))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            make_plan_key(0x08, 0x02): GroupScanPlan(
                group=0x08,
                opcode=0x02,
                rr_max=0x0000,
                instances=(0x00,),
            ),
            make_plan_key(0x08, 0x06): GroupScanPlan(
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
    assert group["namespaces"]["0x02"]["ii_max"] == "0x00"
    assert group["namespaces"]["0x06"]["ii_max"] == "0x0a"
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
                "namespaces": {
                    "0x06": {
                        "instances": {
                            "0x00": {
                                "registers": {
                                    "0x0001": {"raw_hex": "01"},
                                    "0x0004": {"raw_hex": "021703"},
                                }
                            }
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
            make_plan_key(0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0004,
                instances=(0x00,),
            ),
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
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


def test_scan_b524_replays_dual_namespace_fixture_end_to_end(
    dual_namespace_scan_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod
    from helianthus_vrc_explorer.scanner.director import DiscoveredGroup
    from helianthus_vrc_explorer.scanner.register import (
        InstanceAvailabilityProbe,
        namespace_availability_contract,
    )
    from helianthus_vrc_explorer.schema.myvaillant_map import MyvaillantRegisterMap

    transport = RecordingTransport(DummyTransport(dual_namespace_scan_path))

    def fake_prompt_scan_plan(*_args, **_kwargs):
        return {
            make_plan_key(0x00, 0x02): GroupScanPlan(
                group=0x00,
                opcode=0x02,
                rr_max=0x0004,
                instances=(0x00,),
            ),
            make_plan_key(0x09, 0x02): GroupScanPlan(
                group=0x09,
                opcode=0x02,
                rr_max=0x0007,
                instances=(0x00, 0x01),
            ),
            make_plan_key(0x09, 0x06): GroupScanPlan(
                group=0x09,
                opcode=0x06,
                rr_max=0x0007,
                instances=(0x00, 0x01),
            ),
            make_plan_key(0x0C, 0x06): GroupScanPlan(
                group=0x0C,
                opcode=0x06,
                rr_max=0x0007,
                instances=(0x00,),
            ),
        }

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", fake_prompt_scan_plan)
    monkeypatch.setattr(
        scan_mod,
        "discover_groups",
        lambda *_args, **_kwargs: [
            DiscoveredGroup(group=0x00, descriptor=3.0),
            DiscoveredGroup(group=0x09, descriptor=1.0),
            DiscoveredGroup(group=0x0C, descriptor=1.0),
        ],
    )
    monkeypatch.setattr(
        scan_mod,
        "probe_instance_availability",
        lambda *_args, **kwargs: InstanceAvailabilityProbe(
            present=(
                kwargs["instance"] in {0x00, 0x01}
                if kwargs["group"] == 0x09
                else (kwargs["group"] == 0x0C and kwargs["instance"] == 0x00)
            ),
            contract=namespace_availability_contract(
                group=kwargs["group"],
                opcode=kwargs["opcode"],
            ),
            evidence=None,
        ),
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    map_path = tmp_path / "myvaillant_map.csv"
    map_path.write_text(
        "\n".join(
            [
                "group,instance,register,leaf,ebusd_name,register_class,type_hint,opcode",
                "0x09,*,0x0004,radio_device_firmware_local,,state,FW,0x02",
                "0x09,*,0x0004,radio_device_firmware,,state,FW,0x06",
                "0x0C,*,0x0004,device_firmware_version,,state,FW,0x06",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
        myvaillant_map=MyvaillantRegisterMap.from_path(map_path),
    )

    assert artifact["schema_version"] == CURRENT_ARTIFACT_SCHEMA_VERSION
    local_fw = artifact["groups"]["0x09"]["namespaces"]["0x02"]["instances"]["0x00"]["registers"][
        "0x0004"
    ]
    remote_fw = artifact["groups"]["0x09"]["namespaces"]["0x06"]["instances"]["0x00"]["registers"][
        "0x0004"
    ]
    accessory_fw = artifact["groups"]["0x0c"]["instances"]["0x00"]["registers"]["0x0004"]

    assert local_fw["type"] == "FW"
    assert local_fw["value"] == "03.17.02"
    assert local_fw["flags_access"] == "stable_ro"
    assert local_fw["myvaillant_name"] == "radio_device_firmware_local"
    assert remote_fw["type"] == "FW"
    assert remote_fw["value"] == "02.17.03"
    assert remote_fw["flags_access"] == "stable_ro"
    assert remote_fw["myvaillant_name"] == "radio_device_firmware"
    assert accessory_fw["type"] == "FW"
    assert accessory_fw["value"] == "08.05.00"
    assert accessory_fw["read_opcode_label"] == "remote"
    assert accessory_fw["myvaillant_name"] == "device_firmware_version"
    assert (0x02, 0x09, 0x00, 0x0004) in transport.register_reads
    assert (0x06, 0x09, 0x00, 0x0004) in transport.register_reads
    assert (0x06, 0x0C, 0x00, 0x0004) in transport.register_reads


def test_scan_b524_normalizes_legacy_aggressive_preset_to_full_for_textual_default_plan(
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

    assert captured["default_preset"] == "full"
    default_plan = captured["default_plan"]
    assert isinstance(default_plan, dict)
    assert make_plan_key(0x69, 0x02) not in default_plan
    assert make_plan_key(0x69, 0x06) not in default_plan


def test_scan_b524_normalizes_exhaustive_preset_to_research_for_textual_default_plan(
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
        planner_preset="exhaustive",
    )

    assert captured["default_preset"] == "research"
    default_plan = captured["default_plan"]
    assert isinstance(default_plan, dict)
    assert make_plan_key(0x69, 0x02) in default_plan
    assert make_plan_key(0x69, 0x06) in default_plan


def test_scan_b524_applies_research_preset_in_non_interactive_mode(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_unknown_group_69(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="research",
    )

    scan_plan = artifact["meta"]["scan_plan"]["groups"]
    assert "0x69" in scan_plan
    assert scan_plan["0x69"]["dual_namespace"] is True
    assert set(scan_plan["0x69"]["namespaces"]) == {"0x02", "0x06"}
    for namespace in ("0x02", "0x06"):
        assert scan_plan["0x69"]["namespaces"][namespace]["rr_max"] == "0x0030"
        assert scan_plan["0x69"]["namespaces"][namespace]["instances"] == [
            f"0x{ii:02x}" for ii in range(0x0B)
        ]

    group = artifact["groups"]["0x69"]
    assert group["dual_namespace"] is True
    assert set(group["namespaces"]) == {"0x02", "0x06"}
    assert group["namespaces"]["0x02"]["instances"]["0x00"]["present"] is True
    assert group["namespaces"]["0x06"]["instances"]["0x00"]["present"] is True


def test_scan_b524_full_preset_keeps_unknown_groups_out_of_default_plan(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_unknown_group_69(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="full",
    )

    assert "0x69" not in artifact["meta"]["scan_plan"]["groups"]


def test_scan_b524_recommended_plan_keeps_namespace_rr_max(tmp_path: Path) -> None:
    artifact = scan_b524(
        DummyTransport(_write_fixture_group_09(tmp_path)),
        dst=0x15,
        planner_ui="auto",
        planner_preset="recommended",
    )

    plan = artifact["meta"]["scan_plan"]["groups"]["0x09"]
    assert plan["dual_namespace"] is True
    assert plan["namespaces"]["0x02"]["rr_max"] == "0x000f"
    assert plan["namespaces"]["0x06"]["rr_max"] == "0x0035"
    assert artifact["meta"]["scan_plan"]["estimated_register_requests"] == 70


def test_scan_b524_instance_discovery_runs_local_namespace_before_remote(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod
    from helianthus_vrc_explorer.scanner.director import DiscoveredGroup

    fixture = {
        "meta": {"dummy_transport": {"directory_terminator_group": "0x0b"}},
        "groups": {
            "0x09": {
                "descriptor_type": 1.0,
                "namespaces": {
                    "0x02": {"instances": {"0x00": {"registers": {"0x0001": {"raw_hex": "34"}}}}},
                    "0x06": {"instances": {"0x00": {"registers": {"0x0001": {"raw_hex": "01"}}}}},
                },
            },
            "0x0A": {
                "descriptor_type": 1.0,
                "namespaces": {
                    "0x02": {"instances": {"0x00": {"registers": {"0x0001": {"raw_hex": "34"}}}}},
                    "0x06": {"instances": {"0x00": {"registers": {"0x0001": {"raw_hex": "01"}}}}},
                },
            },
        },
    }
    fixture_path = tmp_path / "fixture_group_09_0a_order.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    transport = RecordingTransport(DummyTransport(fixture_path))

    monkeypatch.setattr(
        scan_mod,
        "discover_groups",
        lambda *_args, **_kwargs: [
            DiscoveredGroup(group=0x09, descriptor=1.0),
            DiscoveredGroup(group=0x0A, descriptor=1.0),
        ],
    )
    monkeypatch.setattr(scan_mod, "prompt_scan_plan", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="classic",
    )

    presence_reads = [
        opcode
        for (opcode, gg, _ii, rr) in transport.register_reads
        if gg in {0x09, 0x0A} and rr == 0x0001
    ]
    first_remote_index = next(
        index for index, opcode in enumerate(presence_reads) if opcode == 0x06
    )
    assert all(opcode == 0x02 for opcode in presence_reads[:first_remote_index])
    assert all(opcode == 0x06 for opcode in presence_reads[first_remote_index:])


def test_planner_source_opcodes_include_staged_group_01_remote_but_keep_group_00_local_only() -> (
    None
):
    assert _planner_source_opcodes(0x00) == (0x02,)
    assert _planner_source_opcodes(0x01) == (0x02, 0x06)


def test_scan_b524_disabled_planner_skips_interactive_planner_even_on_tty(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    transport = DummyTransport(_write_fixture_unknown_group_69(tmp_path))

    def _unexpected(*_args, **_kwargs):
        raise AssertionError("planner should stay disabled")

    monkeypatch.setattr(scan_mod, "prompt_scan_plan", _unexpected)
    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        _unexpected,
        raising=False,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        transport,
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="disabled",
        planner_preset="recommended",
    )

    assert artifact["meta"]["incomplete"] is False


def test_scan_unknown_group_probes_both_opcodes_and_two_instances(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_fixture_unknown_group_69(tmp_path)))

    artifact = scan_b524(
        transport,
        dst=0x15,
        planner_ui="auto",
        planner_preset="full",
    )

    group = artifact["groups"]["0x69"]
    assert group["descriptor_observed"] == 1.0
    assert group["dual_namespace"] is True
    assert set(group["namespaces"]) == {"0x02", "0x06"}
    probed_instances = {
        (opcode, ii)
        for (opcode, gg, ii, rr) in transport.register_reads
        if gg == 0x69 and rr == 0x0000 and ii in {0x00, 0x01}
    }
    assert probed_instances >= {
        (0x02, 0x00),
        (0x02, 0x01),
        (0x06, 0x00),
        (0x06, 0x01),
    }


def test_probe_unknown_group_opcodes_ignores_absent_flags_access() -> None:
    class _AbsentProbeTransport(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            if payload == bytes((0x02, 0x00, 0x69, 0x00, 0x00, 0x00)):
                return b"\x00"
            if payload == bytes((0x06, 0x00, 0x69, 0x00, 0x00, 0x00)):
                return b"\x01\x69\x00\x00\x01"
            raise AssertionError(f"unexpected probe payload: {payload.hex()}")

    opcodes, probe_summary = _probe_unknown_group_opcodes(
        _AbsentProbeTransport(),
        dst=0x15,
        group=0x69,
        observer=None,
    )

    assert opcodes == (0x06,)
    assert probe_summary["responsive_opcodes"] == ["0x06"]
    assert probe_summary["candidates"]["0x02"]["flags_access"] == "absent"
    assert probe_summary["candidates"]["0x02"]["responsive"] is False


def test_scan_unknown_group_expands_to_instance_ff_after_readable_probe(tmp_path: Path) -> None:
    transport = RecordingTransport(
        DummyTransport(_write_fixture_unknown_group_69_with_ff(tmp_path))
    )

    artifact = scan_b524(
        transport,
        dst=0x15,
        planner_ui="auto",
        planner_preset="research",
    )

    group = artifact["groups"]["0x69"]
    assert group["dual_namespace"] is False
    assert group["ii_max"] == "0x0a"
    remote_instances = group["instances"]
    assert remote_instances["0x00"]["present"] is True
    assert remote_instances["0xff"]["present"] is True

    assert "0x69" in artifact["meta"]["scan_plan"]["groups"]
    plan_group = artifact["meta"]["scan_plan"]["groups"]["0x69"]
    assert plan_group["rr_max"] == "0x0030"
    assert plan_group["instances"][-1] == "0xff"

    advisory = group["discovery_advisory"]
    assert advisory["proven_register_opcodes"] == ["0x06"]
    assert advisory["opcode_probe"]["responsive_opcodes"] == ["0x06"]

    local_reads = {
        (opcode, ii, rr)
        for (opcode, gg, ii, rr) in transport.register_reads
        if gg == 0x69 and opcode == 0x02
    }
    assert local_reads == {(0x02, 0x00, 0x0000)}
    assert (0x06, 0x69, 0xFF, 0x0000) in transport.register_reads


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


def test_scan_b524_textual_planner_receives_group_01_remote_and_keeps_group_00_local_only(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    captured: dict[str, object] = {}

    def fake_run_textual_scan_plan(groups, **kwargs):
        captured["groups"] = groups
        captured["default_plan"] = kwargs["default_plan"]
        return {}

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        DummyTransport(_write_fixture_groups_00_and_01(tmp_path)),
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="textual",
        planner_preset="recommended",
    )

    planner_groups = captured["groups"]
    assert isinstance(planner_groups, list)
    planner_keys = {(group.group, group.opcode) for group in planner_groups}
    assert (0x00, 0x02) in planner_keys
    assert (0x00, 0x06) not in planner_keys
    assert (0x01, 0x02) in planner_keys
    assert (0x01, 0x06) in planner_keys

    name_by_key = {(group.group, group.opcode): group.name for group in planner_groups}
    assert name_by_key[(0x00, 0x02)] == "Regulator Parameters"
    assert name_by_key[(0x01, 0x02)] == "Hot Water Circuit"
    assert name_by_key[(0x01, 0x06)] == "Secondary Heating Sources"

    default_plan = captured["default_plan"]
    assert isinstance(default_plan, dict)
    assert make_plan_key(0x00, 0x02) not in default_plan
    assert make_plan_key(0x01, 0x02) not in default_plan
    assert make_plan_key(0x01, 0x06) not in default_plan
    assert make_plan_key(0x00, 0x06) not in default_plan
    assert artifact["meta"]["scan_plan"]["estimated_register_requests"] == 0


def test_scan_b524_textual_planner_uses_namespace_owned_labels_for_groups_09_and_0a(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys

    captured: dict[str, object] = {}

    def fake_run_textual_scan_plan(groups, **kwargs):
        captured["groups"] = groups
        captured["default_plan"] = kwargs["default_plan"]
        return {}

    monkeypatch.setattr(
        "helianthus_vrc_explorer.ui.planner_textual.run_textual_scan_plan",
        fake_run_textual_scan_plan,
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)

    artifact = scan_b524(
        DummyTransport(_write_fixture_group_09(tmp_path)),
        dst=0x15,
        observer=_NoopObserver(),
        console=Console(force_terminal=True),
        planner_ui="textual",
        planner_preset="recommended",
    )

    planner_groups = captured["groups"]
    assert isinstance(planner_groups, list)
    planner_label_map = {
        (group.group, group.opcode): (group.name, group.namespace_label) for group in planner_groups
    }
    assert planner_label_map[(0x09, 0x02)] == ("Unknown 0x09 (local)", "local")
    assert planner_label_map[(0x09, 0x06)] == ("Regulators", "remote")
    assert artifact["groups"]["0x09"]["name"] == "Unknown 0x09 (local) / Regulators"


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


def test_scan_b524_replan_promotes_group_01_to_dual_namespace_before_queue_rebuild(
    monkeypatch,
    tmp_path: Path,
) -> None:
    import sys
    from contextlib import contextmanager

    import helianthus_vrc_explorer.scanner.scan as scan_mod

    class _FakeHotkeys:
        def __init__(self, *, enabled: bool) -> None:
            self._enabled = enabled
            self._poll_calls = 0

        def __enter__(self) -> _FakeHotkeys:
            return self

        def __exit__(self, *_exc: object) -> None:
            return None

        def poll(self) -> bool:
            if not self._enabled:
                return False
            self._poll_calls += 1
            return self._poll_calls == 2

        @contextmanager
        def suspend(self):
            yield None

    transport = RecordingTransport(DummyTransport(_write_fixture_group_01_namespaces(tmp_path)))
    planner_calls = {"count": 0}

    def fake_prompt_scan_plan(*_args, **_kwargs):
        planner_calls["count"] += 1
        if planner_calls["count"] == 1:
            return {
                make_plan_key(0x01, 0x02): GroupScanPlan(
                    group=0x01,
                    opcode=0x02,
                    rr_max=0x0001,
                    instances=(0x00,),
                )
            }
        return {
            make_plan_key(0x01, 0x02): GroupScanPlan(
                group=0x01,
                opcode=0x02,
                rr_max=0x0001,
                instances=(0x00,),
            ),
            make_plan_key(0x01, 0x06): GroupScanPlan(
                group=0x01,
                opcode=0x06,
                rr_max=0x0000,
                instances=(0x00,),
            ),
        }

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

    group = artifact["groups"]["0x01"]
    assert group["dual_namespace"] is True
    assert "instances" not in group
    assert (
        group["namespaces"]["0x02"]["instances"]["0x00"]["registers"]["0x0000"]["raw_hex"] == "02"
    )
    assert (
        group["namespaces"]["0x06"]["instances"]["0x00"]["registers"]["0x0000"]["raw_hex"] == "06"
    )

    scan_plan = artifact["meta"]["scan_plan"]["groups"]["0x01"]
    assert scan_plan["dual_namespace"] is True
    assert set(scan_plan["namespaces"]) == {"0x02", "0x06"}
    assert (0x06, 0x01, 0x00, 0x0000) in transport.register_reads


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
            make_plan_key(0x02, 0x02): GroupScanPlan(
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
