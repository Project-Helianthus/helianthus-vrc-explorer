from __future__ import annotations

import json
import logging
import math
from pathlib import Path

import pytest

from helianthus_vrc_explorer.scanner.director import (
    GROUP_CONFIG,
    KNOWN_CORE_GROUPS,
    DiscoveredGroup,
    classify_groups,
    discover_groups,
    group_name_for_opcode,
    group_namespace_profiles,
)
from helianthus_vrc_explorer.transport.base import (
    TransportCommandNotEnabled,
    TransportError,
    TransportInterface,
    TransportRecoveryExhausted,
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.dummy import DummyTransport


class RecordingObserver:
    def __init__(self) -> None:
        self.advanced: list[tuple[str, int]] = []
        self.statuses: list[str] = []
        self.logs: list[tuple[str, str]] = []

    def phase_start(self, _phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        self.advanced.append((phase, advance))

    def phase_set_total(self, _phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_finish(self, _phase: str) -> None:  # noqa: ARG002
        return None

    def status(self, message: str) -> None:
        self.statuses.append(message)

    def log(self, message: str, *, level: str = "info") -> None:
        self.logs.append((message, level))


class RecordingTransport(TransportInterface):
    def __init__(self, inner: TransportInterface) -> None:
        self._inner = inner
        self.probed_groups: list[int] = []

    def send(self, dst: int, payload: bytes) -> bytes:
        if payload and payload[0] == 0x00 and len(payload) >= 2:
            self.probed_groups.append(payload[1])
        return self._inner.send(dst, payload)


def _write_directory_fixture(
    tmp_path: Path,
    *,
    groups: dict[str, dict[str, object]] | None = None,
    terminator_group: str | None = "0x05",
) -> Path:
    fixture = {
        "meta": {"dummy_transport": {}},
        "groups": groups
        if groups is not None
        else {
            "0x00": {"descriptor_type": 3.0, "instances": {}},
            # Intentional hole at 0x01/0x02 (unknown groups => descriptor==0.0)
            "0x03": {"descriptor_type": 1.0, "instances": {}},
        },
    }
    if terminator_group is not None:
        fixture["meta"]["dummy_transport"]["directory_terminator_group"] = terminator_group
    fixture_path = tmp_path / "fixture.json"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")
    return fixture_path


def test_system_information_reads_bounded_identifiers_past_nan(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(DummyTransport(_write_directory_fixture(tmp_path)))

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == list(range(18))

    # Terminator is triggered by the first NaN (GG=0x05), so probing stops there.
    assert transport.probed_groups == list(range(18))


def test_discover_groups_includes_core_with_zero_descriptor(tmp_path: Path) -> None:
    fixture_path = _write_directory_fixture(
        tmp_path,
        groups={
            "0x00": {"descriptor_type": 3.0, "instances": {}},
            "0x02": {"descriptor_type": 0.0, "instances": {}},
        },
        terminator_group="0x04",
    )
    transport = RecordingTransport(DummyTransport(fixture_path))

    discovered = discover_groups(transport, dst=0x15)

    assert frozenset({0x02, 0x03}) == KNOWN_CORE_GROUPS
    assert [group.group for group in discovered] == list(range(18))


def test_discover_groups_keeps_non_core_zero_descriptor_groups(
    tmp_path: Path,
) -> None:
    fixture_path = _write_directory_fixture(
        tmp_path,
        groups={
            "0x00": {"descriptor_type": 3.0, "instances": {}},
            "0x09": {"descriptor_type": 0.0, "instances": {}},
        },
        terminator_group="0x0A",
    )
    transport = RecordingTransport(DummyTransport(fixture_path))

    discovered = discover_groups(transport, dst=0x15)

    assert 0x09 in [group.group for group in discovered]
    assert 0x09 in transport.probed_groups


def test_system_information_probe_identifiers_are_bounded(
    tmp_path: Path,
) -> None:
    fixture_path = _write_directory_fixture(tmp_path, groups={}, terminator_group=None)
    transport = RecordingTransport(DummyTransport(fixture_path))

    discovered = discover_groups(transport, dst=0x15)

    assert len(discovered) == 18
    assert discovered[0].group == 0x00
    assert discovered[-1].group == 0x11
    assert transport.probed_groups[0] == 0x00
    assert transport.probed_groups[-1] == 0x11


def test_system_information_nan_does_not_terminate_discovery(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_directory_fixture(tmp_path)))

    discover_groups(transport, dst=0x15)

    assert transport.probed_groups[-1] == 0x11


class FlakyDirectoryTransport(TransportInterface):
    def __init__(
        self,
        inner: TransportInterface,
        *,
        timeouts: set[int] | None = None,
        errors: set[int] | None = None,
        short_responses: set[int] | None = None,
    ) -> None:
        self._inner = inner
        self._timeouts = timeouts or set()
        self._errors = errors or set()
        self._short_responses = short_responses or set()

    def send(self, dst: int, payload: bytes) -> bytes:
        if payload and payload[0] == 0x00 and len(payload) >= 2:
            gg = payload[1]
            if gg in self._timeouts:
                raise TransportTimeout("boom")
            if gg in self._errors:
                raise TransportError("nope")
            if gg in self._short_responses:
                return b"\x00"
        return self._inner.send(dst, payload)


class OneShotTimeoutDirectoryTransport(TransportInterface):
    def __init__(self, inner: TransportInterface, *, groups: set[int]) -> None:
        self._inner = inner
        self._groups = groups
        self._seen: set[int] = set()

    def send(self, dst: int, payload: bytes) -> bytes:
        if payload and payload[0] == 0x00 and len(payload) >= 2:
            gg = payload[1]
            if gg in self._groups and gg not in self._seen:
                self._seen.add(gg)
                raise TransportTimeout("boom-once")
        return self._inner.send(dst, payload)


class FatalDirectoryTransport(TransportInterface):
    def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
        raise TransportCommandNotEnabled("ERR: command not enabled")


def test_discover_groups_does_not_terminate_on_transient_transport_failures(tmp_path: Path) -> None:
    # Terminator (NaN) starts at GG=0x08.
    fixture_path = _write_directory_fixture(tmp_path)
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    fixture["meta"]["dummy_transport"]["directory_terminator_group"] = "0x08"
    fixture_path.write_text(json.dumps(fixture), encoding="utf-8")

    inner = DummyTransport(fixture_path)
    flaky = FlakyDirectoryTransport(inner, timeouts={0x04}, errors={0x05}, short_responses={0x06})
    transport = RecordingTransport(flaky)

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == [i for i in range(18) if i not in {4, 5}]
    unavailable = next(group for group in discovered if group.group == 6)
    assert math.isnan(unavailable.descriptor)
    assert unavailable.raw_hex == "00"
    # Failures at 0x04/0x05/0x06 must not terminate discovery early.
    assert transport.probed_groups[:4] == [0x00, 0x01, 0x02, 0x03]
    assert transport.probed_groups.count(0x04) == 3
    assert transport.probed_groups.count(0x05) == 3
    assert transport.probed_groups.count(0x06) == 3
    assert transport.probed_groups[-2:] == [0x10, 0x11]


def test_discover_groups_treats_status_only_gg00_as_transient(tmp_path: Path) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    flaky = FlakyDirectoryTransport(inner, short_responses={0x00})
    transport = RecordingTransport(flaky)

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == list(range(18))
    assert math.isnan(discovered[0].descriptor)
    assert discovered[0].raw_hex == "00"
    assert transport.probed_groups.count(0x00) == 3
    assert transport.probed_groups[-1] == 0x11


@pytest.mark.parametrize("failure", [TransportTimeout, TransportError])
def test_system_information_retains_short_response_before_retry_failure(
    tmp_path: Path, failure: type[TransportError]
) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))

    class ShortThenFailTransport(TransportInterface):
        attempts = 0

        def send(self, dst: int, payload: bytes) -> bytes:
            if payload[:3] == b"\x00\x00\x00":
                self.attempts += 1
                if self.attempts == 1:
                    return b"\x01\x02"
                raise failure("retry failure")
            return inner.send(dst, payload)

    discovered = discover_groups(ShortThenFailTransport(), dst=0x15)
    assert [group.group for group in discovered] == list(range(18))
    assert math.isnan(discovered[0].descriptor)
    assert discovered[0].raw_hex == "0102"


def test_discover_groups_retries_known_group_after_single_timeout(tmp_path: Path) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    flaky = OneShotTimeoutDirectoryTransport(inner, groups={0x03})
    transport = RecordingTransport(flaky)

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == list(range(18))
    assert transport.probed_groups.count(0x03) == 2


def test_discovery_keeps_progress_compact_and_quiet_after_recovered_retry(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    observer = RecordingObserver()
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    transport = OneShotTimeoutDirectoryTransport(inner, groups={0x03})
    caplog.set_level(logging.DEBUG, logger="helianthus_vrc_explorer.scanner.director")

    discover_groups(transport, dst=0x15, observer=observer)  # type: ignore[arg-type]

    assert observer.advanced == [("group_discovery", 1)] * 18
    assert observer.statuses == []
    assert observer.logs == []
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_discovery_reports_one_terminal_warning_through_observer_only(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    observer = RecordingObserver()
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    transport = FlakyDirectoryTransport(inner, timeouts={0x04})
    caplog.set_level(logging.DEBUG, logger="helianthus_vrc_explorer.scanner.director")

    discover_groups(transport, dst=0x15, observer=observer)  # type: ignore[arg-type]

    assert observer.logs == [("System information timeout for ID=0x04", "warn")]
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_discovery_propagates_terminal_recovery_with_earlier_op00_records(tmp_path: Path) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))

    class RecoveryExhaustedTransport(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:
            if payload[:3] == b"\x00\x03\x00":
                raise TransportRecoveryExhausted(
                    cause="disconnected",
                    phase="receive",
                    request_attempts=3,
                    reconnect_attempts=2,
                )
            return inner.send(dst, payload)

    with pytest.raises(TransportRecoveryExhausted) as raised:
        discover_groups(RecoveryExhaustedTransport(), dst=0x15)

    preserved = raised.value.system_information
    assert [identifier for identifier, _value, _raw_hex in preserved] == [0x00, 0x01, 0x02]
    assert all(raw_hex is not None for _identifier, _value, raw_hex in preserved)
    assert raised.value.selector == {
        "read_opcode": "0x00",
        "identifier": "0x0003",
        "request_hex": "000300",
    }


def test_classify_groups_logs_descriptor_mismatch_at_info(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="helianthus_vrc_explorer.scanner.director")

    classified = classify_groups([DiscoveredGroup(group=0x02, descriptor=3.0)])

    assert classified[0].descriptor_mismatch is True
    assert classified[0].expected_descriptor == 1.0
    assert any(
        record.levelno == logging.INFO and "Descriptor mismatch for GG=0x02" in record.message
        for record in caplog.records
    )


def test_group_00_rr_max_is_0x00ff() -> None:
    assert GROUP_CONFIG[0x00]["rr_max"] == 0x01FF


def test_group_names_match_docs() -> None:
    assert len(GROUP_CONFIG) == 18
    assert GROUP_CONFIG[0x09]["name"] == "Regulators"
    assert GROUP_CONFIG[0x0A]["name"] == "Thermostats"
    assert GROUP_CONFIG[0x0C]["name"] == "Functional Modules (VR71)"
    assert GROUP_CONFIG[0x0E]["name"] == "Clock"
    assert GROUP_CONFIG[0x0F]["name"] == "Base Stations"


def test_group_config_completeness() -> None:
    assert set(GROUP_CONFIG) == {
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
        0x10,
        0x11,
    }
    assert GROUP_CONFIG[0x08]["name"] == "Unknown"
    assert GROUP_CONFIG[0x00]["namespace_opcodes"] == [0x02]
    assert GROUP_CONFIG[0x00]["rr_max_by_opcode"] == {0x02: 0x01FF}
    assert GROUP_CONFIG[0x00]["ii_max_by_opcode"] == {0x02: 0x00}
    assert GROUP_CONFIG[0x01]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x01]["rr_max_by_opcode"] == {0x02: 0x0013, 0x06: 0x0015}
    assert GROUP_CONFIG[0x01]["ii_max_by_opcode"] == {0x02: 0x00, 0x06: 0x08}
    assert GROUP_CONFIG[0x02]["name_by_opcode"] == {
        0x02: "Heating Circuits",
        0x06: "Secondary Heating Source",
    }
    assert GROUP_CONFIG[0x02]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x02]["ii_max_by_opcode"] == {0x02: 0x0A, 0x06: 0x08}
    assert GROUP_CONFIG[0x02]["rr_max_by_opcode"] == {0x02: 0x0025, 0x06: 0x0015}
    assert GROUP_CONFIG[0x03]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x03]["ii_max_by_opcode"] == {0x02: 0x0A, 0x06: 0x0A}
    assert GROUP_CONFIG[0x04]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x04]["ii_max_by_opcode"] == {0x02: 0x01, 0x06: 0x0A}
    assert GROUP_CONFIG[0x05]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x05]["ii_max_by_opcode"] == {0x02: 0x01, 0x06: 0x0A}
    assert GROUP_CONFIG[0x08]["opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x08]["name_by_opcode"] == {
        0x02: "Unknown",
        0x06: "Unknown",
    }
    assert GROUP_CONFIG[0x08]["rr_max_by_opcode"] == {0x02: 0x0007, 0x06: 0x0004}
    assert GROUP_CONFIG[0x08]["ii_max_by_opcode"] == {0x02: 0x0A, 0x06: 0x0A}
    assert "desc" not in GROUP_CONFIG[0x08]
    assert GROUP_CONFIG[0x09]["rr_max"] == 0x0035
    assert GROUP_CONFIG[0x09]["rr_max_by_opcode"] == {0x02: 0x000F, 0x06: 0x0035}
    assert GROUP_CONFIG[0x0A]["rr_max"] == 0x004D
    assert GROUP_CONFIG[0x0A]["rr_max_by_opcode"] == {0x02: 0x004D, 0x06: 0x0035}
    assert GROUP_CONFIG[0x06]["opcodes"] == [0x06]
    assert GROUP_CONFIG[0x07]["opcodes"] == [0x06]
    assert GROUP_CONFIG[0x0B]["opcodes"] == [0x06]


def test_group_namespace_profiles_support_opcode_first_identity() -> None:
    heat_sources = group_namespace_profiles(0x00)
    hw = group_namespace_profiles(0x01)
    hc = group_namespace_profiles(0x02)
    zones = group_namespace_profiles(0x03)
    solar = group_namespace_profiles(0x04)
    cylinders = group_namespace_profiles(0x05)
    regulators = group_namespace_profiles(0x09)
    thermostats = group_namespace_profiles(0x0A)

    assert sorted(heat_sources) == [0x02]
    assert heat_sources[0x02].name == "Regulator Parameters"

    assert sorted(hw) == [0x02, 0x06]
    assert hw[0x02].rr_max == 0x0013
    assert hw[0x06].name == "Primary Heating Source"
    assert hw[0x06].ii_max == 0x08
    assert hw[0x06].rr_max == 0x0015

    assert sorted(hc) == [0x02, 0x06]
    assert hc[0x02].ii_max == 0x0A
    assert hc[0x06].ii_max == 0x08
    assert hc[0x06].name == "Secondary Heating Source"
    assert zones[0x06].name == "Unknown"
    assert zones[0x06].ii_max == 0x0A
    assert solar[0x02].ii_max == 0x01
    assert solar[0x06].name == "Unknown"
    assert solar[0x06].ii_max == 0x0A
    assert cylinders[0x06].name == "Unknown"
    assert cylinders[0x06].ii_max == 0x0A
    buffer = group_namespace_profiles(0x08)
    assert buffer[0x02].ii_max == 0x0A
    assert buffer[0x06].ii_max == 0x0A
    assert buffer[0x02].name == "Unknown"
    assert buffer[0x06].name == "Unknown"
    assert regulators[0x02].name == "System"
    assert regulators[0x06].name == "Regulators"
    assert thermostats[0x02].name == "Unknown"
    assert thermostats[0x06].name == "Thermostats"


def test_group_name_for_opcode_uses_namespace_owned_labels_for_09_and_0a() -> None:
    assert group_name_for_opcode(0x00, 0x02) == "Regulator Parameters"
    assert group_name_for_opcode(0x00, 0x06) == "Regulator Parameters"
    assert group_name_for_opcode(0x01, 0x02) == "Hot Water Circuit"
    assert group_name_for_opcode(0x01, 0x06) == "Primary Heating Source"
    assert group_name_for_opcode(0x02, 0x06) == "Secondary Heating Source"
    assert group_name_for_opcode(0x03, 0x06) == "Unknown"
    assert group_name_for_opcode(0x04, 0x06) == "Unknown"
    assert group_name_for_opcode(0x05, 0x06) == "Unknown"
    assert group_name_for_opcode(0x08, 0x02) == "Unknown"
    assert group_name_for_opcode(0x08, 0x06) == "Unknown"
    assert group_name_for_opcode(0x09, 0x02) == "System"
    assert group_name_for_opcode(0x09, 0x06) == "Regulators"
    assert group_name_for_opcode(0x0A, 0x02) == "Unknown"
    assert group_name_for_opcode(0x0A, 0x06) == "Thermostats"
    assert group_name_for_opcode(0x0B, 0x02) == "Unknown"
    assert group_name_for_opcode(0x0B, 0x06) == "Functional Modules (VR70)"
    assert group_name_for_opcode(0x0C, 0x02) == "Unknown"
    assert group_name_for_opcode(0x0C, 0x06) == "Functional Modules (VR71)"
    assert group_name_for_opcode(0x0D, 0x02) == "Unknown"
    assert group_name_for_opcode(0x0D, 0x06) == "Unknown"
    assert group_name_for_opcode(0x0E, 0x06) == "Clock"
    assert group_name_for_opcode(0x0F, 0x06) == "Base Stations"


def test_classify_groups_missing_desc() -> None:
    classified = classify_groups([DiscoveredGroup(group=0x08, descriptor=0.0)])

    assert classified[0].name == "Unknown"
    assert classified[0].expected_descriptor is None
    assert classified[0].descriptor_mismatch is False


def test_discover_groups_command_not_enabled_is_fatal() -> None:
    with pytest.raises(TransportCommandNotEnabled):
        discover_groups(FatalDirectoryTransport(), dst=0x15)
