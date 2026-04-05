from __future__ import annotations

import json
import logging
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
    TransportTimeout,
)
from helianthus_vrc_explorer.transport.dummy import DummyTransport


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


def test_discover_groups_stops_after_first_nan_and_keeps_zero_descriptor_groups(
    tmp_path: Path,
) -> None:
    transport = RecordingTransport(DummyTransport(_write_directory_fixture(tmp_path)))

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == [0x00, 0x01, 0x02, 0x03, 0x04]

    # Terminator is triggered by the first NaN (GG=0x05), so probing stops there.
    assert transport.probed_groups == [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]


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
    assert [group.group for group in discovered] == [0x00, 0x01, 0x02, 0x03]


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


def test_discover_groups_keeps_zero_descriptor_unknown_groups_until_nan(
    tmp_path: Path,
) -> None:
    fixture_path = _write_directory_fixture(tmp_path, groups={}, terminator_group=None)
    transport = RecordingTransport(DummyTransport(fixture_path))

    discovered = discover_groups(transport, dst=0x15)

    assert len(discovered) == 0x100
    assert discovered[0].group == 0x00
    assert discovered[-1].group == 0xFF
    assert transport.probed_groups[0] == 0x00
    assert transport.probed_groups[-1] == 0xFF


def test_discover_groups_still_terminates_on_nan(tmp_path: Path) -> None:
    transport = RecordingTransport(DummyTransport(_write_directory_fixture(tmp_path)))

    discover_groups(transport, dst=0x15)

    assert transport.probed_groups[-1] == 0x05


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

    assert [group.group for group in discovered] == [0x00, 0x01, 0x02, 0x03, 0x07]
    # Failures at 0x04/0x05/0x06 must not terminate discovery early.
    assert transport.probed_groups[:4] == [0x00, 0x01, 0x02, 0x03]
    assert transport.probed_groups.count(0x04) == 3
    assert transport.probed_groups.count(0x05) == 3
    assert transport.probed_groups.count(0x06) == 3
    assert transport.probed_groups[-2:] == [0x07, 0x08]


def test_discover_groups_treats_status_only_gg00_as_transient(tmp_path: Path) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    flaky = FlakyDirectoryTransport(inner, short_responses={0x00})
    transport = RecordingTransport(flaky)

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == [0x01, 0x02, 0x03, 0x04]
    assert transport.probed_groups.count(0x00) == 3
    assert transport.probed_groups[-5:] == [0x01, 0x02, 0x03, 0x04, 0x05]


def test_discover_groups_retries_known_group_after_single_timeout(tmp_path: Path) -> None:
    inner = DummyTransport(_write_directory_fixture(tmp_path))
    flaky = OneShotTimeoutDirectoryTransport(inner, groups={0x03})
    transport = RecordingTransport(flaky)

    discovered = discover_groups(transport, dst=0x15)

    assert [group.group for group in discovered] == [0x00, 0x01, 0x02, 0x03, 0x04]
    assert transport.probed_groups.count(0x03) == 2


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
    assert GROUP_CONFIG[0x00]["rr_max"] == 0x00FF


def test_group_names_match_docs() -> None:
    assert len(GROUP_CONFIG) == 18
    assert GROUP_CONFIG[0x09]["name"] == "Regulators"
    assert GROUP_CONFIG[0x0A]["name"] == "Thermostats"
    assert GROUP_CONFIG[0x0C]["name"] == "Functional Modules"


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
    assert GROUP_CONFIG[0x08]["name"] == "Buffer / Solar Cylinder 2"
    assert GROUP_CONFIG[0x01]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x01]["rr_max_by_opcode"] == {0x02: 0x0013, 0x06: 0x0015}
    assert GROUP_CONFIG[0x02]["namespace_opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x02]["ii_max_by_opcode"] == {0x02: 0x0A, 0x06: 0x0A}
    assert GROUP_CONFIG[0x08]["opcodes"] == [0x02, 0x06]
    assert GROUP_CONFIG[0x08]["rr_max_by_opcode"] == {0x02: 0x0007, 0x06: 0x0004}
    assert GROUP_CONFIG[0x08]["ii_max_by_opcode"] == {0x02: 0x00, 0x06: 0x0A}
    assert "desc" not in GROUP_CONFIG[0x08]
    assert GROUP_CONFIG[0x09]["rr_max"] == 0x0035
    assert GROUP_CONFIG[0x09]["rr_max_by_opcode"] == {0x02: 0x000F, 0x06: 0x0035}
    assert GROUP_CONFIG[0x0A]["rr_max"] == 0x004D
    assert GROUP_CONFIG[0x0A]["rr_max_by_opcode"] == {0x02: 0x004D, 0x06: 0x0035}
    assert GROUP_CONFIG[0x06]["opcodes"] == [0x06]
    assert GROUP_CONFIG[0x07]["opcodes"] == [0x06]
    assert GROUP_CONFIG[0x0B]["opcodes"] == [0x06]


def test_group_namespace_profiles_support_opcode_first_identity() -> None:
    hw = group_namespace_profiles(0x01)
    hc = group_namespace_profiles(0x02)
    regulators = group_namespace_profiles(0x09)
    thermostats = group_namespace_profiles(0x0A)

    assert sorted(hw) == [0x02, 0x06]
    assert hw[0x02].rr_max == 0x0013
    assert hw[0x06].rr_max == 0x0015

    assert sorted(hc) == [0x02, 0x06]
    assert hc[0x02].ii_max == 0x0A
    assert hc[0x06].ii_max == 0x0A
    assert regulators[0x02].name == "Unknown 0x09 (local)"
    assert regulators[0x06].name == "Regulators"
    assert thermostats[0x02].name == "Unknown 0x0A (local)"
    assert thermostats[0x06].name == "Thermostats"


def test_group_name_for_opcode_uses_namespace_owned_labels_for_09_and_0a() -> None:
    assert group_name_for_opcode(0x00, 0x02) == "Regulator Parameters"
    assert group_name_for_opcode(0x00, 0x06) == "Primary Heating Sources"
    assert group_name_for_opcode(0x01, 0x02) == "Hot Water Circuit"
    assert group_name_for_opcode(0x01, 0x06) == "Secondary Heating Sources"
    assert group_name_for_opcode(0x09, 0x02) == "Unknown 0x09 (local)"
    assert group_name_for_opcode(0x09, 0x06) == "Regulators"
    assert group_name_for_opcode(0x0A, 0x02) == "Unknown 0x0A (local)"
    assert group_name_for_opcode(0x0A, 0x06) == "Thermostats"


def test_classify_groups_missing_desc() -> None:
    classified = classify_groups([DiscoveredGroup(group=0x08, descriptor=0.0)])

    assert classified[0].name == "Buffer / Solar Cylinder 2"
    assert classified[0].expected_descriptor is None
    assert classified[0].descriptor_mismatch is False


def test_discover_groups_command_not_enabled_is_fatal() -> None:
    with pytest.raises(TransportCommandNotEnabled):
        discover_groups(FatalDirectoryTransport(), dst=0x15)
