from __future__ import annotations

import struct

import pytest

from helianthus_vrc_explorer.protocol.b524 import (
    build_constraint_probe_payload,
    build_directory_probe_payload,
    parse_b524_id,
)
from helianthus_vrc_explorer.protocol.b524_metadata import (
    decode_parameter_description,
    expected_instance_count,
    validate_parameter_edit,
)


def test_complete_description_selectors_keep_instance_and_rr16() -> None:
    assert build_constraint_probe_payload(2, 0x102, instance=3) == bytes.fromhex("0102030201")
    assert build_constraint_probe_payload(3, 0x1234, instance=4, opcode=7) == bytes.fromhex(
        "0703043412"
    )
    selector = parse_b524_id("0703043412")
    assert selector.instance == 4
    assert selector.register == 0x1234


def test_system_information_identifier_is_u16() -> None:
    assert build_directory_probe_payload(0x1234) == bytes.fromhex("003412")


def test_range_validation_is_not_limited_to_enums() -> None:
    response = bytes.fromhex("012700") + struct.pack("<fff", 3.0, 20.0, 0.5)
    description = decode_parameter_description(
        response, opcode=1, group=1, instance=0, register=0x27, type_spec="EXP"
    )
    assert (
        validate_parameter_edit(
            description, type_spec="EXP", value=4.5, encoded=struct.pack("<f", 4.5)
        )
        is None
    )
    assert "range" in validate_parameter_edit(
        description, type_spec="EXP", value=21.0, encoded=struct.pack("<f", 21.0)
    )
    assert "step" in validate_parameter_edit(
        description, type_spec="EXP", value=4.25, encoded=struct.pack("<f", 4.25)
    )


@pytest.mark.parametrize(
    "response",
    [
        bytes.fromhex("0902020000000400"),
        bytes.fromhex("09020300000004000100"),
        bytes.fromhex("09020201000004000100"),
    ],
)
def test_malformed_or_wrong_rr16_description_is_rejected(response: bytes) -> None:
    with pytest.raises(ValueError):
        decode_parameter_description(
            response, opcode=1, group=2, instance=1, register=2, type_spec="UIN"
        )


def test_device_description_is_scoped_to_device_operation() -> None:
    desc = decode_parameter_description(
        bytes.fromhex("030500010005000100"),
        opcode=7,
        group=3,
        instance=2,
        register=5,
        type_spec="UIN",
    )
    assert desc["read_opcode"] == "0x06"
    assert desc["instance"] == "0x02"
    assert validate_parameter_edit(desc, type_spec="UCH", value=2, encoded=b"\x02") is not None


def test_missing_or_legacy_description_warns_instead_of_rejecting() -> None:
    assert (
        validate_parameter_edit(None, type_spec="UIN", value=2, encoded=b"\x02\x00")
        == "unvalidated"
    )
    assert (
        validate_parameter_edit(
            {"qualification": "legacy_incomplete"}, type_spec="UIN", value=2, encoded=b"\x02\x00"
        )
        == "unvalidated"
    )


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -1.0, 2.5, 12.0])
def test_invalid_counts_do_not_limit_instance_discovery(value: float) -> None:
    assert expected_instance_count(value, capacity=11) is None


def test_zero_and_sparse_count_targets_are_preserved() -> None:
    assert expected_instance_count(0.0, capacity=11) == 0
    assert expected_instance_count(3.0, capacity=11) == 3


def test_same_span_width_can_describe_unsigned32_or_float() -> None:
    raw = bytes.fromhex("023412") + struct.pack("<III", 1, 1000, 2)
    desc = decode_parameter_description(
        raw, opcode=7, group=2, instance=5, register=0x1234, type_spec="U32"
    )
    assert desc["max"] == 1000
    assert (
        validate_parameter_edit(desc, type_spec="U32", value=5, encoded=struct.pack("<I", 5))
        is None
    )
    assert "step" in validate_parameter_edit(
        desc, type_spec="U32", value=6, encoded=struct.pack("<I", 6)
    )


@pytest.mark.parametrize(
    "type_spec,spans",
    [("I8", struct.pack("<bbb", -5, 5, 2)), ("I16", struct.pack("<hhh", -5, 5, 2))],
)
def test_signed_description_limits(type_spec: str, spans: bytes) -> None:
    desc = decode_parameter_description(
        bytes.fromhex("020201") + spans,
        opcode=1,
        group=2,
        instance=3,
        register=0x102,
        type_spec=type_spec,
    )
    assert desc["min"] == -5
    assert desc["max"] == 5


def test_date_description_checks_range_without_inventing_day_step() -> None:
    from helianthus_vrc_explorer.protocol.parser import encode_typed_value

    desc = decode_parameter_description(
        bytes.fromhex("03050001011a05011a020000"),
        opcode=1,
        group=3,
        instance=0,
        register=5,
        type_spec="HDA:3",
    )
    assert (
        validate_parameter_edit(
            desc,
            type_spec="HDA:3",
            value="2026-01-03",
            encoded=encode_typed_value("HDA:3", "2026-01-03"),
        )
        == "unvalidated"
    )
    assert desc["step"] is None
    assert desc["step_raw_hex"] == "020000"
    assert "range" in validate_parameter_edit(
        desc,
        type_spec="HDA:3",
        value="2026-01-06",
        encoded=encode_typed_value("HDA:3", "2026-01-06"),
    )


def test_sparse_instance_probe_stops_after_successful_count_not_slot_count() -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import _probe_present_instances
    from helianthus_vrc_explorer.scanner.register import (
        InstanceAvailabilityProbe,
        namespace_availability_contract,
    )
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class NoSend(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:
            raise AssertionError("callback owns discovery")

    def availability(*args, **kwargs):
        return InstanceAvailabilityProbe(
            present=kwargs["instance"] in {2, 6, 9},
            contract=namespace_availability_contract(group=2, opcode=2),
            evidence=None,
        )

    probes = _probe_present_instances(
        NoSend(),
        dst=0x15,
        group=2,
        opcode=2,
        ii_max=10,
        observer=None,
        probe_instance_availability_fn=availability,
        expected_count=2,
    )
    assert set(probes) == set(range(7))
    assert [ii for ii, result in probes.items() if result.present] == [2, 6]


@pytest.mark.parametrize("count", [None, 0, 3])
def test_missing_zero_or_unmet_count_keeps_bounded_fallback(count: int | None) -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import _probe_present_instances
    from helianthus_vrc_explorer.scanner.register import (
        InstanceAvailabilityProbe,
        namespace_availability_contract,
    )

    def availability(*args, **kwargs):
        return InstanceAvailabilityProbe(
            present=kwargs["instance"] == 9,
            contract=namespace_availability_contract(group=2, opcode=2),
            evidence=None,
        )

    probes = _probe_present_instances(
        None,
        dst=0x15,
        group=2,
        opcode=2,
        ii_max=10,
        observer=None,
        probe_instance_availability_fn=availability,
        expected_count=count,
    )
    assert len(probes) == 11
    assert probes[9].present


def test_full_preset_audits_slots_while_recommended_uses_sparse_count() -> None:
    from helianthus_vrc_explorer.ui.planner import PlannerGroup, build_plan_from_preset

    group = PlannerGroup(
        group=2,
        opcode=2,
        name="Heating Circuits",
        descriptor=float("nan"),
        known=True,
        ii_max=10,
        rr_max=37,
        rr_max_full=255,
        present_instances=(3, 7),
        expected_count=2,
    )
    assert build_plan_from_preset([group], preset="recommended")[(2, 2)].instances == (3, 7, 10)
    assert build_plan_from_preset([group], preset="full")[(2, 2)].instances == tuple(range(11))
    assert build_plan_from_preset([group], preset="research")[(2, 2)].instances == tuple(range(11))


def test_default_scan_keeps_system_information_separate_and_targets_writable_descriptions() -> None:
    from helianthus_vrc_explorer.scanner.scan import scan_b524
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class MetadataBus(TransportInterface):
        def __init__(self):
            self.requests = []

        def send(self, dst: int, payload: bytes) -> bytes:
            self.requests.append(payload)
            if payload[0] == 0:
                identifier = int.from_bytes(payload[1:3], "little")
                return struct.pack("<f", 1.0 if identifier == 0 else float("nan"))
            if len(payload) == 5 and payload[0] == 1:
                return bytes.fromhex("020200000004000100")
            if (
                payload[0] == 2
                and payload[2] == 2
                and payload[3] == 3
                and int.from_bytes(payload[4:6], "little") == 2
            ):
                return bytes.fromhex("030202000100")
            return b"\x00"

    bus = MetadataBus()
    artifact = scan_b524(bus, dst=0x15)
    info = artifact["meta"]["system_information"][0]
    assert info["identifier"] == "0x0000"
    assert info["name"] == "circuit_count"
    assert info["raw_hex"] == "0000803f"
    assert artifact["meta"]["instance_counts"]["0x02:0x02"]["observed"] == 1
    assert artifact["meta"]["instance_counts"]["0x02:0x02"]["probed_instances"] == 4
    group = artifact["operations"]["0x02"]["groups"]["0x02"]
    assert group["descriptor_observed"] is None
    assert artifact["meta"]["scan_plan"]["groups"]["0x02"]["operations"]["0x02"]["instances"] == [
        "0x03",
        "0x0a",
    ]
    entry = group["instances"]["0x03"]["registers"]["0x0002"]
    assert entry["parameter_description"]["qualification"] == "matched"
    assert entry["parameter_description"]["instance"] == "0x03"
    assert [p for p in bus.requests if p[0] in {1, 7}] == [bytes.fromhex("0102030200")]
    # The circuit count never restricts the independent device namespace.
    assert "0x06:0x02" not in artifact["meta"]["instance_counts"]


def test_default_description_requests_have_a_hard_budget() -> None:
    from helianthus_vrc_explorer.scanner.scan import scan_b524
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class WritableBus(TransportInterface):
        def __init__(self):
            self.descriptions = 0

        def send(self, dst: int, payload: bytes) -> bytes:
            if payload[0] == 0:
                return struct.pack("<f", float("nan"))
            if payload[0] == 1:
                self.descriptions += 1
                return payload[1:2] + payload[3:5] + bytes.fromhex("0000ffff0100")
            if payload[0] == 2 and payload[2] == 0:
                return b"\x03" + payload[2:3] + payload[4:6] + b"\x01\x00"
            return b"\x00"

    bus = WritableBus()
    artifact = scan_b524(bus, dst=0x15)
    assert bus.descriptions == 256
    assert artifact["meta"]["parameter_description_requests"] == 256
    regs = artifact["operations"]["0x02"]["groups"]["0x00"]["instances"]["0x00"]["registers"]
    assert regs["0x0100"]["parameter_description"]["qualification"] == "unavailable"
    assert regs["0x0100"]["value"] == 1


def test_device_description_probe_uses_complete_op07_selector() -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import probe_parameter_description
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class DeviceBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:
            assert payload == bytes.fromhex("0701053412")
            return bytes.fromhex("013412000064000100")

    result = probe_parameter_description(
        DeviceBus(), dst=0x15, opcode=6, group=1, instance=5, register=0x1234, type_spec="UIN"
    )
    assert result["qualification"] == "matched"
    assert result["description_opcode"] == "0x07"
    assert result["read_opcode"] == "0x06"


def test_unknown_codec_retains_matched_echo_and_raw_description_without_decoding() -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import probe_parameter_description
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class UnknownCodecBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            assert payload == bytes.fromhex("0102053412")
            return bytes.fromhex("023412010203040506")

    result = probe_parameter_description(
        UnknownCodecBus(),
        dst=0x15,
        opcode=2,
        group=2,
        instance=5,
        register=0x1234,
        type_spec=None,
    )

    assert result["qualification"] == "unqualified"
    assert result["reason"] == "parameter codec is unknown"
    assert result["reply_hex"] == "023412010203040506"
    assert result["selector"] == {
        "description_opcode": "0x01",
        "read_opcode": "0x02",
        "group": "0x02",
        "instance": "0x05",
        "register": "0x1234",
    }
    assert result["reply_echo"] == {
        "group": "0x02",
        "register": "0x1234",
        "matches_selector": True,
        "instance": "not_echoed_by_protocol",
    }
    assert "width" not in result
    assert "type" not in result


def test_unknown_codec_with_mismatched_echo_is_unavailable() -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import probe_parameter_description
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class WrongEchoBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            return bytes.fromhex("033412010203")

    result = probe_parameter_description(
        WrongEchoBus(),
        dst=0x15,
        opcode=2,
        group=2,
        instance=5,
        register=0x1234,
        type_spec=None,
    )

    assert result["qualification"] == "unavailable"
    assert result["reply_echo"]["matches_selector"] is False
    assert "echo mismatch" in result["reason"].lower()


def test_unsupported_scalar_codec_retains_echo_as_unqualified_raw_evidence() -> None:
    from helianthus_vrc_explorer.scanner.b524_probe import probe_parameter_description
    from helianthus_vrc_explorer.transport.base import TransportInterface

    class HexCodecBus(TransportInterface):
        def send(self, dst: int, payload: bytes) -> bytes:  # noqa: ARG002
            return bytes.fromhex("023412010203040506")

    result = probe_parameter_description(
        HexCodecBus(),
        dst=0x15,
        opcode=2,
        group=2,
        instance=5,
        register=0x1234,
        type_spec="HEX:2",
    )

    assert result["qualification"] == "unqualified"
    assert result["type"] == "HEX:2"
    assert "unsupported" in result["reason"]
    assert result["reply_echo"]["matches_selector"] is True
    assert "width" not in result


@pytest.mark.parametrize("read_opcode,description_opcode", [(2, 1), (6, 7)])
@pytest.mark.parametrize(
    "new_value,has_description,accepted",
    [("21", True, False), ("4.5", True, True), ("21", False, True)],
)
def test_browse_local_edit_validates_system_and_device_float_parameters(
    monkeypatch, read_opcode, description_opcode, new_value, has_description, accepted
):
    from helianthus_vrc_explorer.ui.browse_store import BrowseStore
    from helianthus_vrc_explorer.ui.browse_textual import _compose_browse_app

    entry = {
        "read_opcode": f"0x{read_opcode:02x}",
        "type": "EXP",
        "flags": 3,
        "writable": True,
        "flags_access": "config_user",
        "value": 3.0,
        "raw_hex": struct.pack("<f", 3).hex(),
        "error": None,
    }
    if has_description:
        entry["parameter_description"] = decode_parameter_description(
            bytes.fromhex("012700") + struct.pack("<fff", 3, 20, 0.5),
            opcode=description_opcode,
            group=1,
            instance=0,
            register=0x27,
            type_spec="EXP",
        )
    artifact = {
        "schema_version": "2.3",
        "meta": {},
        "operations": {
            f"0x{read_opcode:02x}": {
                "groups": {
                    "0x01": {
                        "name": "Parameters",
                        "instances": {"0x00": {"registers": {"0x0027": entry}}},
                    }
                }
            }
        },
    }
    store = BrowseStore.from_artifact(artifact)
    app = _compose_browse_app(artifact, allow_write=True, store=store)
    row = store.rows[0]
    statuses, dialogs = [], []
    monkeypatch.setattr(app, "_set_status", statuses.append)
    monkeypatch.setattr(app, "push_screen", lambda dialog, callback: dialogs.append(dialog))
    app._editing_row_id = row.row_id
    app._on_edit_value_entered(new_value)
    assert bool(dialogs) is accepted
    if not accepted:
        assert statuses[-1].startswith("Edit rejected:")
    else:
        assert app._pending_write is not None
        if not has_description:
            assert "unvalidated" in str(dialogs[0]._lines).lower()
    assert entry["value"] == 3.0  # Confirmation has not mutated the artifact.


def test_float_step_tolerance_does_not_grow_with_quotient() -> None:
    desc = decode_parameter_description(
        bytes.fromhex("012700") + struct.pack("<fff", 0, 1e9, 1),
        opcode=1,
        group=1,
        instance=0,
        register=0x27,
        type_spec="EXP",
    )
    assert "step" in validate_parameter_edit(
        desc, type_spec="EXP", value=1e6 + 0.5, encoded=struct.pack("<f", 1e6 + 0.5)
    )


@pytest.mark.parametrize("writable,accepted", [(True, True), (False, False)])
def test_remote_writable_capability_controls_edit_even_in_state_tab(
    monkeypatch, writable, accepted
):
    from helianthus_vrc_explorer.ui.browse_store import BrowseStore
    from helianthus_vrc_explorer.ui.browse_textual import _compose_browse_app

    entry = {
        "read_opcode": "0x06",
        "type": "UIN",
        "flags": 3 if writable else 1,
        "writable": writable,
        "flags_access": "config_valid",
        "register_class": "state",
        "value": 1,
        "raw_hex": "0100",
    }
    artifact = {
        "schema_version": "2.3",
        "meta": {},
        "operations": {
            "0x06": {
                "groups": {
                    "0x01": {
                        "name": "Device",
                        "instances": {"0x00": {"registers": {"0x0005": entry}}},
                    }
                }
            }
        },
    }
    store = BrowseStore.from_artifact(artifact)
    app = _compose_browse_app(artifact, allow_write=True, store=store)
    row = store.rows[0]
    assert row.tab == "state"
    dialogs, statuses = [], []
    monkeypatch.setattr(app, "_selected_table_row", lambda: row)
    monkeypatch.setattr(app, "_set_status", statuses.append)
    monkeypatch.setattr(app, "push_screen", lambda dialog, callback: dialogs.append(dialog))
    app.action_edit_selected()
    assert bool(dialogs) is accepted
