from __future__ import annotations

import asyncio
import json
import struct
from collections import defaultdict
from concurrent.futures import Future
from copy import deepcopy

import pytest
from textual.widgets import DataTable, OptionList, Static, Tree

from helianthus_vrc_explorer.scanner.b524_parameter_writes import (
    B524ParameterWriteResult,
)
from helianthus_vrc_explorer.scanner.browser_session import BrowserSession
from helianthus_vrc_explorer.schema.parameter_descriptions import description_profile
from helianthus_vrc_explorer.transport.base import TransportInterface, TransportTimeout
from helianthus_vrc_explorer.ui import browse_textual
from helianthus_vrc_explorer.ui.parameter_edit_dialogs import ParameterEnumDialog
from helianthus_vrc_explorer.ui.parameter_editor import parameter_value_display


def _artifact(*, complete_limits: bool = True) -> dict:
    artifact = {
        "schema_version": "2.3",
        "meta": {
            "destination_address": "0x15",
            "scan_timestamp": "2026-10-09T12:00:00Z",
            "identity": {
                "manufacturer": "0xB5",
                "eid": "BASV2",
                "sw": "0507",
                "hw": "1704",
            },
            "profile_context": {
                "profile": "controller_b524",
                "api_version": 1.0,
                "api_revision": 1.0,
            },
        },
        "operations": {
            "0x02": {
                "groups": {
                    "0x09": {
                        "name": "Controller",
                        "instances": {
                            "0x01": {
                                "present": True,
                                "registers": {
                                    "0x0002": {
                                        "name": "operating_mode",
                                        "read_opcode": "0x02",
                                        "type": "UCH",
                                        "value": 2,
                                        "raw_hex": "02",
                                        "reply_hex": "0309020002",
                                        "value_display": "NORMAL (2)",
                                        "enum_raw_name": "NORMAL",
                                        "enum_resolved_name": "NORMAL",
                                        "flags": 3,
                                        "flags_access": "writable_visible",
                                        "response_state": "active",
                                        "last_update": "2026-10-09T12:00:00Z",
                                    }
                                },
                            }
                        },
                    }
                }
            },
            "0x06": {
                "groups": {
                    "0x09": {
                        "name": "Controller identity",
                        "instances": {
                            "0x01": {
                                "present": True,
                                "registers": {
                                    "0x0002": {
                                        "type": "HEX:1",
                                        "read_opcode": "0x06",
                                        "value": "15",
                                        "raw_hex": "15",
                                        "flags_access": "read_only_visible",
                                        "response_state": "active",
                                    },
                                    "0x0004": {
                                        "type": "FW",
                                        "read_opcode": "0x06",
                                        "value": "08.05.00",
                                        "raw_hex": "080500",
                                        "flags_access": "read_only_visible",
                                        "response_state": "active",
                                    },
                                },
                            }
                        },
                    }
                }
            },
        },
    }
    selector = {
        "read_opcode": "0x02",
        "group": "0x09",
        "instance": "0x01",
        "register": "0x0002",
    }
    profile = description_profile(artifact, selector)
    target = artifact["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"][
        "0x0002"
    ]
    target["parameter_description"] = {
        "qualification": "matched",
        "description_opcode": "0x01",
        **selector,
        "type": "UCH",
        "width": 1,
        "min": 1,
        "max": 3,
        "step": 1 if complete_limits else None,
        "target_profile": deepcopy(profile),
        "target_profile_match": True,
    }
    return artifact


def _target_entry(artifact: dict) -> dict:
    return artifact["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"]["registers"][
        "0x0002"
    ]


class ScriptedLiveTransport(TransportInterface):
    def __init__(
        self,
        target_replies: list[bytes | BaseException],
        *,
        identity: bytes = b"\xb5BASV2\x05\x07\x17\x04",
        write_error: BaseException | None = None,
    ) -> None:
        self.target_replies = list(target_replies)
        self.identity = identity
        self.write_error = write_error
        self.requests: list[bytes] = []
        self.writes: list[bytes] = []
        self.counts: defaultdict[bytes, int] = defaultdict(int)

    def send_proto(self, dst, primary, secondary, payload, *, expect_response=True):
        assert (dst, primary, secondary, payload, expect_response) == (
            0x15,
            0x07,
            0x04,
            b"",
            True,
        )
        return self.identity

    def send(self, dst: int, payload: bytes) -> bytes:
        assert dst == 0x15
        self.requests.append(payload)
        self.counts[payload] += 1
        if payload in {bytes.fromhex("000600"), bytes.fromhex("000700")}:
            return struct.pack("<f", 1.0)
        if payload == bytes.fromhex("060009010200"):
            return bytes.fromhex("0109020015")
        if payload == bytes.fromhex("060009010400"):
            return bytes.fromhex("01090400080500")
        if payload == bytes.fromhex("020009010200"):
            reply = self.target_replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply
        raise AssertionError(f"unexpected request {payload.hex()}")

    def send_with_attempt_hook(self, dst, payload, attempt_hook):
        assert dst == 0x15
        attempt_hook()
        self.writes.append(payload)
        if self.write_error is not None:
            raise self.write_error
        return b"\x00"


def _reply(value: int, *, flags: int = 3) -> bytes:
    return bytes((flags, 0x09, 0x02, 0x00, value))


async def _settle(app, pilot) -> None:
    for _ in range(200):
        await pilot.pause()
        if not app._transport_busy:
            return
        await asyncio.sleep(0.001)
    raise AssertionError("Browser transport operation did not settle")


async def _select_target(app, pilot) -> None:
    node = next(
        item
        for item in app._store.tree_nodes
        if item.level == "instance"
        and item.namespace_key == "0x02"
        and item.group_key == "0x09"
        and item.instance_key == "0x01"
    )
    app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[node.node_id])
    await pilot.pause()
    app._selected_node_id = node.node_id
    app.action_tab_config()
    await pilot.pause()
    app._refresh_table()
    table = app.query_one("#browse-table", DataTable)
    table.focus()
    row_index = next(
        index for index, row in enumerate(app._table_rows) if row.register_key == "0x0002"
    )
    table.move_cursor(row=row_index)


async def _choose_first_enum_value(app, pilot) -> None:
    assert isinstance(app.screen, ParameterEnumDialog)
    await pilot.click("#enum-current")
    options = app.screen.query_one("#enum-options", OptionList)
    assert options.display
    await pilot.press("home", "enter")
    await pilot.click("#enum-submit")
    await pilot.pause()


def test_completed_future_is_recorded_without_leaving_browser_busy() -> None:
    async def exercise() -> None:
        app = browse_textual._BrowseApp(_artifact(), allow_write=False)
        async with app.run_test() as pilot:
            completed: Future[int] = Future()
            completed.set_result(7)
            seen: list[int] = []
            app._track_transport_future(completed, status="done", on_success=seen.append)
            await pilot.pause()
            assert seen == [7]
            assert app._transport_busy is False
            assert app._inflight_recorded is True

    asyncio.run(exercise())


def test_offline_preview_preserves_observation_and_persists(tmp_path) -> None:
    artifact = _artifact()
    output = tmp_path / "scan.json"

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            artifact,
            allow_write=False,
            artifact_path=output,
        )
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_target(app, pilot)
            await pilot.press("e")
            await pilot.pause()
            await _choose_first_enum_value(app, pilot)
            assert isinstance(app.screen, browse_textual._ConfirmDialog)
            await pilot.press("enter")
            await pilot.pause()

    asyncio.run(exercise())
    entry = _target_entry(artifact)
    assert (entry["value"], entry["raw_hex"], entry["reply_hex"]) == (
        2,
        "02",
        "0309020002",
    )
    assert entry["local_edit_preview"]["value"] == 1
    assert entry["local_edit_preview"]["device_write"] is False
    assert (
        json.loads(output.read_text())["operations"]["0x02"]["groups"]["0x09"]["instances"]["0x01"][
            "registers"
        ]["0x0002"]["raw_hex"]
        == "02"
    )


def test_incomplete_limits_need_exception_then_concrete_confirmation() -> None:
    artifact = _artifact(complete_limits=False)

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_target(app, pilot)
            await pilot.press("e")
            await pilot.pause()
            await _choose_first_enum_value(app, pilot)
            assert isinstance(app.screen, browse_textual._ConfirmDialog)
            assert app.screen._title == "Confirm incomplete limits exception"
            await pilot.press("enter")
            await pilot.pause()
            assert isinstance(app.screen, browse_textual._ConfirmDialog)
            assert app.screen._title == "Confirm offline preview"
            await pilot.press("escape")

    asyncio.run(exercise())
    assert "local_edit_preview" not in _target_entry(artifact)


def test_qualified_false_enum_gate_rejects_typed_bypass() -> None:
    artifact = _artifact()
    entry = _target_entry(artifact)
    entry["enum_options"] = [
        {
            "value": 1,
            "label": "TIME_CONTROLLED",
            "gate": {
                "state": False,
                "qualification": "qualified",
                "reason": "Feature disabled",
            },
        },
        {"value": 2, "label": "NORMAL"},
    ]

    async def exercise() -> None:
        app = browse_textual._BrowseApp(artifact, allow_write=False)
        async with app.run_test(size=(140, 45)) as pilot:
            await _select_target(app, pilot)
            row = app._selected_table_row()
            assert row is not None
            app._editing_row_id = row.row_id
            app._on_edit_value_entered("1")
            await pilot.pause()
            assert "Feature disabled" in str(app.query_one("#status", Static).render())
            assert app._pending_write is None

    asyncio.run(exercise())


def test_live_connection_rejects_recorded_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact()
    transport = ScriptedLiveTransport([], identity=b"\xb5OTHER\x05\x07\x17\x04")
    monkeypatch.setattr(
        browse_textual.BrowserSession,
        "from_config",
        lambda _config: BrowserSession(transport),
    )

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            artifact,
            allow_write=False,
            connection_settings={
                "protocol": "tcp",
                "host": "example.invalid",
                "port": 9999,
                "src": 0xF7,
                "dst": 0x15,
            },
        )
        async with app.run_test() as pilot:
            await _settle(app, pilot)
            assert app._browser_session is None
            banner = str(app.query_one("#connection-state", Static).render())
            assert "OFFLINE" in banner
            assert "identity mismatch" in banner

    asyncio.run(exercise())
    assert transport.writes == []


def test_live_write_uses_fresh_context_and_changed_enum_readback_preserves_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    artifact = _artifact()
    output = tmp_path / "scan.json"
    transport = ScriptedLiveTransport([_reply(2), _reply(2), _reply(3)])
    monkeypatch.setattr(
        browse_textual.BrowserSession,
        "from_config",
        lambda _config: BrowserSession(transport),
    )

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            artifact,
            allow_write=False,
            connection_settings={
                "protocol": "tcp",
                "host": "example.invalid",
                "port": 9999,
                "src": 0xF7,
                "dst": 0x15,
            },
            artifact_path=output,
        )
        async with app.run_test(size=(140, 45)) as pilot:
            await _settle(app, pilot)
            assert "identity verified" in str(app.query_one("#connection-state", Static).render())
            await _select_target(app, pilot)
            await pilot.press("e")
            await _settle(app, pilot)
            await _choose_first_enum_value(app, pilot)
            assert isinstance(app.screen, browse_textual._ConfirmDialog)
            assert app._pending_write is not None
            assert "old=2" in app._pending_write.preparation.confirmation_text
            await pilot.press("enter")
            await _settle(app, pilot)
            assert "another value" in str(app.query_one("#status", Static).render())

    asyncio.run(exercise())
    assert transport.writes == [bytes.fromhex("02010901020001")]
    entry = _target_entry(artifact)
    assert (entry["value"], entry["raw_hex"]) == (3, "03")
    assert "reply_hex" not in entry
    assert entry["observed_before_live_write"]["reply_hex"] == "0309020002"
    assert entry["validated_readback"]["source"] == "write"
    assert "enum_resolved_name" not in entry
    assert parameter_value_display(entry, opcode=2, group=9, register=2) == "REDUCED (3)"
    assert entry.get("written") is not True
    history = artifact["b524_parameter_write_history"]
    assert history[-1]["result"]["outcome"] == "other"
    assert (
        json.loads(output.read_text())["b524_parameter_write_history"][-1]["result"][
            "readback_raw_hex"
        ]
        == "03"
    )


def test_unknown_write_gets_read_only_recheck_without_resubmit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = _artifact()
    transport = ScriptedLiveTransport(
        [_reply(2), _reply(2), TransportTimeout("readback"), _reply(1)],
        write_error=TransportTimeout("uncertain write acknowledgement"),
    )
    monkeypatch.setattr(
        browse_textual.BrowserSession,
        "from_config",
        lambda _config: BrowserSession(transport),
    )

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            artifact,
            allow_write=False,
            connection_settings={
                "protocol": "ens",
                "host": "example.invalid",
                "port": 9999,
                "src": 0xF7,
                "dst": 0x15,
            },
        )
        async with app.run_test(size=(140, 45)) as pilot:
            await _settle(app, pilot)
            await _select_target(app, pilot)
            await pilot.press("e")
            await _settle(app, pilot)
            await _choose_first_enum_value(app, pilot)
            await pilot.press("enter")
            await _settle(app, pilot)
            assert "outcome unknown" in str(app.query_one("#status", Static).render())
            app.action_recheck()
            await _settle(app, pilot)
            status = str(app.query_one("#status", Static).render())
            assert "recheck found the desired value" in status
            assert "sent no write" in status

    asyncio.run(exercise())
    assert transport.writes == [bytes.fromhex("02010901020001")]
    assert [item["kind"] for item in artifact["b524_parameter_write_history"]] == [
        "write",
        "read_only_recheck",
    ]
    entry = _target_entry(artifact)
    assert entry["value"] == 1
    assert entry["validated_readback"]["source"] == "read_only_recheck"
    assert entry.get("written") is not True


def test_shutdown_harvest_records_completed_write_without_rendering(tmp_path) -> None:
    artifact = _artifact()
    output = tmp_path / "scan.json"
    app = browse_textual._BrowseApp(artifact, allow_write=False, artifact_path=output)
    row = next(
        row
        for row in app._store.rows
        if row.address.read_opcode == "0x02" and row.register_key == "0x0002"
    )
    pending = browse_textual._PendingWrite(
        row_id=row.row_id,
        type_spec="UCH",
        old_value_text="2",
        old_raw_hex="02",
        new_value_text="1",
        new_raw_hex="01",
        new_value=1,
        live=True,
    )
    result = B524ParameterWriteResult(
        outcome="desired",
        target=app._target_for_row(row, destination=0x15),
        write_attempts=1,
        baseline_raw_hex="02",
        readback_raw_hex="01",
    )
    future: Future[B524ParameterWriteResult] = Future()
    future.set_result(result)
    app._inflight_future = future
    app._inflight_recorded = False
    app._inflight_teardown_success = lambda value: app._record_live_result(
        pending, value, kind="write", render=False
    )

    app.close_transport(wait=True)

    assert app._inflight_recorded is True
    assert artifact["b524_parameter_write_history"][-1]["result"]["outcome"] == "desired"
    assert (
        json.loads(output.read_text())["b524_parameter_write_history"][-1]["result"][
            "write_attempts"
        ]
        == 1
    )
