from __future__ import annotations

import asyncio
import struct

import pytest
from textual.widgets import DataTable, Input, Static, Tree

from helianthus_vrc_explorer.scanner.browser_session import BrowserSession
from helianthus_vrc_explorer.schema.parameter_descriptions import attach_bundled_descriptions
from helianthus_vrc_explorer.ui import browse_textual
from tests.test_browser_live_writes import ScriptedLiveTransport, _artifact, _settle


def _circuit_artifact() -> dict:
    artifact = _artifact()
    # Keep native controller identity and use the bundled, exact-profile EXP limits.
    artifact["operations"]["0x02"]["groups"] = {
        "0x02": {
            "instances": {
                "0x00": {
                    "present": True,
                    "registers": {
                        "0x0014": {
                            "read_opcode": "0x02",
                            "type": "EXP",
                            "value": 20.0,
                            "raw_hex": "0000a041",
                            "reply_hex": "030214000000a041",
                            "flags": 3,
                            "flags_access": "writable_visible",
                            "response_state": "active",
                        }
                    },
                }
            }
        }
    }
    attach_bundled_descriptions(artifact)
    return artifact


class _CircuitTransport(ScriptedLiveTransport):
    def __init__(self, values=()) -> None:
        super().__init__([])
        self.values = list(values)

    def send(self, dst: int, payload: bytes) -> bytes:
        if payload == bytes.fromhex("020002001400"):
            self.requests.append(payload)
            value = self.values.pop(0) if self.values else 20
            return bytes.fromhex("03021400") + struct.pack("<f", value)
        return super().send(dst, payload)


@pytest.mark.parametrize("key", ["e", "enter", "ctrl+j", "ctrl+m"])
@pytest.mark.parametrize("live", [False, True])
def test_numeric_editor_keeps_opening_key_out_of_submission(monkeypatch, key, live) -> None:
    artifact = _circuit_artifact()
    transport = _CircuitTransport()
    monkeypatch.setattr(
        browse_textual.BrowserSession, "from_config", lambda config: BrowserSession(transport)
    )

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            artifact,
            allow_write=False,
            connection_settings=(
                {
                    "protocol": "ens",
                    "host": "example.invalid",
                    "port": 9999,
                    "src": 0xF7,
                    "dst": 0x15,
                }
                if live
                else None
            ),
        )
        try:
            async with app.run_test(size=(140, 45)) as pilot:
                await _settle(app, pilot)
                node = next(
                    n
                    for n in app._store.tree_nodes
                    if n.level == "instance" and n.namespace_key == "0x02"
                )
                app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[node.node_id])
                await pilot.pause()
                app._selected_node_id = node.node_id
                app.action_tab_config()
                await pilot.pause()
                app.query_one("#browse-table", DataTable).focus()
                await pilot.press(key)
                await _settle(app, pilot)
                await pilot.pause(0.3)
                assert isinstance(app.screen, browse_textual._InputDialog)
                assert app.screen.query_one(Input).value == "20"
                assert len(app.screen_stack) == 2
                assert app._pending_write is None
                assert transport.writes == []
                await pilot.press("3", "5")
                assert app.screen.query_one(Input).value == "35"
                await pilot.press("enter")
                await pilot.pause(0.3)
                assert isinstance(app.screen, browse_textual._ConfirmDialog)
                assert len(app.screen_stack) == 2
                assert app._pending_write is not None
                assert app._pending_write.live is live
                assert app._pending_write.new_value == 35.0
                assert app._pending_write.preparation.incomplete_limits_confirmation_text is None
                assert app.screen._title == (
                    "Confirm device write" if live else "Confirm offline preview"
                )
                assert transport.writes == []  # Separate concrete confirmation is still required.
                await pilot.press("escape")
                assert transport.writes == []
        finally:
            app.close_transport(wait=True)

    asyncio.run(exercise())


def test_live_numeric_edit_sends_once_only_after_separate_confirmation(monkeypatch) -> None:
    artifact = _circuit_artifact()
    transport = _CircuitTransport([20, 20, 35])
    monkeypatch.setattr(
        browse_textual.BrowserSession, "from_config", lambda config: BrowserSession(transport)
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
        try:
            async with app.run_test(size=(140, 45)) as pilot:
                await _settle(app, pilot)
                node = next(
                    n
                    for n in app._store.tree_nodes
                    if n.level == "instance" and n.namespace_key == "0x02"
                )
                app.query_one("#browse-tree", Tree).select_node(app._tree_node_by_ref[node.node_id])
                await pilot.pause()
                app._selected_node_id = node.node_id
                app.action_tab_config()
                await pilot.pause()
                app.query_one("#browse-table", DataTable).focus()
                await pilot.press("e")
                await _settle(app, pilot)
                await pilot.press("3", "5", "enter")
                assert app.screen._title == "Confirm device write"
                assert transport.writes == []
                await pilot.press("enter")
                await _settle(app, pilot)
                assert "confirmed by desired-value readback" in str(
                    app.query_one("#status", Static).render()
                )
                assert transport.writes == [bytes.fromhex("02010200140000000c42")]
                assert (
                    artifact["b524_parameter_write_history"][-1]["result"]["outcome"] == "desired"
                )
        finally:
            app.close_transport(wait=True)

    asyncio.run(exercise())


def test_postscan_tcp_connection_preserves_daemon_source(monkeypatch) -> None:
    transport = _CircuitTransport()
    seen = []

    def create(config):
        seen.append(config)
        return BrowserSession(transport)

    monkeypatch.setattr(browse_textual.BrowserSession, "from_config", create)

    async def exercise() -> None:
        app = browse_textual._BrowseApp(
            _circuit_artifact(),
            allow_write=False,
            connection_settings={
                "protocol": "tcp",
                "host": "example.invalid",
                "port": 8888,
                "src": None,
                "dst": 0x15,
            },
        )
        try:
            async with app.run_test() as pilot:
                await _settle(app, pilot)
                assert "identity verified" in str(
                    app.query_one("#connection-state", Static).render()
                )
                assert seen[0].source is None
                assert transport.writes == []
        finally:
            app.close_transport(wait=True)

    asyncio.run(exercise())
