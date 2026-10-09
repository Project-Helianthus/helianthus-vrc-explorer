from __future__ import annotations

import asyncio

from textual.app import App
from textual.widgets import Button, Input, OptionList, Static

from helianthus_vrc_explorer.ui.parameter_edit_dialogs import (
    BrowserConnectionDialog,
    ParameterEnumDialog,
)
from helianthus_vrc_explorer.ui.parameter_editor import ParameterEnumChoice


def test_enum_dropdown_retains_unknown_code_and_disables_forbidden_choice() -> None:
    async def run() -> None:
        app: App[str | None] = App()
        choices = [
            ParameterEnumChoice(1, "NORMAL"),
            ParameterEnumChoice(2, "COOL", False, "Cooling disabled"),
        ]
        async with app.run_test(size=(110, 40)) as pilot:
            app.push_screen(
                ParameterEnumDialog(title="Mode", choices=choices, current=99), app.exit
            )
            await pilot.pause()
            assert "UNKNOWN (99)" in str(app.screen.query_one("#enum-current", Button).label)
            await pilot.click("#enum-submit")
            assert "Choose an enabled value" in str(
                app.screen.query_one("#enum-status", Static).render()
            )
            await pilot.click("#enum-current")
            options = app.screen.query_one("#enum-options", OptionList)
            assert options.display
            assert options.get_option_at_index(1).disabled
            await pilot.press("home", "enter")
            await pilot.click("#enum-submit")
            await pilot.pause()
        assert app.return_value == "1"

    asyncio.run(run())


def test_connection_dialog_starts_without_host_and_does_not_connect() -> None:
    async def run() -> None:
        app: App[dict | None] = App()
        async with app.run_test(size=(100, 45)) as pilot:
            app.push_screen(BrowserConnectionDialog(destination=0x15), app.exit)
            await pilot.pause()
            assert app.screen.query_one("#connect-host", Input).value == ""
            await pilot.click("#connect-submit")
            assert "host" in str(app.screen.query_one("#connect-status", Static).render()).lower()
            app.screen.query_one("#connect-host", Input).value = "adapter.example.test"
            app.screen.query_one("#connect-submit", Button).press()
            await pilot.pause()
        assert app.return_value == {
            "protocol": "ens",
            "host": "adapter.example.test",
            "port": 9999,
            "dst": 0x15,
            "src": 0xF7,
        }

    asyncio.run(run())
