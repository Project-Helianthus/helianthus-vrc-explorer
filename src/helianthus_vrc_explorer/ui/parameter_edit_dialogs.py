"""Visual connection and enum controls; importing this module requires Textual."""

from __future__ import annotations

from typing import Any

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, OptionList, Select, Static
from textual.widgets.option_list import Option

from .parameter_editor import ParameterEnumChoice


class ParameterEnumDialog(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    ParameterEnumDialog { align: center middle; }
    ParameterEnumDialog > Vertical { width: 86; height: auto; max-height: 90%;
        padding: 1 2; border: heavy $accent; background: $surface; }
    #enum-current { width: 100%; }
    #enum-options { height: auto; max-height: 15; }
    #enum-buttons { height: 3; }
    """

    def __init__(self, *, title: str, choices: list[ParameterEnumChoice], current: object) -> None:
        super().__init__()
        self._title, self._choices, self._current = title, choices, current
        self._selection = next((c for c in choices if c.value == current and c.enabled), None)

    def compose(self) -> ComposeResult:
        current = next(
            (c.display for c in self._choices if c.value == self._current),
            f"UNKNOWN ({self._current})",
        )
        yield Vertical(
            Label(self._title),
            Button(current + " ▾", id="enum-current"),
            OptionList(
                *[
                    Option(c.display, id=str(c.value), disabled=not c.enabled)
                    for c in self._choices
                ],
                id="enum-options",
                markup=False,
            ),
            Static("Labels do not grant write permission. Disabled choices show their reason."),
            Horizontal(
                Button("Use value", id="enum-submit"),
                Button("Cancel", id="enum-cancel"),
                id="enum-buttons",
            ),
            Static("", id="enum-status"),
        )

    def on_mount(self) -> None:
        self.query_one("#enum-options", OptionList).display = False
        self.query_one("#enum-current", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "enum-current":
            options = self.query_one("#enum-options", OptionList)
            options.display = not options.display
            if options.display:
                options.focus()
        elif event.button.id == "enum-cancel":
            self.dismiss(None)
        elif event.button.id == "enum-submit":
            if self._selection is None:
                self.query_one("#enum-status", Static).update("Choose an enabled value.")
            else:
                self.dismiss(str(self._selection.value))

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        choice = next(c for c in self._choices if str(c.value) == event.option.id)
        if not choice.enabled:
            return
        self._selection = choice
        self.query_one("#enum-current", Button).label = choice.display + " ▾"
        self.query_one("#enum-options", OptionList).display = False
        self.query_one("#enum-submit", Button).focus()

    def action_cancel(self) -> None:
        self.dismiss(None)


class BrowserConnectionDialog(ModalScreen[dict[str, Any] | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    BrowserConnectionDialog { align: center middle; }
    BrowserConnectionDialog > Vertical { width: 76; height: auto; max-height: 95%;
        padding: 1 2; border: heavy $accent; background: $surface; }
    #connect-buttons { height: 3; }
    """

    def __init__(self, *, destination: int) -> None:
        super().__init__()
        self._destination = destination

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Connect to a live regulator"),
            Static(
                "This file is offline. Connection checks identity; each write needs confirmation."
            ),
            Select(
                [("Enhanced adapter (ENS)", "ens"), ("ebusd command port", "tcp")],
                value="ens",
                allow_blank=False,
                id="connect-protocol",
            ),
            Label("Host"),
            Input(id="connect-host"),
            Label("Port"),
            Input(value="9999", id="connect-port"),
            Label("Destination"),
            Input(value=f"0x{self._destination:02X}", id="connect-dst"),
            Label("Source"),
            Input(value="0xF7", id="connect-src"),
            Horizontal(
                Button("Connect", id="connect-submit"),
                Button("Cancel", id="connect-cancel"),
                id="connect-buttons",
            ),
            Static("", id="connect-status"),
        )

    def on_mount(self) -> None:
        self.query_one("#connect-host", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "connect-cancel":
            self.dismiss(None)
        elif event.button.id == "connect-submit":
            from ..scanner.browser_session import BrowserTransportConfig

            try:
                settings: dict[str, Any] = {
                    "protocol": self.query_one("#connect-protocol", Select).value,
                    "host": self.query_one("#connect-host", Input).value.strip(),
                    "port": int(self.query_one("#connect-port", Input).value.strip(), 10),
                    "dst": int(self.query_one("#connect-dst", Input).value.strip(), 0),
                    "src": int(self.query_one("#connect-src", Input).value.strip(), 0),
                }
                BrowserTransportConfig(
                    kind=settings["protocol"],
                    host=settings["host"],
                    port=settings["port"],
                    source=settings["src"],
                    destination=settings["dst"],
                )
            except (TypeError, ValueError) as exc:
                self.query_one("#connect-status", Static).update(str(exc))
                return
            self.dismiss(settings)

    def action_cancel(self) -> None:
        self.dismiss(None)
