"""Visual scan setup and artifact selection without transport I/O."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Checkbox, Collapsible, Input, Label, Select, Static

from ..scanner.b509 import parse_b509_range

_PRESET_DESCRIPTIONS = {
    "recommended": "Profile-guided coverage for normal scans.",
    "full": "Audits declared profile slots independently of observed OP00 counts.",
    "research": "Bounded exploratory coverage for unknown or unqualified areas.",
    "custom": "Starts from explicit visual planner choices.",
}
_PRESET_OPTIONS = tuple((name.title(), name) for name in _PRESET_DESCRIPTIONS)
_PLANNER_OPTIONS = (
    ("Automatic", "auto"),
    ("Textual", "textual"),
    ("Classic", "classic"),
)


@dataclass(frozen=True, slots=True)
class ScanSetup:
    preset: str = "recommended"
    dst: str = "auto"
    dry_run: bool = False
    output_dir: Path = Path("results")
    ebusd_csv_path: Path | None = None
    myvaillant_map_path: Path | None = None
    trace_file: Path | None = None
    b509_range: list[str] | None = None
    b509_dump: bool = False
    b555_dump: bool = False
    b516_dump: bool = False
    planner_ui: str = "auto"
    no_tips: bool = False
    redact: bool = False


def _optional_path(raw: str, *, label: str, existing_file: bool = False) -> Path | None:
    text = raw.strip()
    if not text:
        return None
    path = Path(text).expanduser()
    if existing_file and (not path.exists() or not path.is_file()):
        raise ValueError(f"{label} must be an existing file")
    if not existing_file and path.exists() and path.is_dir():
        raise ValueError(f"{label} must be a file path, not a directory")
    return path


def _csv_path(raw: str, *, label: str) -> Path | None:
    path = _optional_path(raw, label=label, existing_file=True)
    if path is not None and path.suffix.lower() != ".csv":
        raise ValueError(f"{label} must use the .csv extension")
    return path


def _destination(raw: str) -> str:
    text = raw.strip().lower()
    if text == "auto":
        return "auto"
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise ValueError("Destination must be auto or an address such as 0x15") from exc
    if not 0 <= value <= 0xFF or value in {0x00, 0xA9, 0xAA}:
        raise ValueError("Destination must be a non-reserved eBUS address in 0x01..0xFF")
    return f"0x{value:02X}"


def _b509_ranges(raw: str, *, enabled: bool) -> list[str] | None:
    ranges = [item.strip() for item in re.split(r"[,;\n]+", raw) if item.strip()]
    if ranges and not enabled:
        raise ValueError("B509 ranges require you to enable the B509 dump")
    for item in ranges:
        parse_b509_range(item)
    return ranges or None


class ScanSetupApp(App[ScanSetup | None]):
    """Interactive scan configuration. It never constructs or calls a transport."""

    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    Screen { align: center middle; }
    #scan-setup-panel {
        width: 92; height: 96%; padding: 1 2;
        border: heavy $accent; background: $surface;
    }
    #scan-setup-scroll { height: 1fr; }
    .field-label { margin-top: 1; }
    #scan-setup-actions { height: 3; margin-top: 1; }
    #scan-setup-status { min-height: 2; color: $error; }
    #scan-advanced { margin-top: 1; }
    """

    def __init__(self, *, initial: ScanSetup, preset_from_argv: bool) -> None:
        super().__init__()
        if initial.preset not in _PRESET_DESCRIPTIONS:
            raise ValueError("initial preset must be recommended, full, research, or custom")
        if initial.planner_ui not in {value for _, value in _PLANNER_OPTIONS}:
            raise ValueError("initial planner_ui must be auto, textual, or classic")
        self._initial = initial
        self._preset_from_argv = preset_from_argv

    def compose(self) -> ComposeResult:
        initial = self._initial
        description = _PRESET_DESCRIPTIONS[initial.preset]
        if self._preset_from_argv:
            description += " Locked by --preset."
        advanced = Collapsible(
            Checkbox(
                "Use bundled offline fixture (no device I/O)",
                value=initial.dry_run,
                id="scan-dry-run",
            ),
            Label("Trace file", classes="field-label"),
            Input(value=str(initial.trace_file or ""), id="trace-file"),
            Label("ebusd annotation CSV", classes="field-label"),
            Input(value=str(initial.ebusd_csv_path or ""), id="ebusd-csv-path"),
            Label("myVaillant mapping CSV", classes="field-label"),
            Input(value=str(initial.myvaillant_map_path or ""), id="myvaillant-map-path"),
            Checkbox("Read B509 registers", value=initial.b509_dump, id="b509-dump"),
            Label("B509 ranges (comma separated)", classes="field-label"),
            Input(value=",".join(initial.b509_range or []), id="b509-range"),
            Checkbox("Read B555 timers", value=initial.b555_dump, id="b555-dump"),
            Checkbox("Read B516 energy data", value=initial.b516_dump, id="b516-dump"),
            Label("Planner rendering", classes="field-label"),
            Select(
                _PLANNER_OPTIONS,
                value=initial.planner_ui,
                allow_blank=False,
                id="planner-ui",
            ),
            Checkbox("Redact identity in console output", value=initial.redact, id="scan-redact"),
            Checkbox("Show scan tips", value=not initial.no_tips, id="scan-show-tips"),
            title="Advanced and read-only options",
            collapsed=True,
            id="scan-advanced",
        )
        yield Vertical(
            Label("Configure scan"),
            VerticalScroll(
                Label("Coverage preset", classes="field-label"),
                Select(
                    _PRESET_OPTIONS,
                    value=initial.preset,
                    allow_blank=False,
                    disabled=self._preset_from_argv,
                    id="scan-preset",
                ),
                Static(description, id="preset-description"),
                Label("Destination", classes="field-label"),
                Input(value=initial.dst, id="scan-destination"),
                Label("Output directory", classes="field-label"),
                Input(value=str(initial.output_dir), id="scan-output-dir"),
                advanced,
                id="scan-setup-scroll",
            ),
            Horizontal(
                Button("Continue", id="scan-continue", variant="primary"),
                Button("Cancel", id="scan-cancel"),
                id="scan-setup-actions",
            ),
            Static("", id="scan-setup-status"),
            id="scan-setup-panel",
        )

    def on_mount(self) -> None:
        self.query_one("#scan-preset", Select).focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id != "scan-preset" or self._preset_from_argv:
            return
        value = event.value
        if isinstance(value, str) and value in _PRESET_DESCRIPTIONS:
            self.query_one("#preset-description", Static).update(_PRESET_DESCRIPTIONS[value])

    def _selected_setup(self) -> ScanSetup:
        preset = self.query_one("#scan-preset", Select).value
        if not isinstance(preset, str) or preset not in _PRESET_DESCRIPTIONS:
            raise ValueError("Choose a scan preset")
        planner_ui = self.query_one("#planner-ui", Select).value
        if not isinstance(planner_ui, str) or planner_ui not in {
            value for _, value in _PLANNER_OPTIONS
        }:
            raise ValueError("Choose a planner rendering mode")
        output_text = self.query_one("#scan-output-dir", Input).value.strip()
        if not output_text:
            raise ValueError("Output directory must not be empty")
        output_dir = Path(output_text).expanduser()
        if output_dir.exists() and not output_dir.is_dir():
            raise ValueError("Output directory points to an existing file")
        b509_dump = self.query_one("#b509-dump", Checkbox).value
        return ScanSetup(
            preset=preset,
            dst=_destination(self.query_one("#scan-destination", Input).value),
            dry_run=self.query_one("#scan-dry-run", Checkbox).value,
            output_dir=output_dir,
            ebusd_csv_path=_csv_path(
                self.query_one("#ebusd-csv-path", Input).value,
                label="ebusd CSV path",
            ),
            myvaillant_map_path=_csv_path(
                self.query_one("#myvaillant-map-path", Input).value,
                label="myVaillant map path",
            ),
            trace_file=_optional_path(
                self.query_one("#trace-file", Input).value,
                label="Trace file",
            ),
            b509_range=_b509_ranges(
                self.query_one("#b509-range", Input).value,
                enabled=b509_dump,
            ),
            b509_dump=b509_dump,
            b555_dump=self.query_one("#b555-dump", Checkbox).value,
            b516_dump=self.query_one("#b516-dump", Checkbox).value,
            planner_ui=planner_ui,
            no_tips=not self.query_one("#scan-show-tips", Checkbox).value,
            redact=self.query_one("#scan-redact", Checkbox).value,
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "scan-cancel":
            self.action_cancel()
            return
        if event.button.id != "scan-continue":
            return
        try:
            setup = self._selected_setup()
        except (TypeError, ValueError) as exc:
            self.query_one("#scan-setup-status", Static).update(str(exc))
            return
        self.exit(setup)

    def action_cancel(self) -> None:
        self.exit(None)


class ArtifactOpenApp(App[Path | None]):
    """Visual JSON artifact selector with local path validation only."""

    BINDINGS: ClassVar = [Binding("escape", "cancel", "Cancel")]
    CSS = """
    Screen { align: center middle; }
    #artifact-open-panel {
        width: 80; height: auto; padding: 1 2;
        border: heavy $accent; background: $surface;
    }
    #artifact-open-actions { height: 3; margin-top: 1; }
    #artifact-open-status { min-height: 2; color: $error; }
    """

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label("Open scan artifact"),
            Static("Choose an existing JSON scan artifact."),
            Input(placeholder="/path/to/scan.json", id="artifact-path"),
            Horizontal(
                Button("Open", id="artifact-open", variant="primary"),
                Button("Cancel", id="artifact-cancel"),
                id="artifact-open-actions",
            ),
            Static("", id="artifact-open-status"),
            id="artifact-open-panel",
        )

    def on_mount(self) -> None:
        self.query_one("#artifact-path", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "artifact-cancel":
            self.action_cancel()
            return
        if event.button.id != "artifact-open":
            return
        raw = self.query_one("#artifact-path", Input).value.strip()
        path = Path(raw).expanduser() if raw else None
        if path is None or not path.exists() or not path.is_file():
            self.query_one("#artifact-open-status", Static).update(
                "Artifact path must be an existing file"
            )
            return
        if path.suffix.lower() != ".json":
            self.query_one("#artifact-open-status", Static).update(
                "Artifact path must use the .json extension"
            )
            return
        self.exit(path)

    def action_cancel(self) -> None:
        self.exit(None)


def run_scan_setup(*, initial: ScanSetup, preset_from_argv: bool) -> ScanSetup | None:
    """Run visual setup and return the accepted configuration or ``None``."""

    return ScanSetupApp(initial=initial, preset_from_argv=preset_from_argv).run()


def run_artifact_open_modal() -> Path | None:
    """Run the visual JSON artifact selector and return its path or ``None``."""

    return ArtifactOpenApp().run()


__all__ = [
    "ArtifactOpenApp",
    "ScanSetup",
    "ScanSetupApp",
    "run_artifact_open_modal",
    "run_scan_setup",
]
