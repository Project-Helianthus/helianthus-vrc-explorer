from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from ..scanner.observer import ScanObserver
from .emphasis import rich_star_bold_text

_PHASE_LABELS: dict[str, str] = {
    "group_discovery": "Group Discovery",
    "constraint_probe": "Constraint Probe",
    "instance_discovery": "Instance Discovery",
    "register_scan": "Register Scan",
    "b555_dump": "B555 Dump",
    "b516_dump": "B516 Dump",
    "b509_dump": "B509 Dump",
}


def _styled(level: str) -> tuple[str, str]:
    icon = "•"
    if level == "warn":
        return ("⚠", "yellow")
    if level == "error":
        return ("✗", "red")
    if level == "info":
        return ("✓", "green")
    return (icon, "white")


@dataclass(slots=True)
class _Task:
    id: TaskID
    phase: str
    total: int


@dataclass(frozen=True, slots=True)
class ScanSessionPreface:
    app_line: str
    scan_line: str
    rows: tuple[tuple[str, str], ...]


def _render_session_preface(preface: ScanSessionPreface) -> Panel:
    rows = Table.grid(expand=True)
    rows.add_column(style="bold")
    rows.add_column()
    for label, value in preface.rows:
        rows.add_row(f"{label}:", rich_star_bold_text(value))

    body = Group(
        Text(preface.app_line, style="bold"),
        Text(preface.scan_line),
        Rule(style="dim"),
        rows,
    )
    return Panel(body, box=box.ROUNDED)


class NullScanObserver(AbstractContextManager["NullScanObserver"], ScanObserver):
    def __enter__(self) -> NullScanObserver:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def phase_start(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:  # noqa: ARG002
        return None

    def phase_set_total(self, phase: str, *, total: int) -> None:  # noqa: ARG002
        return None

    def phase_finish(self, phase: str) -> None:  # noqa: ARG002
        return None

    def status(self, message: str) -> None:  # noqa: ARG002
        return None

    def log(self, message: str, *, level: str = "info") -> None:  # noqa: ARG002
        return None

    def suspend(self) -> AbstractContextManager[None]:
        return nullcontext()


class RichScanObserver(AbstractContextManager["RichScanObserver"], ScanObserver):
    """Rich-based observer used for interactive scans (TTY)."""

    def __init__(
        self,
        *,
        console: Console,
        title: str,
        subtitle_lines: list[str] | None = None,
        show_tips: bool = True,
        session_preface: ScanSessionPreface | None = None,
    ) -> None:
        self._console = console
        self._title = title
        self._subtitle_lines = subtitle_lines or []
        self._show_tips = show_tips
        self._session_preface = session_preface
        self._started = False
        self._suspend_depth = 0
        self._progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[status]}", style="dim"),
            console=console,
            transient=True,
            expand=True,
            refresh_per_second=10,
        )
        self._tasks: dict[str, _Task] = {}
        self._current_phase: str | None = None

    def __enter__(self) -> RichScanObserver:
        self._progress.start()
        self._started = True
        header_parts: list[RenderableType] = []
        if self._session_preface is None:
            header_parts.append(Rule(self._title, style="dim"))
        else:
            header_parts.append(_render_session_preface(self._session_preface))
        for line in self._subtitle_lines:
            header_parts.append(Text(line, style="dim"))
        if self._show_tips:
            header_parts.extend(
                [
                    Text(
                        "Tip: set `--trace-file` to capture ebusd request/response exchanges.",
                        style="dim",
                    ),
                    Text(
                        "Tip: press `p` during Register Scan to open the scan planner.",
                        style="dim",
                    ),
                ]
            )
        header = Group(
            *header_parts,
        )
        self._progress.console.print(header)
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._started:
            self._progress.stop()
        self._started = False
        self._suspend_depth = 0
        return None

    def phase_start(self, phase: str, *, total: int) -> None:
        label = _PHASE_LABELS.get(phase, phase)
        if phase in self._tasks:
            task = self._tasks[phase]
            self._progress.update(task.id, description=label, completed=0, total=total, status="")
            task.total = total
        else:
            task_id = self._progress.add_task(label, total=total, status="")
            self._tasks[phase] = _Task(id=task_id, phase=phase, total=total)
        self._current_phase = phase

        # Clear other phase status fields so only one "current operation" line shows.
        for other_phase, task in self._tasks.items():
            if other_phase != phase:
                self._progress.update(task.id, status="")

    def phase_advance(self, phase: str, *, advance: int = 1) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        self._current_phase = phase
        self._progress.advance(task.id, advance)

    def phase_set_total(self, phase: str, *, total: int) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        self._progress.update(task.id, total=total)
        task.total = total

    def phase_finish(self, phase: str) -> None:
        task = self._tasks.get(phase)
        if task is None:
            return
        self._progress.update(task.id, completed=task.total)
        self._progress.update(task.id, status="")

    def status(self, message: str) -> None:
        if self._current_phase is None:
            return
        task = self._tasks.get(self._current_phase)
        if task is None:
            return
        self._progress.update(task.id, status=message)

    def log(self, message: str, *, level: str = "info") -> None:
        icon, style = _styled(level)
        self._progress.console.print(f"[{style}]{icon} {message}[/{style}]")

    def suspend(self) -> AbstractContextManager[None]:
        @contextmanager
        def _cm() -> Iterator[None]:
            if not self._started:
                yield None
                return

            self._suspend_depth += 1
            if self._suspend_depth == 1:
                self._progress.stop()
            try:
                yield None
            finally:
                self._suspend_depth -= 1
                if self._started and self._suspend_depth == 0:
                    self._progress.start()

        return _cm()


def make_scan_observer(
    *,
    console: Console,
    title: str,
    subtitle_lines: list[str] | None = None,
    show_tips: bool = True,
    session_preface: ScanSessionPreface | None = None,
) -> AbstractContextManager[ScanObserver]:
    if console.is_terminal:
        return RichScanObserver(
            console=console,
            title=title,
            subtitle_lines=subtitle_lines,
            show_tips=show_tips,
            session_preface=session_preface,
        )
    return NullScanObserver()
