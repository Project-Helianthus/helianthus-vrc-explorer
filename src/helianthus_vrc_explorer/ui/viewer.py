from __future__ import annotations

import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..protocol.parser import ValueParseError, parse_typed_value


def candidate_type_specs_for_length(length: int) -> tuple[str, ...]:
    """Return decode candidates for values of exactly `length` bytes."""

    if length <= 0:
        return ()
    if length == 1:
        return ("UCH", "I8", "BOOL", "HEX:1")
    if length == 2:
        return ("UIN", "I16", "HEX:2")
    if length == 3:
        return ("HDA:3", "HTI", "HEX:3")
    if length == 4:
        return ("EXP", "U32", "I32", "HEX:4")
    # Unknown widths: allow "raw view" and "best-effort string".
    return (f"HEX:{length}", "STR:*")


def cycle_type_spec(current: str | None, candidates: Sequence[str]) -> str | None:
    """Cycle `current` to the next candidate, wrapping around.

    If `current` is None or not present in `candidates`, returns the first candidate.
    """

    if not candidates:
        return None
    if current is None:
        return candidates[0]
    normalized = current.strip().upper()
    normalized_candidates = [c.strip().upper() for c in candidates]
    try:
        idx = normalized_candidates.index(normalized)
    except ValueError:
        return candidates[0]
    return candidates[(idx + 1) % len(candidates)]


def _ensure_meta_dict(artifact: dict[str, Any]) -> dict[str, Any]:
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        artifact["meta"] = meta
    return meta


def _ensure_type_overrides_dict(meta: dict[str, Any]) -> dict[str, Any]:
    overrides = meta.get("type_overrides")
    if not isinstance(overrides, dict):
        overrides = {}
        meta["type_overrides"] = overrides
    return overrides


def get_row_type_override(
    artifact: dict[str, Any],
    *,
    group_key: str,
    rr_key: str,
    namespace_key: str | None = None,
) -> str | None:
    meta = artifact.get("meta")
    if not isinstance(meta, dict):
        return None
    overrides = meta.get("type_overrides")
    if not isinstance(overrides, dict):
        return None
    group_overrides = overrides.get(group_key)
    if not isinstance(group_overrides, dict):
        return None
    if namespace_key is not None:
        namespaces = group_overrides.get("namespaces")
        if isinstance(namespaces, dict):
            namespace_overrides = namespaces.get(namespace_key)
            if isinstance(namespace_overrides, dict):
                value = namespace_overrides.get(rr_key)
                if isinstance(value, str):
                    return value
    value = group_overrides.get(rr_key)
    return value if isinstance(value, str) else None


def set_row_type_override(
    artifact: dict[str, Any],
    *,
    group_key: str,
    rr_key: str,
    type_spec: str,
    namespace_key: str | None = None,
) -> None:
    meta = _ensure_meta_dict(artifact)
    overrides = _ensure_type_overrides_dict(meta)
    group_overrides = overrides.get(group_key)
    if not isinstance(group_overrides, dict):
        group_overrides = {}
        overrides[group_key] = group_overrides
    if namespace_key is None:
        group_overrides[rr_key] = type_spec
        return
    namespaces = group_overrides.get("namespaces")
    if not isinstance(namespaces, dict):
        namespaces = {}
        group_overrides["namespaces"] = namespaces
    namespace_overrides = namespaces.get(namespace_key)
    if not isinstance(namespace_overrides, dict):
        namespace_overrides = {}
        namespaces[namespace_key] = namespace_overrides
    namespace_overrides[rr_key] = type_spec


def _group_instances(group_obj: dict[str, Any], *, namespace_key: str | None) -> dict[str, Any]:
    if namespace_key is not None and bool(group_obj.get("dual_namespace")):
        namespaces = group_obj.get("namespaces")
        if not isinstance(namespaces, dict):
            return {}
        namespace_obj = namespaces.get(namespace_key)
        if not isinstance(namespace_obj, dict):
            return {}
        instances = namespace_obj.get("instances")
        return instances if isinstance(instances, dict) else {}
    instances = group_obj.get("instances")
    return instances if isinstance(instances, dict) else {}


def _iter_row_entries(
    artifact: dict[str, Any],
    *,
    group_key: str,
    rr_key: str,
    namespace_key: str | None = None,
) -> Iterator[dict[str, Any]]:
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return
    group_obj = groups.get(group_key)
    if not isinstance(group_obj, dict):
        return
    instances = _group_instances(group_obj, namespace_key=namespace_key)
    for instance_obj in instances.values():
        if not isinstance(instance_obj, dict):
            continue
        registers = instance_obj.get("registers")
        if not isinstance(registers, dict):
            continue
        entry = registers.get(rr_key)
        if isinstance(entry, dict):
            yield entry


def _value_len_bytes(entry: dict[str, Any]) -> int | None:
    raw_hex = entry.get("raw_hex")
    if not isinstance(raw_hex, str) or not raw_hex:
        return None
    try:
        return len(bytes.fromhex(raw_hex))
    except ValueError:
        return None


def apply_row_type_override(
    artifact: dict[str, Any],
    *,
    group_key: str,
    rr_key: str,
    type_spec: str,
    namespace_key: str | None = None,
) -> None:
    """Apply a per-row override and recompute values/errors for all instances in that row."""

    set_row_type_override(
        artifact,
        group_key=group_key,
        rr_key=rr_key,
        type_spec=type_spec,
        namespace_key=namespace_key,
    )
    for entry in _iter_row_entries(
        artifact,
        group_key=group_key,
        rr_key=rr_key,
        namespace_key=namespace_key,
    ):
        raw_hex = entry.get("raw_hex")
        if not isinstance(raw_hex, str) or not raw_hex:
            continue
        try:
            value_bytes = bytes.fromhex(raw_hex)
        except ValueError:
            continue
        try:
            parsed = parse_typed_value(type_spec, value_bytes)
        except ValueParseError as exc:
            entry["type"] = type_spec
            entry["value"] = None
            entry["error"] = f"parse_error: {exc}"
        else:
            entry["type"] = type_spec
            entry["value"] = parsed
            entry["error"] = None


def _sorted_hex_keys(keys: Sequence[str]) -> list[str]:
    parsed: list[tuple[int, str]] = []
    for k in keys:
        if not isinstance(k, str):
            continue
        try:
            parsed.append((int(k, 0), k))
        except ValueError:
            continue
    parsed.sort(key=lambda x: x[0])
    return [k for (_n, k) in parsed]


@dataclass(slots=True)
class _Sheet:
    group_key: str
    name: str
    namespace_key: str | None
    namespace_label: str | None
    descriptor: float | None
    instance_keys: list[str]
    rr_keys: list[str]


def _build_sheets(artifact: dict[str, Any]) -> list[_Sheet]:
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return []

    sheets: list[_Sheet] = []
    for group_key, group_obj in groups.items():
        if not isinstance(group_key, str) or not isinstance(group_obj, dict):
            continue
        descriptor_obj = group_obj.get(
            "descriptor_observed",
            group_obj.get("descriptor_type"),
        )
        descriptor: float | None
        if isinstance(descriptor_obj, (int, float)) and not isinstance(descriptor_obj, bool):
            descriptor = float(descriptor_obj)
        else:
            descriptor = None

        namespace_views: list[tuple[str | None, str | None, dict[str, Any]]]
        if bool(group_obj.get("dual_namespace")):
            namespaces = group_obj.get("namespaces")
            if not isinstance(namespaces, dict):
                continue
            namespace_views = []
            for namespace_key in _sorted_hex_keys([k for k in namespaces if isinstance(k, str)]):
                namespace_obj = namespaces.get(namespace_key)
                if not isinstance(namespace_obj, dict):
                    continue
                label_obj = namespace_obj.get("label")
                namespace_label = label_obj if isinstance(label_obj, str) else namespace_key
                namespace_views.append(
                    (
                        namespace_key,
                        namespace_label,
                        _group_instances(group_obj, namespace_key=namespace_key),
                    )
                )
        else:
            namespace_views = [(None, None, _group_instances(group_obj, namespace_key=None))]

        for ns_key, ns_label, instances in namespace_views:
            instance_keys = _sorted_hex_keys([k for k in instances if isinstance(k, str)])

            rr_key_set: set[str] = set()
            for instance_obj in instances.values():
                if not isinstance(instance_obj, dict):
                    continue
                registers = instance_obj.get("registers")
                if not isinstance(registers, dict):
                    continue
                for rr_key in registers:
                    if isinstance(rr_key, str):
                        rr_key_set.add(rr_key)

            rr_keys = _sorted_hex_keys(sorted(rr_key_set))

            sheets.append(
                _Sheet(
                    group_key=group_key,
                    name=str(group_obj.get("name") or "Unknown"),
                    namespace_key=ns_key,
                    namespace_label=ns_label,
                    descriptor=descriptor,
                    instance_keys=instance_keys,
                    rr_keys=rr_keys,
                )
            )

    sheets.sort(key=lambda s: int(s.group_key, 0))
    return sheets


@dataclass(slots=True)
class _State:
    sheets: list[_Sheet]
    sheet_idx: int = 0
    row_idx: int = 0
    col_idx: int = 0
    row_scroll: int = 0
    col_scroll: int = 0
    dirty: bool = False


def _format_value(value: object | None) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        # Keep it compact; users can inspect raw hex in the details pane.
        return f"{value:.6g}"
    return str(value)


def _cell_text(entry: dict[str, Any] | None, *, selected: bool) -> Text:
    if entry is None:
        t = Text("")
        if selected:
            t.stylize("reverse")
        return t

    value = entry.get("value")
    raw_hex = entry.get("raw_hex")
    error = entry.get("error")

    val_txt = _format_value(value)
    raw_txt = raw_hex if isinstance(raw_hex, str) else ""
    raw_short = raw_txt[:16] + ("…" if len(raw_txt) > 16 else "")

    err_txt = str(error) if isinstance(error, str) else ""
    err_short = err_txt.split(":", 1)[0] if err_txt else ""

    line2 = raw_short
    if err_short:
        line2 = f"{raw_short} !{err_short}"

    text = Text(f"{val_txt}\n{line2}", style="red" if err_txt else "white")
    if selected:
        text.stylize("reverse")
    return text


def _get_entry(
    artifact: dict[str, Any],
    *,
    group_key: str,
    instance_key: str,
    rr_key: str,
    namespace_key: str | None = None,
) -> dict[str, Any] | None:
    groups = artifact.get("groups")
    if not isinstance(groups, dict):
        return None
    group_obj = groups.get(group_key)
    if not isinstance(group_obj, dict):
        return None
    instances = _group_instances(group_obj, namespace_key=namespace_key)
    instance_obj = instances.get(instance_key)
    if not isinstance(instance_obj, dict):
        return None
    registers = instance_obj.get("registers")
    if not isinstance(registers, dict):
        return None
    entry = registers.get(rr_key)
    return entry if isinstance(entry, dict) else None


def _render(
    console: Console,
    artifact: dict[str, Any],
    state: _State,
) -> RenderableType:
    sheet = state.sheets[state.sheet_idx]
    group_key = sheet.group_key
    namespace_key = sheet.namespace_key

    # Viewport sizing.
    term_w = console.size.width
    term_h = console.size.height
    _ = term_w

    # Rough layout budget:
    # - header panel: ~5 lines
    # - details panel: ~6 lines
    # Remaining goes to table rows. Each RR row renders as a single row (cells are 2-line).
    max_rows = max(3, (term_h - 14))
    max_cols = max(1, min(len(sheet.instance_keys), (term_w - 12) // 18))

    row_scroll = max(0, min(state.row_scroll, max(0, len(sheet.rr_keys) - max_rows)))
    col_scroll = max(0, min(state.col_scroll, max(0, len(sheet.instance_keys) - max_cols)))
    state.row_scroll = row_scroll
    state.col_scroll = col_scroll

    visible_rr = sheet.rr_keys[row_scroll : row_scroll + max_rows]
    visible_ii = sheet.instance_keys[col_scroll : col_scroll + max_cols]

    # Clamp selection into bounds.
    state.row_idx = max(0, min(state.row_idx, max(0, len(sheet.rr_keys) - 1)))
    state.col_idx = max(0, min(state.col_idx, max(0, len(sheet.instance_keys) - 1)))

    selected_rr_key = sheet.rr_keys[state.row_idx] if sheet.rr_keys else ""
    selected_ii_key = sheet.instance_keys[state.col_idx] if sheet.instance_keys else ""

    header = Text.assemble(
        ("Results Viewer", "bold"),
        ("  ", ""),
        (f"Group {group_key}", "cyan"),
        ("  ", ""),
        (sheet.name, "white"),
        ("  ", ""),
        (
            sheet.namespace_label if isinstance(sheet.namespace_label, str) else "single namespace",
            "magenta",
        ),
        ("  ", ""),
        (f"desc={sheet.descriptor:g}" if sheet.descriptor is not None else "desc=?"),
        ("  ", ""),
        (f"[{state.sheet_idx + 1}/{len(state.sheets)}]", "dim"),
    )
    help_line = Text(
        "Keys: arrows/hjkl move | Tab/Shift-Tab switch group | Space cycle row type | q quit",
        style="dim",
    )

    override = get_row_type_override(
        artifact,
        group_key=group_key,
        rr_key=selected_rr_key,
        namespace_key=namespace_key,
    )
    selected_entry = (
        _get_entry(
            artifact,
            group_key=group_key,
            instance_key=selected_ii_key,
            rr_key=selected_rr_key,
            namespace_key=namespace_key,
        )
        if selected_rr_key and selected_ii_key
        else None
    )
    raw_hex = selected_entry.get("raw_hex") if isinstance(selected_entry, dict) else None
    raw_len = _value_len_bytes(selected_entry) if isinstance(selected_entry, dict) else None

    details_lines: list[str] = []
    details_lines.append(
        f"Selected: NS={sheet.namespace_label or '-'} RR={selected_rr_key} II={selected_ii_key}"
    )
    details_lines.append(
        f"type={selected_entry.get('type') if selected_entry else None} override={override}"
    )
    details_lines.append(f"raw_len={raw_len} raw_hex={raw_hex}")
    details_lines.append(f"error={selected_entry.get('error') if selected_entry else None}")
    details = Text("\n".join(details_lines), style="dim")

    table = Table(show_header=True, header_style="bold dim", box=None, pad_edge=False)
    table.add_column("RR", style="magenta", no_wrap=True)
    for ii in visible_ii:
        table.add_column(ii, style="white", no_wrap=True)

    for rr in visible_rr:
        row_cells: list[RenderableType] = [Text(rr, style="magenta")]
        for ii in visible_ii:
            entry = _get_entry(
                artifact,
                group_key=group_key,
                instance_key=ii,
                rr_key=rr,
                namespace_key=namespace_key,
            )
            selected = (ii == selected_ii_key) and (rr == selected_rr_key)
            row_cells.append(_cell_text(entry, selected=selected))
        table.add_row(*row_cells)

    header_panel = Panel(Group(header, help_line), style="dim", padding=(1, 1))
    details_panel = Panel(details, title="Details", title_align="left", style="dim", padding=(1, 1))
    return Group(header_panel, table, details_panel)


def _adjust_scroll_to_selection(state: _State, *, max_rows: int, max_cols: int) -> None:
    sheet = state.sheets[state.sheet_idx]
    if state.row_idx < state.row_scroll:
        state.row_scroll = state.row_idx
    if state.row_idx >= state.row_scroll + max_rows:
        state.row_scroll = state.row_idx - max_rows + 1
    if state.col_idx < state.col_scroll:
        state.col_scroll = state.col_idx
    if state.col_idx >= state.col_scroll + max_cols:
        state.col_scroll = state.col_idx - max_cols + 1

    state.row_scroll = max(0, min(state.row_scroll, max(0, len(sheet.rr_keys) - max_rows)))
    state.col_scroll = max(0, min(state.col_scroll, max(0, len(sheet.instance_keys) - max_cols)))


def _read_key() -> str:
    # Raw mode; stdin provides bytes.
    ch = os.read(sys.stdin.fileno(), 1)
    if not ch:
        return ""
    if ch == b"\x03":  # Ctrl+C
        raise KeyboardInterrupt
    if ch == b"\x1b":
        seq = os.read(sys.stdin.fileno(), 2)
        if seq == b"[A":
            return "UP"
        if seq == b"[B":
            return "DOWN"
        if seq == b"[C":
            return "RIGHT"
        if seq == b"[D":
            return "LEFT"
        if seq == b"[Z":
            return "SHIFT_TAB"
        return "ESC"
    if ch == b"\t":
        return "TAB"
    if ch == b" ":
        return "SPACE"
    try:
        return ch.decode("utf-8")
    except UnicodeDecodeError:
        return ""


@contextmanager
def _raw_terminal() -> Iterator[None]:
    if sys.platform == "win32":
        yield None
        return

    import termios  # noqa: PLC0415
    import tty  # noqa: PLC0415

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        yield None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def run_results_viewer(console: Console, artifact: dict[str, Any]) -> bool:
    """Run the post-scan interactive viewer.

    Returns:
        True if the artifact was modified (type overrides applied), else False.
    """

    interactive = (
        console.is_terminal
        and sys.stdin.isatty()
        and sys.stdout.isatty()
        and sys.platform != "win32"
    )
    if not interactive:
        return False

    sheets = _build_sheets(artifact)
    if not sheets:
        return False

    state = _State(sheets=sheets)

    with (
        Live(
            _render(console, artifact, state),
            console=console,
            transient=True,
            screen=True,
            auto_refresh=False,
        ) as live,
        _raw_terminal(),
    ):
        while True:
            # Recompute viewport extents for scroll adjustments.
            term_w = console.size.width
            term_h = console.size.height
            max_rows = max(3, (term_h - 14))
            max_cols = max(
                1, min(len(state.sheets[state.sheet_idx].instance_keys), (term_w - 12) // 18)
            )

            key = _read_key()
            if not key:
                continue

            if key in {"q", "Q", "ESC"}:
                break

            if key in {"TAB"}:
                state.sheet_idx = (state.sheet_idx + 1) % len(state.sheets)
                state.row_idx = 0
                state.col_idx = 0
                state.row_scroll = 0
                state.col_scroll = 0
            elif key in {"SHIFT_TAB"}:
                state.sheet_idx = (state.sheet_idx - 1) % len(state.sheets)
                state.row_idx = 0
                state.col_idx = 0
                state.row_scroll = 0
                state.col_scroll = 0
            elif key in {"UP", "k", "K"}:
                state.row_idx = max(0, state.row_idx - 1)
            elif key in {"DOWN", "j", "J"}:
                sheet = state.sheets[state.sheet_idx]
                state.row_idx = min(len(sheet.rr_keys) - 1, state.row_idx + 1)
            elif key in {"LEFT", "h", "H"}:
                state.col_idx = max(0, state.col_idx - 1)
            elif key in {"RIGHT", "l", "L"}:
                sheet = state.sheets[state.sheet_idx]
                state.col_idx = min(len(sheet.instance_keys) - 1, state.col_idx + 1)
            elif key == "SPACE":
                sheet = state.sheets[state.sheet_idx]
                if sheet.rr_keys and sheet.instance_keys:
                    rr_key = sheet.rr_keys[state.row_idx]

                    # Use an existing override, or fall back to the first cell's type.
                    current = get_row_type_override(
                        artifact,
                        group_key=sheet.group_key,
                        rr_key=rr_key,
                        namespace_key=sheet.namespace_key,
                    )
                    if current is None:
                        first_entry = _get_entry(
                            artifact,
                            group_key=sheet.group_key,
                            instance_key=sheet.instance_keys[state.col_idx],
                            rr_key=rr_key,
                            namespace_key=sheet.namespace_key,
                        )
                        current = first_entry.get("type") if isinstance(first_entry, dict) else None

                    # Determine byte length from the first entry in the row with raw bytes.
                    row_len: int | None = None
                    for entry in _iter_row_entries(
                        artifact,
                        group_key=sheet.group_key,
                        rr_key=rr_key,
                        namespace_key=sheet.namespace_key,
                    ):
                        row_len = _value_len_bytes(entry)
                        if row_len is not None:
                            break
                    if row_len is not None and row_len > 0:
                        candidates = candidate_type_specs_for_length(row_len)
                        next_type = cycle_type_spec(current, candidates)
                        if next_type is not None:
                            apply_row_type_override(
                                artifact,
                                group_key=sheet.group_key,
                                rr_key=rr_key,
                                type_spec=next_type,
                                namespace_key=sheet.namespace_key,
                            )
                            state.dirty = True

            _adjust_scroll_to_selection(state, max_rows=max_rows, max_cols=max_cols)
            live.update(_render(console, artifact, state), refresh=True)

    return state.dirty
