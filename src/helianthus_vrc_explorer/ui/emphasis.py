from __future__ import annotations

from html import escape as _escape_html

from rich.text import Text


def _iter_star_segments(text: str) -> list[tuple[str, bool]]:
    segments: list[tuple[str, bool]] = []
    cursor = 0
    while True:
        start = text.find("*", cursor)
        if start < 0:
            segments.append((text[cursor:], False))
            break
        end = text.find("*", start + 1)
        if end < 0:
            segments.append((text[cursor:], False))
            break
        segments.append((text[cursor:start], False))
        segments.append((text[start + 1 : end], True))
        cursor = end + 1
    return [(segment, bold) for segment, bold in segments if segment]


def rich_star_bold_text(text: str) -> Text:
    out = Text()
    for segment, bold in _iter_star_segments(text):
        out.append(segment, style="bold" if bold else "")
    return out


def strip_star_bold_markers(text: str) -> str:
    return "".join(segment for segment, _bold in _iter_star_segments(text))


def html_star_bold(text: str) -> str:
    parts: list[str] = []
    for segment, bold in _iter_star_segments(text):
        escaped = _escape_html(segment)
        if bold:
            parts.append(f"<strong>{escaped}</strong>")
        else:
            parts.append(escaped)
    return "".join(parts)
